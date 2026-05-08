package com.thesis.carapace.proxy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.BinaryMessage;
import org.springframework.web.socket.WebSocketSession;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Transparently decrypts AES-256-GCM encrypted file downloads coming back
 * from CFMS so the browser can consume plaintext chunks directly.
 *
 * <p>Wire format on the CFMS→client direction (multiplex frames):
 * <ol>
 *   <li>{@code transfer_file} — file metadata (sha256, file_size, total_chunks, ...)</li>
 *   <li>One or more {@code file_chunk} envelopes, each carrying a base64 ciphertext piece</li>
 *   <li>{@code aes_key} envelope with key + nonce + GCM tag</li>
 *   <li>(no explicit conclusion for plain downloads — see CFMS connection_handler)</li>
 * </ol>
 *
 * <p>This class intercepts {@code file_chunk} (buffers ciphertext, does not forward)
 * and {@code aes_key} (performs GCM decryption, then bursts plaintext chunks back
 * to the client as ordinary {@code file_chunk} envelopes — no key material exposed).
 * All other frames pass through unchanged.
 */
@Slf4j
@Component
public class CfmsDownloadDecryptor {

    private static final byte FRAME_TYPE_PROCESS = 0;
    private static final byte FRAME_TYPE_CONCLUSION = 1;
    private static final int HEADER_SIZE = 5;

    private final ObjectMapper mapper = new ObjectMapper();

    /** key = clientSessionId + ":" + frameId */
    private final Map<String, DownloadStream> streams = new ConcurrentHashMap<>();

    /**
     * Process a single frame from CFMS bound for the client. Either forwards
     * (possibly transformed) frames via {@code forward}, or buffers them.
     *
     * @return true if the frame was handled (do not double-forward); false if
     *         the caller should fall back to plain forwarding (e.g. parsing
     *         failed and we want graceful degradation).
     */
    public boolean handleFromCfms(
            WebSocketSession clientSession,
            byte[] framePayload,
            FrameSender forward
    ) {
        if (framePayload.length < HEADER_SIZE) {
            return false;
        }

        int frameId = ByteBuffer.wrap(framePayload, 0, 4).getInt();
        byte frameType = framePayload[4];
        String key = clientSession.getId() + ":" + frameId;

        // Conclusion always passes through; clean up any per-stream state.
        if (frameType == FRAME_TYPE_CONCLUSION) {
            streams.remove(key);
            return false;
        }

        // Try to parse the JSON envelope. CFMS PROCESS frames in our protocol
        // are always orjson-dumped objects with an "action" key.
        JsonNode envelope = tryParseJson(framePayload, HEADER_SIZE);
        if (envelope == null || !envelope.hasNonNull("action")) {
            return false;
        }

        String action = envelope.get("action").asText();
        switch (action) {
            case "transfer_file":
                onTransferFile(key, envelope);
                return false; // forward as-is
            case "file_chunk":
                return onFileChunk(key, envelope);
            case "aes_key":
                return onAesKey(key, frameId, envelope, forward);
            default:
                return false;
        }
    }

    /** Drop any in-flight state for this client (called on disconnect). */
    public void onClientDisconnect(WebSocketSession clientSession) {
        String prefix = clientSession.getId() + ":";
        streams.keySet().removeIf(k -> k.startsWith(prefix));
    }

    private void onTransferFile(String key, JsonNode envelope) {
        JsonNode data = envelope.path("data");
        DownloadStream stream = new DownloadStream();
        stream.fileSize = data.path("file_size").asLong(0);
        stream.totalChunks = data.path("total_chunks").asInt(0);
        stream.sha256 = data.path("sha256").asText(null);
        streams.put(key, stream);
    }

    private boolean onFileChunk(String key, JsonNode envelope) {
        DownloadStream stream = streams.get(key);
        if (stream == null) {
            // We never saw a transfer_file for this frame; let the chunk
            // flow through unchanged so the client can choose to error out.
            return false;
        }
        JsonNode data = envelope.path("data");
        int index = data.path("index").asInt(-1);
        String b64 = data.path("chunk").asText("");
        if (index < 0 || b64.isEmpty()) {
            return false;
        }
        try {
            byte[] cipher = Base64.getDecoder().decode(b64);
            stream.encryptedChunks.put(index, cipher);
            stream.totalCipherBytes += cipher.length;
        } catch (IllegalArgumentException e) {
            log.warn("[DECRYPT] non-base64 file_chunk for {}: {}", key, e.getMessage());
            return false;
        }
        // Suppress: we'll send plaintext after aes_key arrives.
        return true;
    }

    private boolean onAesKey(
            String key,
            int frameId,
            JsonNode envelope,
            FrameSender forward
    ) {
        DownloadStream stream = streams.remove(key);
        if (stream == null) {
            return false; // no prior chunks; let it pass through
        }

        JsonNode data = envelope.path("data");
        byte[] aesKey = decodeOrNull(data.path("key").asText(""));
        byte[] nonce = decodeOrNull(data.path("nonce").asText(""));
        byte[] tag = decodeOrNull(data.path("tag").asText(""));

        if (aesKey == null || nonce == null || tag == null) {
            log.warn("[DECRYPT] aes_key envelope missing key/nonce/tag for {}", key);
            return false; // upstream may handle; don't suppress
        }

        // Concatenate ciphertext in chunk-index order.
        byte[] cipher = concatChunks(stream);
        byte[] plaintext;
        try {
            plaintext = decryptGcm(aesKey, nonce, cipher, tag);
        } catch (Exception e) {
            log.error("[DECRYPT] GCM decryption failed for {}: {}", key, e.getMessage());
            // Suppress aes_key but emit a synthetic error CONCLUSION so the
            // client doesn't hang forever waiting on a download that broke.
            sendConclusion(forward, frameId,
                    "{\"code\":500,\"message\":\"Carapace: GCM decryption failed\",\"data\":{}}");
            return true;
        }

        // Burst plaintext back as file_chunk envelopes preserving original chunk
        // boundaries so the frontend's progress accounting still works.
        int cursor = 0;
        for (Map.Entry<Integer, byte[]> e : stream.encryptedChunks.entrySet()) {
            int idx = e.getKey();
            int len = e.getValue().length;
            byte[] plainSlice = new byte[len];
            System.arraycopy(plaintext, cursor, plainSlice, 0, len);
            cursor += len;

            ObjectNode chunkEnv = mapper.createObjectNode();
            chunkEnv.put("action", "file_chunk");
            ObjectNode chunkData = mapper.createObjectNode();
            chunkData.put("index", idx);
            chunkData.put("hash", "");           // recomputing client-side is cheap; skip here
            chunkData.put("chunk", Base64.getEncoder().encodeToString(plainSlice));
            chunkEnv.set("data", chunkData);
            sendProcess(forward, frameId, chunkEnv.toString());
        }

        // Send a synthetic conclusion so the frontend can stop waiting.
        // CFMS itself does not send a conclusion for downloads, so the client
        // currently exits its loop on receiving aes_key. We simulate the same
        // exit signal by sending a conclusion frame instead.
        sendConclusion(forward, frameId,
                "{\"code\":200,\"message\":\"download complete\",\"data\":{}}");
        return true;
    }

    // ----- helpers -----

    private static byte[] concatChunks(DownloadStream stream) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(stream.totalCipherBytes);
        // TreeMap iteration is ordered by chunk index ascending.
        for (byte[] piece : stream.encryptedChunks.values()) {
            baos.writeBytes(piece);
        }
        return baos.toByteArray();
    }

    private static byte[] decryptGcm(byte[] key, byte[] nonce, byte[] cipher, byte[] tag)
            throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(tag.length * 8, nonce));
        // Java's GCM expects ciphertext || tag concatenated.
        byte[] combined = new byte[cipher.length + tag.length];
        System.arraycopy(cipher, 0, combined, 0, cipher.length);
        System.arraycopy(tag, 0, combined, cipher.length, tag.length);
        return c.doFinal(combined);
    }

    private static byte[] decodeOrNull(String b64) {
        if (b64 == null || b64.isEmpty()) return null;
        try {
            return Base64.getDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private JsonNode tryParseJson(byte[] frame, int offset) {
        try {
            return mapper.readTree(new String(
                    frame, offset, frame.length - offset, StandardCharsets.UTF_8));
        } catch (IOException e) {
            return null;
        }
    }

    private static void sendProcess(FrameSender forward, int frameId, String json) {
        forward.send(buildFrame(frameId, FRAME_TYPE_PROCESS, json));
    }

    private static void sendConclusion(FrameSender forward, int frameId, String json) {
        forward.send(buildFrame(frameId, FRAME_TYPE_CONCLUSION, json));
    }

    private static BinaryMessage buildFrame(int frameId, byte frameType, String json) {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[HEADER_SIZE + body.length];
        out[0] = (byte) (frameId >>> 24);
        out[1] = (byte) (frameId >>> 16);
        out[2] = (byte) (frameId >>> 8);
        out[3] = (byte) frameId;
        out[4] = frameType;
        System.arraycopy(body, 0, out, HEADER_SIZE, body.length);
        return new BinaryMessage(out);
    }

    @FunctionalInterface
    public interface FrameSender {
        void send(BinaryMessage frame);
    }

    /**
     * In-flight state for a single download stream. {@code encryptedChunks}
     * is a TreeMap-backed structure so iteration produces chunks in index order
     * regardless of arrival order (CFMS sends them in order today, but this
     * makes us robust against future reordering).
     */
    private static final class DownloadStream {
        long fileSize;
        int totalChunks;
        String sha256;
        int totalCipherBytes;
        final java.util.TreeMap<Integer, byte[]> encryptedChunks = new java.util.TreeMap<>();
    }
}
