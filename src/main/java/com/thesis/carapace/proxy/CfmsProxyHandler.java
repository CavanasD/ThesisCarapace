package com.thesis.carapace.proxy;

import com.thesis.carapace.defender.WafCheckResult;
import com.thesis.carapace.defender.WafEngine;
import com.thesis.carapace.defender.WafEventStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import okio.ByteString;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.*;
import org.springframework.web.socket.handler.AbstractWebSocketHandler;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
@RequiredArgsConstructor
public class CfmsProxyHandler extends AbstractWebSocketHandler {

    @Value("${cfms.internal.url}")
    private String cfmsUrl;

    private final OkHttpClient okHttpClient;
    private final WafEngine wafEngine;
    private final WafEventStore eventStore;
    private final CfmsDownloadDecryptor downloadDecryptor;

    // clientSession.getId() → 连接 CFMS 的 OkHttp WebSocket
    // 用 CompletableFuture 避免 onOpen 回调前收到消息的竞态问题
    private final ConcurrentHashMap<String, CompletableFuture<WebSocket>> cfmsSockets = new ConcurrentHashMap<>();

    // 客户端连入

    @Override
    public void afterConnectionEstablished(WebSocketSession clientSession) {
        eventStore.incrementConnections();
        log.info("[PROXY] Client connected: {} from {}", clientSession.getId(), getIp(clientSession));

        CompletableFuture<WebSocket> future = new CompletableFuture<>();
        cfmsSockets.put(clientSession.getId(), future);

        Request request = new Request.Builder().url(cfmsUrl).build();
        okHttpClient.newWebSocket(request, new WebSocketListener() {

            @Override
            public void onOpen(WebSocket ws, Response response) {
                future.complete(ws);
                log.info("[PROXY] CFMS link up for client {}", clientSession.getId());
            }

            // CFMS → 客户端：交给解密器先处理（GCM 解密、抑制 aes_key），
            // 透明传输 / 非下载帧走原路转发。
            @Override
            public void onMessage(WebSocket ws, ByteString bytes) {
                byte[] frame = bytes.toByteArray();
                boolean handled = downloadDecryptor.handleFromCfms(
                        clientSession,
                        frame,
                        msg -> sendToClient(clientSession, msg)
                );
                if (!handled) {
                    sendToClient(clientSession, new BinaryMessage(frame));
                }
            }

            @Override
            public void onMessage(WebSocket ws, String text) {
                sendToClient(clientSession, new TextMessage(text));
            }

            @Override
            public void onClosing(WebSocket ws, int code, String reason) {
                ws.close(1000, null);
            }

            @Override
            public void onClosed(WebSocket ws, int code, String reason) {
                closeClient(clientSession);
            }

            @Override
            public void onFailure(WebSocket ws, Throwable t, Response response) {
                log.error("[PROXY] CFMS link failed for {}: {}", clientSession.getId(), t.getMessage());
                future.completeExceptionally(t);
                closeClient(clientSession);
            }
        });
    }

    // 客户端 → CFMS：经过 WAF

    @Override
    protected void handleBinaryMessage(WebSocketSession clientSession, BinaryMessage message) {
        byte[] payload = message.getPayload().array();
        String ip = getIp(clientSession);
        String action = extractAction(payload);

        WafCheckResult result = wafEngine.inspect(payload);
        var event = eventStore.record(ip, action, result.blocked(), result.ruleName(), result.reason());

        if (result.blocked()) {
            log.warn("[WAF BLOCK] ip={} action={} rule='{}' reason='{}'",
                    ip, action, result.ruleName(), result.reason());
            sendWafBlock(clientSession, payload, event);
            return;
        }

        CompletableFuture<WebSocket> future = cfmsSockets.get(clientSession.getId());
        if (future == null) return;

        future.orTimeout(3, TimeUnit.SECONDS)
              .thenAccept(ws -> ws.send(ByteString.of(payload)))
              .exceptionally(e -> {
                  log.error("[PROXY] Forward failed: {}", e.getMessage());
                  return null;
              });
    }

    // 连接断开

    @Override
    public void afterConnectionClosed(WebSocketSession clientSession, CloseStatus status) {
        eventStore.decrementConnections();
        downloadDecryptor.onClientDisconnect(clientSession);
        CompletableFuture<WebSocket> future = cfmsSockets.remove(clientSession.getId());
        if (future != null) {
            future.thenAccept(ws -> ws.close(1000, "Client disconnected"))
                  .exceptionally(e -> null);
        }
        log.info("[PROXY] Client disconnected: {}", clientSession.getId());
    }

    // 工具方法

    private void sendToClient(WebSocketSession session, WebSocketMessage<?> msg) {
        try {
            if (session.isOpen()) {
                synchronized (session) { session.sendMessage(msg); }
            }
        } catch (IOException e) {
            log.error("[PROXY] Failed to forward to client: {}", e.getMessage());
        }
    }

    private void closeClient(WebSocketSession session) {
        try { if (session.isOpen()) session.close(); } catch (IOException ignored) {}
    }

    // 把 WAF 拦截结果作为 CONCLUSION 帧回给客户端（frame_id 不变）
    private void sendWafBlock(WebSocketSession session, byte[] payload,
                              com.thesis.carapace.defender.WafEvent event) {
        if (payload.length < 4) return;
        int frameId = ((payload[0] & 0xFF) << 24) | ((payload[1] & 0xFF) << 16)
                    | ((payload[2] & 0xFF) << 8)  |  (payload[3] & 0xFF);

        String json = "{\"code\":403,\"message\":\"WAF Blocked\",\"waf\":true,\"data\":{"
                + "\"encryptedId\":\"" + event.encryptedId() + "\","
                + "\"defenseType\":\"" + jesc(event.defenseType()) + "\","
                + "\"rule\":\""        + jesc(event.ruleName())   + "\","
                + "\"reason\":\""      + jesc(event.reason())     + "\","
                + "\"action\":\""      + jesc(event.action())     + "\""
                + "}}";

        byte[] jsonBytes = json.getBytes(StandardCharsets.UTF_8);
        byte[] frame = new byte[5 + jsonBytes.length];
        frame[0] = (byte)(frameId >>> 24);
        frame[1] = (byte)(frameId >>> 16);
        frame[2] = (byte)(frameId >>> 8);
        frame[3] = (byte) frameId;
        frame[4] = 1; // FRAME_TYPE_CONCLUSION
        System.arraycopy(jsonBytes, 0, frame, 5, jsonBytes.length);
        sendToClient(session, new BinaryMessage(frame));
    }

    private String jesc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    // 从 CFMS 二进制帧中提取 action 字段（前 5 字节是帧头）
    private String extractAction(byte[] payload) {
        if (payload.length <= 5) return "unknown";
        try {
            String json = new String(payload, 5, Math.min(payload.length - 5, 300), StandardCharsets.UTF_8);
            int idx = json.indexOf("\"action\"");
            if (idx < 0) return "binary";
            int start = json.indexOf('"', idx + 9) + 1;
            int end   = json.indexOf('"', start);
            return (start > 0 && end > start) ? json.substring(start, end) : "unknown";
        } catch (Exception e) {
            return "binary";
        }
    }

    private String getIp(WebSocketSession session) {
        InetSocketAddress addr = session.getRemoteAddress();
        return addr != null ? addr.getAddress().getHostAddress() : "unknown";
    }
}
