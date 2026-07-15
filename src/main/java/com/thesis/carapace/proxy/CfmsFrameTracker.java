package com.thesis.carapace.proxy;

import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks multiplexed CFMS streams. Only the first PROCESS frame of a client
 * stream is the JSON control envelope; later frames with the same id are file
 * bytes or streaming protocol data and must bypass WAF regexes and audit I/O.
 */
@Component
public class CfmsFrameTracker {

    static final int HEADER_SIZE = 5;
    static final int PROCESS = 0;
    static final int CONCLUSION = 1;

    private final ConcurrentHashMap<String, Set<Integer>> streams = new ConcurrentHashMap<>();

    public void open(String sessionId) {
        streams.computeIfAbsent(sessionId, ignored -> ConcurrentHashMap.newKeySet());
    }

    public boolean shouldInspect(String sessionId, byte[] payload) {
        if (payload.length < HEADER_SIZE || Byte.toUnsignedInt(payload[4]) != PROCESS) {
            return false;
        }
        return streams.computeIfAbsent(sessionId, ignored -> ConcurrentHashMap.newKeySet())
                .add(frameId(payload));
    }

    public void onUpstreamFrame(String sessionId, byte[] payload) {
        if (payload.length < HEADER_SIZE || Byte.toUnsignedInt(payload[4]) != CONCLUSION) {
            return;
        }
        Set<Integer> active = streams.get(sessionId);
        if (active != null) active.remove(frameId(payload));
    }

    public void finish(String sessionId, byte[] payload) {
        if (payload.length < HEADER_SIZE) return;
        Set<Integer> active = streams.get(sessionId);
        if (active != null) active.remove(frameId(payload));
    }

    public void close(String sessionId) {
        streams.remove(sessionId);
    }

    private int frameId(byte[] payload) {
        return ((payload[0] & 0xFF) << 24)
                | ((payload[1] & 0xFF) << 16)
                | ((payload[2] & 0xFF) << 8)
                | (payload[3] & 0xFF);
    }
}
