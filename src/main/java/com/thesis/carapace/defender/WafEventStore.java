package com.thesis.carapace.defender;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@Component
@RequiredArgsConstructor
public class WafEventStore {

    private static final int MAX_EVENTS = 500;

    @Value("${security.jwt.secret}")
    private String jwtSecret;

    private final WafEventPersister persister;

    private final Deque<WafEvent> events = new ConcurrentLinkedDeque<>();
    private final List<SseEmitter> emitters = new CopyOnWriteArrayList<>();

    private final AtomicLong idCounter       = new AtomicLong(0);
    private final AtomicLong totalRequests   = new AtomicLong();
    private final AtomicLong blockedRequests = new AtomicLong();
    private final AtomicLong activeConnections = new AtomicLong();

    // 24-bit XOR mask derived from JWT secret — obfuscates log IDs
    private long idMask = 0xABCDEFL;

    @PostConstruct
    void init() {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(jwtSecret.getBytes());
            idMask = ((hash[0] & 0xFFL) << 16) | ((hash[1] & 0xFFL) << 8) | (hash[2] & 0xFFL);
        } catch (Exception ignored) {}

        // Replay today's persisted events into the ring buffer so dashboard
        // history survives restarts. Counters reflect ALL of today's events;
        // older days remain on disk but are not loaded.
        List<WafEvent> persisted = persister.loadRecent(MAX_EVENTS);
        long maxId = 0;
        long blocked = 0;
        for (WafEvent ev : persisted) {
            events.addLast(ev);
            if (ev.id() > maxId) maxId = ev.id();
            if (ev.blocked()) blocked++;
        }
        idCounter.set(maxId);
        totalRequests.set(persisted.size());
        blockedRequests.set(blocked);
        if (!persisted.isEmpty()) {
            log.info("[WAF-PERSIST] Replayed {} event(s) from today's log", persisted.size());
        }
    }

    public WafEvent record(String clientIp, String action,
                           boolean blocked, String ruleName, String reason) {
        long rawId = idCounter.incrementAndGet();
        String encId = "WAF-" + String.format("%06X", (rawId ^ idMask) & 0xFFFFFFL);
        String defenseType = deriveDefenseType(blocked, ruleName, reason);

        WafEvent event = new WafEvent(rawId, encId, defenseType,
                Instant.now(), clientIp, action, blocked, ruleName, reason);

        totalRequests.incrementAndGet();
        if (blocked) blockedRequests.incrementAndGet();

        if (events.size() >= MAX_EVENTS) events.pollFirst();
        events.addLast(event);

        // Persist asynchronously — never blocks the request path.
        persister.persist(event);

        emitters.removeIf(emitter -> {
            try {
                emitter.send(SseEmitter.event().name("waf-event").data(event));
                return false;
            } catch (IOException e) {
                return true;
            }
        });
        return event;
    }

    private String deriveDefenseType(boolean blocked, String ruleName, String reason) {
        if (!blocked || ruleName == null) return "ALLOWED";
        return switch (ruleName) {
            case "SQL Injection Detection"      -> "HEUR/WAF.SQLi.PatternMatch";
            case "XSS Detection"               -> "HEUR/WAF.XSS.ScriptInject";
            case "Path Traversal Detection"    -> "HEUR/WAF.FS.PathTraversal";
            case "Command Injection Detection" -> "HEUR/WAF.Exec.CmdInject";
            case "File Type Detection"         -> deriveFileType(reason);
            default -> "HEUR/WAF.Generic." + ruleName.replaceAll("[^A-Za-z0-9]", "");
        };
    }

    private String deriveFileType(String reason) {
        if (reason != null && reason.contains("magic")) return "HEUR/WAF.Upload.MaliciousHeader";
        return "HEUR/WAF.Upload.DangerousExt";
    }

    public List<WafEvent> recent(int limit) {
        return events.stream()
                .sorted((a, b) -> b.timestamp().compareTo(a.timestamp()))
                .limit(limit)
                .toList();
    }

    public List<WafEvent> allEvents() {
        return events.stream()
                .sorted((a, b) -> b.timestamp().compareTo(a.timestamp()))
                .toList();
    }

    public SseEmitter subscribe() {
        SseEmitter emitter = new SseEmitter(0L);
        emitters.add(emitter);
        emitter.onCompletion(() -> emitters.remove(emitter));
        emitter.onTimeout(() -> emitters.remove(emitter));
        emitter.onError(e -> emitters.remove(emitter));
        return emitter;
    }

    public long getTotal()   { return totalRequests.get(); }
    public long getBlocked() { return blockedRequests.get(); }
    public void incrementConnections() { activeConnections.incrementAndGet(); }
    public void decrementConnections() { activeConnections.decrementAndGet(); }
    public long getActiveConnections()  { return activeConnections.get(); }
}
