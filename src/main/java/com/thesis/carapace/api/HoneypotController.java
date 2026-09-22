package com.thesis.carapace.api;

import com.thesis.carapace.defender.WafEvent;
import com.thesis.carapace.defender.WafEventStore;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class HoneypotController {

    public static final String RULE_NAME = "Honeypot Trigger";
    private final WafEventStore eventStore;

    /**
     * An inert teaching decoy. It never authenticates, executes or persists the
     * supplied body. Only request metadata is recorded for the detection demo.
     */
    @RequestMapping("/decoy/admin/login")
    public ResponseEntity<Map<String, String>> trigger(HttpServletRequest request) {
        String path = request.getRequestURI();
        String action = request.getMethod() + " " + path;
        String reason = "Decoy endpoint accessed; client=" + classifyClient(request.getHeader("User-Agent"));
        eventStore.record(clientIp(request), action, true, RULE_NAME, reason);
        return ResponseEntity.status(404).body(Map.of(
                "error", "not_found",
                "message", "The requested resource was not found"
        ));
    }

    @GetMapping("/api/honeypot/events")
    public List<WafEvent> events(@RequestParam(defaultValue = "100") int limit) {
        int safeLimit = Math.max(1, Math.min(limit, 500));
        return eventStore.allEvents().stream()
                .filter(event -> RULE_NAME.equals(event.ruleName()))
                .limit(safeLimit)
                .toList();
    }

    @GetMapping("/api/honeypot/stats")
    public Map<String, Long> stats() {
        long triggers = eventStore.allEvents().stream()
                .filter(event -> RULE_NAME.equals(event.ruleName()))
                .count();
        return Map.of("triggers", triggers);
    }

    private String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",", 2)[0].trim();
        }
        return request.getRemoteAddr();
    }

    private String classifyClient(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) return "unknown";
        String normalized = userAgent.toLowerCase();
        if (normalized.contains("curl")) return "curl";
        if (normalized.contains("python")) return "python";
        if (normalized.contains("mozilla")) return "browser";
        return "other";
    }
}
