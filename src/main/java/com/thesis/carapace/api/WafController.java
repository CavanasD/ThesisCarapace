package com.thesis.carapace.api;

import com.thesis.carapace.defender.WafEngine;
import com.thesis.carapace.defender.WafEvent;
import com.thesis.carapace.defender.WafEventStore;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/waf")
@RequiredArgsConstructor
public class WafController {

    private final WafEngine wafEngine;
    private final WafEventStore eventStore;

    @GetMapping(value = "/events/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter streamEvents() {
        return eventStore.subscribe();
    }

    @GetMapping("/events")
    public List<WafEvent> recentEvents(@RequestParam(defaultValue = "500") int limit) {
        return eventStore.recent(limit);
    }

    @GetMapping(value = "/events/export", produces = "text/csv;charset=UTF-8")
    public ResponseEntity<String> exportEvents() {
        StringBuilder csv = new StringBuilder(
                "id,encryptedId,defenseType,timestamp,clientIp,action,blocked,ruleName,reason\n");
        for (WafEvent ev : eventStore.allEvents()) {
            csv.append(csvRow(ev));
        }
        return ResponseEntity.ok()
                .header("Content-Disposition", "attachment; filename=\"waf-events.csv\"")
                .body(csv.toString());
    }

    @GetMapping("/stats")
    public Map<String, Long> stats() {
        return Map.of(
                "total",       eventStore.getTotal(),
                "blocked",     eventStore.getBlocked(),
                "connections", eventStore.getActiveConnections()
        );
    }

    @GetMapping("/rules")
    public List<Map<String, Object>> rules() {
        return wafEngine.getRules().stream()
                .map(rule -> Map.<String, Object>of(
                        "name",    rule.name(),
                        "enabled", wafEngine.isEnabled(rule.name())
                ))
                .toList();
    }

    @PutMapping("/rules/{name}")
    public ResponseEntity<Map<String, Object>> toggleRule(
            @PathVariable String name,
            @RequestBody Map<String, Boolean> body) {
        boolean enable = Boolean.TRUE.equals(body.get("enabled"));
        boolean exists = wafEngine.getRules().stream().anyMatch(r -> r.name().equals(name));
        if (!exists) return ResponseEntity.notFound().build();
        if (enable) wafEngine.enableRule(name);
        else        wafEngine.disableRule(name);
        return ResponseEntity.ok(Map.of("name", name, "enabled", enable));
    }

    private String csvRow(WafEvent ev) {
        return String.format("%d,%s,%s,%s,%s,%s,%b,%s,%s\n",
                ev.id(),
                ev.encryptedId(),
                csvEsc(ev.defenseType()),
                ev.timestamp(),
                csvEsc(ev.clientIp()),
                csvEsc(ev.action()),
                ev.blocked(),
                ev.ruleName() == null ? "" : csvEsc(ev.ruleName()),
                ev.reason()   == null ? "" : csvEsc(ev.reason()));
    }

    private String csvEsc(String s) {
        if (s == null) return "";
        if (s.contains(",") || s.contains("\"") || s.contains("\n"))
            return "\"" + s.replace("\"", "\"\"") + "\"";
        return s;
    }
}
