package com.thesis.carapace.vuln;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 漏洞开关 admin REST 端点。
 *
 *   GET /api/admin/vuln          → 列出所有漏洞当前状态
 *   PUT /api/admin/vuln/{name}   → body {"enabled": true|false} 切换
 *
 * 端点由 SecurityConfig 的无会话管理令牌保护；LAB_MODE=false 时，
 * 即使管理员也不能打开漏洞。
 */
@RestController
@RequestMapping("/api/admin/vuln")
@RequiredArgsConstructor
public class VulnController {

    private final VulnSwitchRegistry registry;

    @GetMapping
    public Map<String, Boolean> list() {
        return registry.snapshot();
    }

    @PutMapping("/{name}")
    public ResponseEntity<Map<String, Object>> toggle(
            @PathVariable String name,
            @RequestBody Map<String, Boolean> body) {
        boolean enable = Boolean.TRUE.equals(body.get("enabled"));
        if (!registry.contains(name)) return ResponseEntity.notFound().build();
        if (enable && !registry.isLabMode()) {
            return ResponseEntity.status(403).body(Map.of(
                    "name", name,
                    "enabled", false,
                    "error", "LAB_MODE is disabled"
            ));
        }
        boolean ok = registry.setEnabled(name, enable);
        if (!ok) return ResponseEntity.status(409).body(Map.of(
                "name", name,
                "enabled", registry.isEnabled(name),
                "error", "Switch update rejected"
        ));
        return ResponseEntity.ok(Map.of("name", name, "enabled", enable));
    }
}
