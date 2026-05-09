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
 * 当前不做认证 — 演示项目，权限由前端 admin 路由控制。
 * 真要加认证，沿用 SecurityConfig 现有的过滤链即可。
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
        boolean ok = registry.setEnabled(name, enable);
        if (!ok) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(Map.of("name", name, "enabled", enable));
    }
}
