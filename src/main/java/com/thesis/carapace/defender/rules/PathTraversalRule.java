package com.thesis.carapace.defender.rules;

import com.thesis.carapace.defender.WafCheckResult;
import com.thesis.carapace.defender.WafRule;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.List;

@Component
@ConditionalOnProperty(name = "defender.rule.path-traversal.enabled", havingValue = "true", matchIfMissing = true)
public class PathTraversalRule implements WafRule {

    private static final List<String> PATTERNS = List.of(
            "../", "..\\",
            "%2e%2e%2f", "%2e%2e/", "..%2f",   // URL 编码变形
            "%252e%252e",                         // 双重编码
            "/etc/passwd", "/etc/shadow",
            "c:\\windows", "c:/windows"
    );

    @Override
    public String name() { return "Path Traversal Detection"; }

    @Override
    public WafCheckResult inspect(byte[] payload) {
        if (payload.length <= 5) return WafCheckResult.allowed();
        try {
            String json = new String(payload, 5, payload.length - 5, StandardCharsets.UTF_8);
            if (!json.startsWith("{")) return WafCheckResult.allowed();
            String lower = json.toLowerCase();
            for (String pattern : PATTERNS) {
                if (lower.contains(pattern)) {
                    return WafCheckResult.blocked(name(), "Pattern: \"" + pattern + "\"");
                }
            }
        } catch (Exception ignored) {}
        return WafCheckResult.allowed();
    }
}
