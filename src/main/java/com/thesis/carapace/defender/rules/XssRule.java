package com.thesis.carapace.defender.rules;

import com.thesis.carapace.defender.WafCheckResult;
import com.thesis.carapace.defender.WafRule;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.List;

@Component
@ConditionalOnProperty(name = "defender.rule.xss.enabled", havingValue = "true", matchIfMissing = true)
public class XssRule implements WafRule {

    private static final List<String> PATTERNS = List.of(
            "<script", "</script>",
            "javascript:",
            "onerror=", "onload=", "onclick=", "onmouseover=",
            "<img ", "<iframe", "<svg",
            "alert(", "confirm(", "prompt(",
            "document.cookie", "document.write",
            "&#x", "\\u003c"   // 编码变形
    );

    @Override
    public String name() { return "XSS Detection"; }

    @Override
    public WafCheckResult inspect(byte[] payload) {
        if (payload.length <= 5) return WafCheckResult.allowed();
        try {
            String json = new String(payload, 5, payload.length - 5, StandardCharsets.UTF_8);
            if (!json.startsWith("{")) return WafCheckResult.allowed();
            String lower = json.toLowerCase();
            for (String pattern : PATTERNS) {
                if (lower.contains(pattern.toLowerCase())) {
                    return WafCheckResult.blocked(name(), "Pattern: \"" + pattern + "\"");
                }
            }
        } catch (Exception ignored) {}
        return WafCheckResult.allowed();
    }
}
