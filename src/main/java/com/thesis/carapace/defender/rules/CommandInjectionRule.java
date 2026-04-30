package com.thesis.carapace.defender.rules;

import com.thesis.carapace.defender.WafCheckResult;
import com.thesis.carapace.defender.WafRule;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.List;

@Component
@ConditionalOnProperty(name = "defender.rule.cmd-injection.enabled", havingValue = "true", matchIfMissing = true)
public class CommandInjectionRule implements WafRule {

    private static final List<String> PATTERNS = List.of(
            "; ls", "; cat", "; rm", "; wget", "; curl",
            "| ls", "| cat", "| id", "| whoami",
            "&& id", "&& whoami",
            "`id`", "$(id)", "$(whoami)",
            "/bin/sh", "/bin/bash",
            "cmd.exe", "powershell"
    );

    @Override
    public String name() { return "Command Injection Detection"; }

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
