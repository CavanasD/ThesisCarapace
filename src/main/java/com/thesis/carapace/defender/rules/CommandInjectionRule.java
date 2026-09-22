package com.thesis.carapace.defender.rules;

import com.thesis.carapace.defender.WafCheckResult;
import com.thesis.carapace.defender.WafRule;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
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
        String json = WafPayloads.jsonBody(payload);
        if (json == null) return WafCheckResult.allowed();

        String lower = json.toLowerCase();
        for (String pattern : PATTERNS) {
            if (lower.contains(pattern)) {
                return WafCheckResult.blocked(name(), "Pattern: \"" + pattern + "\"");
            }
        }
        return WafCheckResult.allowed();
    }
}
