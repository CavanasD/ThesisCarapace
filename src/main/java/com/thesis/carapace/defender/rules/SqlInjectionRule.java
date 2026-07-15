package com.thesis.carapace.defender.rules;

import com.thesis.carapace.defender.WafCheckResult;
import com.thesis.carapace.defender.WafRule;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@ConditionalOnProperty(name = "defender.rule.sqli.enabled", havingValue = "true", matchIfMissing = true)
public class SqlInjectionRule implements WafRule {

    private static final List<String> PATTERNS = List.of(
            "' or ", "' or'", " or 1=1", " or '1'='1",
            "union select", "union all select",
            "drop table", "drop database",
            "insert into", "delete from",
            "'; --", "' --", "--", "/*", "*/"
    );

    @Override
    public String name() {
        return "SQL Injection Detection";
    }

    @Override
    public WafCheckResult inspect(byte[] payload) {
        String body = WafPayloads.jsonBody(payload);
        if (body == null) return WafCheckResult.allowed();

        String lower = body.toLowerCase();
        for (String pattern : PATTERNS) {
            if (lower.contains(pattern)) {
                return WafCheckResult.blocked(name(), "Matched pattern: \"" + pattern + "\"");
            }
        }
        return WafCheckResult.allowed();
    }
}
