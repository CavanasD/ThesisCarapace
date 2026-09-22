package com.thesis.carapace.defender;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.core.env.Environment;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
public class WafEngine {

    private final List<WafRule> rules;
    // 运行时禁用的规则名（不用重启即可切换）
    private final Set<String> disabledRules = ConcurrentHashMap.newKeySet();

    private static final Map<String, String> RULE_PROPERTIES = Map.of(
            "SQL Injection Detection", "defender.rule.sqli.enabled",
            "XSS Detection", "defender.rule.xss.enabled",
            "Path Traversal Detection", "defender.rule.path-traversal.enabled",
            "Command Injection Detection", "defender.rule.cmd-injection.enabled",
            "File Type Detection", "defender.rule.file-type.enabled"
    );

    public WafEngine(List<WafRule> rules, Environment environment) {
        this.rules = rules;
        rules.forEach(rule -> {
            String property = RULE_PROPERTIES.get(rule.name());
            if (property != null && !environment.getProperty(property, Boolean.class, true)) {
                disabledRules.add(rule.name());
            }
        });
        log.info("WafEngine ready. Rules: {}", rules.stream()
                .map(rule -> rule.name() + "=" + isEnabled(rule.name())).toList());
    }

    public WafCheckResult inspect(byte[] payload) {
        for (WafRule rule : rules) {
            if (disabledRules.contains(rule.name())) continue;
            WafCheckResult result = rule.inspect(payload);
            if (result.blocked()) return result;
        }
        return WafCheckResult.allowed();
    }

    public void disableRule(String name) { disabledRules.add(name); }
    public void enableRule(String name)  { disabledRules.remove(name); }
    public void setAllRulesEnabled(boolean enabled) {
        if (enabled) {
            disabledRules.clear();
        } else {
            rules.forEach(rule -> disabledRules.add(rule.name()));
        }
        log.info("All WAF rules are now {}", enabled ? "enabled" : "disabled");
    }
    public boolean isEnabled(String name) { return !disabledRules.contains(name); }
    public List<WafRule> getRules()      { return rules; }
}
