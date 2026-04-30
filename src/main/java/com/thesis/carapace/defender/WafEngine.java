package com.thesis.carapace.defender;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
public class WafEngine {

    private final List<WafRule> rules;
    // 运行时禁用的规则名（不用重启即可切换）
    private final Set<String> disabledRules = ConcurrentHashMap.newKeySet();

    public WafEngine(List<WafRule> rules) {
        this.rules = rules;
        log.info("WafEngine ready. Rules: {}", rules.stream().map(WafRule::name).toList());
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
    public boolean isEnabled(String name) { return !disabledRules.contains(name); }
    public List<WafRule> getRules()      { return rules; }
}
