package com.thesis.carapace.defender.rules;

import com.thesis.carapace.defender.WafCheckResult;
import com.thesis.carapace.defender.WafRule;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
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
        // CFMS 帧格式：前 5 字节是帧头（4字节 frame_id + 1字节 frame_type）
        if (payload.length <= 5) return WafCheckResult.allowed();

        String body;
        try {
            body = new String(payload, 5, payload.length - 5, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return WafCheckResult.allowed(); // 二进制数据，跳过
        }

        // 只检查 JSON 帧，二进制文件块以 { 开头的概率极低
        if (!body.startsWith("{")) return WafCheckResult.allowed();

        String lower = body.toLowerCase();
        for (String pattern : PATTERNS) {
            if (lower.contains(pattern)) {
                return WafCheckResult.blocked(name(), "Matched pattern: \"" + pattern + "\"");
            }
        }
        return WafCheckResult.allowed();
    }
}
