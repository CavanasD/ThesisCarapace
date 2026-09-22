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
            "'; --", "' --", "--", "/*", "*/",
            // ORDER BY / 标识符位置注入的带外读取。标识符位无法参数化绑定，
            // 攻击者常借报错函数把子查询结果带进错误串：
            //   sort_by=extractvalue(1,concat(0x7e,(SELECT flag FROM lab_flags)))
            // 上面的特征子串规则对这类 payload 完全无感（不含 ' or / union select
            // / 注释符），必须新增报错注入函数与元数据表的模式才能覆盖。
            "extractvalue", "updatexml", "exp(", "geometrycollection(",
            "information_schema"
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
