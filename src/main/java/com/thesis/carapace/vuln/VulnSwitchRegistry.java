package com.thesis.carapace.vuln;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 漏洞开关运行时注册表。所有 vuln.* 漏洞代码通过 {@link #isEnabled(String)}
 * 查询当前开关状态，admin 面板通过 {@link #setEnabled(String, boolean)}
 * 热切换，无需重启。
 *
 * 规范名称（key）固定为：ssrf / jwt-alg-none / cors / log4shell。
 * 启动时从 application.properties 读初值，以便 git 仓库默认行为可控。
 */
@Slf4j
@Service
public class VulnSwitchRegistry {

    public static final String SSRF = "ssrf";
    public static final String JWT_ALG_NONE = "jwt-alg-none";
    public static final String CORS = "cors";
    public static final String LOG4SHELL = "log4shell";

    private final Map<String, Boolean> state = new ConcurrentHashMap<>();

    @Value("${vuln.ssrf.enabled:false}")
    private boolean initSsrf;
    @Value("${vuln.jwt.alg-none.enabled:false}")
    private boolean initJwtAlgNone;
    @Value("${vuln.cors.enabled:false}")
    private boolean initCors;
    @Value("${vuln.log4shell.enabled:false}")
    private boolean initLog4shell;

    @PostConstruct
    void init() {
        state.put(SSRF, initSsrf);
        state.put(JWT_ALG_NONE, initJwtAlgNone);
        state.put(CORS, initCors);
        state.put(LOG4SHELL, initLog4shell);
        log.info("VulnSwitchRegistry initialized: {}", state);
    }

    public boolean isEnabled(String name) {
        return Boolean.TRUE.equals(state.get(name));
    }

    /** @return true if name is recognized and was updated; false if unknown. */
    public boolean setEnabled(String name, boolean enabled) {
        if (!state.containsKey(name)) return false;
        state.put(name, enabled);
        log.warn("[VULN SWITCH] {} -> {}", name, enabled);
        return true;
    }

    /** Snapshot of all switches in deterministic order, for the admin panel. */
    public Map<String, Boolean> snapshot() {
        Map<String, Boolean> out = new LinkedHashMap<>();
        out.put(SSRF, isEnabled(SSRF));
        out.put(JWT_ALG_NONE, isEnabled(JWT_ALG_NONE));
        out.put(CORS, isEnabled(CORS));
        out.put(LOG4SHELL, isEnabled(LOG4SHELL));
        return out;
    }
}
