package com.thesis.carapace.vuln;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * CORS 漏洞演示
 *
 * vuln.cors.enabled=false（默认）：只允许 cors.allowed-origins 配置的源
 * vuln.cors.enabled=true ：反射 Origin 头 + 允许 credentials
 *
 * 危险性：任意第三方网站可以带 Cookie 发跨域请求，CSRF 防御完全失效
 *
 * 攻击示例：
 *   fetch("http://your-server/api/waf/stats", {
 *     credentials: "include",
 *     headers: { "Origin": "https://evil.com" }
 *   }).then(r => r.json()).then(console.log)
 */
@Slf4j
@Configuration
public class CorsVulnConfig {

    @Bean
    public OncePerRequestFilter corsVulnFilter(VulnSwitchRegistry vulnSwitches) {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
                    throws java.io.IOException, jakarta.servlet.ServletException {
                if (!vulnSwitches.isEnabled(VulnSwitchRegistry.CORS)) {
                    // 关闭时回退到 Spring Security 原生 CORS 处理（CorsConfig 提供的白名单）
                    chain.doFilter(req, res);
                    return;
                }
                String origin = req.getHeader("Origin");
                if (origin != null) {
                    // 漏洞：直接把 Origin 反射回去，并允许 credentials
                    res.setHeader("Access-Control-Allow-Origin", origin);
                    res.setHeader("Access-Control-Allow-Credentials", "true");
                    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
                    res.setHeader("Access-Control-Allow-Headers", "*");
                    log.warn("[CORS VULN] Reflected origin: {}", origin);
                }
                if ("OPTIONS".equalsIgnoreCase(req.getMethod())) {
                    res.setStatus(HttpServletResponse.SC_OK);
                    return;
                }
                chain.doFilter(req, res);
            }
        };
    }
}
