package com.thesis.carapace.vuln;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * SSRF 漏洞演示端点
 *
 * vuln.ssrf.enabled=false（默认）：URL 白名单，只允许 https:// 外部链接
 * vuln.ssrf.enabled=true ：直接 fetch 任意 URL，包括内网地址
 *
 * 攻击示例：GET /api/preview?url=http://127.0.0.1:5104
 * → 返回 CFMS 内网响应，绕过所有网络隔离
 */
@Slf4j
@RestController
@RequestMapping("/api")
public class SsrfController {

    @Value("${vuln.ssrf.enabled:false}")
    private boolean ssrfEnabled;

    private static final List<String> ALLOWED_PREFIXES = List.of(
            "https://", "http://cdn.", "http://img."
    );

    @GetMapping("/preview")
    public ResponseEntity<String> preview(@RequestParam String url) {
        log.info("[SSRF] preview request: url={} vuln={}", url, ssrfEnabled);

        if (!ssrfEnabled) {
            // 安全版本：白名单检查
            boolean allowed = ALLOWED_PREFIXES.stream().anyMatch(url::startsWith);
            if (!allowed) {
                return ResponseEntity.status(403).body("URL not allowed. Only external HTTPS links are permitted.");
            }
        }
        // 漏洞版本 / 通过白名单：直接发出请求
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setRequestMethod("GET");
            try (InputStream is = conn.getInputStream()) {
                String body = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                // 截断防止返回超大内容
                return ResponseEntity.ok(body.substring(0, Math.min(body.length(), 4096)));
            }
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Request failed: " + e.getMessage());
        }
    }
}
