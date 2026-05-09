package com.thesis.carapace.vuln;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Map;

/**
 * JWT alg:none 漏洞演示
 *
 * vuln.jwt.alg-none.enabled=false（默认）：正常验证 HMAC-SHA256 签名
 * vuln.jwt.alg-none.enabled=true ：接受 alg=none 的无签名 token
 *
 * 攻击示例：
 *   header  = base64url({"alg":"none","typ":"JWT"})
 *   payload = base64url({"sub":"admin","role":"ADMIN"})
 *   token   = header + "." + payload + "."   ← 签名为空
 *   GET /api/admin/config  -H "Authorization: Bearer <token>"
 */
@Slf4j
@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminController {

    private final VulnSwitchRegistry vulnSwitches;

    @Value("${security.jwt.secret}")
    private String jwtSecret;

    @GetMapping("/config")
    public ResponseEntity<?> getConfig(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body("Missing token");
        }
        String token = authHeader.substring(7);
        log.info("[JWT] Token received, alg-none-enabled={}", vulnSwitches.isEnabled(VulnSwitchRegistry.JWT_ALG_NONE));

        if (!validateJwt(token)) {
            return ResponseEntity.status(401).body("Invalid token");
        }

        return ResponseEntity.ok(Map.of(
                "message", "Admin access granted",
                "hint",    "You can see this because your JWT was accepted",
                "secret",  jwtSecret
        ));
    }

    private boolean validateJwt(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) return false;

        try {
            String headerJson = new String(Base64.getUrlDecoder().decode(pad(parts[0])));

            // 漏洞：接受 alg:none，直接信任 payload 不验签名
            if (vulnSwitches.isEnabled(VulnSwitchRegistry.JWT_ALG_NONE)
                    && headerJson.toLowerCase().contains("\"none\"")) {
                log.warn("[JWT VULN] Accepted alg:none token!");
                return true;
            }

            // 安全：验证 HMAC-SHA256 签名
            if (parts.length < 3) return false;
            String signInput = parts[0] + "." + parts[1];
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(jwtSecret.getBytes(), "HmacSHA256"));
            String expected = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(signInput.getBytes()));
            return expected.equals(parts[2]);

        } catch (Exception e) {
            log.error("[JWT] Validation error: {}", e.getMessage());
            return false;
        }
    }

    private String pad(String base64url) {
        return switch (base64url.length() % 4) {
            case 2 -> base64url + "==";
            case 3 -> base64url + "=";
            default -> base64url;
        };
    }
}
