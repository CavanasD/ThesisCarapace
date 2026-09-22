package com.thesis.carapace;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "security.admin.token=test-admin-token",
                "waf.log.dir=build/test-waf-logs",
                "waf.backup.dir=build/test-waf-backups"
        })
class CarapaceApplicationTests {

    @LocalServerPort
    private int port;

    private final HttpClient http = HttpClient.newHttpClient();

    @Test
    void contextLoads() {
    }

    @Test
    void managementApiRequiresAdminToken() throws Exception {
        HttpResponse<String> anonymous = send(HttpRequest.newBuilder(uri("/api/waf/stats")).GET().build());
        assertEquals(401, anonymous.statusCode());

        HttpResponse<String> administrator = send(HttpRequest.newBuilder(uri("/api/waf/stats"))
                .header("X-Admin-Token", "test-admin-token")
                .GET()
                .build());
        assertEquals(200, administrator.statusCode());
    }

    @Test
    void allWafRulesCanBeToggledInOneRequest() throws Exception {
        HttpResponse<String> disabled = send(HttpRequest.newBuilder(uri("/api/waf/rules"))
                .header("X-Admin-Token", "test-admin-token")
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString("{\"enabled\":false}"))
                .build());
        assertEquals(200, disabled.statusCode());
        assertFalse(disabled.body().contains("\"enabled\":true"));

        HttpResponse<String> enabled = send(HttpRequest.newBuilder(uri("/api/waf/rules"))
                .header("X-Admin-Token", "test-admin-token")
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString("{\"enabled\":true}"))
                .build());
        assertEquals(200, enabled.statusCode());
        assertTrue(enabled.body().contains("\"enabled\":true"));
    }

    @Test
    void honeypotIsInertAndDetectionIsAdminOnly() throws Exception {
        HttpResponse<String> trigger = send(HttpRequest.newBuilder(uri("/decoy/admin/login"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"username\":\"admin\",\"password\":\"demo\"}"))
                .build());
        assertEquals(404, trigger.statusCode());
        assertFalse(trigger.body().contains("demo"));

        assertEquals(401, send(HttpRequest.newBuilder(uri("/api/honeypot/events")).GET().build()).statusCode());
        HttpResponse<String> events = send(HttpRequest.newBuilder(uri("/api/honeypot/events"))
                .header("X-Admin-Token", "test-admin-token")
                .GET().build());
        assertEquals(200, events.statusCode());
        assertTrue(events.body().contains("Honeypot Trigger"));
        assertFalse(events.body().contains("demo"));
    }

    @Test
    void labSwitchCannotBeEnabledOutsideLabMode() throws Exception {
        HttpResponse<String> response = send(HttpRequest.newBuilder(uri("/api/admin/vuln/ssrf"))
                .header("X-Admin-Token", "test-admin-token")
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString("{\"enabled\":true}"))
                .build());

        assertEquals(403, response.statusCode());
        assertFalse(response.body().contains("\"enabled\":true"));
    }

    @Test
    void corsUsesExplicitOriginWhitelist() throws Exception {
        HttpResponse<String> allowed = send(HttpRequest.newBuilder(uri("/api/waf/stats"))
                .header("Origin", "http://localhost:5173")
                .header("Access-Control-Request-Method", "GET")
                .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
                .build());
        assertEquals(200, allowed.statusCode());
        assertEquals("http://localhost:5173",
                allowed.headers().firstValue("Access-Control-Allow-Origin").orElse(""));

        HttpResponse<String> rejected = send(HttpRequest.newBuilder(uri("/api/waf/stats"))
                .header("Origin", "https://attacker.invalid")
                .header("Access-Control-Request-Method", "GET")
                .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
                .build());
        assertEquals(403, rejected.statusCode());
    }

    @Test
    void prometheusMetricsAreAuthenticatedAndExposeQueueState() throws Exception {
        assertEquals(401, send(HttpRequest.newBuilder(uri("/actuator/prometheus")).GET().build()).statusCode());

        HttpResponse<String> response = send(HttpRequest.newBuilder(uri("/actuator/prometheus"))
                .header("X-Admin-Token", "test-admin-token")
                .GET()
                .build());
        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains("carapace_waf_persistence_queue_depth"));
    }

    private URI uri(String path) {
        return URI.create("http://127.0.0.1:" + port + path);
    }

    private HttpResponse<String> send(HttpRequest request) throws Exception {
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

}
