package com.thesis.carapace.defender.rules;

import com.thesis.carapace.defender.WafCheckResult;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SqlInjectionRuleTest {

    private final SqlInjectionRule rule = new SqlInjectionRule();

    @Test
    void blocksSqlPatternInJsonFrame() {
        WafCheckResult result = rule.inspect(frame("{\"action\":\"search\",\"data\":{\"q\":\"' or 1=1\"}}"));

        assertTrue(result.blocked());
    }

    @Test
    void allowsBinaryChunkContainingSqlCommentBytes() {
        byte[] payload = new byte[] {0, 0, 0, 1, 0, '{', 'm', 'p', '4', '-', '-', 0, 1, 2, 3};

        WafCheckResult result = rule.inspect(payload);

        assertFalse(result.blocked());
    }

    @Test
    void allowsBase64UrlCredentialContainingAdjacentHyphens() {
        WafCheckResult result = rule.inspect(frame("{\"action\":\"server_info\",\"token\":\"header.payload.signature--suffix\",\"data\":{}}"));

        assertFalse(result.blocked());
    }

    @Test
    void stillInspectsBusinessFieldsNamedToken() {
        WafCheckResult result = rule.inspect(frame("{\"action\":\"search\",\"token\":\"credential\",\"data\":{\"token\":\"' or 1=1 --\"}}"));

        assertTrue(result.blocked());
    }

    private byte[] frame(String body) {
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        byte[] payload = new byte[5 + bodyBytes.length];
        payload[3] = 1;
        System.arraycopy(bodyBytes, 0, payload, 5, bodyBytes.length);
        return payload;
    }
}
