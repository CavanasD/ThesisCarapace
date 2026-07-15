package com.thesis.carapace.defender.rules;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

final class WafPayloads {

    private static final ObjectMapper JSON = new ObjectMapper();

    private WafPayloads() {}

    static String jsonBody(byte[] payload) {
        if (payload.length <= 5) return null;

        String body;
        try {
            body = StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(payload, 5, payload.length - 5))
                    .toString();
        } catch (CharacterCodingException e) {
            return null;
        }

        String trimmed = body.trim();
        if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) return null;

        try {
            JSON.readTree(trimmed);
            return trimmed;
        } catch (Exception e) {
            return null;
        }
    }
}
