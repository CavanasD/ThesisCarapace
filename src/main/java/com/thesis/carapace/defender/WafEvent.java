package com.thesis.carapace.defender;

import java.time.Instant;

public record WafEvent(
        long id,
        String encryptedId,
        String defenseType,
        Instant timestamp,
        String clientIp,
        String action,
        boolean blocked,
        String ruleName,
        String reason
) {}
