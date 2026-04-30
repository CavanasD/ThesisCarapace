package com.thesis.carapace.defender;

public record WafCheckResult(boolean blocked, String ruleName, String reason) {

    public static WafCheckResult allowed() {
        return new WafCheckResult(false, null, null);
    }

    public static WafCheckResult blocked(String ruleName, String reason) {
        return new WafCheckResult(true, ruleName, reason);
    }
}
