package com.thesis.carapace.vuln;

import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VulnSwitchRegistryTest {

    @Test
    void configuredVulnerabilityIsIgnoredWithoutLabMode() {
        VulnSwitchRegistry registry = registry(false, true);

        assertFalse(registry.isEnabled(VulnSwitchRegistry.SSRF));
        assertFalse(registry.setEnabled(VulnSwitchRegistry.SSRF, true));
    }

    @Test
    void labModeAllowsExplicitSwitches() {
        VulnSwitchRegistry registry = registry(true, false);

        assertTrue(registry.setEnabled(VulnSwitchRegistry.SSRF, true));
        assertTrue(registry.isEnabled(VulnSwitchRegistry.SSRF));
    }

    private VulnSwitchRegistry registry(boolean labMode, boolean initialSsrf) {
        VulnSwitchRegistry registry = new VulnSwitchRegistry();
        ReflectionTestUtils.setField(registry, "labMode", labMode);
        ReflectionTestUtils.setField(registry, "initSsrf", initialSsrf);
        ReflectionTestUtils.setField(registry, "initJwtAlgNone", false);
        ReflectionTestUtils.setField(registry, "initCors", false);
        ReflectionTestUtils.setField(registry, "initLog4shell", false);
        registry.init();
        return registry;
    }
}
