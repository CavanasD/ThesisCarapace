package com.thesis.carapace.defender;

// hook 点：每条 WAF 规则实现这个接口，挂到 WafEngine 上
public interface WafRule {
    String name();
    WafCheckResult inspect(byte[] payload);
}
