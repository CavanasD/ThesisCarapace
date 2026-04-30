package com.thesis.carapace.defender.rules;

import com.thesis.carapace.defender.WafCheckResult;
import com.thesis.carapace.defender.WafRule;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.List;

// 拦截上传危险文件类型（通过文件名或 magic bytes 检测）
@Component
@ConditionalOnProperty(name = "defender.rule.file-type.enabled", havingValue = "true", matchIfMissing = true)
public class FileTypeRule implements WafRule {

    private static final List<String> DANGEROUS_EXTENSIONS = List.of(
            ".php", ".php3", ".php5", ".phtml",
            ".jsp", ".jspx",
            ".py", ".sh", ".bash",
            ".exe", ".dll", ".so",
            ".pl", ".rb", ".lua"
    );

    // 常见危险文件 magic bytes
    private static final byte[] ELF_MAGIC  = {0x7f, 0x45, 0x4c, 0x46}; // ELF
    private static final byte[] MZ_MAGIC   = {0x4d, 0x5a};             // PE/EXE

    @Override
    public String name() { return "File Type Detection"; }

    @Override
    public WafCheckResult inspect(byte[] payload) {
        if (payload.length <= 5) return WafCheckResult.allowed();

        try {
            String json = new String(payload, 5, payload.length - 5, StandardCharsets.UTF_8);
            if (!json.startsWith("{")) {
                // 是二进制文件块，从帧体起点（offset 5）检查 magic bytes
                return checkMagicBytes(payload, 5);
            }
            // 是 JSON 帧，检查文件名（title 字段）
            String lower = json.toLowerCase();
            for (String ext : DANGEROUS_EXTENSIONS) {
                if (lower.contains("\"title\"") && lower.contains(ext)) {
                    return WafCheckResult.blocked(name(), "Dangerous file extension: " + ext);
                }
            }
        } catch (Exception ignored) {
            return checkMagicBytes(payload, 5);
        }
        return WafCheckResult.allowed();
    }

    private WafCheckResult checkMagicBytes(byte[] payload, int offset) {
        if (startsWith(payload, offset, ELF_MAGIC))  return WafCheckResult.blocked(name(), "ELF binary detected (magic bytes)");
        if (startsWith(payload, offset, MZ_MAGIC))   return WafCheckResult.blocked(name(), "PE/EXE binary detected (magic bytes)");
        return WafCheckResult.allowed();
    }

    private boolean startsWith(byte[] data, int offset, byte[] magic) {
        if (data.length - offset < magic.length) return false;
        for (int i = 0; i < magic.length; i++) {
            if (data[offset + i] != magic[i]) return false;
        }
        return true;
    }
}
