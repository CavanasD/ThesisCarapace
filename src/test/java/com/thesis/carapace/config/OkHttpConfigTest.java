package com.thesis.carapace.config;

import okhttp3.OkHttpClient;
import org.junit.jupiter.api.Test;

import java.nio.file.NoSuchFileException;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OkHttpConfigTest {

    @Test
    void defaultClientKeepsStandardHostnameVerification() throws Exception {
        var client = new OkHttpConfig().okHttpClient("");

        assertSame(new OkHttpClient().hostnameVerifier(), client.hostnameVerifier());
    }

    @Test
    void configuredCertificateMustExist() {
        assertThrows(
                NoSuchFileException.class,
                () -> new OkHttpConfig().okHttpClient("missing-drive-core-ca.pem")
        );
    }
}
