package com.thesis.carapace.config;

import okhttp3.OkHttpClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.concurrent.TimeUnit;

@Configuration
public class OkHttpConfig {

    @Bean
    public OkHttpClient okHttpClient(
            @Value("${cfms.tls.ca-cert:}") String caCertificateFile
    ) throws Exception {
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .pingInterval(30, TimeUnit.SECONDS);

        if (!caCertificateFile.isBlank()) {
            X509TrustManager trustManager = trustManager(Path.of(caCertificateFile));
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new X509TrustManager[]{trustManager}, null);
            builder.sslSocketFactory(sslContext.getSocketFactory(), trustManager);
        }

        // Keep OkHttp's standard hostname verifier. The Compose certificate has
        // DNS:drive-core in its SAN and is the only CA mounted into this process.
        return builder.build();
    }

    private X509TrustManager trustManager(Path certificateFile) throws Exception {
        Certificate certificate;
        try (InputStream input = Files.newInputStream(certificateFile)) {
            certificate = CertificateFactory.getInstance("X.509").generateCertificate(input);
        }

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setCertificateEntry("drive-core", certificate);

        TrustManagerFactory factory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        factory.init(keyStore);
        for (var manager : factory.getTrustManagers()) {
            if (manager instanceof X509TrustManager x509TrustManager) {
                return x509TrustManager;
            }
        }
        throw new IllegalStateException("No X509TrustManager for the configured CFMS CA");
    }
}
