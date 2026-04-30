package com.thesis.carapace.config;

import okhttp3.OkHttpClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

@Configuration
public class OkHttpConfig {

    // 信任 CFMS 自签证书（仅用于内网连接，不对外）
    @Bean
    public OkHttpClient okHttpClient() throws Exception {
        X509TrustManager trustAll = new X509TrustManager() {
            @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            @Override public void checkClientTrusted(X509Certificate[] c, String t) {}
            @Override public void checkServerTrusted(X509Certificate[] c, String t) {}
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{trustAll}, new SecureRandom());

        return new OkHttpClient.Builder()
                .sslSocketFactory(sslContext.getSocketFactory(), trustAll)
                .hostnameVerifier((hostname, session) -> true)
                .pingInterval(30, TimeUnit.SECONDS)
                .build();
    }
}
