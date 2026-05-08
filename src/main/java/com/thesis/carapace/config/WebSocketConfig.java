package com.thesis.carapace.config;

import com.thesis.carapace.proxy.CfmsProxyHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;
import org.springframework.web.socket.server.standard.ServletServerContainerFactoryBean;

@Configuration
@EnableWebSocket
@RequiredArgsConstructor
public class WebSocketConfig implements WebSocketConfigurer {

    private final CfmsProxyHandler cfmsProxyHandler;

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(cfmsProxyHandler, "/ws")
                .setAllowedOrigins("*");
    }

    /**
     * The embedded servlet container's WebSocket implementation defaults to a
     * tiny 8 KB binary message buffer. CFMS file uploads chunk at 64 KB and the
     * proxy bursts decrypted plaintext bytes back to the browser at multi-MB
     * granularity, so anything under a few megabytes here will quietly drop
     * the WebSocket the moment a real file moves through.
     *
     * 8 MB covers our chunk size (64 KB) with plenty of headroom for the
     * Java→browser plaintext bursts after AES-GCM decryption.
     */
    @Bean
    public ServletServerContainerFactoryBean wsContainerFactory() {
        ServletServerContainerFactoryBean factory = new ServletServerContainerFactoryBean();
        factory.setMaxBinaryMessageBufferSize(8 * 1024 * 1024);
        factory.setMaxTextMessageBufferSize(8 * 1024 * 1024);
        factory.setMaxSessionIdleTimeout(0L); // 0 = no idle timeout (downloads can take time)
        return factory;
    }
}
