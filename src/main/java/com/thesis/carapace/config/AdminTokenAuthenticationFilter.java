package com.thesis.carapace.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

/**
 * Stateless authentication for the gateway management plane. The token can be
 * supplied as either {@code X-Admin-Token} or {@code Authorization: Bearer ...}.
 * An empty configured token deliberately authenticates nobody.
 */
@Component
public class AdminTokenAuthenticationFilter extends OncePerRequestFilter {

    private final byte[] expectedToken;

    public AdminTokenAuthenticationFilter(@Value("${security.admin.token:}") String expectedToken) {
        this.expectedToken = expectedToken.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String supplied = request.getHeader("X-Admin-Token");
        if (supplied == null) {
            String authorization = request.getHeader("Authorization");
            if (authorization != null && authorization.startsWith("Bearer ")) {
                supplied = authorization.substring(7);
            }
        }

        if (supplied != null && expectedToken.length > 0
                && MessageDigest.isEqual(expectedToken, supplied.getBytes(StandardCharsets.UTF_8))) {
            var authorities = List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken("carapace-admin", null, authorities));
        }
        filterChain.doFilter(request, response);
    }
}
