package com.zamaz.mcp.security.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Security headers filter that adds modern security headers to all responses.
 * Implements security best practices for web applications.
 */
@Component
@Order(2)
@Slf4j
public class SecurityHeadersFilter implements Filter {

    @Value("${security.headers.csp:default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; frame-ancestors 'none';}")
    private String contentSecurityPolicy;

    @Value("${security.headers.referrer-policy:strict-origin-when-cross-origin}")
    private String referrerPolicy;

    @Value("${security.headers.permissions-policy:geolocation=(), microphone=(), camera=()}")
    private String permissionsPolicy;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Content Security Policy
        httpResponse.setHeader("Content-Security-Policy", contentSecurityPolicy);

        // X-Content-Type-Options
        httpResponse.setHeader("X-Content-Type-Options", "nosniff");

        // X-Frame-Options (already set by Spring Security, but ensuring it's there)
        httpResponse.setHeader("X-Frame-Options", "DENY");

        // X-XSS-Protection (legacy but still useful for older browsers)
        httpResponse.setHeader("X-XSS-Protection", "1; mode=block");

        // Referrer Policy
        httpResponse.setHeader("Referrer-Policy", referrerPolicy);

        // Permissions Policy (formerly Feature Policy)
        httpResponse.setHeader("Permissions-Policy", permissionsPolicy);

        // Strict Transport Security (HSTS) - handled by Spring Security but ensuring
        // consistency
        httpResponse.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");

        // Cache Control for sensitive endpoints
        String requestURI = ((jakarta.servlet.http.HttpServletRequest) request).getRequestURI();
        if (requestURI.contains("/api/") && !requestURI.contains("/public/")) {
            httpResponse.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
            httpResponse.setHeader("Pragma", "no-cache");
            httpResponse.setHeader("Expires", "0");
        }

        // Cross-Origin Embedder Policy
        httpResponse.setHeader("Cross-Origin-Embedder-Policy", "require-corp");

        // Cross-Origin Opener Policy
        httpResponse.setHeader("Cross-Origin-Opener-Policy", "same-origin");

        // Cross-Origin Resource Policy
        httpResponse.setHeader("Cross-Origin-Resource-Policy", "same-origin");

        // Server header removal (security through obscurity)
        httpResponse.setHeader("Server", "");

        // Custom security headers for debugging (only in development)
        String profile = System.getProperty("spring.profiles.active", "");
        if (profile.contains("dev") || profile.contains("local")) {
            httpResponse.setHeader("X-Security-Headers", "enabled");
        }

        chain.doFilter(request, response);
    }
}