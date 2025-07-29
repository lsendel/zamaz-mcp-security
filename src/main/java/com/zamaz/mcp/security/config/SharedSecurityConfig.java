package com.zamaz.mcp.security.config;

import com.zamaz.mcp.security.filter.SecurityHeadersFilter;
import com.zamaz.mcp.security.tenant.TenantFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * Shared security configuration for all MCP services.
 * Provides consistent security patterns, CORS configuration, and security
 * headers.
 */
@Configuration
@RequiredArgsConstructor
public class SharedSecurityConfig {

    private final TenantFilter tenantFilter;

    @Value("${cors.allowed-origins:http://localhost:3000,http://localhost:8080}")
    private String[] allowedOrigins;

    @Value("${cors.allowed-methods:GET,POST,PUT,DELETE,OPTIONS}")
    private String[] allowedMethods;

    @Value("${cors.allowed-headers:*}")
    private String[] allowedHeaders;

    @Value("${cors.allow-credentials:true}")
    private boolean allowCredentials;

    @Value("${cors.max-age:3600}")
    private long maxAge;

    /**
     * Configure CORS for all services.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Set allowed origins
        configuration.setAllowedOriginPatterns(Arrays.asList(allowedOrigins));

        // Set allowed methods
        configuration.setAllowedMethods(Arrays.asList(allowedMethods));

        // Set allowed headers
        if (allowedHeaders.length == 1 && "*".equals(allowedHeaders[0])) {
            configuration.addAllowedHeader("*");
        } else {
            configuration.setAllowedHeaders(Arrays.asList(allowedHeaders));
        }

        // Set credentials
        configuration.setAllowCredentials(allowCredentials);

        // Set max age
        configuration.setMaxAge(maxAge);

        // Expose common headers
        configuration.setExposedHeaders(List.of(
                "Authorization",
                "X-Organization-ID",
                "X-Request-ID",
                "X-Correlation-ID",
                "X-Total-Count",
                "X-Page-Count"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * Security headers filter for modern security headers.
     */
    @Bean
    public SecurityHeadersFilter securityHeadersFilter() {
        return new SecurityHeadersFilter();
    }

    /**
     * Configure common security filters for all services.
     */
    public void configureCommonSecurity(HttpSecurity http) throws Exception {
        http
                // Add tenant filter first
                .addFilterBefore(tenantFilter, UsernamePasswordAuthenticationFilter.class)

                // Add security headers filter
                .addFilterAfter(securityHeadersFilter(), TenantFilter.class)

                // Configure CORS
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // Disable CSRF for stateless APIs
                .csrf(csrf -> csrf.disable())

                // Configure frame options
                .headers(headers -> headers
                        .frameOptions().deny()
                        .contentTypeOptions().and()
                        .httpStrictTransportSecurity(hstsConfig -> hstsConfig
                                .maxAgeInSeconds(31536000)
                                .includeSubdomains(true)
                                .preload(true)));
    }

    /**
     * Common endpoint matchers for public endpoints.
     */
    public static class CommonEndpoints {
        public static final String[] PUBLIC_ENDPOINTS = {
                "/actuator/health",
                "/actuator/info",
                "/api/v1/auth/login",
                "/api/v1/auth/register",
                "/api/v1/auth/forgot-password",
                "/api/v1/auth/reset-password",
                "/error"
        };

        public static final String[] AUTHENTICATED_ENDPOINTS = {
                "/api/v1/**",
                "/tools/**",
                "/resources/**"
        };

        public static final String[] ADMIN_ENDPOINTS = {
                "/api/v1/admin/**",
                "/actuator/**"
        };
    }
}