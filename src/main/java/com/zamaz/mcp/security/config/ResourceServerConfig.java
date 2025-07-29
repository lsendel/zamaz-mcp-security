package com.zamaz.mcp.security.config;

import com.zamaz.mcp.security.jwt.JwtAuthenticationConverter;
import com.zamaz.mcp.security.jwt.JwtKeyManager;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.SecretKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Modern Resource Server configuration using OAuth2 JWT with proper token
 * validation.
 * Supports both HMAC and RSA key validation based on configuration.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class ResourceServerConfig {

    private final JwtKeyManager keyManager;
    private final JwtAuthenticationConverter jwtAuthenticationConverter;
    private final SharedSecurityConfig sharedSecurityConfig;

    @Value("${jwt.issuer:mcp-auth-server}")
    private String issuer;

    @Bean
    public SecurityFilterChain resourceServerFilterChain(HttpSecurity http) throws Exception {
        // Apply shared security configuration
        sharedSecurityConfig.configureCommonSecurity(http);

        http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(SharedSecurityConfig.CommonEndpoints.PUBLIC_ENDPOINTS).permitAll()
                        .requestMatchers(SharedSecurityConfig.CommonEndpoints.ADMIN_ENDPOINTS).hasRole("ADMIN")
                        .requestMatchers(SharedSecurityConfig.CommonEndpoints.AUTHENTICATED_ENDPOINTS).authenticated()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .decoder(jwtDecoder())
                                .jwtAuthenticationConverter(jwtAuthenticationConverter)))
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        if (keyManager.isUsingRSA()) {
            // Use RSA public key for verification
            RSAPublicKey publicKey = keyManager.getRSAPublicKey();
            return NimbusJwtDecoder.withPublicKey(publicKey).build();
        } else {
            // Use HMAC secret key for verification
            SecretKey secretKey = (SecretKey) keyManager.getVerificationKey();
            return NimbusJwtDecoder.withSecretKey(secretKey).build();
        }
    }
}