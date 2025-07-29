package com.zamaz.mcp.security.config;

import com.zamaz.mcp.security.jwt.JwtAuthenticationConverter;
import com.zamaz.mcp.security.jwt.JwtKeyManager;
import com.zamaz.mcp.security.jwt.JwtTokenCustomizer;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import javax.crypto.SecretKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Modern JWT configuration supporting both HMAC and RSA signing algorithms.
 * Implements proper JWT key management with RS256 signing for production.
 */
@Configuration
@RequiredArgsConstructor
public class ModernJwtConfig {

    private final JwtKeyManager keyManager;

    /**
     * JWT Decoder for validating incoming JWT tokens
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        if (keyManager.isUsingRSA()) {
            return NimbusJwtDecoder.withPublicKey(keyManager.getRSAPublicKey()).build();
        } else {
            SecretKey secretKey = (SecretKey) keyManager.getVerificationKey();
            return NimbusJwtDecoder.withSecretKey(secretKey).build();
        }
    }

    /**
     * JWT Encoder for creating JWT tokens
     */
    @Bean
    public JwtEncoder jwtEncoder() {
        if (keyManager.isUsingRSA()) {
            RSAPublicKey publicKey = keyManager.getRSAPublicKey();
            RSAPrivateKey privateKey = keyManager.getRSAPrivateKey();

            JWK jwk = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .build();

            JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
            return new NimbusJwtEncoder(jwks);
        } else {
            SecretKey secretKey = (SecretKey) keyManager.getSigningKey();

            JWK jwk = new com.nimbusds.jose.jwk.OctetSequenceKey.Builder(secretKey)
                    .build();

            JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
            return new NimbusJwtEncoder(jwks);
        }
    }

    /**
     * JWT Authentication Converter for extracting authorities from JWT tokens
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        return new JwtAuthenticationConverter();
    }

    /**
     * JWT Token Customizer for adding custom claims
     */
    @Bean
    @ConditionalOnProperty(name = "spring.security.oauth2.authorizationserver.enabled", havingValue = "true")
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return new JwtTokenCustomizer();
    }

    /**
     * JWK Set endpoint for public key discovery (RS256 only)
     */
    @Bean
    @ConditionalOnProperty(name = "jwt.signing.algorithm", havingValue = "RS256")
    public JWKSource<SecurityContext> jwkSource() {
        if (keyManager.isUsingRSA()) {
            RSAPublicKey publicKey = keyManager.getRSAPublicKey();
            RSAPrivateKey privateKey = keyManager.getRSAPrivateKey();

            JWK jwk = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID("mcp-rsa-key")
                    .build();

            return new ImmutableJWKSet<>(new JWKSet(jwk));
        }

        throw new IllegalStateException("JWK source can only be created for RSA keys");
    }
}