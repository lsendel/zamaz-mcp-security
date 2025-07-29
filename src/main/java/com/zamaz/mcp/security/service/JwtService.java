package com.zamaz.mcp.security.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

/**
 * Service for JWT token generation and validation.
 * Provides consistent JWT handling across all MCP services.
 */
@Slf4j
@Service
public class JwtService {

    private final SecretKey key;
    private final long accessTokenValidity;
    private final long refreshTokenValidity;
    private final String issuer;

    public JwtService(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-validity:3600}") long accessTokenValidity,
            @Value("${jwt.refresh-token-validity:86400}") long refreshTokenValidity,
            @Value("${jwt.issuer:mcp-services}") String issuer) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenValidity = accessTokenValidity * 1000; // Convert to milliseconds
        this.refreshTokenValidity = refreshTokenValidity * 1000;
        this.issuer = issuer;
    }

    /**
     * Generate an access token
     */
    public String generateAccessToken(String subject, Map<String, Object> claims) {
        return generateToken(subject, claims, accessTokenValidity);
    }

    /**
     * Generate a refresh token
     */
    public String generateRefreshToken(String subject) {
        return generateToken(subject, Map.of("type", "refresh"), refreshTokenValidity);
    }

    /**
     * Generate a token with custom claims using modern JJWT 0.12.x builder patterns
     */
    private String generateToken(String subject, Map<String, Object> claims, long validity) {
        Instant now = Instant.now();
        Instant expiration = now.plus(validity, ChronoUnit.MILLIS);

        JwtBuilder builder = Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(subject)
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration));

        if (claims != null && !claims.isEmpty()) {
            builder.claims(claims);
        }

        return builder.signWith(key).compact();
    }

    /**
     * Validate and parse a token
     */
    public Claims validateToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(key)
                    .requireIssuer(issuer)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            log.debug("JWT token expired: {}", e.getMessage());
            throw new JwtValidationException("Token has expired", e);
        } catch (UnsupportedJwtException e) {
            log.warn("Unsupported JWT token: {}", e.getMessage());
            throw new JwtValidationException("Token is not supported", e);
        } catch (MalformedJwtException e) {
            log.warn("Malformed JWT token: {}", e.getMessage());
            throw new JwtValidationException("Token is malformed", e);
        } catch (JwtException e) {
            log.warn("JWT validation failed: {}", e.getMessage());
            throw new JwtValidationException("Token validation failed", e);
        } catch (IllegalArgumentException e) {
            log.warn("JWT token is invalid: {}", e.getMessage());
            throw new JwtValidationException("Token is invalid", e);
        }
    }

    /**
     * Extract subject from token
     */
    public String getSubject(String token) {
        return validateToken(token).getSubject();
    }

    /**
     * Extract a specific claim from token
     */
    public Object getClaim(String token, String claimName) {
        return validateToken(token).get(claimName);
    }

    /**
     * Extract a specific claim with type safety
     */
    public <T> T getClaim(String token, String claimName, Class<T> requiredType) {
        return validateToken(token).get(claimName, requiredType);
    }

    /**
     * Generate token with organization, roles, and permissions claims
     */
    public String generateTokenWithClaims(String subject, String organizationId,
            java.util.Set<String> roles,
            java.util.Set<String> permissions) {
        Map<String, Object> claims = new java.util.HashMap<>();

        if (organizationId != null) {
            claims.put("organizationId", organizationId);
        }

        if (roles != null && !roles.isEmpty()) {
            claims.put("roles", roles);
        }

        if (permissions != null && !permissions.isEmpty()) {
            claims.put("permissions", permissions);
        }

        // Add token metadata
        claims.put("token_version", "1.0");
        claims.put("issuer_service", "mcp-security");

        return generateAccessToken(subject, claims);
    }

    /**
     * Check if token is expired
     */
    public boolean isTokenExpired(String token) {
        try {
            Claims claims = validateToken(token);
            return claims.getExpiration().before(new Date());
        } catch (JwtValidationException e) {
            return true;
        }
    }

    /**
     * Custom exception for JWT validation errors
     */
    public static class JwtValidationException extends RuntimeException {
        public JwtValidationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}