package com.zamaz.mcp.security.jwt;

import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.function.Function;

/**
 * Modern JWT decoder implementation using JJWT 0.12.x patterns.
 * Replaces deprecated JWT parser methods with modern decoder implementation.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtDecoder {

    private final JwtKeyManager keyManager;

    /**
     * Parse and validate JWT token using modern JJWT decoder
     */
    public Claims parseToken(String token) {
        try {
            JwtParser parser = Jwts.parser()
                    .verifyWith((java.security.Key) keyManager.getVerificationKey())
                    .build();

            return parser.parseSignedClaims(token).getPayload();
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
        return getClaimFromToken(token, Claims::getSubject);
    }

    /**
     * Extract expiration date from token
     */
    public Date getExpirationDate(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    /**
     * Extract issued at date from token
     */
    public Date getIssuedAtDate(String token) {
        return getClaimFromToken(token, Claims::getIssuedAt);
    }

    /**
     * Extract a specific claim from token
     */
    public <T> T getClaim(String token, String claimName, Class<T> requiredType) {
        Claims claims = parseToken(token);
        return claims.get(claimName, requiredType);
    }

    /**
     * Extract a specific claim using a resolver function
     */
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = parseToken(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Check if token is expired
     */
    public boolean isTokenExpired(String token) {
        try {
            final Date expiration = getExpirationDate(token);
            return expiration.before(new Date());
        } catch (JwtValidationException e) {
            return true;
        }
    }

    /**
     * Validate token against a specific subject
     */
    public boolean validateToken(String token, String expectedSubject) {
        try {
            final String subject = getSubject(token);
            return (expectedSubject.equals(subject) && !isTokenExpired(token));
        } catch (JwtValidationException e) {
            return false;
        }
    }

    /**
     * Get all claims from token
     */
    public Claims getAllClaims(String token) {
        return parseToken(token);
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