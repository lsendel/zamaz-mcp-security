package com.zamaz.mcp.security.service;

import com.zamaz.mcp.security.jwt.JwtKeyManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Modern authentication service demonstrating JWT token generation with custom
 * claims.
 * Uses Spring Security OAuth2 JWT encoder with proper RS256/HS256 support.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ModernAuthenticationService {

    private final JwtEncoder jwtEncoder;
    private final JwtKeyManager keyManager;

    /**
     * Generate access token with modern Spring Security OAuth2 patterns
     */
    public String generateAccessToken(Authentication authentication, String organizationId) {
        Instant now = Instant.now();
        Instant expiry = now.plus(1, ChronoUnit.HOURS);

        // Extract authorities from authentication
        Set<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        // Build JWT claims using modern JwtClaimsSet builder
        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
                .issuer("mcp-auth-server")
                .subject(authentication.getName())
                .audience(java.util.List.of("mcp-services"))
                .issuedAt(now)
                .expiresAt(expiry)
                .claim("scope", String.join(" ", authorities))
                .claim("authorities", authorities)
                .claim("username", authentication.getName())
                .claim("token_version", "2.0")
                .claim("signing_algorithm", keyManager.getSigningAlgorithm());

        // Add organization context if provided
        if (organizationId != null && !organizationId.trim().isEmpty()) {
            claimsBuilder.claim("organizationId", organizationId);
        }

        // Add authentication details if available
        if (authentication.getDetails() instanceof java.util.Map) {
            @SuppressWarnings("unchecked")
            java.util.Map<String, Object> details = (java.util.Map<String, Object>) authentication.getDetails();

            // Add roles if present
            if (details.containsKey("roles")) {
                claimsBuilder.claim("roles", details.get("roles"));
            }

            // Add permissions if present
            if (details.containsKey("permissions")) {
                claimsBuilder.claim("permissions", details.get("permissions"));
            }
        }

        JwtClaimsSet claims = claimsBuilder.build();

        // Encode JWT using modern Spring Security OAuth2 encoder
        String token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        log.debug("Generated access token for user: {} with algorithm: {}",
                authentication.getName(), keyManager.getSigningAlgorithm());

        return token;
    }

    /**
     * Generate refresh token with minimal claims
     */
    public String generateRefreshToken(Authentication authentication) {
        Instant now = Instant.now();
        Instant expiry = now.plus(7, ChronoUnit.DAYS);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("mcp-auth-server")
                .subject(authentication.getName())
                .audience(java.util.List.of("mcp-services"))
                .issuedAt(now)
                .expiresAt(expiry)
                .claim("token_type", "refresh")
                .claim("token_version", "2.0")
                .build();

        String token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        log.debug("Generated refresh token for user: {}", authentication.getName());

        return token;
    }

    /**
     * Generate service-to-service token for internal communication
     */
    public String generateServiceToken(String serviceId, Set<String> scopes) {
        Instant now = Instant.now();
        Instant expiry = now.plus(30, ChronoUnit.MINUTES);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("mcp-auth-server")
                .subject(serviceId)
                .audience(java.util.List.of("mcp-services"))
                .issuedAt(now)
                .expiresAt(expiry)
                .claim("scope", String.join(" ", scopes))
                .claim("client_type", "service")
                .claim("token_type", "service")
                .claim("token_version", "2.0")
                .build();

        String token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        log.debug("Generated service token for service: {} with scopes: {}", serviceId, scopes);

        return token;
    }

    /**
     * Generate token with custom claims for specific use cases
     */
    public String generateCustomToken(String subject, java.util.Map<String, Object> customClaims,
            long validityMinutes) {
        Instant now = Instant.now();
        Instant expiry = now.plus(validityMinutes, ChronoUnit.MINUTES);

        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
                .issuer("mcp-auth-server")
                .subject(subject)
                .audience(java.util.List.of("mcp-services"))
                .issuedAt(now)
                .expiresAt(expiry)
                .claim("token_version", "2.0");

        // Add custom claims
        customClaims.forEach(claimsBuilder::claim);

        JwtClaimsSet claims = claimsBuilder.build();
        String token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        log.debug("Generated custom token for subject: {} with {} custom claims",
                subject, customClaims.size());

        return token;
    }

    /**
     * Get current signing algorithm information
     */
    public String getSigningAlgorithmInfo() {
        return String.format("Current signing algorithm: %s, Using RSA: %s",
                keyManager.getSigningAlgorithm(), keyManager.isUsingRSA());
    }
}