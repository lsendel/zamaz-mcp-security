package com.zamaz.mcp.security.jwt;

import com.zamaz.mcp.security.model.McpUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Modern JWT service using JJWT 0.12.x with updated builder patterns.
 * Implements RS256 signing for production and proper key management.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class JwtService {

    private final JwtKeyManager keyManager;

    @Value("${jwt.expiration:86400000}") // Default 24 hours
    private long expiration;

    @Value("${jwt.issuer:mcp-auth-server}")
    private String issuer;

    private JwtParser jwtParser;

    @PostConstruct
    public void init() {
        this.jwtParser = Jwts.parser()
                .verifyWith((java.security.Key) keyManager.getVerificationKey())
                .requireIssuer(issuer)
                .build();

        log.info("JWT Service initialized with algorithm: {}", keyManager.getSigningAlgorithm());
    }

    /**
     * Generate JWT token for user.
     */
    public String generateToken(McpUser user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", user.getUsername());
        claims.put("email", user.getEmail());
        claims.put("organizationId", user.getCurrentOrganizationId());
        claims.put("organizationIds", user.getOrganizationIds());
        claims.put("roles", user.getRoles());

        return createToken(claims, user.getId());
    }

    /**
     * Create token with claims using modern JJWT 0.12.x builder patterns.
     */
    private String createToken(Map<String, Object> claims, String subject) {
        Instant now = Instant.now();
        Instant expiry = now.plus(expiration, ChronoUnit.MILLIS);

        JwtBuilder builder = Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .signWith((java.security.Key) keyManager.getSigningKey());

        return builder.compact();
    }

    /**
     * Create token from existing claims using modern patterns.
     */
    private String createToken(Claims claims) {
        Instant now = Instant.now();
        Instant expiry = now.plus(expiration, ChronoUnit.MILLIS);

        return Jwts.builder()
                .claims(claims)
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .signWith((java.security.Key) keyManager.getSigningKey())
                .compact();
    }

    /**
     * Validate token using modern JJWT 0.12.x parser.
     */
    public boolean isTokenValid(String token) {
        try {
            jwtParser.parseSignedClaims(token);
            return !isTokenExpired(token);
        } catch (Exception e) {
            log.debug("Token validation failed: {}", e.getClass().getSimpleName());
            return false;
        }
    }

    /**
     * Extract user ID from token.
     */
    public String extractUserId(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extract username from token.
     */
    public String extractUsername(String token) {
        return extractClaim(token, claims -> claims.get("username", String.class));
    }

    /**
     * Extract organization ID from token.
     */
    public String extractOrganizationId(String token) {
        return extractClaim(token, claims -> claims.get("organizationId", String.class));
    }

    /**
     * Extract organization IDs from token.
     */
    @SuppressWarnings("unchecked")
    public List<String> extractOrganizationIds(String token) {
        return extractClaim(token, claims -> (List<String>) claims.get("organizationIds"));
    }

    /**
     * Extract roles from token.
     */
    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        return extractClaim(token, claims -> (List<String>) claims.get("roles"));
    }

    /**
     * Extract expiration date from token.
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extract claim using resolver function.
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extract all claims from token using modern JJWT 0.12.x parser.
     */
    public Claims extractAllClaims(String token) {
        return jwtParser.parseSignedClaims(token).getPayload();
    }

    /**
     * Check if token is expired.
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Generate refresh token with existing claims using modern patterns.
     */
    public String refreshToken(String token) {
        final Claims claims = extractAllClaims(token);

        // Create new claims map from existing claims
        Map<String, Object> refreshClaims = new HashMap<>(claims);

        // Remove timing claims as they will be set by createToken
        refreshClaims.remove("iat");
        refreshClaims.remove("exp");
        refreshClaims.remove("nbf");

        return createToken(refreshClaims, claims.getSubject());
    }

    /**
     * Get configured expiration time in milliseconds.
     */
    public long getExpirationTime() {
        return expiration;
    }
}