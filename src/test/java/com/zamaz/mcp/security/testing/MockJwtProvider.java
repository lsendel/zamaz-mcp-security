package com.zamaz.mcp.security.testing;

import com.zamaz.mcp.security.domain.Permission;
import com.zamaz.mcp.security.domain.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Provides mock JWT tokens for testing purposes.
 */
public class MockJwtProvider {

    private static final SecretKey SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final String ISSUER = "mcp-test";

    /**
     * Creates a valid JWT token with default claims.
     */
    public static String createToken() {
        return builder().build();
    }

    /**
     * Creates a JWT token for a specific user and organization.
     */
    public static String createToken(String userId, String organizationId) {
        return builder()
            .withUserId(userId)
            .withOrganizationId(organizationId)
            .build();
    }

    /**
     * Creates an expired JWT token.
     */
    public static String createExpiredToken() {
        return builder()
            .withExpiry(Instant.now().minusSeconds(3600))
            .build();
    }

    /**
     * Creates a JWT token with invalid signature.
     */
    public static String createInvalidToken() {
        SecretKey wrongKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        return Jwts.builder()
            .setSubject("test-user")
            .setIssuedAt(new Date())
            .setExpiration(Date.from(Instant.now().plusSeconds(3600)))
            .signWith(wrongKey)
            .compact();
    }

    /**
     * Creates a builder for custom JWT tokens.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Parses a token to extract claims (for testing).
     */
    public static Claims parseToken(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(SECRET_KEY)
            .build()
            .parseClaimsJws(token)
            .getBody();
    }

    /**
     * Gets the secret key used for signing (for test configuration).
     */
    public static SecretKey getSecretKey() {
        return SECRET_KEY;
    }

    /**
     * Builder for creating custom JWT tokens.
     */
    public static class Builder {
        private String userId = "test-user";
        private String username = "test@example.com";
        private String organizationId = "test-org";
        private Set<Role> roles = new HashSet<>(List.of(Role.USER));
        private Set<Permission> permissions = new HashSet<>();
        private Instant issuedAt = Instant.now();
        private Instant expiry = Instant.now().plusSeconds(3600);
        private Map<String, Object> customClaims = new HashMap<>();

        public Builder withUserId(String userId) {
            this.userId = userId;
            return this;
        }

        public Builder withUsername(String username) {
            this.username = username;
            return this;
        }

        public Builder withOrganizationId(String organizationId) {
            this.organizationId = organizationId;
            return this;
        }

        public Builder withRole(Role role) {
            this.roles.add(role);
            return this;
        }

        public Builder withRoles(Role... roles) {
            this.roles.addAll(Arrays.asList(roles));
            return this;
        }

        public Builder withPermission(Permission permission) {
            this.permissions.add(permission);
            return this;
        }

        public Builder withPermissions(Permission... permissions) {
            this.permissions.addAll(Arrays.asList(permissions));
            return this;
        }

        public Builder withIssuedAt(Instant issuedAt) {
            this.issuedAt = issuedAt;
            return this;
        }

        public Builder withExpiry(Instant expiry) {
            this.expiry = expiry;
            return this;
        }

        public Builder withCustomClaim(String key, Object value) {
            this.customClaims.put(key, value);
            return this;
        }

        public Builder asSystemAdmin() {
            this.roles.clear();
            this.roles.add(Role.SYSTEM_ADMIN);
            this.permissions.addAll(Arrays.asList(Permission.values()));
            return this;
        }

        public Builder asOrgAdmin() {
            this.roles.clear();
            this.roles.add(Role.ORG_ADMIN);
            this.permissions.addAll(Arrays.asList(
                Permission.DEBATE_CREATE,
                Permission.DEBATE_UPDATE,
                Permission.DEBATE_DELETE,
                Permission.DEBATE_VIEW,
                Permission.TEMPLATE_MANAGE,
                Permission.USER_MANAGE
            ));
            return this;
        }

        public String build() {
            Map<String, Object> claims = new HashMap<>(customClaims);
            claims.put("userId", userId);
            claims.put("username", username);
            claims.put("organizationId", organizationId);
            claims.put("roles", roles.stream().map(Role::name).collect(Collectors.toList()));
            claims.put("permissions", permissions.stream().map(Permission::name).collect(Collectors.toList()));

            return Jwts.builder()
                .setClaims(claims)
                .setSubject(userId)
                .setIssuer(ISSUER)
                .setIssuedAt(Date.from(issuedAt))
                .setExpiration(Date.from(expiry))
                .signWith(SECRET_KEY)
                .compact();
        }
    }

    /**
     * Pre-built tokens for common test scenarios.
     */
    public static class Tokens {
        
        public static String systemAdmin() {
            return builder().asSystemAdmin().build();
        }

        public static String orgAdmin(String organizationId) {
            return builder()
                .withOrganizationId(organizationId)
                .asOrgAdmin()
                .build();
        }

        public static String regularUser(String organizationId) {
            return builder()
                .withOrganizationId(organizationId)
                .withPermissions(Permission.DEBATE_VIEW, Permission.DEBATE_CREATE)
                .build();
        }

        public static String readOnlyUser(String organizationId) {
            return builder()
                .withOrganizationId(organizationId)
                .withPermissions(Permission.DEBATE_VIEW)
                .build();
        }

        public static String multiOrgUser(String primaryOrg, String... additionalOrgs) {
            Builder builder = builder()
                .withOrganizationId(primaryOrg)
                .withPermissions(Permission.DEBATE_VIEW, Permission.DEBATE_CREATE);
            
            // Add additional orgs as custom claims
            List<String> allOrgs = new ArrayList<>();
            allOrgs.add(primaryOrg);
            allOrgs.addAll(Arrays.asList(additionalOrgs));
            builder.withCustomClaim("organizations", allOrgs);
            
            return builder.build();
        }

        public static String expiredToken() {
            return createExpiredToken();
        }

        public static String invalidToken() {
            return createInvalidToken();
        }

        public static String tokenExpiringIn(int seconds) {
            return builder()
                .withExpiry(Instant.now().plusSeconds(seconds))
                .build();
        }
    }
}