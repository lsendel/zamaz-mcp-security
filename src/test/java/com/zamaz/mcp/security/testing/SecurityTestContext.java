package com.zamaz.mcp.security.testing;

import com.zamaz.mcp.security.domain.SecurityContext;
import com.zamaz.mcp.security.domain.Permission;
import com.zamaz.mcp.security.domain.Role;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Provides pre-configured security contexts for testing.
 */
public class SecurityTestContext {

    /**
     * Creates a security context for a system administrator.
     */
    public static SecurityContext systemAdmin() {
        return builder()
            .withUserId("system-admin")
            .withUsername("admin@system.com")
            .withRole(Role.SYSTEM_ADMIN)
            .withGlobalPermissions(Permission.values()) // All permissions
            .build();
    }

    /**
     * Creates a security context for an organization administrator.
     */
    public static SecurityContext organizationAdmin(String organizationId) {
        return builder()
            .withUserId("org-admin-" + organizationId)
            .withUsername("admin@org.com")
            .withOrganizationId(organizationId)
            .withRole(Role.ORG_ADMIN)
            .withOrganizationPermissions(organizationId, 
                Permission.DEBATE_CREATE,
                Permission.DEBATE_UPDATE,
                Permission.DEBATE_DELETE,
                Permission.DEBATE_VIEW,
                Permission.TEMPLATE_MANAGE,
                Permission.USER_MANAGE
            )
            .build();
    }

    /**
     * Creates a security context for a regular user.
     */
    public static SecurityContext regularUser(String organizationId) {
        return builder()
            .withUserId("user-" + UUID.randomUUID())
            .withUsername("user@example.com")
            .withOrganizationId(organizationId)
            .withRole(Role.USER)
            .withOrganizationPermissions(organizationId,
                Permission.DEBATE_CREATE,
                Permission.DEBATE_VIEW
            )
            .build();
    }

    /**
     * Creates a security context for an anonymous user.
     */
    public static SecurityContext anonymous() {
        return new SecurityContext(
            null, null, null, 
            Collections.emptySet(), 
            Collections.emptyMap(),
            Collections.emptyMap(),
            null
        );
    }

    /**
     * Creates a builder for custom security contexts.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Sets the current security context in Spring Security.
     */
    public static void setContext(SecurityContext context) {
        if (context.getUserId() == null) {
            SecurityContextHolder.clearContext();
            return;
        }

        List<GrantedAuthority> authorities = new ArrayList<>();
        
        // Add roles as authorities
        context.getRoles().forEach(role -> 
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.name()))
        );
        
        // Add permissions as authorities
        context.getGlobalPermissions().forEach(permission ->
            authorities.add(new SimpleGrantedAuthority(permission.name()))
        );

        Authentication auth = new UsernamePasswordAuthenticationToken(
            context.getUsername(),
            null,
            authorities
        );

        SecurityContextHolder.getContext().setAuthentication(auth);
        
        // Store the full context for retrieval
        SecurityContextThreadLocal.set(context);
    }

    /**
     * Clears the current security context.
     */
    public static void clearContext() {
        SecurityContextHolder.clearContext();
        SecurityContextThreadLocal.clear();
    }

    /**
     * Executes a runnable with a specific security context.
     */
    public static void runAs(SecurityContext context, Runnable action) {
        SecurityContext previousContext = SecurityContextThreadLocal.get();
        try {
            setContext(context);
            action.run();
        } finally {
            if (previousContext != null) {
                setContext(previousContext);
            } else {
                clearContext();
            }
        }
    }

    /**
     * Executes a supplier with a specific security context.
     */
    public static <T> T runAs(SecurityContext context, java.util.function.Supplier<T> supplier) {
        SecurityContext previousContext = SecurityContextThreadLocal.get();
        try {
            setContext(context);
            return supplier.get();
        } finally {
            if (previousContext != null) {
                setContext(previousContext);
            } else {
                clearContext();
            }
        }
    }

    /**
     * Builder for creating custom security contexts.
     */
    public static class Builder {
        private String userId;
        private String username;
        private String organizationId;
        private Set<Role> roles = new HashSet<>();
        private Set<Permission> globalPermissions = new HashSet<>();
        private Map<String, Set<Permission>> organizationPermissions = new HashMap<>();
        private Map<String, Set<Permission>> contextPermissions = new HashMap<>();
        private Instant tokenExpiry;

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

        public Builder withGlobalPermission(Permission permission) {
            this.globalPermissions.add(permission);
            return this;
        }

        public Builder withGlobalPermissions(Permission... permissions) {
            this.globalPermissions.addAll(Arrays.asList(permissions));
            return this;
        }

        public Builder withOrganizationPermissions(String orgId, Permission... permissions) {
            this.organizationPermissions.computeIfAbsent(orgId, k -> new HashSet<>())
                .addAll(Arrays.asList(permissions));
            return this;
        }

        public Builder withContextPermissions(String context, Permission... permissions) {
            this.contextPermissions.computeIfAbsent(context, k -> new HashSet<>())
                .addAll(Arrays.asList(permissions));
            return this;
        }

        public Builder withTokenExpiry(Instant expiry) {
            this.tokenExpiry = expiry;
            return this;
        }

        public Builder withValidToken() {
            this.tokenExpiry = Instant.now().plusSeconds(3600); // 1 hour
            return this;
        }

        public Builder withExpiredToken() {
            this.tokenExpiry = Instant.now().minusSeconds(3600); // Expired 1 hour ago
            return this;
        }

        public SecurityContext build() {
            return new SecurityContext(
                userId,
                username,
                organizationId,
                roles,
                organizationPermissions,
                contextPermissions,
                tokenExpiry
            );
        }
    }

    /**
     * Thread-local storage for security context.
     */
    private static class SecurityContextThreadLocal {
        private static final ThreadLocal<SecurityContext> CONTEXT = new ThreadLocal<>();

        public static void set(SecurityContext context) {
            CONTEXT.set(context);
        }

        public static SecurityContext get() {
            return CONTEXT.get();
        }

        public static void clear() {
            CONTEXT.remove();
        }
    }

    /**
     * Creates test contexts for common scenarios.
     */
    public static class Scenarios {
        
        /**
         * User with access to multiple organizations.
         */
        public static SecurityContext multiOrganizationUser(String... organizationIds) {
            Builder builder = builder()
                .withUserId("multi-org-user")
                .withUsername("multiorg@example.com")
                .withRole(Role.USER);
            
            for (String orgId : organizationIds) {
                builder.withOrganizationPermissions(orgId,
                    Permission.DEBATE_CREATE,
                    Permission.DEBATE_VIEW
                );
            }
            
            // Set the first org as current
            if (organizationIds.length > 0) {
                builder.withOrganizationId(organizationIds[0]);
            }
            
            return builder.build();
        }

        /**
         * User with limited permissions.
         */
        public static SecurityContext readOnlyUser(String organizationId) {
            return builder()
                .withUserId("readonly-user")
                .withUsername("readonly@example.com")
                .withOrganizationId(organizationId)
                .withRole(Role.USER)
                .withOrganizationPermissions(organizationId, Permission.DEBATE_VIEW)
                .build();
        }

        /**
         * User with context-specific permissions.
         */
        public static SecurityContext contextSpecificUser(String organizationId, String resourceId) {
            return builder()
                .withUserId("context-user")
                .withUsername("context@example.com")
                .withOrganizationId(organizationId)
                .withRole(Role.USER)
                .withOrganizationPermissions(organizationId, Permission.DEBATE_VIEW)
                .withContextPermissions(resourceId, 
                    Permission.DEBATE_UPDATE,
                    Permission.DEBATE_DELETE
                )
                .build();
        }
    }
}