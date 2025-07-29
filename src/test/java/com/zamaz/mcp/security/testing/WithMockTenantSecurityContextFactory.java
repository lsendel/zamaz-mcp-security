package com.zamaz.mcp.security.testing;

import com.zamaz.mcp.security.domain.Permission;
import com.zamaz.mcp.security.domain.Role;
import com.zamaz.mcp.security.domain.SecurityContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Factory for creating security contexts from @WithMockTenant annotations.
 */
public class WithMockTenantSecurityContextFactory 
        implements WithSecurityContextFactory<WithMockTenant> {

    @Override
    public org.springframework.security.core.context.SecurityContext createSecurityContext(
            WithMockTenant annotation) {
        
        // Build the custom security context
        SecurityTestContext.Builder builder = SecurityTestContext.builder()
            .withUserId(annotation.userId())
            .withUsername(annotation.username())
            .withOrganizationId(annotation.tenantId());

        // Set token expiry
        if (annotation.expired()) {
            builder.withExpiredToken();
        } else {
            builder.withValidToken();
        }

        // Handle special role cases
        if (annotation.isSystemAdmin()) {
            builder.withRole(Role.SYSTEM_ADMIN);
            // System admins get all permissions globally
            builder.withGlobalPermissions(Permission.values());
        } else if (annotation.isOrgAdmin()) {
            builder.withRole(Role.ORG_ADMIN);
            // Org admins get all permissions for their organization
            Set<Permission> orgAdminPerms = EnumSet.of(
                Permission.DEBATE_CREATE,
                Permission.DEBATE_UPDATE,
                Permission.DEBATE_DELETE,
                Permission.DEBATE_VIEW,
                Permission.TEMPLATE_MANAGE,
                Permission.USER_MANAGE
            );
            builder.withOrganizationPermissions(annotation.tenantId(), 
                orgAdminPerms.toArray(new Permission[0]));
        } else {
            // Parse regular roles
            for (String roleStr : annotation.roles()) {
                try {
                    Role role = Role.valueOf(roleStr);
                    builder.withRole(role);
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("Invalid role: " + roleStr);
                }
            }

            // Parse permissions for the primary organization
            List<Permission> perms = new ArrayList<>();
            for (String permStr : annotation.permissions()) {
                try {
                    perms.add(Permission.valueOf(permStr));
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("Invalid permission: " + permStr);
                }
            }
            builder.withOrganizationPermissions(annotation.tenantId(), 
                perms.toArray(new Permission[0]));
        }

        // Add additional organizations with same permissions
        for (String additionalOrg : annotation.additionalOrganizations()) {
            List<Permission> perms = new ArrayList<>();
            for (String permStr : annotation.permissions()) {
                perms.add(Permission.valueOf(permStr));
            }
            builder.withOrganizationPermissions(additionalOrg, 
                perms.toArray(new Permission[0]));
        }

        SecurityContext customContext = builder.build();

        // Create Spring Security context
        org.springframework.security.core.context.SecurityContext springContext = 
            SecurityContextHolder.createEmptyContext();

        // Build authorities
        List<GrantedAuthority> authorities = new ArrayList<>();
        
        // Add roles
        customContext.getRoles().forEach(role -> 
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.name()))
        );
        
        // Add permissions based on context
        if (annotation.isSystemAdmin()) {
            // Global permissions for system admin
            for (Permission perm : Permission.values()) {
                authorities.add(new SimpleGrantedAuthority(perm.name()));
            }
        } else {
            // Organization-specific permissions
            Set<Permission> orgPerms = customContext.getOrganizationPermissions()
                .getOrDefault(annotation.tenantId(), Collections.emptySet());
            orgPerms.forEach(perm -> 
                authorities.add(new SimpleGrantedAuthority(perm.name()))
            );
        }

        // Create authentication token
        Authentication auth = new MockTenantAuthenticationToken(
            customContext,
            annotation.username(),
            authorities
        );

        springContext.setAuthentication(auth);
        
        return springContext;
    }

    /**
     * Custom authentication token that carries the full security context.
     */
    public static class MockTenantAuthenticationToken 
            extends UsernamePasswordAuthenticationToken {
        
        private final SecurityContext securityContext;

        public MockTenantAuthenticationToken(SecurityContext context, 
                                           String principal, 
                                           Collection<? extends GrantedAuthority> authorities) {
            super(principal, null, authorities);
            this.securityContext = context;
        }

        public SecurityContext getSecurityContext() {
            return securityContext;
        }
    }
}