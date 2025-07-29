package com.zamaz.mcp.security.testing;

import org.springframework.security.test.context.support.WithSecurityContext;

import java.lang.annotation.*;

/**
 * Annotation to run tests with a mock tenant security context.
 * This provides a convenient way to test multi-tenant scenarios.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@WithSecurityContext(factory = WithMockTenantSecurityContextFactory.class)
public @interface WithMockTenant {
    
    /**
     * The tenant/organization ID to use.
     */
    String tenantId() default "test-tenant";
    
    /**
     * The user ID within the tenant.
     */
    String userId() default "test-user";
    
    /**
     * The username.
     */
    String username() default "test@example.com";
    
    /**
     * The roles to assign to the user.
     */
    String[] roles() default {"USER"};
    
    /**
     * The permissions to grant at the organization level.
     */
    String[] permissions() default {"DEBATE_VIEW", "DEBATE_CREATE"};
    
    /**
     * Whether the user should be an organization admin.
     */
    boolean isOrgAdmin() default false;
    
    /**
     * Whether the user should be a system admin.
     */
    boolean isSystemAdmin() default false;
    
    /**
     * Additional organization IDs the user has access to.
     */
    String[] additionalOrganizations() default {};
    
    /**
     * Whether the token should be expired.
     */
    boolean expired() default false;
}