package com.zamaz.mcp.security.annotation;

import com.zamaz.mcp.security.rbac.Permission;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation for method-level permission checking
 * Usage: @RequiresPermission(Permission.DEBATE_CREATE)
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresPermission {
    
    /**
     * Required permission(s) - user must have ALL specified permissions
     */
    Permission[] value();
    
    /**
     * Alternative permissions - user must have ANY of these permissions
     * Takes precedence over value() if specified
     */
    Permission[] anyOf() default {};
    
    /**
     * Resource ID parameter name for resource-specific authorization
     * e.g., "debateId" for debate-specific permissions
     */
    String resourceParam() default "";
    
    /**
     * Organization context required
     */
    boolean requireOrganization() default true;
    
    /**
     * Custom error message when permission is denied
     */
    String message() default "Access denied: insufficient permissions";
}