package com.zamaz.mcp.security.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to mark methods that require specific roles.
 * Used for role-based authorization.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresRole {
    
    /**
     * The role required to access this method.
     * Examples: "ADMIN", "USER", "MODERATOR"
     */
    String value();
    
    /**
     * Whether the role must be organization-specific.
     * If true, user must have the role within the current organization.
     */
    boolean organizationScope() default true;
}