package com.zamaz.mcp.security.context;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Holds the security context in thread-local storage
 */
@Component
@Slf4j
public class SecurityContextHolder {
    
    private static final ThreadLocal<SecurityContext> contextHolder = new ThreadLocal<>();
    
    /**
     * Get the current security context
     */
    public SecurityContext getContext() {
        SecurityContext context = contextHolder.get();
        if (context == null) {
            context = new SecurityContext();
            contextHolder.set(context);
        }
        return context;
    }
    
    /**
     * Set the security context
     */
    public void setContext(SecurityContext context) {
        if (context == null) {
            log.warn("Setting null security context");
        }
        contextHolder.set(context);
    }
    
    /**
     * Clear the security context
     */
    public void clearContext() {
        contextHolder.remove();
    }
    
    /**
     * Get the current user ID
     */
    public String getCurrentUserId() {
        SecurityContext context = getContext();
        return context != null ? context.getUserId() : null;
    }
    
    /**
     * Get the current organization ID
     */
    public String getCurrentOrganizationId() {
        SecurityContext context = getContext();
        return context != null ? context.getOrganizationId() : null;
    }
    
    /**
     * Check if the current user is authenticated
     */
    public boolean isAuthenticated() {
        SecurityContext context = getContext();
        return context != null && context.isAuthenticated();
    }
    
    /**
     * Check if the current user is a system admin
     */
    public boolean isSystemAdmin() {
        SecurityContext context = getContext();
        return context != null && context.isSystemAdmin();
    }
}