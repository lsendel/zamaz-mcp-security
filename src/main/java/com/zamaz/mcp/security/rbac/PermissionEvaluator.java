package com.zamaz.mcp.security.rbac;

import com.zamaz.mcp.security.context.SecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.UUID;

/**
 * Evaluates permissions based on user's roles and context
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class PermissionEvaluator {
    
    private final RoleService roleService;
    
    /**
     * Check if the current user has a specific permission
     */
    public boolean hasPermission(SecurityContext context, Permission permission) {
        if (context == null || context.getUserId() == null) {
            log.debug("No security context or user ID, denying permission: {}", permission);
            return false;
        }
        
        // System admin bypass
        if (context.isSystemAdmin()) {
            log.debug("System admin access granted for permission: {}", permission);
            return true;
        }
        
        // Get user's roles
        Set<Role> userRoles = roleService.getUserRoles(
            UUID.fromString(context.getUserId()),
            UUID.fromString(context.getOrganizationId())
        );
        
        // Check if any role has the permission
        boolean hasPermission = userRoles.stream()
            .anyMatch(role -> role.hasPermission(permission));
        
        log.debug("Permission {} {} for user {} in organization {}", 
            permission, 
            hasPermission ? "granted" : "denied",
            context.getUserId(), 
            context.getOrganizationId()
        );
        
        return hasPermission;
    }
    
    /**
     * Check if the current user has any of the specified permissions
     */
    public boolean hasAnyPermission(SecurityContext context, Permission... permissions) {
        for (Permission permission : permissions) {
            if (hasPermission(context, permission)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Check if the current user has all of the specified permissions
     */
    public boolean hasAllPermissions(SecurityContext context, Permission... permissions) {
        for (Permission permission : permissions) {
            if (!hasPermission(context, permission)) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Check if the current user has permission for a specific resource
     */
    public boolean hasPermissionForResource(SecurityContext context, Permission permission, String resourceId) {
        // First check basic permission
        if (!hasPermission(context, permission)) {
            return false;
        }
        
        // Additional resource-specific checks can be implemented here
        // For example, checking if the user owns the resource or has specific access
        
        return true;
    }
    
    /**
     * Check if the current user is the owner of a resource
     */
    public boolean isResourceOwner(SecurityContext context, String resourceType, String resourceId) {
        // This would typically check against a database to verify ownership
        // For now, we'll implement a basic check
        
        log.debug("Checking ownership for user {} on {} with ID {}", 
            context.getUserId(), resourceType, resourceId);
        
        // Implementation would vary based on resource type
        return roleService.isResourceOwner(
            UUID.fromString(context.getUserId()),
            resourceType,
            resourceId
        );
    }
}