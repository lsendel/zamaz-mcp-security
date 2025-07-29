package com.zamaz.mcp.security.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Represents a permission in the system.
 * Permissions are specific actions that can be performed on resources.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Permission {
    
    private String id;
    private String name;
    private String description;
    private String service;
    private String action;
    
    /**
     * Create a permission from a permission string.
     * Format: "service:action" (e.g., "debate:create", "context:read")
     */
    public static Permission fromString(String permission) {
        String[] parts = permission.split(":");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid permission format. Expected 'service:action'");
        }
        
        Permission p = new Permission();
        p.setName(permission);
        p.setService(parts[0]);
        p.setAction(parts[1]);
        p.setDescription(String.format("Permission to %s %s", parts[1], parts[0]));
        return p;
    }
    
    /**
     * Check if this permission matches a required permission.
     * Supports wildcards in action (e.g., "debate:*" matches "debate:create")
     */
    public boolean matches(String requiredPermission) {
        if (name.equals(requiredPermission)) {
            return true;
        }
        
        Permission required = fromString(requiredPermission);
        
        // Check service match
        if (!service.equals(required.getService())) {
            return false;
        }
        
        // Check action match (support wildcards)
        return action.equals("*") || action.equals(required.getAction());
    }
}