package com.zamaz.mcp.security.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

/**
 * Represents a role in the system.
 * Roles are collections of permissions that define what a user can do.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Role {
    
    private String id;
    private String name;
    private String description;
    private Set<Permission> permissions;
    private boolean isSystemRole; // System roles like SYSTEM_ADMIN, USER
    
    /**
     * Check if this role has a specific permission.
     */
    public boolean hasPermission(String permission) {
        return permissions.stream()
                .anyMatch(p -> p.matches(permission));
    }
    
    /**
     * Check if this role has a specific permission object.
     */
    public boolean hasPermission(Permission permission) {
        return permissions.contains(permission);
    }
    
    /**
     * Add a permission to this role.
     */
    public void addPermission(Permission permission) {
        permissions.add(permission);
    }
    
    /**
     * Remove a permission from this role.
     */
    public void removePermission(Permission permission) {
        permissions.remove(permission);
    }
    
    /**
     * Common system roles.
     */
    public static class SystemRoles {
        public static final String SYSTEM_ADMIN = "SYSTEM_ADMIN";
        public static final String ORG_ADMIN = "ORG_ADMIN";
        public static final String USER = "USER";
        public static final String MODERATOR = "MODERATOR";
        public static final String VIEWER = "VIEWER";
    }
}