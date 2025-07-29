package com.zamaz.mcp.security.context;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

/**
 * Security context holding user authentication and authorization information
 */
@Data
@NoArgsConstructor
public class SecurityContext implements Serializable {
    
    private String userId;
    private String organizationId;
    private String username;
    private String email;
    private Set<String> roles = new HashSet<>();
    private Set<String> permissions = new HashSet<>();
    private boolean authenticated;
    private boolean systemAdmin;
    private String token;
    private long tokenExpiry;
    
    /**
     * Check if the context has a specific role
     */
    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }
    
    /**
     * Check if the context has any of the specified roles
     */
    public boolean hasAnyRole(String... roles) {
        if (this.roles == null) {
            return false;
        }
        
        for (String role : roles) {
            if (this.roles.contains(role)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Check if the context has all of the specified roles
     */
    public boolean hasAllRoles(String... roles) {
        if (this.roles == null) {
            return false;
        }
        
        for (String role : roles) {
            if (!this.roles.contains(role)) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Add a role to the context
     */
    public void addRole(String role) {
        if (this.roles == null) {
            this.roles = new HashSet<>();
        }
        this.roles.add(role);
    }
    
    /**
     * Add multiple roles to the context
     */
    public void addRoles(Set<String> roles) {
        if (this.roles == null) {
            this.roles = new HashSet<>();
        }
        this.roles.addAll(roles);
    }
    
    /**
     * Check if the token is expired
     */
    public boolean isTokenExpired() {
        return System.currentTimeMillis() > tokenExpiry;
    }
    
    /**
     * Clear the security context
     */
    public void clear() {
        this.userId = null;
        this.organizationId = null;
        this.username = null;
        this.email = null;
        this.roles = new HashSet<>();
        this.permissions = new HashSet<>();
        this.authenticated = false;
        this.systemAdmin = false;
        this.token = null;
        this.tokenExpiry = 0;
    }
}