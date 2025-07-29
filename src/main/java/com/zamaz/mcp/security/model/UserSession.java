package com.zamaz.mcp.security.model;

import java.io.Serializable;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

/**
 * User session model containing security context and user attributes.
 * Used for session-based authentication and authorization.
 */
public class UserSession implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private String sessionId;
    private String userId;
    private String username;
    private String email;
    private Set<String> roles;
    private Set<String> permissions;
    private String organizationId;
    private String organizationName;
    private Map<String, Object> attributes;
    private Instant createdAt;
    private Instant lastAccessedAt;
    private boolean mfaVerified;
    private String authenticationMethod;
    
    // Constructor
    public UserSession() {}
    
    // Builder pattern
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private final UserSession session = new UserSession();
        
        public Builder sessionId(String sessionId) {
            session.sessionId = sessionId;
            return this;
        }
        
        public Builder userId(String userId) {
            session.userId = userId;
            return this;
        }
        
        public Builder username(String username) {
            session.username = username;
            return this;
        }
        
        public Builder email(String email) {
            session.email = email;
            return this;
        }
        
        public Builder roles(Set<String> roles) {
            session.roles = roles;
            return this;
        }
        
        public Builder permissions(Set<String> permissions) {
            session.permissions = permissions;
            return this;
        }
        
        public Builder organizationId(String organizationId) {
            session.organizationId = organizationId;
            return this;
        }
        
        public Builder organizationName(String organizationName) {
            session.organizationName = organizationName;
            return this;
        }
        
        public Builder attributes(Map<String, Object> attributes) {
            session.attributes = attributes;
            return this;
        }
        
        public Builder createdAt(Instant createdAt) {
            session.createdAt = createdAt;
            return this;
        }
        
        public Builder lastAccessedAt(Instant lastAccessedAt) {
            session.lastAccessedAt = lastAccessedAt;
            return this;
        }
        
        public Builder mfaVerified(boolean mfaVerified) {
            session.mfaVerified = mfaVerified;
            return this;
        }
        
        public Builder authenticationMethod(String authenticationMethod) {
            session.authenticationMethod = authenticationMethod;
            return this;
        }
        
        public UserSession build() {
            if (session.createdAt == null) {
                session.createdAt = Instant.now();
            }
            if (session.lastAccessedAt == null) {
                session.lastAccessedAt = session.createdAt;
            }
            return session;
        }
    }
    
    // Getters and setters
    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }
    
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    
    public Set<String> getRoles() { return roles; }
    public void setRoles(Set<String> roles) { this.roles = roles; }
    
    public Set<String> getPermissions() { return permissions; }
    public void setPermissions(Set<String> permissions) { this.permissions = permissions; }
    
    public String getOrganizationId() { return organizationId; }
    public void setOrganizationId(String organizationId) { this.organizationId = organizationId; }
    
    public String getOrganizationName() { return organizationName; }
    public void setOrganizationName(String organizationName) { this.organizationName = organizationName; }
    
    public Map<String, Object> getAttributes() { return attributes; }
    public void setAttributes(Map<String, Object> attributes) { this.attributes = attributes; }
    
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    
    public Instant getLastAccessedAt() { return lastAccessedAt; }
    public void setLastAccessedAt(Instant lastAccessedAt) { this.lastAccessedAt = lastAccessedAt; }
    
    public boolean isMfaVerified() { return mfaVerified; }
    public void setMfaVerified(boolean mfaVerified) { this.mfaVerified = mfaVerified; }
    
    public String getAuthenticationMethod() { return authenticationMethod; }
    public void setAuthenticationMethod(String authenticationMethod) { 
        this.authenticationMethod = authenticationMethod; 
    }
    
    // Helper methods
    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }
    
    public boolean hasPermission(String permission) {
        return permissions != null && permissions.contains(permission);
    }
    
    public Object getAttribute(String key) {
        return attributes != null ? attributes.get(key) : null;
    }
    
    public void setAttribute(String key, Object value) {
        if (attributes == null) {
            attributes = new java.util.HashMap<>();
        }
        attributes.put(key, value);
    }
}