package com.zamaz.mcp.security.model;

import java.io.Serializable;
import java.time.Instant;

/**
 * Session information model for Redis storage.
 * Contains session metadata and security context.
 */
public class SessionInfo implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private String sessionId;
    private String userId;
    private Instant createdAt;
    private Instant lastAccessedAt;
    private Instant expiresAt;
    private Instant invalidatedAt;
    private String userAgent;
    private String ipAddress;
    private boolean active;
    private String organizationId;
    private String deviceId;
    private String deviceType;
    
    // Constructor
    public SessionInfo() {}
    
    // Getters and setters
    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }
    
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }
    
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    
    public Instant getLastAccessedAt() { return lastAccessedAt; }
    public void setLastAccessedAt(Instant lastAccessedAt) { this.lastAccessedAt = lastAccessedAt; }
    
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    
    public Instant getInvalidatedAt() { return invalidatedAt; }
    public void setInvalidatedAt(Instant invalidatedAt) { this.invalidatedAt = invalidatedAt; }
    
    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
    
    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
    
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
    
    public String getOrganizationId() { return organizationId; }
    public void setOrganizationId(String organizationId) { this.organizationId = organizationId; }
    
    public String getDeviceId() { return deviceId; }
    public void setDeviceId(String deviceId) { this.deviceId = deviceId; }
    
    public String getDeviceType() { return deviceType; }
    public void setDeviceType(String deviceType) { this.deviceType = deviceType; }
    
    // Helper methods
    public boolean isExpired() {
        return expiresAt != null && expiresAt.isBefore(Instant.now());
    }
    
    public long getIdleTimeSeconds() {
        if (lastAccessedAt == null) return 0;
        return Instant.now().getEpochSecond() - lastAccessedAt.getEpochSecond();
    }
}