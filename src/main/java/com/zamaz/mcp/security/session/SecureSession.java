package com.zamaz.mcp.security.session;

import lombok.Builder;
import lombok.Data;

import java.io.Serializable;
import java.time.Instant;
import java.util.Map;

/**
 * Secure Session
 * Represents a secure user session with security attributes
 */
@Data
@Builder
public class SecureSession implements Serializable {
    
    private String sessionId;
    private String userId;
    private String organizationId;
    private SessionType sessionType;
    private Instant createdAt;
    private Instant lastAccessedAt;
    private Instant expiresAt;
    private Map<String, Object> attributes;
    private boolean active;
    
    // Security attributes
    private String clientIp;
    private String userAgent;
    private String deviceFingerprint;
    
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
    
    public boolean isValid() {
        return active && !isExpired();
    }
    
    public long getAgeInMinutes() {
        return java.time.Duration.between(createdAt, Instant.now()).toMinutes();
    }
    
    public long getIdleTimeInMinutes() {
        return java.time.Duration.between(lastAccessedAt, Instant.now()).toMinutes();
    }
}
