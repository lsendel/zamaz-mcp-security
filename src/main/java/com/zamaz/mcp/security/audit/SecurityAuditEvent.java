package com.zamaz.mcp.security.audit;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.Map;

/**
 * Security Audit Event
 * Represents a structured security event for logging and analysis
 */
@Data
@Builder
public class SecurityAuditEvent {
    
    private Instant timestamp;
    private SecurityAuditLogger.SecurityEventType eventType;
    private SecurityAuditLogger.RiskLevel riskLevel;
    private String description;
    private String userId;
    private String organizationId;
    private String sessionId;
    private String userAgent;
    private String clientIp;
    private Map<String, Object> additionalData;
    
    // Computed fields for analysis
    public String getEventId() {
        return eventType + "-" + timestamp.toEpochMilli();
    }
    
    public boolean isCritical() {
        return riskLevel == SecurityAuditLogger.RiskLevel.CRITICAL;
    }
    
    public boolean isHighRisk() {
        return riskLevel == SecurityAuditLogger.RiskLevel.HIGH || 
               riskLevel == SecurityAuditLogger.RiskLevel.CRITICAL;
    }
    
    public boolean isAuthenticationEvent() {
        return eventType == SecurityAuditLogger.SecurityEventType.AUTHENTICATION_SUCCESS ||
               eventType == SecurityAuditLogger.SecurityEventType.AUTHENTICATION_FAILURE;
    }
    
    public boolean isAuthorizationEvent() {
        return eventType == SecurityAuditLogger.SecurityEventType.AUTHORIZATION_SUCCESS ||
               eventType == SecurityAuditLogger.SecurityEventType.AUTHORIZATION_FAILURE ||
               eventType == SecurityAuditLogger.SecurityEventType.PERMISSION_DENIED ||
               eventType == SecurityAuditLogger.SecurityEventType.ROLE_DENIED;
    }
    
    public boolean isSuspiciousEvent() {
        return eventType == SecurityAuditLogger.SecurityEventType.SUSPICIOUS_ACTIVITY ||
               eventType == SecurityAuditLogger.SecurityEventType.SECURITY_VIOLATION ||
               eventType == SecurityAuditLogger.SecurityEventType.PRIVILEGE_ESCALATION_ATTEMPT;
    }
}
