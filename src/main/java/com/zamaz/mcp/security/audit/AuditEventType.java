package com.zamaz.mcp.security.audit;

/**
 * Enumeration of audit event types for security and compliance logging
 */
public enum AuditEventType {
    
    // Authentication events
    AUTHENTICATION_SUCCESS("AUTH_SUCCESS", "User authentication succeeded"),
    AUTHENTICATION_FAILURE("AUTH_FAILURE", "User authentication failed"),
    LOGOUT("LOGOUT", "User logged out"),
    SESSION_TIMEOUT("SESSION_TIMEOUT", "User session timed out"),
    PASSWORD_CHANGE("PASSWORD_CHANGE", "User password changed"),
    ACCOUNT_LOCKED("ACCOUNT_LOCKED", "User account locked"),
    ACCOUNT_UNLOCKED("ACCOUNT_UNLOCKED", "User account unlocked"),
    
    // Authorization events
    AUTHORIZATION_SUCCESS("AUTHZ_SUCCESS", "User authorization succeeded"),
    AUTHORIZATION_FAILURE("AUTHZ_FAILURE", "User authorization failed"),
    PERMISSION_GRANTED("PERMISSION_GRANTED", "Permission granted to user"),
    PERMISSION_DENIED("PERMISSION_DENIED", "Permission denied to user"),
    ROLE_ASSIGNED("ROLE_ASSIGNED", "Role assigned to user"),
    ROLE_REMOVED("ROLE_REMOVED", "Role removed from user"),
    
    // Data access events
    DATA_ACCESS("DATA_ACCESS", "Data accessed"),
    DATA_CREATE("DATA_CREATE", "Data created"),
    DATA_UPDATE("DATA_UPDATE", "Data updated"),
    DATA_DELETE("DATA_DELETE", "Data deleted"),
    DATA_EXPORT("DATA_EXPORT", "Data exported"),
    DATA_IMPORT("DATA_IMPORT", "Data imported"),
    
    // System events
    SYSTEM_STARTUP("SYSTEM_STARTUP", "System started"),
    SYSTEM_SHUTDOWN("SYSTEM_SHUTDOWN", "System shut down"),
    CONFIGURATION_CHANGE("CONFIG_CHANGE", "System configuration changed"),
    BACKUP_CREATED("BACKUP_CREATED", "System backup created"),
    BACKUP_RESTORED("BACKUP_RESTORED", "System backup restored"),
    
    // Security events
    SECURITY_VIOLATION("SECURITY_VIOLATION", "Security violation detected"),
    SUSPICIOUS_ACTIVITY("SUSPICIOUS_ACTIVITY", "Suspicious activity detected"),
    RATE_LIMIT_EXCEEDED("RATE_LIMIT_EXCEEDED", "Rate limit exceeded"),
    INTRUSION_DETECTED("INTRUSION_DETECTED", "Intrusion attempt detected"),
    MALWARE_DETECTED("MALWARE_DETECTED", "Malware detected"),
    
    // Business events
    DEBATE_CREATED("DEBATE_CREATED", "Debate created"),
    DEBATE_UPDATED("DEBATE_UPDATED", "Debate updated"),
    DEBATE_DELETED("DEBATE_DELETED", "Debate deleted"),
    DEBATE_PUBLISHED("DEBATE_PUBLISHED", "Debate published"),
    DEBATE_ARCHIVED("DEBATE_ARCHIVED", "Debate archived"),
    
    ORGANIZATION_CREATED("ORG_CREATED", "Organization created"),
    ORGANIZATION_UPDATED("ORG_UPDATED", "Organization updated"),
    ORGANIZATION_DELETED("ORG_DELETED", "Organization deleted"),
    ORGANIZATION_SUSPENDED("ORG_SUSPENDED", "Organization suspended"),
    ORGANIZATION_ACTIVATED("ORG_ACTIVATED", "Organization activated"),
    
    USER_CREATED("USER_CREATED", "User created"),
    USER_UPDATED("USER_UPDATED", "User updated"),
    USER_DELETED("USER_DELETED", "User deleted"),
    USER_SUSPENDED("USER_SUSPENDED", "User suspended"),
    USER_ACTIVATED("USER_ACTIVATED", "User activated"),
    
    // API events
    API_REQUEST("API_REQUEST", "API request received"),
    API_RESPONSE("API_RESPONSE", "API response sent"),
    API_ERROR("API_ERROR", "API error occurred"),
    API_RATE_LIMITED("API_RATE_LIMITED", "API request rate limited"),
    API_KEY_CREATED("API_KEY_CREATED", "API key created"),
    API_KEY_REVOKED("API_KEY_REVOKED", "API key revoked"),
    
    // Compliance events
    GDPR_DATA_REQUEST("GDPR_DATA_REQUEST", "GDPR data request received"),
    GDPR_DATA_EXPORT("GDPR_DATA_EXPORT", "GDPR data export completed"),
    GDPR_DATA_DELETION("GDPR_DATA_DELETION", "GDPR data deletion completed"),
    GDPR_CONSENT_GIVEN("GDPR_CONSENT_GIVEN", "GDPR consent given"),
    GDPR_CONSENT_WITHDRAWN("GDPR_CONSENT_WITHDRAWN", "GDPR consent withdrawn"),
    
    DATA_RETENTION_POLICY_APPLIED("DATA_RETENTION_APPLIED", "Data retention policy applied"),
    DATA_ANONYMIZATION("DATA_ANONYMIZATION", "Data anonymization completed"),
    AUDIT_LOG_ACCESSED("AUDIT_LOG_ACCESSED", "Audit log accessed"),
    
    // Infrastructure events
    DATABASE_CONNECTION_FAILED("DB_CONNECTION_FAILED", "Database connection failed"),
    DATABASE_CONNECTION_RESTORED("DB_CONNECTION_RESTORED", "Database connection restored"),
    CACHE_CLEARED("CACHE_CLEARED", "Cache cleared"),
    SERVICE_STARTED("SERVICE_STARTED", "Service started"),
    SERVICE_STOPPED("SERVICE_STOPPED", "Service stopped"),
    SERVICE_HEALTH_CHECK_FAILED("SERVICE_HEALTH_FAILED", "Service health check failed"),
    
    // Operational events
    MAINTENANCE_MODE_ENABLED("MAINTENANCE_ENABLED", "Maintenance mode enabled"),
    MAINTENANCE_MODE_DISABLED("MAINTENANCE_DISABLED", "Maintenance mode disabled"),
    FEATURE_FLAG_CHANGED("FEATURE_FLAG_CHANGED", "Feature flag changed"),
    DEPLOYMENT_STARTED("DEPLOYMENT_STARTED", "Deployment started"),
    DEPLOYMENT_COMPLETED("DEPLOYMENT_COMPLETED", "Deployment completed"),
    DEPLOYMENT_FAILED("DEPLOYMENT_FAILED", "Deployment failed"),
    
    // Custom events
    CUSTOM_EVENT("CUSTOM_EVENT", "Custom audit event");
    
    private final String code;
    private final String description;
    
    AuditEventType(String code, String description) {
        this.code = code;
        this.description = description;
    }
    
    public String getCode() {
        return code;
    }
    
    public String getDescription() {
        return description;
    }
    
    /**
     * Get event type by code
     */
    public static AuditEventType fromCode(String code) {
        for (AuditEventType type : values()) {
            if (type.getCode().equals(code)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown audit event type code: " + code);
    }
    
    /**
     * Check if this is a security-related event
     */
    public boolean isSecurityEvent() {
        return name().startsWith("AUTHENTICATION_") || 
               name().startsWith("AUTHORIZATION_") || 
               name().startsWith("SECURITY_") ||
               name().startsWith("SUSPICIOUS_") ||
               name().startsWith("INTRUSION_") ||
               name().startsWith("MALWARE_") ||
               name().startsWith("RATE_LIMIT_");
    }
    
    /**
     * Check if this is a compliance-related event
     */
    public boolean isComplianceEvent() {
        return name().startsWith("GDPR_") ||
               name().startsWith("DATA_RETENTION_") ||
               name().startsWith("DATA_ANONYMIZATION") ||
               name().startsWith("AUDIT_LOG_");
    }
    
    /**
     * Check if this is a business-related event
     */
    public boolean isBusinessEvent() {
        return name().startsWith("DEBATE_") ||
               name().startsWith("ORGANIZATION_") ||
               name().startsWith("USER_") ||
               name().startsWith("API_");
    }
    
    /**
     * Check if this is a system-related event
     */
    public boolean isSystemEvent() {
        return name().startsWith("SYSTEM_") ||
               name().startsWith("DATABASE_") ||
               name().startsWith("SERVICE_") ||
               name().startsWith("CACHE_") ||
               name().startsWith("MAINTENANCE_") ||
               name().startsWith("DEPLOYMENT_");
    }
    
    /**
     * Get severity level for this event type
     */
    public AuditSeverity getSeverity() {
        if (name().contains("FAILURE") || name().contains("FAILED") || name().contains("ERROR") ||
            name().contains("VIOLATION") || name().contains("SUSPICIOUS") || name().contains("INTRUSION") ||
            name().contains("MALWARE") || name().contains("DENIED")) {
            return AuditSeverity.HIGH;
        }
        
        if (name().contains("WARNING") || name().contains("TIMEOUT") || name().contains("LOCKED") ||
            name().contains("RATE_LIMITED") || name().contains("SUSPENDED")) {
            return AuditSeverity.MEDIUM;
        }
        
        if (isSecurityEvent() || isComplianceEvent()) {
            return AuditSeverity.MEDIUM;
        }
        
        return AuditSeverity.LOW;
    }
    
    /**
     * Audit severity levels
     */
    public enum AuditSeverity {
        LOW, MEDIUM, HIGH, CRITICAL
    }
}