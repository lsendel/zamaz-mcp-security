package com.zamaz.mcp.security.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Security Audit Log entity for tracking authentication and authorization
 * events.
 * Provides comprehensive audit trail for compliance and security monitoring.
 */
@Entity
@Table(name = "security_audit_log", indexes = {
        @Index(name = "idx_audit_log_user", columnList = "userId"),
        @Index(name = "idx_audit_log_organization", columnList = "organizationId"),
        @Index(name = "idx_audit_log_event_type", columnList = "eventType"),
        @Index(name = "idx_audit_log_outcome", columnList = "outcome"),
        @Index(name = "idx_audit_log_risk_level", columnList = "riskLevel"),
        @Index(name = "idx_audit_log_timestamp", columnList = "timestamp"),
        @Index(name = "idx_audit_log_ip_address", columnList = "ipAddress"),
        @Index(name = "idx_audit_log_session", columnList = "sessionId")
})
@Data
@EqualsAndHashCode(exclude = { "user" })
@ToString(exclude = { "user" })
public class SecurityAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // Event Classification
    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 50)
    private SecurityEventType eventType;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_category", nullable = false, length = 50)
    private EventCategory eventCategory;

    @Column(name = "event_description", length = 1000)
    private String eventDescription;

    // Subject Information
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    @Column(name = "user_id", insertable = false, updatable = false)
    private UUID userId;

    @Column(name = "username", length = 255)
    private String username;

    @Column(name = "organization_id")
    private UUID organizationId;

    // Resource Information
    @Column(name = "resource_type", length = 100)
    private String resourceType;

    @Column(name = "resource_id", length = 255)
    private String resourceId;

    @Column(name = "resource_name", length = 500)
    private String resourceName;

    @Column(name = "action", length = 100)
    private String action;

    // Request Context
    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 1000)
    private String userAgent;

    @Column(name = "session_id", length = 255)
    private String sessionId;

    @Column(name = "request_id", length = 255)
    private String requestId;

    @Column(name = "correlation_id", length = 255)
    private String correlationId;

    // Geographic Information
    @Column(name = "country_code", length = 2)
    private String countryCode;

    @Column(name = "region", length = 100)
    private String region;

    @Column(name = "city", length = 100)
    private String city;

    @Column(name = "latitude")
    private Double latitude;

    @Column(name = "longitude")
    private Double longitude;

    // Event Outcome
    @Enumerated(EnumType.STRING)
    @Column(name = "outcome", nullable = false, length = 20)
    private AuditOutcome outcome;

    @Column(name = "outcome_reason", length = 500)
    private String outcomeReason;

    @Column(name = "error_code", length = 50)
    private String errorCode;

    @Column(name = "error_message", length = 1000)
    private String errorMessage;

    // Risk Assessment
    @Enumerated(EnumType.STRING)
    @Column(name = "risk_level", nullable = false, length = 20)
    private RiskLevel riskLevel = RiskLevel.LOW;

    @Column(name = "risk_score", nullable = false)
    private Integer riskScore = 0;

    @Column(name = "risk_factors", columnDefinition = "jsonb")
    private String riskFactors; // JSON array of risk factors

    @Column(name = "anomaly_detected", nullable = false)
    private Boolean anomalyDetected = false;

    @Column(name = "anomaly_score")
    private Double anomalyScore;

    // Additional Details
    @Column(name = "details", columnDefinition = "jsonb")
    private String details; // JSON object with additional event details

    @Column(name = "before_state", columnDefinition = "jsonb")
    private String beforeState; // JSON object representing state before change

    @Column(name = "after_state", columnDefinition = "jsonb")
    private String afterState; // JSON object representing state after change

    // Compliance and Retention
    @Column(name = "compliance_tags", columnDefinition = "TEXT")
    private String complianceTags; // JSON array of compliance tags (GDPR, SOX, etc.)

    @Column(name = "retention_period_days")
    private Integer retentionPeriodDays;

    @Column(name = "archived", nullable = false)
    private Boolean archived = false;

    @Column(name = "archived_at")
    private LocalDateTime archivedAt;

    // Timestamp
    @CreationTimestamp
    @Column(name = "timestamp", nullable = false, updatable = false)
    private LocalDateTime timestamp;

    @Column(name = "server_timestamp", nullable = false)
    private LocalDateTime serverTimestamp = LocalDateTime.now();

    // Enums
    public enum SecurityEventType {
        // Authentication Events
        LOGIN_SUCCESS, LOGIN_FAILURE, LOGOUT, SESSION_TIMEOUT,
        MFA_SUCCESS, MFA_FAILURE, MFA_BYPASS_ATTEMPT,
        PASSWORD_CHANGE, PASSWORD_RESET, ACCOUNT_LOCKED, ACCOUNT_UNLOCKED,

        // Authorization Events
        PERMISSION_GRANTED, PERMISSION_DENIED, ROLE_ASSIGNED, ROLE_REMOVED,
        PRIVILEGE_ESCALATION_ATTEMPT, UNAUTHORIZED_ACCESS_ATTEMPT,

        // Resource Access Events
        RESOURCE_ACCESSED, RESOURCE_CREATED, RESOURCE_MODIFIED, RESOURCE_DELETED,
        SENSITIVE_DATA_ACCESS, BULK_DATA_EXPORT,

        // Administrative Events
        USER_CREATED, USER_MODIFIED, USER_DELETED, USER_ACTIVATED, USER_DEACTIVATED,
        ROLE_CREATED, ROLE_MODIFIED, ROLE_DELETED,
        PERMISSION_CREATED, PERMISSION_MODIFIED, PERMISSION_DELETED,
        CONFIGURATION_CHANGED, SECURITY_POLICY_CHANGED,

        // Security Events
        SUSPICIOUS_ACTIVITY, BRUTE_FORCE_ATTEMPT, ANOMALY_DETECTED,
        SECURITY_VIOLATION, COMPLIANCE_VIOLATION,
        TOKEN_ISSUED, TOKEN_REVOKED, TOKEN_EXPIRED,

        // System Events
        SYSTEM_STARTUP, SYSTEM_SHUTDOWN, SERVICE_STARTED, SERVICE_STOPPED,
        DATABASE_CONNECTION, API_CALL, INTEGRATION_EVENT,
        
        // OAuth2 Client Events
        OAUTH2_CLIENT_REGISTERED, OAUTH2_CLIENT_UPDATED, OAUTH2_CLIENT_DELETED,
        OAUTH2_CLIENT_ACTIVATED, OAUTH2_CLIENT_DEACTIVATED, OAUTH2_CLIENT_REACTIVATED,
        OAUTH2_CLIENT_SECRET_REGENERATED, OAUTH2_CLIENT_SCOPE_CHANGED,
        OAUTH2_CLIENT_REDIRECT_URI_CHANGED,
        
        // OAuth2 Flow Events
        OAUTH2_AUTHORIZATION_CODE_ISSUED, OAUTH2_ACCESS_TOKEN_ISSUED,
        OAUTH2_REFRESH_TOKEN_ISSUED, OAUTH2_TOKEN_INTROSPECTED,
        OAUTH2_CONSENT_GRANTED, OAUTH2_CONSENT_REVOKED
    }

    public enum EventCategory {
        AUTHENTICATION, AUTHORIZATION, ACCESS_CONTROL, DATA_ACCESS,
        ADMINISTRATION, CONFIGURATION, SECURITY, COMPLIANCE, SYSTEM
    }

    public enum AuditOutcome {
        SUCCESS, FAILURE, BLOCKED, ERROR, WARNING
    }

    public enum RiskLevel {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    // Helper Methods
    public boolean isHighRisk() {
        return riskLevel == RiskLevel.HIGH || riskLevel == RiskLevel.CRITICAL;
    }

    public boolean isSecurityEvent() {
        return eventCategory == EventCategory.SECURITY ||
                eventType.name().contains("VIOLATION") ||
                eventType.name().contains("SUSPICIOUS") ||
                eventType.name().contains("ANOMALY");
    }

    public boolean isFailureEvent() {
        return outcome == AuditOutcome.FAILURE || outcome == AuditOutcome.BLOCKED;
    }

    public boolean requiresAlert() {
        return isHighRisk() || anomalyDetected || isSecurityEvent();
    }

    public void markAsArchived() {
        this.archived = true;
        this.archivedAt = LocalDateTime.now();
    }

    public boolean isRetentionExpired() {
        if (retentionPeriodDays == null) {
            return false;
        }

        LocalDateTime expiryDate = timestamp.plusDays(retentionPeriodDays);
        return LocalDateTime.now().isAfter(expiryDate);
    }
}