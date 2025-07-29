package com.zamaz.mcp.security.audit;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.Map;

/**
 * Comprehensive audit event for security and compliance logging
 */
@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuditEvent {
    
    // Event identification
    @JsonProperty("event_id")
    private String eventId;
    
    @JsonProperty("event_type")
    private AuditEventType eventType;
    
    @JsonProperty("event_category")
    private String eventCategory;
    
    @JsonProperty("event_outcome")
    private AuditOutcome outcome;
    
    @JsonProperty("severity")
    private AuditEventType.AuditSeverity severity;
    
    // Temporal information
    @JsonProperty("timestamp")
    private Instant timestamp;
    
    @JsonProperty("duration")
    private Long duration;
    
    // Actor information (who)
    @JsonProperty("actor")
    private AuditActor actor;
    
    // Target information (what)
    @JsonProperty("target")
    private AuditTarget target;
    
    // Context information (where/how)
    @JsonProperty("context")
    private AuditContext context;
    
    // Event details
    @JsonProperty("description")
    private String description;
    
    @JsonProperty("details")
    private Map<String, Object> details;
    
    @JsonProperty("tags")
    private String[] tags;
    
    // Risk and compliance
    @JsonProperty("risk_score")
    private Integer riskScore;
    
    @JsonProperty("compliance_flags")
    private String[] complianceFlags;
    
    // Correlation
    @JsonProperty("correlation_id")
    private String correlationId;
    
    @JsonProperty("trace_id")
    private String traceId;
    
    @JsonProperty("span_id")
    private String spanId;
    
    @JsonProperty("parent_event_id")
    private String parentEventId;
    
    // Technical details
    @JsonProperty("source_system")
    private String sourceSystem;
    
    @JsonProperty("source_component")
    private String sourceComponent;
    
    @JsonProperty("version")
    private String version;
    
    @JsonProperty("schema_version")
    private String schemaVersion;
    
    /**
     * Actor information (who performed the action)
     */
    @Data
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class AuditActor {
        @JsonProperty("user_id")
        private String userId;
        
        @JsonProperty("username")
        private String username;
        
        @JsonProperty("email")
        private String email;
        
        @JsonProperty("organization_id")
        private String organizationId;
        
        @JsonProperty("organization_name")
        private String organizationName;
        
        @JsonProperty("session_id")
        private String sessionId;
        
        @JsonProperty("roles")
        private String[] roles;
        
        @JsonProperty("permissions")
        private String[] permissions;
        
        @JsonProperty("authentication_method")
        private String authenticationMethod;
        
        @JsonProperty("ip_address")
        private String ipAddress;
        
        @JsonProperty("user_agent")
        private String userAgent;
        
        @JsonProperty("geolocation")
        private String geolocation;
        
        @JsonProperty("device_id")
        private String deviceId;
        
        @JsonProperty("is_admin")
        private Boolean isAdmin;
        
        @JsonProperty("is_system")
        private Boolean isSystem;
        
        @JsonProperty("impersonated_by")
        private String impersonatedBy;
    }
    
    /**
     * Target information (what was acted upon)
     */
    @Data
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class AuditTarget {
        @JsonProperty("resource_type")
        private String resourceType;
        
        @JsonProperty("resource_id")
        private String resourceId;
        
        @JsonProperty("resource_name")
        private String resourceName;
        
        @JsonProperty("resource_owner")
        private String resourceOwner;
        
        @JsonProperty("organization_id")
        private String organizationId;
        
        @JsonProperty("parent_resource_id")
        private String parentResourceId;
        
        @JsonProperty("resource_attributes")
        private Map<String, Object> resourceAttributes;
        
        @JsonProperty("data_classification")
        private String dataClassification;
        
        @JsonProperty("sensitivity_level")
        private String sensitivityLevel;
        
        @JsonProperty("retention_period")
        private String retentionPeriod;
        
        @JsonProperty("access_level")
        private String accessLevel;
        
        @JsonProperty("encryption_status")
        private String encryptionStatus;
    }
    
    /**
     * Context information (where and how the action occurred)
     */
    @Data
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class AuditContext {
        @JsonProperty("application")
        private String application;
        
        @JsonProperty("service")
        private String service;
        
        @JsonProperty("environment")
        private String environment;
        
        @JsonProperty("region")
        private String region;
        
        @JsonProperty("datacenter")
        private String datacenter;
        
        @JsonProperty("cluster")
        private String cluster;
        
        @JsonProperty("instance_id")
        private String instanceId;
        
        @JsonProperty("request_id")
        private String requestId;
        
        @JsonProperty("http_method")
        private String httpMethod;
        
        @JsonProperty("http_path")
        private String httpPath;
        
        @JsonProperty("http_status_code")
        private Integer httpStatusCode;
        
        @JsonProperty("api_version")
        private String apiVersion;
        
        @JsonProperty("protocol")
        private String protocol;
        
        @JsonProperty("encryption_in_transit")
        private Boolean encryptionInTransit;
        
        @JsonProperty("authentication_required")
        private Boolean authenticationRequired;
        
        @JsonProperty("authorization_required")
        private Boolean authorizationRequired;
        
        @JsonProperty("mfa_required")
        private Boolean mfaRequired;
        
        @JsonProperty("network_zone")
        private String networkZone;
        
        @JsonProperty("vpn_connection")
        private Boolean vpnConnection;
        
        @JsonProperty("threat_indicators")
        private String[] threatIndicators;
    }
    
    /**
     * Audit outcome enumeration
     */
    public enum AuditOutcome {
        SUCCESS("success", "Operation completed successfully"),
        FAILURE("failure", "Operation failed"),
        PARTIAL_SUCCESS("partial_success", "Operation partially completed"),
        UNKNOWN("unknown", "Operation outcome unknown"),
        TIMEOUT("timeout", "Operation timed out"),
        CANCELLED("cancelled", "Operation was cancelled"),
        BLOCKED("blocked", "Operation was blocked"),
        PENDING("pending", "Operation is pending");
        
        private final String code;
        private final String description;
        
        AuditOutcome(String code, String description) {
            this.code = code;
            this.description = description;
        }
        
        public String getCode() {
            return code;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * Create a builder with default values
     */
    public static AuditEventBuilder builder() {
        return new AuditEventBuilder()
            .eventId(java.util.UUID.randomUUID().toString())
            .timestamp(Instant.now())
            .outcome(AuditOutcome.SUCCESS)
            .schemaVersion("1.0.0")
            .version("1.0.0");
    }
    
    /**
     * Set event category based on event type
     */
    public AuditEvent withEventCategory() {
        if (eventType != null) {
            if (eventType.isSecurityEvent()) {
                this.eventCategory = "security";
            } else if (eventType.isComplianceEvent()) {
                this.eventCategory = "compliance";
            } else if (eventType.isBusinessEvent()) {
                this.eventCategory = "business";
            } else if (eventType.isSystemEvent()) {
                this.eventCategory = "system";
            } else {
                this.eventCategory = "general";
            }
            
            // Set severity based on event type
            if (this.severity == null) {
                this.severity = eventType.getSeverity();
            }
        }
        return this;
    }
    
    /**
     * Add a detail to the event
     */
    public AuditEvent addDetail(String key, Object value) {
        if (this.details == null) {
            this.details = new java.util.HashMap<>();
        }
        this.details.put(key, value);
        return this;
    }
    
    /**
     * Add multiple details to the event
     */
    public AuditEvent addDetails(Map<String, Object> details) {
        if (this.details == null) {
            this.details = new java.util.HashMap<>();
        }
        this.details.putAll(details);
        return this;
    }
    
    /**
     * Add a tag to the event
     */
    public AuditEvent addTag(String tag) {
        if (this.tags == null) {
            this.tags = new String[]{tag};
        } else {
            String[] newTags = new String[this.tags.length + 1];
            System.arraycopy(this.tags, 0, newTags, 0, this.tags.length);
            newTags[this.tags.length] = tag;
            this.tags = newTags;
        }
        return this;
    }
    
    /**
     * Add multiple tags to the event
     */
    public AuditEvent addTags(String... tags) {
        for (String tag : tags) {
            addTag(tag);
        }
        return this;
    }
    
    /**
     * Calculate risk score based on event properties
     */
    public AuditEvent calculateRiskScore() {
        int score = 0;
        
        // Base score by event type
        if (eventType != null) {
            switch (eventType.getSeverity()) {
                case CRITICAL:
                    score += 80;
                    break;
                case HIGH:
                    score += 60;
                    break;
                case MEDIUM:
                    score += 40;
                    break;
                case LOW:
                    score += 20;
                    break;
            }
        }
        
        // Adjust based on outcome
        if (outcome == AuditOutcome.FAILURE || outcome == AuditOutcome.BLOCKED) {
            score += 20;
        }
        
        // Adjust based on context
        if (context != null) {
            if (context.threatIndicators != null && context.threatIndicators.length > 0) {
                score += 30;
            }
            if (Boolean.FALSE.equals(context.encryptionInTransit)) {
                score += 10;
            }
            if (Boolean.FALSE.equals(context.vpnConnection) && 
                (eventType != null && eventType.isSecurityEvent())) {
                score += 10;
            }
        }
        
        // Adjust based on actor
        if (actor != null && Boolean.TRUE.equals(actor.isAdmin)) {
            score += 10;
        }
        
        // Adjust based on target
        if (target != null && "sensitive".equals(target.dataClassification)) {
            score += 15;
        }
        
        this.riskScore = Math.min(100, score);
        return this;
    }
    
    /**
     * Convert to JSON string
     */
    public String toJson() {
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            mapper.registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule());
            return mapper.writeValueAsString(this);
        } catch (Exception e) {
            return "{\"error\":\"Failed to serialize audit event: " + e.getMessage() + "\"}";
        }
    }
}