package com.zamaz.mcp.security.correlation;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Security Incident
 * Represents a detected security incident that requires attention
 */
@Data
@Builder
public class SecurityIncident {
    
    @Builder.Default
    private String id = UUID.randomUUID().toString();
    
    private String type;
    private String description;
    private Severity severity;
    private Status status;
    private Instant timestamp;
    private Map<String, Object> details;
    
    // Optional fields
    private String assignedTo;
    private Instant resolvedAt;
    private String resolution;
    
    public enum Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }
    
    public enum Status {
        OPEN, IN_PROGRESS, RESOLVED, CLOSED, FALSE_POSITIVE
    }
    
    public boolean isCritical() {
        return severity == Severity.CRITICAL;
    }
    
    public boolean isHighPriority() {
        return severity == Severity.HIGH || severity == Severity.CRITICAL;
    }
    
    public boolean isOpen() {
        return status == Status.OPEN || status == Status.IN_PROGRESS;
    }
}
