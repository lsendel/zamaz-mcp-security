package com.zamaz.mcp.security.monitoring;

import com.zamaz.mcp.security.entity.SecurityAuditLog;

import java.io.Serializable;
import java.time.Instant;
import java.util.Map;

/**
 * Security alert model representing a triggered security alert.
 */
public class SecurityAlert implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private String alertId;
    private String ruleId;
    private String ruleName;
    private AlertSeverity severity;
    private Instant triggeredAt;
    private SecurityAuditLog triggerEvent;
    private int relatedEventCount;
    private String description;
    private double riskScore;
    private AlertStatus status = AlertStatus.NEW;
    private String assignedTo;
    private Instant acknowledgedAt;
    private String resolution;
    private Instant resolvedAt;
    private Map<String, Object> metadata;
    
    // Constructor
    public SecurityAlert() {}
    
    // Getters and setters
    public String getAlertId() { return alertId; }
    public void setAlertId(String alertId) { this.alertId = alertId; }
    
    public String getRuleId() { return ruleId; }
    public void setRuleId(String ruleId) { this.ruleId = ruleId; }
    
    public String getRuleName() { return ruleName; }
    public void setRuleName(String ruleName) { this.ruleName = ruleName; }
    
    public AlertSeverity getSeverity() { return severity; }
    public void setSeverity(AlertSeverity severity) { this.severity = severity; }
    
    public Instant getTriggeredAt() { return triggeredAt; }
    public void setTriggeredAt(Instant triggeredAt) { this.triggeredAt = triggeredAt; }
    
    public SecurityAuditLog getTriggerEvent() { return triggerEvent; }
    public void setTriggerEvent(SecurityAuditLog triggerEvent) { this.triggerEvent = triggerEvent; }
    
    public int getRelatedEventCount() { return relatedEventCount; }
    public void setRelatedEventCount(int relatedEventCount) { this.relatedEventCount = relatedEventCount; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public double getRiskScore() { return riskScore; }
    public void setRiskScore(double riskScore) { this.riskScore = riskScore; }
    
    public AlertStatus getStatus() { return status; }
    public void setStatus(AlertStatus status) { this.status = status; }
    
    public String getAssignedTo() { return assignedTo; }
    public void setAssignedTo(String assignedTo) { this.assignedTo = assignedTo; }
    
    public Instant getAcknowledgedAt() { return acknowledgedAt; }
    public void setAcknowledgedAt(Instant acknowledgedAt) { this.acknowledgedAt = acknowledgedAt; }
    
    public String getResolution() { return resolution; }
    public void setResolution(String resolution) { this.resolution = resolution; }
    
    public Instant getResolvedAt() { return resolvedAt; }
    public void setResolvedAt(Instant resolvedAt) { this.resolvedAt = resolvedAt; }
    
    public Map<String, Object> getMetadata() { return metadata; }
    public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
}

/**
 * Alert severity levels
 */
enum AlertSeverity {
    LOW(2.0),
    MEDIUM(4.0),
    HIGH(7.0),
    CRITICAL(9.0);
    
    private final double baseScore;
    
    AlertSeverity(double baseScore) {
        this.baseScore = baseScore;
    }
    
    public double getBaseScore() {
        return baseScore;
    }
}

/**
 * Alert status
 */
enum AlertStatus {
    NEW,
    ACKNOWLEDGED,
    INVESTIGATING,
    RESOLVED,
    FALSE_POSITIVE,
    ESCALATED
}