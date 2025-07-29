package com.zamaz.mcp.security.monitoring.rules;

import com.zamaz.mcp.security.entity.SecurityAuditLog;
import com.zamaz.mcp.security.monitoring.AlertSeverity;

import java.util.List;
import java.util.Set;

/**
 * Interface for security alert rules.
 * Defines how security events should trigger alerts.
 */
public interface SecurityAlertRule {
    
    /**
     * Get unique rule identifier
     */
    String getRuleId();
    
    /**
     * Get rule name
     */
    String getRuleName();
    
    /**
     * Get rule description
     */
    String getDescription();
    
    /**
     * Get alert severity
     */
    AlertSeverity getSeverity();
    
    /**
     * Check if rule is enabled
     */
    boolean isEnabled();
    
    /**
     * Get event types this rule monitors
     */
    Set<SecurityAuditLog.SecurityEventType> getEventTypes();
    
    /**
     * Get time window in minutes for event correlation
     */
    int getTimeWindowMinutes();
    
    /**
     * Check if an event matches this rule's criteria
     */
    boolean matches(SecurityAuditLog event);
    
    /**
     * Evaluate if the rule should trigger based on recent events
     */
    boolean evaluate(List<SecurityAuditLog> recentEvents, SecurityAuditLog currentEvent);
    
    /**
     * Format alert message with event details
     */
    String formatAlertMessage(SecurityAuditLog triggerEvent, List<SecurityAuditLog> relatedEvents);
}