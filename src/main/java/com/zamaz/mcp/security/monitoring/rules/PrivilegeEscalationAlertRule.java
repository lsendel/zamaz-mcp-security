package com.zamaz.mcp.security.monitoring.rules;

import com.zamaz.mcp.security.entity.SecurityAuditLog;
import com.zamaz.mcp.security.monitoring.AlertSeverity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Alert rule for detecting privilege escalation attempts.
 */
@Component
public class PrivilegeEscalationAlertRule implements SecurityAlertRule {
    
    @Value("${security.alerts.privilege-escalation.enabled:true}")
    private boolean enabled;
    
    private static final Set<SecurityAuditLog.SecurityEventType> MONITORED_EVENTS = Set.of(
        SecurityAuditLog.SecurityEventType.PERMISSION_DENIED,
        SecurityAuditLog.SecurityEventType.PRIVILEGE_ESCALATION_ATTEMPT,
        SecurityAuditLog.SecurityEventType.UNAUTHORIZED_ACCESS_ATTEMPT,
        SecurityAuditLog.SecurityEventType.ROLE_ASSIGNED,
        SecurityAuditLog.SecurityEventType.PERMISSION_CREATED
    );
    
    @Override
    public String getRuleId() {
        return "PRIVILEGE_ESCALATION";
    }
    
    @Override
    public String getRuleName() {
        return "Privilege Escalation Detection";
    }
    
    @Override
    public String getDescription() {
        return "Detects attempts to gain unauthorized elevated privileges";
    }
    
    @Override
    public AlertSeverity getSeverity() {
        return AlertSeverity.CRITICAL;
    }
    
    @Override
    public boolean isEnabled() {
        return enabled;
    }
    
    @Override
    public Set<SecurityAuditLog.SecurityEventType> getEventTypes() {
        return MONITORED_EVENTS;
    }
    
    @Override
    public int getTimeWindowMinutes() {
        return 15;
    }
    
    @Override
    public boolean matches(SecurityAuditLog event) {
        return MONITORED_EVENTS.contains(event.getEventType());
    }
    
    @Override
    public boolean evaluate(List<SecurityAuditLog> recentEvents, SecurityAuditLog currentEvent) {
        if (currentEvent.getEventType() == SecurityAuditLog.SecurityEventType.PRIVILEGE_ESCALATION_ATTEMPT) {
            return true; // Always alert on direct escalation attempts
        }
        
        // Look for patterns of permission denied followed by role/permission changes
        String userId = currentEvent.getUserId() != null ? 
            currentEvent.getUserId().toString() : currentEvent.getUsername();
        
        if (userId == null) return false;
        
        List<SecurityAuditLog> userEvents = recentEvents.stream()
            .filter(e -> userId.equals(e.getUserId() != null ? 
                e.getUserId().toString() : e.getUsername()))
            .collect(Collectors.toList());
        
        // Count permission denied events
        long deniedCount = userEvents.stream()
            .filter(e -> e.getEventType() == SecurityAuditLog.SecurityEventType.PERMISSION_DENIED ||
                        e.getEventType() == SecurityAuditLog.SecurityEventType.UNAUTHORIZED_ACCESS_ATTEMPT)
            .count();
        
        // Check if user recently got new roles/permissions after denials
        boolean recentPrivilegeChange = userEvents.stream()
            .anyMatch(e -> e.getEventType() == SecurityAuditLog.SecurityEventType.ROLE_ASSIGNED ||
                          e.getEventType() == SecurityAuditLog.SecurityEventType.PERMISSION_CREATED);
        
        // Alert if multiple denials followed by privilege change
        return deniedCount >= 3 && recentPrivilegeChange;
    }
    
    @Override
    public String formatAlertMessage(SecurityAuditLog triggerEvent, List<SecurityAuditLog> relatedEvents) {
        StringBuilder message = new StringBuilder();
        message.append("Potential privilege escalation detected:\n\n");
        
        if (triggerEvent.getEventType() == SecurityAuditLog.SecurityEventType.PRIVILEGE_ESCALATION_ATTEMPT) {
            message.append("Direct privilege escalation attempt:\n");
            message.append(String.format("  User: %s\n", triggerEvent.getUsername()));
            message.append(String.format("  Description: %s\n", triggerEvent.getEventDescription()));
        } else {
            String userId = triggerEvent.getUserId() != null ? 
                triggerEvent.getUserId().toString() : triggerEvent.getUsername();
            
            List<SecurityAuditLog> userEvents = relatedEvents.stream()
                .filter(e -> userId.equals(e.getUserId() != null ? 
                    e.getUserId().toString() : e.getUsername()))
                .collect(Collectors.toList());
            
            message.append(String.format("Suspicious activity pattern for user: %s\n", userId));
            
            // Show denied attempts
            userEvents.stream()
                .filter(e -> e.getEventType() == SecurityAuditLog.SecurityEventType.PERMISSION_DENIED)
                .forEach(e -> message.append(String.format("  - Permission denied: %s\n", 
                    e.getEventDescription())));
            
            // Show privilege changes
            userEvents.stream()
                .filter(e -> e.getEventType() == SecurityAuditLog.SecurityEventType.ROLE_ASSIGNED)
                .forEach(e -> message.append(String.format("  - Role assigned: %s\n", 
                    e.getEventDescription())));
        }
        
        message.append(String.format("\nTotal related events: %d", relatedEvents.size()));
        
        return message.toString();
    }
}