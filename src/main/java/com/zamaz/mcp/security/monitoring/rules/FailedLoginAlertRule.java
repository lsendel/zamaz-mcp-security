package com.zamaz.mcp.security.monitoring.rules;

import com.zamaz.mcp.security.entity.SecurityAuditLog;
import com.zamaz.mcp.security.monitoring.AlertSeverity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Alert rule for detecting excessive failed login attempts.
 */
@Component
public class FailedLoginAlertRule implements SecurityAlertRule {
    
    @Value("${security.alerts.failed-login.threshold:5}")
    private int threshold;
    
    @Value("${security.alerts.failed-login.time-window:5}")
    private int timeWindowMinutes;
    
    @Value("${security.alerts.failed-login.enabled:true}")
    private boolean enabled;
    
    @Override
    public String getRuleId() {
        return "FAILED_LOGIN_ATTEMPTS";
    }
    
    @Override
    public String getRuleName() {
        return "Failed Login Attempts Detection";
    }
    
    @Override
    public String getDescription() {
        return "Detects excessive failed login attempts that may indicate brute force attacks";
    }
    
    @Override
    public AlertSeverity getSeverity() {
        return AlertSeverity.HIGH;
    }
    
    @Override
    public boolean isEnabled() {
        return enabled;
    }
    
    @Override
    public Set<SecurityAuditLog.SecurityEventType> getEventTypes() {
        return Set.of(SecurityAuditLog.SecurityEventType.LOGIN_FAILURE);
    }
    
    @Override
    public int getTimeWindowMinutes() {
        return timeWindowMinutes;
    }
    
    @Override
    public boolean matches(SecurityAuditLog event) {
        return event.getEventType() == SecurityAuditLog.SecurityEventType.LOGIN_FAILURE;
    }
    
    @Override
    public boolean evaluate(List<SecurityAuditLog> recentEvents, SecurityAuditLog currentEvent) {
        // Group by username
        Map<String, List<SecurityAuditLog>> byUsername = recentEvents.stream()
            .filter(e -> e.getUsername() != null)
            .collect(Collectors.groupingBy(SecurityAuditLog::getUsername));
        
        // Check if any user exceeded threshold
        for (Map.Entry<String, List<SecurityAuditLog>> entry : byUsername.entrySet()) {
            if (entry.getValue().size() >= threshold) {
                return true;
            }
        }
        
        // Group by IP address
        Map<String, List<SecurityAuditLog>> byIp = recentEvents.stream()
            .filter(e -> e.getIpAddress() != null)
            .collect(Collectors.groupingBy(SecurityAuditLog::getIpAddress));
        
        // Check if any IP exceeded threshold
        for (Map.Entry<String, List<SecurityAuditLog>> entry : byIp.entrySet()) {
            if (entry.getValue().size() >= threshold) {
                return true;
            }
        }
        
        return false;
    }
    
    @Override
    public String formatAlertMessage(SecurityAuditLog triggerEvent, List<SecurityAuditLog> relatedEvents) {
        StringBuilder message = new StringBuilder();
        message.append("Multiple failed login attempts detected:\n");
        
        // Group by username
        Map<String, Long> usernameCounts = relatedEvents.stream()
            .filter(e -> e.getUsername() != null)
            .collect(Collectors.groupingBy(
                SecurityAuditLog::getUsername,
                Collectors.counting()
            ));
        
        if (!usernameCounts.isEmpty()) {
            message.append("\nBy username:\n");
            usernameCounts.entrySet().stream()
                .filter(e -> e.getValue() >= threshold)
                .forEach(e -> message.append(String.format("  - %s: %d attempts\n", 
                    e.getKey(), e.getValue())));
        }
        
        // Group by IP
        Map<String, Long> ipCounts = relatedEvents.stream()
            .filter(e -> e.getIpAddress() != null)
            .collect(Collectors.groupingBy(
                SecurityAuditLog::getIpAddress,
                Collectors.counting()
            ));
        
        if (!ipCounts.isEmpty()) {
            message.append("\nBy IP address:\n");
            ipCounts.entrySet().stream()
                .filter(e -> e.getValue() >= threshold)
                .forEach(e -> message.append(String.format("  - %s: %d attempts\n", 
                    e.getKey(), e.getValue())));
        }
        
        message.append(String.format("\nTotal events: %d in last %d minutes", 
            relatedEvents.size(), timeWindowMinutes));
        
        return message.toString();
    }
}