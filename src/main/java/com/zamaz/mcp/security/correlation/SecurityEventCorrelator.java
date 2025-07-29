package com.zamaz.mcp.security.correlation;

import com.zamaz.mcp.security.audit.SecurityAuditEvent;
import com.zamaz.mcp.security.audit.SecurityAuditLogger;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Security Event Correlator
 * Analyzes security events to detect patterns and potential threats
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SecurityEventCorrelator {

    private final SecurityIncidentManager incidentManager;
    
    // Event storage for correlation (time-based sliding window)
    private final Map<String, List<SecurityAuditEvent>> userEvents = new ConcurrentHashMap<>();
    private final Map<String, List<SecurityAuditEvent>> ipEvents = new ConcurrentHashMap<>();
    private final Map<String, List<SecurityAuditEvent>> organizationEvents = new ConcurrentHashMap<>();
    
    // Correlation thresholds
    private static final int MAX_AUTH_FAILURES_PER_USER = 5;
    private static final int MAX_AUTH_FAILURES_PER_IP = 10;
    private static final int MAX_PERMISSION_DENIALS_PER_USER = 10;
    private static final Duration CORRELATION_WINDOW = Duration.ofMinutes(15);
    private static final int MAX_SUSPICIOUS_ACTIVITIES_PER_IP = 3;
    
    // Cleanup scheduler
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    
    public SecurityEventCorrelator(SecurityIncidentManager incidentManager) {
        this.incidentManager = incidentManager;
        // Schedule cleanup of old events every 5 minutes
        scheduler.scheduleAtFixedRate(this::cleanupOldEvents, 5, 5, TimeUnit.MINUTES);
    }
    
    /**
     * Correlate a new security event with existing events
     */
    public void correlateEvent(SecurityAuditEvent event) {
        try {
            // Store the event for correlation
            storeEvent(event);
            
            // Perform correlation analysis
            analyzeAuthenticationPatterns(event);
            analyzeAuthorizationPatterns(event);
            analyzeSuspiciousActivityPatterns(event);
            analyzePrivilegeEscalationPatterns(event);
            analyzeMultiUserPatterns(event);
            
        } catch (Exception e) {
            log.error("Failed to correlate security event: {}", e.getMessage(), e);
        }
    }
    
    /**
     * Store event in correlation storage
     */
    private void storeEvent(SecurityAuditEvent event) {
        Instant cutoff = Instant.now().minus(CORRELATION_WINDOW);
        
        // Store by user
        if (event.getUserId() != null) {
            userEvents.computeIfAbsent(event.getUserId(), k -> new ArrayList<>())
                .add(event);
        }
        
        // Store by IP
        if (event.getClientIp() != null) {
            ipEvents.computeIfAbsent(event.getClientIp(), k -> new ArrayList<>())
                .add(event);
        }
        
        // Store by organization
        if (event.getOrganizationId() != null) {
            organizationEvents.computeIfAbsent(event.getOrganizationId(), k -> new ArrayList<>())
                .add(event);
        }
    }
    
    /**
     * Analyze authentication failure patterns
     */
    private void analyzeAuthenticationPatterns(SecurityAuditEvent event) {
        if (event.getEventType() != SecurityAuditLogger.SecurityEventType.AUTHENTICATION_FAILURE) {
            return;
        }
        
        Instant cutoff = Instant.now().minus(CORRELATION_WINDOW);
        
        // Check for repeated failures by user
        if (event.getUserId() != null) {
            List<SecurityAuditEvent> userFailures = getUserEvents(event.getUserId())
                .stream()
                .filter(e -> e.getTimestamp().isAfter(cutoff))
                .filter(e -> e.getEventType() == SecurityAuditLogger.SecurityEventType.AUTHENTICATION_FAILURE)
                .collect(Collectors.toList());
                
            if (userFailures.size() >= MAX_AUTH_FAILURES_PER_USER) {
                createSecurityIncident("BRUTE_FORCE_USER", 
                    "Multiple authentication failures for user: " + event.getUserId(),
                    SecurityIncident.Severity.HIGH,
                    Map.of("userId", event.getUserId(), "failureCount", userFailures.size()));
            }
        }
        
        // Check for repeated failures by IP
        if (event.getClientIp() != null) {
            List<SecurityAuditEvent> ipFailures = getIpEvents(event.getClientIp())
                .stream()
                .filter(e -> e.getTimestamp().isAfter(cutoff))
                .filter(e -> e.getEventType() == SecurityAuditLogger.SecurityEventType.AUTHENTICATION_FAILURE)
                .collect(Collectors.toList());
                
            if (ipFailures.size() >= MAX_AUTH_FAILURES_PER_IP) {
                createSecurityIncident("BRUTE_FORCE_IP", 
                    "Multiple authentication failures from IP: " + event.getClientIp(),
                    SecurityIncident.Severity.CRITICAL,
                    Map.of("clientIp", event.getClientIp(), "failureCount", ipFailures.size()));
            }
        }
    }
    
    /**
     * Analyze authorization failure patterns
     */
    private void analyzeAuthorizationPatterns(SecurityAuditEvent event) {
        if (event.getEventType() != SecurityAuditLogger.SecurityEventType.PERMISSION_DENIED) {
            return;
        }
        
        Instant cutoff = Instant.now().minus(CORRELATION_WINDOW);
        
        if (event.getUserId() != null) {
            List<SecurityAuditEvent> permissionDenials = getUserEvents(event.getUserId())
                .stream()
                .filter(e -> e.getTimestamp().isAfter(cutoff))
                .filter(e -> e.getEventType() == SecurityAuditLogger.SecurityEventType.PERMISSION_DENIED)
                .collect(Collectors.toList());
                
            if (permissionDenials.size() >= MAX_PERMISSION_DENIALS_PER_USER) {
                createSecurityIncident("EXCESSIVE_PERMISSION_DENIALS", 
                    "Excessive permission denials for user: " + event.getUserId(),
                    SecurityIncident.Severity.MEDIUM,
                    Map.of("userId", event.getUserId(), "denialCount", permissionDenials.size()));
            }
        }
    }
    
    /**
     * Analyze suspicious activity patterns
     */
    private void analyzeSuspiciousActivityPatterns(SecurityAuditEvent event) {
        if (event.getEventType() != SecurityAuditLogger.SecurityEventType.SUSPICIOUS_ACTIVITY) {
            return;
        }
        
        Instant cutoff = Instant.now().minus(CORRELATION_WINDOW);
        
        if (event.getClientIp() != null) {
            List<SecurityAuditEvent> suspiciousActivities = getIpEvents(event.getClientIp())
                .stream()
                .filter(e -> e.getTimestamp().isAfter(cutoff))
                .filter(e -> e.getEventType() == SecurityAuditLogger.SecurityEventType.SUSPICIOUS_ACTIVITY)
                .collect(Collectors.toList());
                
            if (suspiciousActivities.size() >= MAX_SUSPICIOUS_ACTIVITIES_PER_IP) {
                createSecurityIncident("COORDINATED_ATTACK", 
                    "Multiple suspicious activities from IP: " + event.getClientIp(),
                    SecurityIncident.Severity.CRITICAL,
                    Map.of("clientIp", event.getClientIp(), "activityCount", suspiciousActivities.size()));
            }
        }
    }
    
    /**
     * Analyze privilege escalation patterns
     */
    private void analyzePrivilegeEscalationPatterns(SecurityAuditEvent event) {
        if (event.getEventType() != SecurityAuditLogger.SecurityEventType.PRIVILEGE_ESCALATION_ATTEMPT) {
            return;
        }
        
        // Any privilege escalation attempt is immediately flagged as high priority
        createSecurityIncident("PRIVILEGE_ESCALATION", 
            "Privilege escalation attempt detected",
            SecurityIncident.Severity.CRITICAL,
            Map.of("userId", event.getUserId(), "timestamp", event.getTimestamp().toString()));
    }
    
    /**
     * Analyze patterns across multiple users in the same organization
     */
    private void analyzeMultiUserPatterns(SecurityAuditEvent event) {
        if (event.getOrganizationId() == null) {
            return;
        }
        
        Instant cutoff = Instant.now().minus(CORRELATION_WINDOW);
        
        List<SecurityAuditEvent> orgEvents = getOrganizationEvents(event.getOrganizationId())
            .stream()
            .filter(e -> e.getTimestamp().isAfter(cutoff))
            .collect(Collectors.toList());
        
        // Check for coordinated suspicious activities
        Set<String> usersWithSuspiciousActivity = orgEvents.stream()
            .filter(e -> e.isSuspiciousEvent())
            .map(SecurityAuditEvent::getUserId)
            .filter(Objects::nonNull)
            .collect(Collectors.toSet());
            
        if (usersWithSuspiciousActivity.size() >= 3) {
            createSecurityIncident("COORDINATED_ORG_ATTACK", 
                "Coordinated suspicious activity in organization: " + event.getOrganizationId(),
                SecurityIncident.Severity.CRITICAL,
                Map.of("organizationId", event.getOrganizationId(), 
                      "affectedUsers", usersWithSuspiciousActivity.size()));
        }
    }
    
    /**
     * Create a security incident
     */
    private void createSecurityIncident(String type, String description, 
                                      SecurityIncident.Severity severity, 
                                      Map<String, Object> details) {
        SecurityIncident incident = SecurityIncident.builder()
            .type(type)
            .description(description)
            .severity(severity)
            .timestamp(Instant.now())
            .details(details)
            .status(SecurityIncident.Status.OPEN)
            .build();
            
        incidentManager.createIncident(incident);
        
        log.warn("Security incident created: {} - {}", type, description);
    }
    
    /**
     * Get events for a specific user
     */
    private List<SecurityAuditEvent> getUserEvents(String userId) {
        return userEvents.getOrDefault(userId, new ArrayList<>());
    }
    
    /**
     * Get events for a specific IP
     */
    private List<SecurityAuditEvent> getIpEvents(String ip) {
        return ipEvents.getOrDefault(ip, new ArrayList<>());
    }
    
    /**
     * Get events for a specific organization
     */
    private List<SecurityAuditEvent> getOrganizationEvents(String organizationId) {
        return organizationEvents.getOrDefault(organizationId, new ArrayList<>());
    }
    
    /**
     * Clean up old events outside the correlation window
     */
    private void cleanupOldEvents() {
        Instant cutoff = Instant.now().minus(CORRELATION_WINDOW);
        
        cleanupEventMap(userEvents, cutoff);
        cleanupEventMap(ipEvents, cutoff);
        cleanupEventMap(organizationEvents, cutoff);
        
        log.debug("Cleaned up old security events before: {}", cutoff);
    }
    
    /**
     * Clean up old events from a map
     */
    private void cleanupEventMap(Map<String, List<SecurityAuditEvent>> eventMap, Instant cutoff) {
        eventMap.values().forEach(events -> 
            events.removeIf(event -> event.getTimestamp().isBefore(cutoff)));
        
        // Remove empty lists
        eventMap.entrySet().removeIf(entry -> entry.getValue().isEmpty());
    }
    
    /**
     * Get correlation statistics
     */
    public CorrelationStatistics getStatistics() {
        return CorrelationStatistics.builder()
            .totalUsers(userEvents.size())
            .totalIps(ipEvents.size())
            .totalOrganizations(organizationEvents.size())
            .totalEvents(userEvents.values().stream().mapToInt(List::size).sum())
            .correlationWindow(CORRELATION_WINDOW)
            .build();
    }
}
