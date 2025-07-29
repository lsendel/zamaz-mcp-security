package com.zamaz.mcp.security.correlation;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Security Incident Manager
 * Manages security incidents and coordinates response actions
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SecurityIncidentManager {

    private final SecurityAlertService alertService;
    private final Map<String, SecurityIncident> incidents = new ConcurrentHashMap<>();
    
    /**
     * Create a new security incident
     */
    public SecurityIncident createIncident(SecurityIncident incident) {
        incidents.put(incident.getId(), incident);
        
        log.warn("Security incident created: {} - {} (Severity: {})", 
            incident.getType(), incident.getDescription(), incident.getSeverity());
        
        // Send alerts based on severity
        if (incident.isCritical()) {
            alertService.sendCriticalAlert(incident);
        } else if (incident.isHighPriority()) {
            alertService.sendHighPriorityAlert(incident);
        } else {
            alertService.sendStandardAlert(incident);
        }
        
        // Auto-trigger response actions
        triggerAutomatedResponse(incident);
        
        return incident;
    }
    
    /**
     * Update an existing incident
     */
    public SecurityIncident updateIncident(String incidentId, SecurityIncident.Status status, 
                                         String assignedTo, String resolution) {
        SecurityIncident incident = incidents.get(incidentId);
        if (incident == null) {
            throw new IllegalArgumentException("Incident not found: " + incidentId);
        }
        
        incident.setStatus(status);
        if (assignedTo != null) {
            incident.setAssignedTo(assignedTo);
        }
        if (resolution != null) {
            incident.setResolution(resolution);
        }
        
        if (status == SecurityIncident.Status.RESOLVED || status == SecurityIncident.Status.CLOSED) {
            incident.setResolvedAt(Instant.now());
        }
        
        log.info("Security incident updated: {} - Status: {}", incidentId, status);
        return incident;
    }
    
    /**
     * Get incident by ID
     */
    public SecurityIncident getIncident(String incidentId) {
        return incidents.get(incidentId);
    }
    
    /**
     * Get all open incidents
     */
    public List<SecurityIncident> getOpenIncidents() {
        return incidents.values().stream()
            .filter(SecurityIncident::isOpen)
            .sorted(Comparator.comparing(SecurityIncident::getTimestamp).reversed())
            .collect(Collectors.toList());
    }
    
    /**
     * Get incidents by severity
     */
    public List<SecurityIncident> getIncidentsBySeverity(SecurityIncident.Severity severity) {
        return incidents.values().stream()
            .filter(incident -> incident.getSeverity() == severity)
            .sorted(Comparator.comparing(SecurityIncident::getTimestamp).reversed())
            .collect(Collectors.toList());
    }
    
    /**
     * Get critical incidents
     */
    public List<SecurityIncident> getCriticalIncidents() {
        return getIncidentsBySeverity(SecurityIncident.Severity.CRITICAL);
    }
    
    /**
     * Get incident statistics
     */
    public IncidentStatistics getStatistics() {
        Map<SecurityIncident.Severity, Long> severityCount = incidents.values().stream()
            .collect(Collectors.groupingBy(
                SecurityIncident::getSeverity,
                Collectors.counting()
            ));
            
        Map<SecurityIncident.Status, Long> statusCount = incidents.values().stream()
            .collect(Collectors.groupingBy(
                SecurityIncident::getStatus,
                Collectors.counting()
            ));
        
        return IncidentStatistics.builder()
            .totalIncidents(incidents.size())
            .openIncidents(getOpenIncidents().size())
            .criticalIncidents(getCriticalIncidents().size())
            .severityBreakdown(severityCount)
            .statusBreakdown(statusCount)
            .build();
    }
    
    /**
     * Trigger automated response actions based on incident type and severity
     */
    private void triggerAutomatedResponse(SecurityIncident incident) {
        switch (incident.getType()) {
            case "BRUTE_FORCE_USER":
                // Could trigger user account lockout
                log.warn("Automated response: Consider locking user account for incident: {}", 
                    incident.getId());
                break;
                
            case "BRUTE_FORCE_IP":
                // Could trigger IP blocking
                log.warn("Automated response: Consider blocking IP for incident: {}", 
                    incident.getId());
                break;
                
            case "PRIVILEGE_ESCALATION":
                // Could trigger immediate session termination
                log.error("Automated response: Consider terminating user sessions for incident: {}", 
                    incident.getId());
                break;
                
            case "COORDINATED_ATTACK":
                // Could trigger enhanced monitoring
                log.error("Automated response: Enhancing monitoring for incident: {}", 
                    incident.getId());
                break;
                
            default:
                log.info("No automated response configured for incident type: {}", 
                    incident.getType());
        }
    }
    
    /**
     * Clean up resolved incidents older than specified days
     */
    public void cleanupOldIncidents(int daysToKeep) {
        Instant cutoff = Instant.now().minusSeconds(daysToKeep * 24 * 60 * 60);
        
        List<String> toRemove = incidents.values().stream()
            .filter(incident -> incident.getStatus() == SecurityIncident.Status.RESOLVED || 
                              incident.getStatus() == SecurityIncident.Status.CLOSED)
            .filter(incident -> incident.getResolvedAt() != null && 
                              incident.getResolvedAt().isBefore(cutoff))
            .map(SecurityIncident::getId)
            .collect(Collectors.toList());
        
        toRemove.forEach(incidents::remove);
        
        if (!toRemove.isEmpty()) {
            log.info("Cleaned up {} old resolved incidents", toRemove.size());
        }
    }
}
