package com.zamaz.mcp.security.correlation;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

/**
 * Incident Statistics
 * Provides metrics about security incidents
 */
@Data
@Builder
public class IncidentStatistics {
    private int totalIncidents;
    private int openIncidents;
    private int criticalIncidents;
    private Map<SecurityIncident.Severity, Long> severityBreakdown;
    private Map<SecurityIncident.Status, Long> statusBreakdown;
}
