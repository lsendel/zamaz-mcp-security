package com.zamaz.mcp.security.correlation;

import lombok.Builder;
import lombok.Data;

import java.time.Duration;

/**
 * Correlation Statistics
 * Provides metrics about the security event correlation system
 */
@Data
@Builder
public class CorrelationStatistics {
    private int totalUsers;
    private int totalIps;
    private int totalOrganizations;
    private int totalEvents;
    private Duration correlationWindow;
}
