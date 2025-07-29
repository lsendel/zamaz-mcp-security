package com.zamaz.mcp.security.session;

import lombok.Builder;
import lombok.Data;

import java.time.Duration;

/**
 * Session Statistics
 * Provides metrics about user sessions
 */
@Data
@Builder
public class SessionStatistics {
    private long totalActiveSessions;
    private long sessionsCreatedToday;
    private long sessionsExpiredToday;
    private Duration averageSessionDuration;
}
