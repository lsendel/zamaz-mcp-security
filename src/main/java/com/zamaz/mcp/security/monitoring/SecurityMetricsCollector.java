package com.zamaz.mcp.security.monitoring;

import com.zamaz.mcp.security.entity.SecurityAuditLog;
import io.micrometer.core.instrument.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Collects security metrics for monitoring and alerting.
 * Integrates with Micrometer for Prometheus/Grafana dashboards.
 */
@Component
public class SecurityMetricsCollector {
    
    private final MeterRegistry meterRegistry;
    
    // Counters
    private final Counter authenticationSuccessCounter;
    private final Counter authenticationFailureCounter;
    private final Counter authorizationDeniedCounter;
    private final Counter securityAlertCounter;
    private final Counter tokenIssuedCounter;
    private final Counter tokenRevokedCounter;
    
    // Gauges
    private final AtomicInteger activeSessions = new AtomicInteger(0);
    private final AtomicInteger activeAlerts = new AtomicInteger(0);
    
    // Timers
    private final Timer authenticationTimer;
    private final Timer authorizationTimer;
    
    // Distribution summaries
    private final DistributionSummary alertRiskScore;
    
    // Tags for dimensional metrics
    private final ConcurrentHashMap<String, Counter> eventTypeCounters = new ConcurrentHashMap<>();
    
    @Autowired
    public SecurityMetricsCollector(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
        
        // Initialize counters
        this.authenticationSuccessCounter = Counter.builder("security.authentication.success")
            .description("Number of successful authentications")
            .register(meterRegistry);
            
        this.authenticationFailureCounter = Counter.builder("security.authentication.failure")
            .description("Number of failed authentications")
            .register(meterRegistry);
            
        this.authorizationDeniedCounter = Counter.builder("security.authorization.denied")
            .description("Number of authorization denials")
            .register(meterRegistry);
            
        this.securityAlertCounter = Counter.builder("security.alerts.triggered")
            .description("Number of security alerts triggered")
            .register(meterRegistry);
            
        this.tokenIssuedCounter = Counter.builder("security.tokens.issued")
            .description("Number of tokens issued")
            .register(meterRegistry);
            
        this.tokenRevokedCounter = Counter.builder("security.tokens.revoked")
            .description("Number of tokens revoked")
            .register(meterRegistry);
        
        // Initialize gauges
        meterRegistry.gauge("security.sessions.active", activeSessions);
        meterRegistry.gauge("security.alerts.active", activeAlerts);
        
        // Initialize timers
        this.authenticationTimer = Timer.builder("security.authentication.duration")
            .description("Authentication processing time")
            .register(meterRegistry);
            
        this.authorizationTimer = Timer.builder("security.authorization.duration")
            .description("Authorization check duration")
            .register(meterRegistry);
        
        // Initialize distribution summaries
        this.alertRiskScore = DistributionSummary.builder("security.alerts.risk_score")
            .description("Risk scores of triggered alerts")
            .publishPercentiles(0.5, 0.75, 0.95, 0.99)
            .register(meterRegistry);
    }
    
    /**
     * Record security event
     */
    public void recordSecurityEvent(SecurityAuditLog event) {
        // Get or create counter for event type
        Counter eventCounter = eventTypeCounters.computeIfAbsent(
            event.getEventType().name(),
            eventType -> Counter.builder("security.events")
                .tag("type", eventType)
                .tag("category", event.getEventCategory().name())
                .description("Security events by type")
                .register(meterRegistry)
        );
        
        eventCounter.increment();
        
        // Update specific metrics based on event type
        switch (event.getEventType()) {
            case LOGIN_SUCCESS:
                authenticationSuccessCounter.increment();
                break;
            case LOGIN_FAILURE:
                authenticationFailureCounter.increment();
                break;
            case PERMISSION_DENIED:
            case UNAUTHORIZED_ACCESS_ATTEMPT:
                authorizationDeniedCounter.increment();
                break;
            case TOKEN_ISSUED:
            case OAUTH2_ACCESS_TOKEN_ISSUED:
                tokenIssuedCounter.increment();
                break;
            case TOKEN_REVOKED:
                tokenRevokedCounter.increment();
                break;
        }
        
        // Record risk level
        if (event.getRiskLevel() != null) {
            meterRegistry.counter("security.events.risk_level",
                "level", event.getRiskLevel().name()).increment();
        }
    }
    
    /**
     * Record authentication timing
     */
    public Timer.Sample startAuthenticationTimer() {
        return Timer.start(meterRegistry);
    }
    
    public void recordAuthenticationTime(Timer.Sample sample, boolean success) {
        sample.stop(Timer.builder("security.authentication.duration")
            .tag("success", String.valueOf(success))
            .register(meterRegistry));
    }
    
    /**
     * Record authorization timing
     */
    public Timer.Sample startAuthorizationTimer() {
        return Timer.start(meterRegistry);
    }
    
    public void recordAuthorizationTime(Timer.Sample sample, boolean granted) {
        sample.stop(Timer.builder("security.authorization.duration")
            .tag("granted", String.valueOf(granted))
            .register(meterRegistry));
    }
    
    /**
     * Record security alert
     */
    public void recordSecurityAlert(SecurityAlert alert) {
        securityAlertCounter.increment();
        
        // Record by severity
        meterRegistry.counter("security.alerts.severity",
            "severity", alert.getSeverity().name()).increment();
        
        // Record by rule
        meterRegistry.counter("security.alerts.rule",
            "rule", alert.getRuleId()).increment();
        
        // Record risk score
        alertRiskScore.record(alert.getRiskScore());
        
        activeAlerts.incrementAndGet();
    }
    
    /**
     * Update session metrics
     */
    public void updateActiveSessions(int count) {
        activeSessions.set(count);
    }
    
    public void incrementActiveSessions() {
        activeSessions.incrementAndGet();
    }
    
    public void decrementActiveSessions() {
        activeSessions.decrementAndGet();
    }
    
    /**
     * Update alert metrics
     */
    public void alertResolved() {
        activeAlerts.decrementAndGet();
    }
    
    /**
     * Record failed login attempts by IP
     */
    public void recordFailedLoginByIp(String ipAddress) {
        meterRegistry.counter("security.failed_login.by_ip",
            "ip", sanitizeIp(ipAddress)).increment();
    }
    
    /**
     * Record data access patterns
     */
    public void recordDataAccess(String resourceType, String action, boolean granted) {
        meterRegistry.counter("security.data_access",
            "resource", resourceType,
            "action", action,
            "granted", String.valueOf(granted)
        ).increment();
    }
    
    /**
     * Get current metrics snapshot
     */
    public SecurityMetricsSnapshot getSnapshot() {
        SecurityMetricsSnapshot snapshot = new SecurityMetricsSnapshot();
        
        snapshot.setAuthenticationSuccessCount(
            (long) authenticationSuccessCounter.count());
        snapshot.setAuthenticationFailureCount(
            (long) authenticationFailureCounter.count());
        snapshot.setAuthorizationDeniedCount(
            (long) authorizationDeniedCounter.count());
        snapshot.setActiveSessionCount(activeSessions.get());
        snapshot.setActiveAlertCount(activeAlerts.get());
        snapshot.setTokensIssuedCount((long) tokenIssuedCounter.count());
        snapshot.setTokensRevokedCount((long) tokenRevokedCounter.count());
        
        return snapshot;
    }
    
    /**
     * Sanitize IP address for metric tags
     */
    private String sanitizeIp(String ip) {
        // Replace last octet with 'x' for privacy
        if (ip != null && ip.contains(".")) {
            String[] parts = ip.split("\\.");
            if (parts.length == 4) {
                return parts[0] + "." + parts[1] + "." + parts[2] + ".x";
            }
        }
        return "unknown";
    }
    
    /**
     * Security metrics snapshot
     */
    public static class SecurityMetricsSnapshot {
        private long authenticationSuccessCount;
        private long authenticationFailureCount;
        private long authorizationDeniedCount;
        private int activeSessionCount;
        private int activeAlertCount;
        private long tokensIssuedCount;
        private long tokensRevokedCount;
        
        // Getters and setters
        public long getAuthenticationSuccessCount() { return authenticationSuccessCount; }
        public void setAuthenticationSuccessCount(long count) { this.authenticationSuccessCount = count; }
        
        public long getAuthenticationFailureCount() { return authenticationFailureCount; }
        public void setAuthenticationFailureCount(long count) { this.authenticationFailureCount = count; }
        
        public long getAuthorizationDeniedCount() { return authorizationDeniedCount; }
        public void setAuthorizationDeniedCount(long count) { this.authorizationDeniedCount = count; }
        
        public int getActiveSessionCount() { return activeSessionCount; }
        public void setActiveSessionCount(int count) { this.activeSessionCount = count; }
        
        public int getActiveAlertCount() { return activeAlertCount; }
        public void setActiveAlertCount(int count) { this.activeAlertCount = count; }
        
        public long getTokensIssuedCount() { return tokensIssuedCount; }
        public void setTokensIssuedCount(long count) { this.tokensIssuedCount = count; }
        
        public long getTokensRevokedCount() { return tokensRevokedCount; }
        public void setTokensRevokedCount(long count) { this.tokensRevokedCount = count; }
    }
}