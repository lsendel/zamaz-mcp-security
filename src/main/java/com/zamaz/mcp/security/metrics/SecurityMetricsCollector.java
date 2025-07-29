package com.zamaz.mcp.security.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Security Metrics Collector
 * Collects and exposes security-related metrics for monitoring
 */
@Component
@RequiredArgsConstructor
public class SecurityMetricsCollector {

    private final MeterRegistry meterRegistry;
    
    // Authentication metrics
    private Counter authenticationSuccessCounter;
    private Counter authenticationFailureCounter;
    private Timer authenticationTimer;
    
    // Authorization metrics
    private Counter authorizationSuccessCounter;
    private Counter authorizationFailureCounter;
    private Counter permissionDeniedCounter;
    private Counter roleDeniedCounter;
    
    // Security violation metrics
    private Counter securityViolationCounter;
    private Counter suspiciousActivityCounter;
    private Counter privilegeEscalationCounter;
    
    // Session metrics
    private Counter sessionCreatedCounter;
    private Counter sessionExpiredCounter;
    private final AtomicLong activeSessions = new AtomicLong(0);
    
    // JWT metrics
    private Counter jwtValidationSuccessCounter;
    private Counter jwtValidationFailureCounter;
    private Timer jwtValidationTimer;
    
    // Request security metrics
    private Counter maliciousRequestCounter;
    private Counter rateLimitExceededCounter;
    
    // User activity metrics
    private final ConcurrentHashMap<String, AtomicLong> userActivityCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicLong> organizationActivityCounts = new ConcurrentHashMap<>();
    
    @PostConstruct
    public void initializeMetrics() {
        // Authentication metrics
        authenticationSuccessCounter = Counter.builder("security.authentication.success")
            .description("Number of successful authentications")
            .register(meterRegistry);
            
        authenticationFailureCounter = Counter.builder("security.authentication.failure")
            .description("Number of failed authentications")
            .register(meterRegistry);
            
        authenticationTimer = Timer.builder("security.authentication.duration")
            .description("Authentication processing time")
            .register(meterRegistry);
        
        // Authorization metrics
        authorizationSuccessCounter = Counter.builder("security.authorization.success")
            .description("Number of successful authorizations")
            .register(meterRegistry);
            
        authorizationFailureCounter = Counter.builder("security.authorization.failure")
            .description("Number of failed authorizations")
            .register(meterRegistry);
            
        permissionDeniedCounter = Counter.builder("security.permission.denied")
            .description("Number of permission denials")
            .register(meterRegistry);
            
        roleDeniedCounter = Counter.builder("security.role.denied")
            .description("Number of role denials")
            .register(meterRegistry);
        
        // Security violation metrics
        securityViolationCounter = Counter.builder("security.violation.total")
            .description("Number of security violations")
            .register(meterRegistry);
            
        suspiciousActivityCounter = Counter.builder("security.suspicious.activity")
            .description("Number of suspicious activities detected")
            .register(meterRegistry);
            
        privilegeEscalationCounter = Counter.builder("security.privilege.escalation")
            .description("Number of privilege escalation attempts")
            .register(meterRegistry);
        
        // Session metrics
        sessionCreatedCounter = Counter.builder("security.session.created")
            .description("Number of sessions created")
            .register(meterRegistry);
            
        sessionExpiredCounter = Counter.builder("security.session.expired")
            .description("Number of sessions expired")
            .register(meterRegistry);
            
        Gauge.builder("security.session.active")
            .description("Number of active sessions")
            .register(meterRegistry, activeSessions, AtomicLong::get);
        
        // JWT metrics
        jwtValidationSuccessCounter = Counter.builder("security.jwt.validation.success")
            .description("Number of successful JWT validations")
            .register(meterRegistry);
            
        jwtValidationFailureCounter = Counter.builder("security.jwt.validation.failure")
            .description("Number of failed JWT validations")
            .register(meterRegistry);
            
        jwtValidationTimer = Timer.builder("security.jwt.validation.duration")
            .description("JWT validation processing time")
            .register(meterRegistry);
        
        // Request security metrics
        maliciousRequestCounter = Counter.builder("security.request.malicious")
            .description("Number of malicious requests blocked")
            .register(meterRegistry);
            
        rateLimitExceededCounter = Counter.builder("security.rate.limit.exceeded")
            .description("Number of rate limit violations")
            .register(meterRegistry);
    }
    
    // Authentication metrics methods
    public void recordAuthenticationSuccess(String method) {
        authenticationSuccessCounter.increment(
            io.micrometer.core.instrument.Tags.of("method", method));
    }
    
    public void recordAuthenticationFailure(String method, String reason) {
        authenticationFailureCounter.increment(
            io.micrometer.core.instrument.Tags.of("method", method, "reason", reason));
    }
    
    public Timer.Sample startAuthenticationTimer() {
        return Timer.start(meterRegistry);
    }
    
    public void stopAuthenticationTimer(Timer.Sample sample) {
        sample.stop(authenticationTimer);
    }
    
    // Authorization metrics methods
    public void recordAuthorizationSuccess(String resource) {
        authorizationSuccessCounter.increment(
            io.micrometer.core.instrument.Tags.of("resource", resource));
    }
    
    public void recordAuthorizationFailure(String resource, String reason) {
        authorizationFailureCounter.increment(
            io.micrometer.core.instrument.Tags.of("resource", resource, "reason", reason));
    }
    
    public void recordPermissionDenied(String permission) {
        permissionDeniedCounter.increment(
            io.micrometer.core.instrument.Tags.of("permission", permission));
    }
    
    public void recordRoleDenied(String role) {
        roleDeniedCounter.increment(
            io.micrometer.core.instrument.Tags.of("role", role));
    }
    
    // Security violation metrics methods
    public void recordSecurityViolation(String type, String source) {
        securityViolationCounter.increment(
            io.micrometer.core.instrument.Tags.of("type", type, "source", source));
    }
    
    public void recordSuspiciousActivity(String activity) {
        suspiciousActivityCounter.increment(
            io.micrometer.core.instrument.Tags.of("activity", activity));
    }
    
    public void recordPrivilegeEscalationAttempt(String attemptedAction) {
        privilegeEscalationCounter.increment(
            io.micrometer.core.instrument.Tags.of("action", attemptedAction));
    }
    
    // Session metrics methods
    public void recordSessionCreated() {
        sessionCreatedCounter.increment();
        activeSessions.incrementAndGet();
    }
    
    public void recordSessionExpired() {
        sessionExpiredCounter.increment();
        activeSessions.decrementAndGet();
    }
    
    // JWT metrics methods
    public void recordJwtValidationSuccess() {
        jwtValidationSuccessCounter.increment();
    }
    
    public void recordJwtValidationFailure(String reason) {
        jwtValidationFailureCounter.increment(
            io.micrometer.core.instrument.Tags.of("reason", reason));
    }
    
    public Timer.Sample startJwtValidationTimer() {
        return Timer.start(meterRegistry);
    }
    
    public void stopJwtValidationTimer(Timer.Sample sample) {
        sample.stop(jwtValidationTimer);
    }
    
    // Request security metrics methods
    public void recordMaliciousRequest(String type, String userAgent) {
        maliciousRequestCounter.increment(
            io.micrometer.core.instrument.Tags.of("type", type, "user_agent", userAgent));
    }
    
    public void recordRateLimitExceeded(String endpoint) {
        rateLimitExceededCounter.increment(
            io.micrometer.core.instrument.Tags.of("endpoint", endpoint));
    }
    
    // User activity tracking
    public void recordUserActivity(String userId) {
        userActivityCounts.computeIfAbsent(userId, k -> {
            AtomicLong counter = new AtomicLong(0);
            Gauge.builder("security.user.activity")
                .description("User activity count")
                .tag("userId", userId)
                .register(meterRegistry, counter, AtomicLong::get);
            return counter;
        }).incrementAndGet();
    }
    
    // Organization activity tracking
    public void recordOrganizationActivity(String organizationId) {
        organizationActivityCounts.computeIfAbsent(organizationId, k -> {
            AtomicLong counter = new AtomicLong(0);
            Gauge.builder("security.organization.activity")
                .description("Organization activity count")
                .tag("organizationId", organizationId)
                .register(meterRegistry, counter, AtomicLong::get);
            return counter;
        }).incrementAndGet();
    }
    
    // Utility methods for getting current metric values
    public long getAuthenticationSuccessCount() {
        return (long) authenticationSuccessCounter.count();
    }
    
    public long getAuthenticationFailureCount() {
        return (long) authenticationFailureCounter.count();
    }
    
    public long getSecurityViolationCount() {
        return (long) securityViolationCounter.count();
    }
    
    public long getActiveSessionCount() {
        return activeSessions.get();
    }
    
    public double getAuthenticationSuccessRate() {
        long success = getAuthenticationSuccessCount();
        long failure = getAuthenticationFailureCount();
        long total = success + failure;
        return total > 0 ? (double) success / total : 0.0;
    }
}
