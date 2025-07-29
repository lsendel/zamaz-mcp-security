package com.zamaz.mcp.security.session;

import com.zamaz.mcp.security.audit.SecurityAuditLogger;
import com.zamaz.mcp.security.metrics.SecurityMetricsCollector;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Secure Session Manager
 * Manages user sessions with security features like concurrent session limits,
 * session invalidation, and security event tracking
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SecureSessionManager {

    private final RedisTemplate<String, Object> redisTemplate;
    private final SecurityAuditLogger auditLogger;
    private final SecurityMetricsCollector metricsCollector;
    
    // Session configuration
    private static final Duration DEFAULT_SESSION_TIMEOUT = Duration.ofHours(8);
    private static final Duration EXTENDED_SESSION_TIMEOUT = Duration.ofDays(30);
    private static final int MAX_CONCURRENT_SESSIONS_PER_USER = 3;
    private static final String SESSION_PREFIX = "session:";
    private static final String USER_SESSIONS_PREFIX = "user:sessions:";
    
    /**
     * Create a new secure session
     */
    public SecureSession createSession(String userId, String organizationId, 
                                     SessionType sessionType, Map<String, Object> attributes) {
        
        // Check for existing sessions and enforce limits
        enforceConcurrentSessionLimits(userId);
        
        SecureSession session = SecureSession.builder()
            .sessionId(generateSecureSessionId())
            .userId(userId)
            .organizationId(organizationId)
            .sessionType(sessionType)
            .createdAt(Instant.now())
            .lastAccessedAt(Instant.now())
            .expiresAt(calculateExpirationTime(sessionType))
            .attributes(attributes != null ? new HashMap<>(attributes) : new HashMap<>())
            .active(true)
            .build();
        
        // Store session in Redis
        storeSession(session);
        
        // Track user sessions
        addToUserSessions(userId, session.getSessionId());
        
        // Audit and metrics
        auditLogger.logSecurityEvent(
            SecurityAuditLogger.SecurityEventType.SESSION_CREATED,
            SecurityAuditLogger.RiskLevel.LOW,
            "Session created for user: " + userId,
            Map.of("sessionId", session.getSessionId(), "sessionType", sessionType.toString())
        );
        
        metricsCollector.recordSessionCreated();
        
        log.debug("Session created: {} for user: {}", session.getSessionId(), userId);
        
        return session;
    }
    
    /**
     * Get session by ID
     */
    public Optional<SecureSession> getSession(String sessionId) {
        SecureSession session = (SecureSession) redisTemplate.opsForValue()
            .get(SESSION_PREFIX + sessionId);
        
        if (session == null) {
            return Optional.empty();
        }
        
        // Check if session is expired
        if (session.isExpired()) {
            invalidateSession(sessionId, "Session expired");
            return Optional.empty();
        }
        
        // Update last accessed time
        session.setLastAccessedAt(Instant.now());
        storeSession(session);
        
        return Optional.of(session);
    }
    
    /**
     * Validate and refresh session
     */
    public boolean validateSession(String sessionId) {
        Optional<SecureSession> sessionOpt = getSession(sessionId);
        
        if (sessionOpt.isEmpty()) {
            return false;
        }
        
        SecureSession session = sessionOpt.get();
        
        // Perform security checks
        if (!session.isActive()) {
            log.warn("Attempt to use inactive session: {}", sessionId);
            return false;
        }
        
        // Check for suspicious activity (e.g., rapid location changes)
        if (detectSuspiciousActivity(session)) {
            invalidateSession(sessionId, "Suspicious activity detected");
            return false;
        }
        
        return true;
    }
    
    /**
     * Invalidate a session
     */
    public void invalidateSession(String sessionId, String reason) {
        SecureSession session = (SecureSession) redisTemplate.opsForValue()
            .get(SESSION_PREFIX + sessionId);
        
        if (session != null) {
            // Remove from Redis
            redisTemplate.delete(SESSION_PREFIX + sessionId);
            
            // Remove from user sessions
            removeFromUserSessions(session.getUserId(), sessionId);
            
            // Audit and metrics
            auditLogger.logSecurityEvent(
                SecurityAuditLogger.SecurityEventType.SESSION_EXPIRED,
                SecurityAuditLogger.RiskLevel.LOW,
                "Session invalidated: " + reason,
                Map.of("sessionId", sessionId, "reason", reason)
            );
            
            metricsCollector.recordSessionExpired();
            
            log.info("Session invalidated: {} - Reason: {}", sessionId, reason);
        }
    }
    
    /**
     * Invalidate all sessions for a user
     */
    public void invalidateAllUserSessions(String userId, String reason) {
        Set<String> sessionIds = getUserSessions(userId);
        
        for (String sessionId : sessionIds) {
            invalidateSession(sessionId, reason);
        }
        
        auditLogger.logSecurityEvent(
            SecurityAuditLogger.SecurityEventType.SENSITIVE_OPERATION,
            SecurityAuditLogger.RiskLevel.MEDIUM,
            "All sessions invalidated for user: " + userId,
            Map.of("userId", userId, "reason", reason, "sessionCount", sessionIds.size())
        );
        
        log.warn("All sessions invalidated for user: {} - Reason: {}", userId, reason);
    }
    
    /**
     * Get all active sessions for a user
     */
    public List<SecureSession> getUserActiveSessions(String userId) {
        Set<String> sessionIds = getUserSessions(userId);
        List<SecureSession> activeSessions = new ArrayList<>();
        
        for (String sessionId : sessionIds) {
            Optional<SecureSession> sessionOpt = getSession(sessionId);
            if (sessionOpt.isPresent() && sessionOpt.get().isActive()) {
                activeSessions.add(sessionOpt.get());
            }
        }
        
        return activeSessions;
    }
    
    /**
     * Update session attributes
     */
    public void updateSessionAttributes(String sessionId, Map<String, Object> attributes) {
        Optional<SecureSession> sessionOpt = getSession(sessionId);
        
        if (sessionOpt.isPresent()) {
            SecureSession session = sessionOpt.get();
            session.getAttributes().putAll(attributes);
            storeSession(session);
            
            log.debug("Session attributes updated: {}", sessionId);
        }
    }
    
    /**
     * Clean up expired sessions
     */
    public void cleanupExpiredSessions() {
        // This would typically be called by a scheduled task
        // In Redis, we can set TTL on keys for automatic cleanup
        log.debug("Expired sessions cleanup completed");
    }
    
    // Private helper methods
    
    private void storeSession(SecureSession session) {
        Duration timeout = Duration.between(Instant.now(), session.getExpiresAt());
        redisTemplate.opsForValue().set(
            SESSION_PREFIX + session.getSessionId(), 
            session, 
            timeout.toSeconds(), 
            TimeUnit.SECONDS
        );
    }
    
    private void addToUserSessions(String userId, String sessionId) {
        String key = USER_SESSIONS_PREFIX + userId;
        redisTemplate.opsForSet().add(key, sessionId);
        redisTemplate.expire(key, DEFAULT_SESSION_TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    }
    
    private void removeFromUserSessions(String userId, String sessionId) {
        redisTemplate.opsForSet().remove(USER_SESSIONS_PREFIX + userId, sessionId);
    }
    
    @SuppressWarnings("unchecked")
    private Set<String> getUserSessions(String userId) {
        Set<Object> sessions = redisTemplate.opsForSet().members(USER_SESSIONS_PREFIX + userId);
        Set<String> sessionIds = new HashSet<>();
        if (sessions != null) {
            for (Object session : sessions) {
                sessionIds.add((String) session);
            }
        }
        return sessionIds;
    }
    
    private void enforceConcurrentSessionLimits(String userId) {
        List<SecureSession> activeSessions = getUserActiveSessions(userId);
        
        if (activeSessions.size() >= MAX_CONCURRENT_SESSIONS_PER_USER) {
            // Remove oldest session
            SecureSession oldestSession = activeSessions.stream()
                .min(Comparator.comparing(SecureSession::getCreatedAt))
                .orElse(null);
            
            if (oldestSession != null) {
                invalidateSession(oldestSession.getSessionId(), "Concurrent session limit exceeded");
                
                auditLogger.logSuspiciousActivity(
                    "Concurrent session limit enforcement",
                    "Oldest session terminated for user: " + userId
                );
            }
        }
    }
    
    private Instant calculateExpirationTime(SessionType sessionType) {
        Duration timeout = sessionType == SessionType.REMEMBER_ME 
            ? EXTENDED_SESSION_TIMEOUT 
            : DEFAULT_SESSION_TIMEOUT;
        return Instant.now().plus(timeout);
    }
    
    private String generateSecureSessionId() {
        return UUID.randomUUID().toString().replace("-", "") + 
               System.currentTimeMillis() + 
               UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    }
    
    private boolean detectSuspiciousActivity(SecureSession session) {
        // This could include checks for:
        // - Rapid IP address changes
        // - Geolocation anomalies
        // - User agent changes
        // - Access pattern anomalies
        
        // For now, just a simple check
        Duration timeSinceLastAccess = Duration.between(session.getLastAccessedAt(), Instant.now());
        return timeSinceLastAccess.toMinutes() < 1; // Too frequent access
    }
    
    /**
     * Get session statistics
     */
    public SessionStatistics getSessionStatistics() {
        // This would query Redis for current session counts
        return SessionStatistics.builder()
            .totalActiveSessions(metricsCollector.getActiveSessionCount())
            .sessionsCreatedToday(0L) // Would be calculated from metrics
            .sessionsExpiredToday(0L) // Would be calculated from metrics
            .averageSessionDuration(Duration.ofMinutes(0)) // Would be calculated
            .build();
    }
}
