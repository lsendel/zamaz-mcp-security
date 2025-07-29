package com.zamaz.mcp.security.service;

import com.zamaz.mcp.security.audit.SecurityAuditService;
import com.zamaz.mcp.security.model.SessionInfo;
import com.zamaz.mcp.security.model.UserSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Service for managing user sessions with Redis backing.
 * Handles session lifecycle, concurrent session control, and session monitoring.
 */
@Service
public class SessionManagementService {
    
    private static final Logger logger = LoggerFactory.getLogger(SessionManagementService.class);
    
    private static final String SESSION_KEY_PREFIX = "session:";
    private static final String USER_SESSIONS_KEY_PREFIX = "user-sessions:";
    private static final String SESSION_METADATA_KEY_PREFIX = "session-metadata:";
    
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    
    @Autowired
    private RedisTemplate<String, String> stringRedisTemplate;
    
    @Autowired
    private SessionRepository<? extends Session> sessionRepository;
    
    @Autowired
    private SecurityAuditService auditService;
    
    @Value("${security.session.timeout:1800}")
    private int sessionTimeout;
    
    @Value("${security.session.max-concurrent:5}")
    private int maxConcurrentSessions;
    
    /**
     * Create a new session for user
     */
    public SessionInfo createSession(String userId, String userAgent, String ipAddress) {
        logger.info("Creating new session for user: {}", userId);
        
        // Check concurrent session limit
        enforceSessionLimit(userId);
        
        // Create session info
        SessionInfo sessionInfo = new SessionInfo();
        sessionInfo.setSessionId(UUID.randomUUID().toString());
        sessionInfo.setUserId(userId);
        sessionInfo.setCreatedAt(Instant.now());
        sessionInfo.setLastAccessedAt(Instant.now());
        sessionInfo.setExpiresAt(Instant.now().plusSeconds(sessionTimeout));
        sessionInfo.setUserAgent(userAgent);
        sessionInfo.setIpAddress(ipAddress);
        sessionInfo.setActive(true);
        
        // Store session in Redis
        storeSession(sessionInfo);
        
        // Add to user's session list
        addUserSession(userId, sessionInfo.getSessionId());
        
        // Audit log
        auditService.logAuthenticationSuccess(userId, sessionInfo.getSessionId());
        
        logger.info("Session created successfully: {}", sessionInfo.getSessionId());
        
        return sessionInfo;
    }
    
    /**
     * Update session last accessed time
     */
    public void touchSession(String sessionId) {
        String key = SESSION_KEY_PREFIX + sessionId;
        
        SessionInfo sessionInfo = (SessionInfo) redisTemplate.opsForValue().get(key);
        if (sessionInfo != null && sessionInfo.isActive()) {
            sessionInfo.setLastAccessedAt(Instant.now());
            sessionInfo.setExpiresAt(Instant.now().plusSeconds(sessionTimeout));
            
            redisTemplate.opsForValue().set(key, sessionInfo, sessionTimeout, TimeUnit.SECONDS);
        }
    }
    
    /**
     * Get session information
     */
    public Optional<SessionInfo> getSession(String sessionId) {
        String key = SESSION_KEY_PREFIX + sessionId;
        SessionInfo sessionInfo = (SessionInfo) redisTemplate.opsForValue().get(key);
        
        if (sessionInfo != null && sessionInfo.isActive() && 
            sessionInfo.getExpiresAt().isAfter(Instant.now())) {
            return Optional.of(sessionInfo);
        }
        
        return Optional.empty();
    }
    
    /**
     * Invalidate a session
     */
    public void invalidateSession(String sessionId) {
        logger.info("Invalidating session: {}", sessionId);
        
        String key = SESSION_KEY_PREFIX + sessionId;
        SessionInfo sessionInfo = (SessionInfo) redisTemplate.opsForValue().get(key);
        
        if (sessionInfo != null) {
            sessionInfo.setActive(false);
            sessionInfo.setInvalidatedAt(Instant.now());
            
            // Keep for audit trail
            redisTemplate.opsForValue().set(key, sessionInfo, 24, TimeUnit.HOURS);
            
            // Remove from user's active sessions
            removeUserSession(sessionInfo.getUserId(), sessionId);
            
            // Audit log
            auditService.logResourceAccess("session", "logout", sessionId, true);
        }
    }
    
    /**
     * Invalidate all sessions for a user
     */
    public void invalidateUserSessions(String userId) {
        logger.info("Invalidating all sessions for user: {}", userId);
        
        Set<String> sessionIds = getUserSessionIds(userId);
        
        for (String sessionId : sessionIds) {
            invalidateSession(sessionId);
        }
        
        // Clear user's session list
        stringRedisTemplate.delete(USER_SESSIONS_KEY_PREFIX + userId);
    }
    
    /**
     * Get all active sessions for a user
     */
    public List<SessionInfo> getUserSessions(String userId) {
        Set<String> sessionIds = getUserSessionIds(userId);
        
        return sessionIds.stream()
            .map(this::getSession)
            .filter(Optional::isPresent)
            .map(Optional::get)
            .filter(SessionInfo::isActive)
            .sorted(Comparator.comparing(SessionInfo::getCreatedAt).reversed())
            .collect(Collectors.toList());
    }
    
    /**
     * Get session count for a user
     */
    public long getUserSessionCount(String userId) {
        return getUserSessionIds(userId).size();
    }
    
    /**
     * Check if session is valid and active
     */
    public boolean isSessionValid(String sessionId) {
        return getSession(sessionId).map(SessionInfo::isActive).orElse(false);
    }
    
    /**
     * Extend session timeout
     */
    public void extendSession(String sessionId, int additionalSeconds) {
        String key = SESSION_KEY_PREFIX + sessionId;
        SessionInfo sessionInfo = (SessionInfo) redisTemplate.opsForValue().get(key);
        
        if (sessionInfo != null && sessionInfo.isActive()) {
            Instant newExpiry = sessionInfo.getExpiresAt().plusSeconds(additionalSeconds);
            sessionInfo.setExpiresAt(newExpiry);
            
            long ttl = Duration.between(Instant.now(), newExpiry).getSeconds();
            redisTemplate.opsForValue().set(key, sessionInfo, ttl, TimeUnit.SECONDS);
        }
    }
    
    /**
     * Get session metadata
     */
    public Map<String, Object> getSessionMetadata(String sessionId) {
        String key = SESSION_METADATA_KEY_PREFIX + sessionId;
        Map<Object, Object> entries = redisTemplate.opsForHash().entries(key);
        
        Map<String, Object> metadata = new HashMap<>();
        entries.forEach((k, v) -> metadata.put(k.toString(), v));
        
        return metadata;
    }
    
    /**
     * Set session metadata
     */
    public void setSessionMetadata(String sessionId, String key, Object value) {
        String hashKey = SESSION_METADATA_KEY_PREFIX + sessionId;
        redisTemplate.opsForHash().put(hashKey, key, value);
        redisTemplate.expire(hashKey, sessionTimeout, TimeUnit.SECONDS);
    }
    
    /**
     * Clean up expired sessions (scheduled task)
     */
    @Scheduled(fixedDelay = 300000) // Every 5 minutes
    public void cleanupExpiredSessions() {
        logger.debug("Running session cleanup task");
        
        Set<String> keys = redisTemplate.keys(SESSION_KEY_PREFIX + "*");
        if (keys == null) return;
        
        int cleaned = 0;
        for (String key : keys) {
            SessionInfo sessionInfo = (SessionInfo) redisTemplate.opsForValue().get(key);
            
            if (sessionInfo != null && 
                (!sessionInfo.isActive() || sessionInfo.getExpiresAt().isBefore(Instant.now()))) {
                
                // Remove from user's session list if still there
                removeUserSession(sessionInfo.getUserId(), sessionInfo.getSessionId());
                
                // Delete if older than 24 hours
                if (sessionInfo.getInvalidatedAt() != null && 
                    sessionInfo.getInvalidatedAt().isBefore(Instant.now().minus(Duration.ofHours(24)))) {
                    redisTemplate.delete(key);
                    cleaned++;
                }
            }
        }
        
        if (cleaned > 0) {
            logger.info("Cleaned up {} expired sessions", cleaned);
        }
    }
    
    /**
     * Monitor suspicious session activity
     */
    public void checkSuspiciousActivity(String sessionId, String currentIp, String currentUserAgent) {
        SessionInfo sessionInfo = getSession(sessionId).orElse(null);
        if (sessionInfo == null) return;
        
        boolean suspicious = false;
        String reason = null;
        
        // Check for IP address change
        if (!currentIp.equals(sessionInfo.getIpAddress())) {
            suspicious = true;
            reason = "IP address changed from " + sessionInfo.getIpAddress() + " to " + currentIp;
        }
        
        // Check for user agent change
        if (!currentUserAgent.equals(sessionInfo.getUserAgent())) {
            suspicious = true;
            reason = "User agent changed";
        }
        
        if (suspicious) {
            logger.warn("Suspicious activity detected for session {}: {}", sessionId, reason);
            auditService.logSuspiciousActivity("session_anomaly", reason, 0.7);
        }
    }
    
    // Private helper methods
    
    private void storeSession(SessionInfo sessionInfo) {
        String key = SESSION_KEY_PREFIX + sessionInfo.getSessionId();
        redisTemplate.opsForValue().set(key, sessionInfo, sessionTimeout, TimeUnit.SECONDS);
    }
    
    private void addUserSession(String userId, String sessionId) {
        String key = USER_SESSIONS_KEY_PREFIX + userId;
        stringRedisTemplate.opsForSet().add(key, sessionId);
        stringRedisTemplate.expire(key, 30, TimeUnit.DAYS);
    }
    
    private void removeUserSession(String userId, String sessionId) {
        String key = USER_SESSIONS_KEY_PREFIX + userId;
        stringRedisTemplate.opsForSet().remove(key, sessionId);
    }
    
    private Set<String> getUserSessionIds(String userId) {
        String key = USER_SESSIONS_KEY_PREFIX + userId;
        Set<String> sessionIds = stringRedisTemplate.opsForSet().members(key);
        return sessionIds != null ? sessionIds : new HashSet<>();
    }
    
    private void enforceSessionLimit(String userId) {
        Set<String> sessionIds = getUserSessionIds(userId);
        
        if (sessionIds.size() >= maxConcurrentSessions) {
            // Get all sessions and sort by creation time
            List<SessionInfo> sessions = sessionIds.stream()
                .map(this::getSession)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .filter(SessionInfo::isActive)
                .sorted(Comparator.comparing(SessionInfo::getCreatedAt))
                .collect(Collectors.toList());
            
            // Invalidate oldest sessions
            int toRemove = sessions.size() - maxConcurrentSessions + 1;
            for (int i = 0; i < toRemove && i < sessions.size(); i++) {
                invalidateSession(sessions.get(i).getSessionId());
                logger.info("Invalidated old session due to concurrent session limit: {}", 
                    sessions.get(i).getSessionId());
            }
        }
    }
}