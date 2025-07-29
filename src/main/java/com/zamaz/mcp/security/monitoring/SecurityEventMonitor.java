package com.zamaz.mcp.security.monitoring;

import com.zamaz.mcp.security.entity.SecurityAuditLog;
import com.zamaz.mcp.security.monitoring.rules.SecurityAlertRule;
import com.zamaz.mcp.security.repository.SecurityAuditLogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * Real-time security event monitoring service.
 * Monitors security events, detects patterns, and triggers alerts based on configurable rules.
 */
@Service
public class SecurityEventMonitor {
    
    private static final Logger logger = LoggerFactory.getLogger(SecurityEventMonitor.class);
    
    private static final String EVENT_COUNTER_PREFIX = "security:event:counter:";
    private static final String ALERT_HISTORY_PREFIX = "security:alert:history:";
    private static final String ANOMALY_DETECTION_PREFIX = "security:anomaly:";
    
    @Autowired
    private SecurityAuditLogRepository auditLogRepository;
    
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    
    @Autowired
    private ApplicationEventPublisher eventPublisher;
    
    @Autowired
    private List<SecurityAlertRule> alertRules;
    
    // In-memory event buffers for real-time processing
    private final Map<String, EventBuffer> eventBuffers = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> eventCounters = new ConcurrentHashMap<>();
    
    /**
     * Process security event in real-time
     */
    @Async
    public void processSecurityEvent(SecurityAuditLog event) {
        logger.debug("Processing security event: {} - {}", event.getEventType(), event.getEventDescription());
        
        // Update event counters
        updateEventCounters(event);
        
        // Buffer event for pattern detection
        bufferEvent(event);
        
        // Check alert rules
        checkAlertRules(event);
        
        // Detect anomalies
        detectAnomalies(event);
        
        // Update metrics
        updateMetrics(event);
    }
    
    /**
     * Check all alert rules against the event
     */
    private void checkAlertRules(SecurityAuditLog event) {
        for (SecurityAlertRule rule : alertRules) {
            if (rule.isEnabled() && rule.matches(event)) {
                evaluateRule(rule, event);
            }
        }
    }
    
    /**
     * Evaluate a specific alert rule
     */
    private void evaluateRule(SecurityAlertRule rule, SecurityAuditLog event) {
        String ruleKey = rule.getRuleId();
        
        // Get recent events matching the rule criteria
        List<SecurityAuditLog> recentEvents = getRecentEvents(
            rule.getEventTypes(), 
            rule.getTimeWindowMinutes()
        );
        
        // Apply rule conditions
        if (rule.evaluate(recentEvents, event)) {
            triggerAlert(rule, event, recentEvents);
        }
    }
    
    /**
     * Trigger security alert
     */
    private void triggerAlert(SecurityAlertRule rule, SecurityAuditLog triggerEvent, 
                            List<SecurityAuditLog> relatedEvents) {
        logger.warn("Security alert triggered: {} - {}", rule.getRuleName(), rule.getDescription());
        
        SecurityAlert alert = new SecurityAlert();
        alert.setAlertId(UUID.randomUUID().toString());
        alert.setRuleId(rule.getRuleId());
        alert.setRuleName(rule.getRuleName());
        alert.setSeverity(rule.getSeverity());
        alert.setTriggeredAt(Instant.now());
        alert.setTriggerEvent(triggerEvent);
        alert.setRelatedEventCount(relatedEvents.size());
        alert.setDescription(rule.formatAlertMessage(triggerEvent, relatedEvents));
        
        // Calculate risk score
        double riskScore = calculateRiskScore(rule, relatedEvents);
        alert.setRiskScore(riskScore);
        
        // Store alert
        storeAlert(alert);
        
        // Publish alert event
        eventPublisher.publishEvent(new SecurityAlertEvent(alert));
        
        // Send notifications based on severity
        sendAlertNotifications(alert);
    }
    
    /**
     * Detect anomalies using statistical analysis
     */
    private void detectAnomalies(SecurityAuditLog event) {
        String eventTypeKey = ANOMALY_DETECTION_PREFIX + event.getEventType();
        
        // Get historical baseline
        AnomalyBaseline baseline = getOrCreateBaseline(event.getEventType());
        
        // Calculate deviation from baseline
        double deviation = calculateDeviation(event, baseline);
        
        if (deviation > baseline.getThreshold()) {
            logger.warn("Anomaly detected for event type {}: deviation={}", 
                event.getEventType(), deviation);
            
            // Create anomaly alert
            SecurityAlert anomalyAlert = createAnomalyAlert(event, deviation, baseline);
            storeAlert(anomalyAlert);
            eventPublisher.publishEvent(new SecurityAlertEvent(anomalyAlert));
        }
        
        // Update baseline with new data point
        updateBaseline(baseline, event);
    }
    
    /**
     * Update event counters for rate monitoring
     */
    private void updateEventCounters(SecurityAuditLog event) {
        // Update global counter
        incrementCounter("global", 60);
        
        // Update event type counter
        incrementCounter(event.getEventType().name(), 60);
        
        // Update user-specific counter if available
        if (event.getUserId() != null) {
            incrementCounter("user:" + event.getUserId(), 60);
        }
        
        // Update organization-specific counter if available
        if (event.getOrganizationId() != null) {
            incrementCounter("org:" + event.getOrganizationId(), 60);
        }
    }
    
    /**
     * Buffer events for pattern detection
     */
    private void bufferEvent(SecurityAuditLog event) {
        String bufferKey = event.getEventType().name();
        EventBuffer buffer = eventBuffers.computeIfAbsent(bufferKey, 
            k -> new EventBuffer(1000)); // Keep last 1000 events per type
        
        buffer.add(event);
    }
    
    /**
     * Get recent events matching criteria
     */
    private List<SecurityAuditLog> getRecentEvents(Set<SecurityAuditLog.SecurityEventType> eventTypes, 
                                                  int timeWindowMinutes) {
        LocalDateTime since = LocalDateTime.now().minusMinutes(timeWindowMinutes);
        
        if (eventTypes == null || eventTypes.isEmpty()) {
            return auditLogRepository.findByTimestampAfter(since);
        } else {
            return auditLogRepository.findByEventTypeInAndTimestampAfter(eventTypes, since);
        }
    }
    
    /**
     * Calculate risk score for an alert
     */
    private double calculateRiskScore(SecurityAlertRule rule, List<SecurityAuditLog> events) {
        double baseScore = rule.getSeverity().getBaseScore();
        
        // Adjust based on event frequency
        double frequencyMultiplier = Math.min(2.0, 1.0 + (events.size() / 100.0));
        
        // Adjust based on risk levels of individual events
        double avgEventRisk = events.stream()
            .mapToDouble(e -> e.getRiskLevel() != null ? e.getRiskLevel().ordinal() : 1)
            .average()
            .orElse(1.0);
        
        return Math.min(10.0, baseScore * frequencyMultiplier * (avgEventRisk / 3.0));
    }
    
    /**
     * Send alert notifications
     */
    private void sendAlertNotifications(SecurityAlert alert) {
        // High and critical alerts require immediate notification
        if (alert.getSeverity() == AlertSeverity.HIGH || 
            alert.getSeverity() == AlertSeverity.CRITICAL) {
            
            // Send email notification
            sendEmailNotification(alert);
            
            // Send webhook notification
            sendWebhookNotification(alert);
            
            // Log to SIEM if configured
            sendToSIEM(alert);
        }
    }
    
    /**
     * Scheduled task to analyze patterns
     */
    @Scheduled(fixedDelay = 60000) // Every minute
    public void analyzePatterns() {
        logger.debug("Running pattern analysis");
        
        // Analyze brute force patterns
        analyzeBruteForcePatterns();
        
        // Analyze privilege escalation attempts
        analyzePrivilegeEscalation();
        
        // Analyze data exfiltration patterns
        analyzeDataExfiltration();
        
        // Clean up old buffers
        cleanupOldBuffers();
    }
    
    /**
     * Analyze brute force attack patterns
     */
    private void analyzeBruteForcePatterns() {
        EventBuffer loginFailures = eventBuffers.get(
            SecurityAuditLog.SecurityEventType.LOGIN_FAILURE.name());
        
        if (loginFailures == null) return;
        
        // Group by IP address
        Map<String, List<SecurityAuditLog>> byIp = loginFailures.getRecentEvents(5)
            .stream()
            .filter(e -> e.getIpAddress() != null)
            .collect(Collectors.groupingBy(SecurityAuditLog::getIpAddress));
        
        // Check for rapid failures from same IP
        byIp.forEach((ip, events) -> {
            if (events.size() >= 5) {
                logger.warn("Potential brute force attack from IP: {} ({} failures)", 
                    ip, events.size());
                
                // Create pattern-based alert
                createPatternAlert("BRUTE_FORCE", 
                    "Brute force attack detected from " + ip,
                    AlertSeverity.HIGH, events);
            }
        });
    }
    
    /**
     * Store alert in repository and cache
     */
    private void storeAlert(SecurityAlert alert) {
        String key = ALERT_HISTORY_PREFIX + alert.getAlertId();
        redisTemplate.opsForValue().set(key, alert, 7, TimeUnit.DAYS);
        
        // Also store in time-series for querying
        String tsKey = ALERT_HISTORY_PREFIX + "ts:" + 
            Instant.now().toEpochMilli() + ":" + alert.getAlertId();
        redisTemplate.opsForValue().set(tsKey, alert.getAlertId(), 7, TimeUnit.DAYS);
    }
    
    /**
     * Helper methods
     */
    private void incrementCounter(String counterType, int ttlSeconds) {
        String key = EVENT_COUNTER_PREFIX + counterType + ":" + 
            (System.currentTimeMillis() / 1000); // Per second
        
        redisTemplate.opsForValue().increment(key);
        redisTemplate.expire(key, ttlSeconds, TimeUnit.SECONDS);
    }
    
    private AnomalyBaseline getOrCreateBaseline(SecurityAuditLog.SecurityEventType eventType) {
        // Simplified baseline - in production would use more sophisticated models
        return new AnomalyBaseline(eventType.name(), 3.0); // 3 standard deviations
    }
    
    private double calculateDeviation(SecurityAuditLog event, AnomalyBaseline baseline) {
        // Simplified deviation calculation
        return Math.random() * 5; // Placeholder
    }
    
    private void updateBaseline(AnomalyBaseline baseline, SecurityAuditLog event) {
        // Update baseline statistics
        baseline.addDataPoint(1.0); // Simplified
    }
    
    private SecurityAlert createAnomalyAlert(SecurityAuditLog event, double deviation, 
                                           AnomalyBaseline baseline) {
        SecurityAlert alert = new SecurityAlert();
        alert.setAlertId(UUID.randomUUID().toString());
        alert.setRuleId("ANOMALY_DETECTION");
        alert.setRuleName("Anomaly Detection");
        alert.setSeverity(AlertSeverity.MEDIUM);
        alert.setTriggeredAt(Instant.now());
        alert.setTriggerEvent(event);
        alert.setDescription(String.format(
            "Anomalous activity detected for %s (deviation: %.2f)",
            event.getEventType(), deviation));
        alert.setRiskScore(deviation);
        
        return alert;
    }
    
    private void createPatternAlert(String patternType, String description, 
                                  AlertSeverity severity, List<SecurityAuditLog> events) {
        SecurityAlert alert = new SecurityAlert();
        alert.setAlertId(UUID.randomUUID().toString());
        alert.setRuleId("PATTERN_" + patternType);
        alert.setRuleName(patternType + " Pattern Detection");
        alert.setSeverity(severity);
        alert.setTriggeredAt(Instant.now());
        alert.setRelatedEventCount(events.size());
        alert.setDescription(description);
        alert.setRiskScore(severity.getBaseScore());
        
        storeAlert(alert);
        eventPublisher.publishEvent(new SecurityAlertEvent(alert));
    }
    
    private void analyzePrivilegeEscalation() {
        // Implement privilege escalation detection
    }
    
    private void analyzeDataExfiltration() {
        // Implement data exfiltration detection
    }
    
    private void cleanupOldBuffers() {
        eventBuffers.values().forEach(EventBuffer::cleanup);
    }
    
    private void updateMetrics(SecurityAuditLog event) {
        // Update Prometheus metrics or other monitoring systems
    }
    
    private void sendEmailNotification(SecurityAlert alert) {
        // Implement email notification
        logger.info("Would send email notification for alert: {}", alert.getAlertId());
    }
    
    private void sendWebhookNotification(SecurityAlert alert) {
        // Implement webhook notification
        logger.info("Would send webhook notification for alert: {}", alert.getAlertId());
    }
    
    private void sendToSIEM(SecurityAlert alert) {
        // Implement SIEM integration
        logger.info("Would send to SIEM for alert: {}", alert.getAlertId());
    }
    
    /**
     * Inner class for event buffering
     */
    private static class EventBuffer {
        private final int maxSize;
        private final LinkedList<SecurityAuditLog> events = new LinkedList<>();
        
        public EventBuffer(int maxSize) {
            this.maxSize = maxSize;
        }
        
        public synchronized void add(SecurityAuditLog event) {
            events.addFirst(event);
            if (events.size() > maxSize) {
                events.removeLast();
            }
        }
        
        public synchronized List<SecurityAuditLog> getRecentEvents(int minutes) {
            LocalDateTime since = LocalDateTime.now().minusMinutes(minutes);
            return events.stream()
                .filter(e -> e.getTimestamp().isAfter(since))
                .collect(Collectors.toList());
        }
        
        public synchronized void cleanup() {
            LocalDateTime cutoff = LocalDateTime.now().minusHours(1);
            events.removeIf(e -> e.getTimestamp().isBefore(cutoff));
        }
    }
    
    /**
     * Anomaly baseline tracker
     */
    private static class AnomalyBaseline {
        private final String metric;
        private final double threshold;
        private double mean = 0;
        private double variance = 0;
        private long count = 0;
        
        public AnomalyBaseline(String metric, double threshold) {
            this.metric = metric;
            this.threshold = threshold;
        }
        
        public void addDataPoint(double value) {
            count++;
            double delta = value - mean;
            mean += delta / count;
            variance += delta * (value - mean);
        }
        
        public double getThreshold() {
            return threshold;
        }
        
        public double getStandardDeviation() {
            return count > 1 ? Math.sqrt(variance / (count - 1)) : 0;
        }
    }
}