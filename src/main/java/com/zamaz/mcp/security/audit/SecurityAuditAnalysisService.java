package com.zamaz.mcp.security.audit;

import com.zamaz.mcp.security.entity.SecurityAuditLog;
import com.zamaz.mcp.security.repository.SecurityAuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Security audit analysis and alerting service.
 * Analyzes audit logs for suspicious patterns and generates alerts.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SecurityAuditAnalysisService {

    private final SecurityAuditLogRepository auditLogRepository;
    private final SecurityAlertService alertService;

    // Thresholds for suspicious activity detection
    private static final int FAILED_LOGIN_THRESHOLD = 5;
    private static final int SUSPICIOUS_IP_THRESHOLD = 10;
    private static final int HIGH_RISK_EVENT_THRESHOLD = 3;
    private static final int MINUTES_WINDOW = 15;

    /**
     * Analyze recent audit logs for suspicious patterns.
     * Runs every 5 minutes.
     */
    @Scheduled(fixedRate = 300000) // 5 minutes
    @Transactional(readOnly = true)
    public void analyzeRecentActivity() {
        log.debug("Starting security audit analysis");

        LocalDateTime analysisWindow = LocalDateTime.now().minusMinutes(MINUTES_WINDOW);

        try {
            // Analyze failed authentication attempts
            analyzeFailedAuthentications(analysisWindow);

            // Analyze suspicious IP activity
            analyzeSuspiciousIpActivity(analysisWindow);

            // Analyze high-risk events
            analyzeHighRiskEvents(analysisWindow);

            // Analyze anomaly patterns
            analyzeAnomalyPatterns(analysisWindow);

            log.debug("Completed security audit analysis");

        } catch (Exception e) {
            log.error("Error during security audit analysis", e);
        }
    }

    /**
     * Analyze failed authentication attempts.
     */
    private void analyzeFailedAuthentications(LocalDateTime since) {
        List<SecurityAuditLog> failedAttempts = auditLogRepository.findFailedAuthenticationsSince(since);

        // Group by username
        Map<String, Integer> failuresByUser = new HashMap<>();
        Map<String, Integer> failuresByIp = new HashMap<>();

        for (SecurityAuditLog log : failedAttempts) {
            if (log.getUsername() != null) {
                failuresByUser.merge(log.getUsername(), 1, Integer::sum);
            }
            if (log.getIpAddress() != null) {
                failuresByIp.merge(log.getIpAddress(), 1, Integer::sum);
            }
        }

        // Check for brute force attempts by user
        for (Map.Entry<String, Integer> entry : failuresByUser.entrySet()) {
            if (entry.getValue() >= FAILED_LOGIN_THRESHOLD) {
                alertService.sendBruteForceAlert(
                        entry.getKey(),
                        entry.getValue(),
                        MINUTES_WINDOW,
                        "Multiple failed login attempts detected");
            }
        }

        // Check for brute force attempts by IP
        for (Map.Entry<String, Integer> entry : failuresByIp.entrySet()) {
            if (entry.getValue() >= FAILED_LOGIN_THRESHOLD) {
                alertService.sendSuspiciousIpAlert(
                        entry.getKey(),
                        entry.getValue(),
                        MINUTES_WINDOW,
                        "Multiple failed login attempts from IP");
            }
        }
    }

    /**
     * Analyze suspicious IP activity.
     */
    private void analyzeSuspiciousIpActivity(LocalDateTime since) {
        List<Object[]> topIps = auditLogRepository.findTopIpAddressesSince(
                since, PageRequest.of(0, 20));

        for (Object[] result : topIps) {
            String ipAddress = (String) result[0];
            Long eventCount = (Long) result[1];

            if (eventCount >= SUSPICIOUS_IP_THRESHOLD) {
                // Get recent events from this IP
                List<SecurityAuditLog> ipEvents = auditLogRepository
                        .findByIpAddressOrderByTimestampDesc(ipAddress, PageRequest.of(0, 50))
                        .getContent();

                // Analyze event patterns
                analyzeIpEventPatterns(ipAddress, ipEvents);
            }
        }
    }

    /**
     * Analyze event patterns for a specific IP.
     */
    private void analyzeIpEventPatterns(String ipAddress, List<SecurityAuditLog> events) {
        Map<SecurityAuditLog.SecurityEventType, Integer> eventTypeCounts = new HashMap<>();
        Map<String, Integer> userCounts = new HashMap<>();
        int failureCount = 0;

        for (SecurityAuditLog event : events) {
            eventTypeCounts.merge(event.getEventType(), 1, Integer::sum);

            if (event.getUsername() != null) {
                userCounts.merge(event.getUsername(), 1, Integer::sum);
            }

            if (event.getOutcome() == SecurityAuditLog.AuditOutcome.FAILURE) {
                failureCount++;
            }
        }

        // Check for suspicious patterns
        boolean suspicious = false;
        StringBuilder reasons = new StringBuilder();

        // Multiple users from same IP
        if (userCounts.size() > 5) {
            suspicious = true;
            reasons.append("Multiple users (").append(userCounts.size()).append(") from same IP; ");
        }

        // High failure rate
        double failureRate = (double) failureCount / events.size();
        if (failureRate > 0.5) {
            suspicious = true;
            reasons.append("High failure rate (").append(String.format("%.1f%%", failureRate * 100)).append("); ");
        }

        // Rapid-fire requests
        if (events.size() > 20) {
            LocalDateTime firstEvent = events.get(events.size() - 1).getTimestamp();
            LocalDateTime lastEvent = events.get(0).getTimestamp();
            long minutesDiff = java.time.Duration.between(firstEvent, lastEvent).toMinutes();

            if (minutesDiff < 5) {
                suspicious = true;
                reasons.append("Rapid requests (").append(events.size()).append(" in ").append(minutesDiff)
                        .append(" minutes); ");
            }
        }

        if (suspicious) {
            alertService.sendSuspiciousIpAlert(
                    ipAddress,
                    events.size(),
                    MINUTES_WINDOW,
                    "Suspicious activity patterns: " + reasons.toString());
        }
    }

    /**
     * Analyze high-risk events.
     */
    private void analyzeHighRiskEvents(LocalDateTime since) {
        List<SecurityAuditLog> highRiskEvents = auditLogRepository
                .findByTimestampBetween(since, LocalDateTime.now(), PageRequest.of(0, 100))
                .getContent()
                .stream()
                .filter(log -> log.getRiskLevel() == SecurityAuditLog.RiskLevel.HIGH ||
                        log.getRiskLevel() == SecurityAuditLog.RiskLevel.CRITICAL)
                .toList();

        if (highRiskEvents.size() >= HIGH_RISK_EVENT_THRESHOLD) {
            alertService.sendHighRiskActivityAlert(
                    highRiskEvents.size(),
                    MINUTES_WINDOW,
                    "Multiple high-risk security events detected");
        }

        // Check for critical events
        List<SecurityAuditLog> criticalEvents = highRiskEvents.stream()
                .filter(log -> log.getRiskLevel() == SecurityAuditLog.RiskLevel.CRITICAL)
                .toList();

        for (SecurityAuditLog criticalEvent : criticalEvents) {
            alertService.sendCriticalSecurityAlert(
                    criticalEvent.getEventType().name(),
                    criticalEvent.getEventDescription(),
                    criticalEvent.getUsername(),
                    criticalEvent.getIpAddress());
        }
    }

    /**
     * Analyze anomaly patterns.
     */
    private void analyzeAnomalyPatterns(LocalDateTime since) {
        List<SecurityAuditLog> anomalies = auditLogRepository
                .findByAnomalyDetectedTrueOrderByTimestampDesc(PageRequest.of(0, 50))
                .getContent()
                .stream()
                .filter(log -> log.getTimestamp().isAfter(since))
                .toList();

        if (anomalies.size() >= 3) {
            // Group anomalies by user
            Map<String, List<SecurityAuditLog>> anomaliesByUser = anomalies.stream()
                    .filter(log -> log.getUsername() != null)
                    .collect(java.util.stream.Collectors.groupingBy(SecurityAuditLog::getUsername));

            for (Map.Entry<String, List<SecurityAuditLog>> entry : anomaliesByUser.entrySet()) {
                if (entry.getValue().size() >= 2) {
                    double avgAnomalyScore = entry.getValue().stream()
                            .mapToDouble(log -> log.getAnomalyScore() != null ? log.getAnomalyScore() : 0.0)
                            .average()
                            .orElse(0.0);

                    alertService.sendAnomalyAlert(
                            entry.getKey(),
                            entry.getValue().size(),
                            avgAnomalyScore,
                            "Multiple anomalous activities detected for user");
                }
            }
        }
    }

    /**
     * Generate security summary report.
     */
    @Transactional(readOnly = true)
    public SecuritySummaryReport generateSummaryReport(LocalDateTime startTime, LocalDateTime endTime) {
        SecuritySummaryReport report = new SecuritySummaryReport();
        report.setStartTime(startTime);
        report.setEndTime(endTime);

        // Event counts by type
        List<Object[]> eventTypeCounts = auditLogRepository.countEventsByTypeInRange(startTime, endTime);
        Map<String, Long> eventTypeMap = new HashMap<>();
        for (Object[] result : eventTypeCounts) {
            eventTypeMap.put(result[0].toString(), (Long) result[1]);
        }
        report.setEventCountsByType(eventTypeMap);

        // Event counts by outcome
        List<Object[]> outcomeCounts = auditLogRepository.countEventsByOutcomeInRange(startTime, endTime);
        Map<String, Long> outcomeMap = new HashMap<>();
        for (Object[] result : outcomeCounts) {
            outcomeMap.put(result[0].toString(), (Long) result[1]);
        }
        report.setEventCountsByOutcome(outcomeMap);

        // Event counts by risk level
        List<Object[]> riskLevelCounts = auditLogRepository.countEventsByRiskLevelInRange(startTime, endTime);
        Map<String, Long> riskLevelMap = new HashMap<>();
        for (Object[] result : riskLevelCounts) {
            riskLevelMap.put(result[0].toString(), (Long) result[1]);
        }
        report.setEventCountsByRiskLevel(riskLevelMap);

        // Top IP addresses
        List<Object[]> topIps = auditLogRepository.findTopIpAddressesSince(startTime, PageRequest.of(0, 10));
        Map<String, Long> topIpMap = new HashMap<>();
        for (Object[] result : topIps) {
            topIpMap.put((String) result[0], (Long) result[1]);
        }
        report.setTopIpAddresses(topIpMap);

        // Top users
        List<Object[]> topUsers = auditLogRepository.findTopUsersSince(startTime, PageRequest.of(0, 10));
        Map<String, Long> topUserMap = new HashMap<>();
        for (Object[] result : topUsers) {
            topUserMap.put((String) result[0], (Long) result[1]);
        }
        report.setTopUsers(topUserMap);

        return report;
    }

    /**
     * Security summary report data structure.
     */
    public static class SecuritySummaryReport {
        private LocalDateTime startTime;
        private LocalDateTime endTime;
        private Map<String, Long> eventCountsByType;
        private Map<String, Long> eventCountsByOutcome;
        private Map<String, Long> eventCountsByRiskLevel;
        private Map<String, Long> topIpAddresses;
        private Map<String, Long> topUsers;

        // Getters and setters
        public LocalDateTime getStartTime() {
            return startTime;
        }

        public void setStartTime(LocalDateTime startTime) {
            this.startTime = startTime;
        }

        public LocalDateTime getEndTime() {
            return endTime;
        }

        public void setEndTime(LocalDateTime endTime) {
            this.endTime = endTime;
        }

        public Map<String, Long> getEventCountsByType() {
            return eventCountsByType;
        }

        public void setEventCountsByType(Map<String, Long> eventCountsByType) {
            this.eventCountsByType = eventCountsByType;
        }

        public Map<String, Long> getEventCountsByOutcome() {
            return eventCountsByOutcome;
        }

        public void setEventCountsByOutcome(Map<String, Long> eventCountsByOutcome) {
            this.eventCountsByOutcome = eventCountsByOutcome;
        }

        public Map<String, Long> getEventCountsByRiskLevel() {
            return eventCountsByRiskLevel;
        }

        public void setEventCountsByRiskLevel(Map<String, Long> eventCountsByRiskLevel) {
            this.eventCountsByRiskLevel = eventCountsByRiskLevel;
        }

        public Map<String, Long> getTopIpAddresses() {
            return topIpAddresses;
        }

        public void setTopIpAddresses(Map<String, Long> topIpAddresses) {
            this.topIpAddresses = topIpAddresses;
        }

        public Map<String, Long> getTopUsers() {
            return topUsers;
        }

        public void setTopUsers(Map<String, Long> topUsers) {
            this.topUsers = topUsers;
        }
    }
}