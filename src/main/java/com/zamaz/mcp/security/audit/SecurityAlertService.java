package com.zamaz.mcp.security.audit;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Security alert service for sending notifications about security events.
 * Handles different types of security alerts and notifications.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SecurityAlertService {

    private final ApplicationEventPublisher eventPublisher;

    @Value("${security.alerts.enabled:true}")
    private boolean alertsEnabled;

    @Value("${security.alerts.webhook.url:}")
    private String webhookUrl;

    @Value("${security.alerts.email.enabled:false}")
    private boolean emailAlertsEnabled;

    /**
     * Send brute force attack alert.
     */
    @Async
    public void sendBruteForceAlert(String username, int attemptCount, int timeWindowMinutes, String description) {
        log.warn("SECURITY ALERT - Brute Force: User '{}' had {} failed login attempts in {} minutes - {}",
                username, attemptCount, timeWindowMinutes, description);

        if (!alertsEnabled) {
            return;
        }

        SecurityAlert alert = SecurityAlert.builder()
                .alertType(SecurityAlert.AlertType.BRUTE_FORCE)
                .severity(SecurityAlert.Severity.HIGH)
                .title("Brute Force Attack Detected")
                .description(description)
                .username(username)
                .metadata(Map.of(
                        "attemptCount", attemptCount,
                        "timeWindowMinutes", timeWindowMinutes))
                .timestamp(LocalDateTime.now())
                .build();

        sendAlert(alert);
    }

    /**
     * Send suspicious IP activity alert.
     */
    @Async
    public void sendSuspiciousIpAlert(String ipAddress, int eventCount, int timeWindowMinutes, String description) {
        log.warn("SECURITY ALERT - Suspicious IP: IP '{}' generated {} events in {} minutes - {}",
                ipAddress, eventCount, timeWindowMinutes, description);

        if (!alertsEnabled) {
            return;
        }

        SecurityAlert alert = SecurityAlert.builder()
                .alertType(SecurityAlert.AlertType.SUSPICIOUS_IP)
                .severity(SecurityAlert.Severity.MEDIUM)
                .title("Suspicious IP Activity")
                .description(description)
                .ipAddress(ipAddress)
                .metadata(Map.of(
                        "eventCount", eventCount,
                        "timeWindowMinutes", timeWindowMinutes))
                .timestamp(LocalDateTime.now())
                .build();

        sendAlert(alert);
    }

    /**
     * Send high-risk activity alert.
     */
    @Async
    public void sendHighRiskActivityAlert(int eventCount, int timeWindowMinutes, String description) {
        log.error("SECURITY ALERT - High Risk Activity: {} high-risk events in {} minutes - {}",
                eventCount, timeWindowMinutes, description);

        if (!alertsEnabled) {
            return;
        }

        SecurityAlert alert = SecurityAlert.builder()
                .alertType(SecurityAlert.AlertType.HIGH_RISK_ACTIVITY)
                .severity(SecurityAlert.Severity.HIGH)
                .title("High Risk Activity Detected")
                .description(description)
                .metadata(Map.of(
                        "eventCount", eventCount,
                        "timeWindowMinutes", timeWindowMinutes))
                .timestamp(LocalDateTime.now())
                .build();

        sendAlert(alert);
    }

    /**
     * Send critical security alert.
     */
    @Async
    public void sendCriticalSecurityAlert(String eventType, String description, String username, String ipAddress) {
        log.error("CRITICAL SECURITY ALERT - {}: {} (User: {}, IP: {})",
                eventType, description, username, ipAddress);

        if (!alertsEnabled) {
            return;
        }

        SecurityAlert alert = SecurityAlert.builder()
                .alertType(SecurityAlert.AlertType.CRITICAL_SECURITY_EVENT)
                .severity(SecurityAlert.Severity.CRITICAL)
                .title("Critical Security Event")
                .description(description)
                .username(username)
                .ipAddress(ipAddress)
                .metadata(Map.of("eventType", eventType))
                .timestamp(LocalDateTime.now())
                .build();

        sendAlert(alert);
    }

    /**
     * Send anomaly detection alert.
     */
    @Async
    public void sendAnomalyAlert(String username, int anomalyCount, double avgAnomalyScore, String description) {
        log.warn("SECURITY ALERT - Anomaly Detected: User '{}' had {} anomalous activities (avg score: {:.2f}) - {}",
                username, anomalyCount, avgAnomalyScore, description);

        if (!alertsEnabled) {
            return;
        }

        SecurityAlert alert = SecurityAlert.builder()
                .alertType(SecurityAlert.AlertType.ANOMALY_DETECTED)
                .severity(avgAnomalyScore >= 0.8 ? SecurityAlert.Severity.HIGH : SecurityAlert.Severity.MEDIUM)
                .title("Anomalous Activity Detected")
                .description(description)
                .username(username)
                .metadata(Map.of(
                        "anomalyCount", anomalyCount,
                        "avgAnomalyScore", avgAnomalyScore))
                .timestamp(LocalDateTime.now())
                .build();

        sendAlert(alert);
    }

    /**
     * Send alert through configured channels.
     */
    private void sendAlert(SecurityAlert alert) {
        try {
            // Publish as application event for internal handling
            eventPublisher.publishEvent(alert);

            // Send webhook notification if configured
            if (webhookUrl != null && !webhookUrl.isEmpty()) {
                sendWebhookAlert(alert);
            }

            // Send email notification if enabled
            if (emailAlertsEnabled) {
                sendEmailAlert(alert);
            }

        } catch (Exception e) {
            log.error("Failed to send security alert: {}", e.getMessage(), e);
        }
    }

    /**
     * Send alert via webhook.
     */
    private void sendWebhookAlert(SecurityAlert alert) {
        // Implementation would use RestTemplate or WebClient to send HTTP POST
        log.info("Would send webhook alert to: {} - {}", webhookUrl, alert.getTitle());
    }

    /**
     * Send alert via email.
     */
    private void sendEmailAlert(SecurityAlert alert) {
        // Implementation would use JavaMailSender or similar
        log.info("Would send email alert: {}", alert.getTitle());
    }

    /**
     * Security alert data structure.
     */
    public static class SecurityAlert {
        private AlertType alertType;
        private Severity severity;
        private String title;
        private String description;
        private String username;
        private String ipAddress;
        private Map<String, Object> metadata;
        private LocalDateTime timestamp;

        public enum AlertType {
            BRUTE_FORCE,
            SUSPICIOUS_IP,
            HIGH_RISK_ACTIVITY,
            CRITICAL_SECURITY_EVENT,
            ANOMALY_DETECTED
        }

        public enum Severity {
            LOW, MEDIUM, HIGH, CRITICAL
        }

        public static SecurityAlertBuilder builder() {
            return new SecurityAlertBuilder();
        }

        // Getters
        public AlertType getAlertType() {
            return alertType;
        }

        public Severity getSeverity() {
            return severity;
        }

        public String getTitle() {
            return title;
        }

        public String getDescription() {
            return description;
        }

        public String getUsername() {
            return username;
        }

        public String getIpAddress() {
            return ipAddress;
        }

        public Map<String, Object> getMetadata() {
            return metadata;
        }

        public LocalDateTime getTimestamp() {
            return timestamp;
        }

        public static class SecurityAlertBuilder {
            private SecurityAlert alert = new SecurityAlert();

            public SecurityAlertBuilder alertType(AlertType alertType) {
                alert.alertType = alertType;
                return this;
            }

            public SecurityAlertBuilder severity(Severity severity) {
                alert.severity = severity;
                return this;
            }

            public SecurityAlertBuilder title(String title) {
                alert.title = title;
                return this;
            }

            public SecurityAlertBuilder description(String description) {
                alert.description = description;
                return this;
            }

            public SecurityAlertBuilder username(String username) {
                alert.username = username;
                return this;
            }

            public SecurityAlertBuilder ipAddress(String ipAddress) {
                alert.ipAddress = ipAddress;
                return this;
            }

            public SecurityAlertBuilder metadata(Map<String, Object> metadata) {
                alert.metadata = metadata;
                return this;
            }

            public SecurityAlertBuilder timestamp(LocalDateTime timestamp) {
                alert.timestamp = timestamp;
                return this;
            }

            public SecurityAlert build() {
                return alert;
            }
        }
    }
}