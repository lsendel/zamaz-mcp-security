package com.zamaz.mcp.security.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zamaz.mcp.security.entity.SecurityAuditLog;
import com.zamaz.mcp.security.entity.User;
import com.zamaz.mcp.security.repository.SecurityAuditLogRepository;
import com.zamaz.mcp.security.tenant.TenantSecurityContext;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Security audit service for logging authentication and authorization events.
 * Provides comprehensive audit trail for compliance and security monitoring.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SecurityAuditService {

    private final SecurityAuditLogRepository auditLogRepository;
    private final ObjectMapper objectMapper;

    /**
     * Log authentication success event.
     */
    @Async
    @Transactional
    public void logAuthenticationSuccess(String username, String sessionId) {
        SecurityAuditLog auditLog = createBaseAuditLog(
                SecurityAuditLog.SecurityEventType.LOGIN_SUCCESS,
                SecurityAuditLog.EventCategory.AUTHENTICATION,
                "User successfully authenticated");

        auditLog.setUsername(username);
        auditLog.setSessionId(sessionId);
        auditLog.setOutcome(SecurityAuditLog.AuditOutcome.SUCCESS);
        auditLog.setRiskLevel(SecurityAuditLog.RiskLevel.LOW);

        // Add authentication details
        Map<String, Object> details = new HashMap<>();
        details.put("authenticationMethod", "password");
        details.put("loginType", "standard");
        setAuditDetails(auditLog, details);

        saveAuditLog(auditLog);
        log.info("Logged authentication success for user: {}", username);
    }

    /**
     * Log authentication failure event.
     */
    @Async
    @Transactional
    public void logAuthenticationFailure(String username, String reason, String errorCode) {
        SecurityAuditLog auditLog = createBaseAuditLog(
                SecurityAuditLog.SecurityEventType.LOGIN_FAILURE,
                SecurityAuditLog.EventCategory.AUTHENTICATION,
                "Authentication failed: " + reason);

        auditLog.setUsername(username);
        auditLog.setOutcome(SecurityAuditLog.AuditOutcome.FAILURE);
        auditLog.setOutcomeReason(reason);
        auditLog.setErrorCode(errorCode);
        auditLog.setRiskLevel(SecurityAuditLog.RiskLevel.MEDIUM);

        // Add failure details
        Map<String, Object> details = new HashMap<>();
        details.put("failureReason", reason);
        details.put("errorCode", errorCode);
        setAuditDetails(auditLog, details);

        saveAuditLog(auditLog);
        log.warn("Logged authentication failure for user: {} - {}", username, reason);
    }

    /**
     * Log authorization success event.
     */
    @Async
    @Transactional
    public void logAuthorizationSuccess(String resource, String action, String resourceId) {
        SecurityAuditLog auditLog = createBaseAuditLog(
                SecurityAuditLog.SecurityEventType.PERMISSION_GRANTED,
                SecurityAuditLog.EventCategory.AUTHORIZATION,
                String.format("Permission granted for %s:%s", resource, action));

        auditLog.setResourceType(resource);
        auditLog.setAction(action);
        auditLog.setResourceId(resourceId);
        auditLog.setOutcome(SecurityAuditLog.AuditOutcome.SUCCESS);
        auditLog.setRiskLevel(SecurityAuditLog.RiskLevel.LOW);

        // Add authorization details
        Map<String, Object> details = new HashMap<>();
        details.put("permissionType", "granted");
        details.put("evaluationMethod", "rbac");
        setAuditDetails(auditLog, details);

        saveAuditLog(auditLog);
        log.debug("Logged authorization success for {}:{} on {}", resource, action, resourceId);
    }

    /**
     * Log authorization failure event.
     */
    @Async
    @Transactional
    public void logAuthorizationFailure(String resource, String action, String resourceId, String reason) {
        SecurityAuditLog auditLog = createBaseAuditLog(
                SecurityAuditLog.SecurityEventType.PERMISSION_DENIED,
                SecurityAuditLog.EventCategory.AUTHORIZATION,
                String.format("Permission denied for %s:%s - %s", resource, action, reason));

        auditLog.setResourceType(resource);
        auditLog.setAction(action);
        auditLog.setResourceId(resourceId);
        auditLog.setOutcome(SecurityAuditLog.AuditOutcome.FAILURE);
        auditLog.setOutcomeReason(reason);
        auditLog.setRiskLevel(SecurityAuditLog.RiskLevel.MEDIUM);

        // Add authorization details
        Map<String, Object> details = new HashMap<>();
        details.put("denialReason", reason);
        details.put("evaluationMethod", "rbac");
        setAuditDetails(auditLog, details);

        saveAuditLog(auditLog);
        log.warn("Logged authorization failure for {}:{} on {} - {}", resource, action, resourceId, reason);
    }

    /**
     * Log security violation event.
     */
    @Async
    @Transactional
    public void logSecurityViolation(String violationType, String description, SecurityAuditLog.RiskLevel riskLevel) {
        SecurityAuditLog auditLog = createBaseAuditLog(
                SecurityAuditLog.SecurityEventType.SECURITY_VIOLATION,
                SecurityAuditLog.EventCategory.SECURITY,
                description);

        auditLog.setOutcome(SecurityAuditLog.AuditOutcome.BLOCKED);
        auditLog.setOutcomeReason(violationType);
        auditLog.setRiskLevel(riskLevel);

        // Add violation details
        Map<String, Object> details = new HashMap<>();
        details.put("violationType", violationType);
        details.put("severity", riskLevel.name());
        setAuditDetails(auditLog, details);

        saveAuditLog(auditLog);
        log.error("Logged security violation: {} - {}", violationType, description);
    }

    /**
     * Log suspicious activity event.
     */
    @Async
    @Transactional
    public void logSuspiciousActivity(String activityType, String description, double anomalyScore) {
        SecurityAuditLog auditLog = createBaseAuditLog(
                SecurityAuditLog.SecurityEventType.SUSPICIOUS_ACTIVITY,
                SecurityAuditLog.EventCategory.SECURITY,
                description);

        auditLog.setOutcome(SecurityAuditLog.AuditOutcome.WARNING);
        auditLog.setAnomalyDetected(true);
        auditLog.setAnomalyScore(anomalyScore);
        auditLog.setRiskLevel(determineRiskLevel(anomalyScore));

        // Add activity details
        Map<String, Object> details = new HashMap<>();
        details.put("activityType", activityType);
        details.put("anomalyScore", anomalyScore);
        details.put("detectionMethod", "behavioral_analysis");
        setAuditDetails(auditLog, details);

        saveAuditLog(auditLog);
        log.warn("Logged suspicious activity: {} - {} (score: {})", activityType, description, anomalyScore);
    }

    /**
     * Log resource access event.
     */
    @Async
    @Transactional
    public void logResourceAccess(String resourceType, String resourceId, String action, boolean success) {
        SecurityAuditLog.SecurityEventType eventType = success ? SecurityAuditLog.SecurityEventType.RESOURCE_ACCESSED
                : SecurityAuditLog.SecurityEventType.UNAUTHORIZED_ACCESS_ATTEMPT;

        SecurityAuditLog auditLog = createBaseAuditLog(
                eventType,
                SecurityAuditLog.EventCategory.ACCESS_CONTROL,
                String.format("Resource access: %s:%s (%s)", resourceType, action, success ? "success" : "denied"));

        auditLog.setResourceType(resourceType);
        auditLog.setResourceId(resourceId);
        auditLog.setAction(action);
        auditLog.setOutcome(success ? SecurityAuditLog.AuditOutcome.SUCCESS : SecurityAuditLog.AuditOutcome.FAILURE);
        auditLog.setRiskLevel(success ? SecurityAuditLog.RiskLevel.LOW : SecurityAuditLog.RiskLevel.MEDIUM);

        // Add access details
        Map<String, Object> details = new HashMap<>();
        details.put("accessType", action);
        details.put("accessResult", success ? "granted" : "denied");
        setAuditDetails(auditLog, details);

        saveAuditLog(auditLog);
        log.debug("Logged resource access: {}:{} - {}", resourceType, action, success ? "success" : "denied");
    }

    /**
     * Log administrative action.
     */
    @Async
    @Transactional
    public void logAdministrativeAction(String actionType, String description, Object beforeState, Object afterState) {
        SecurityAuditLog auditLog = createBaseAuditLog(
                SecurityAuditLog.SecurityEventType.CONFIGURATION_CHANGED,
                SecurityAuditLog.EventCategory.ADMINISTRATION,
                description);

        auditLog.setAction(actionType);
        auditLog.setOutcome(SecurityAuditLog.AuditOutcome.SUCCESS);
        auditLog.setRiskLevel(SecurityAuditLog.RiskLevel.MEDIUM);

        // Set before/after states
        try {
            if (beforeState != null) {
                auditLog.setBeforeState(objectMapper.writeValueAsString(beforeState));
            }
            if (afterState != null) {
                auditLog.setAfterState(objectMapper.writeValueAsString(afterState));
            }
        } catch (Exception e) {
            log.warn("Failed to serialize state for audit log", e);
        }

        // Add administrative details
        Map<String, Object> details = new HashMap<>();
        details.put("actionType", actionType);
        details.put("hasBeforeState", beforeState != null);
        details.put("hasAfterState", afterState != null);
        setAuditDetails(auditLog, details);

        saveAuditLog(auditLog);
        log.info("Logged administrative action: {} - {}", actionType, description);
    }

    /**
     * Log MFA event.
     */
    @Async
    @Transactional
    public void logMfaEvent(String username, boolean success, String mfaMethod) {
        SecurityAuditLog.SecurityEventType eventType = success ? SecurityAuditLog.SecurityEventType.MFA_SUCCESS
                : SecurityAuditLog.SecurityEventType.MFA_FAILURE;

        SecurityAuditLog auditLog = createBaseAuditLog(
                eventType,
                SecurityAuditLog.EventCategory.AUTHENTICATION,
                String.format("MFA %s using %s", success ? "success" : "failure", mfaMethod));

        auditLog.setUsername(username);
        auditLog.setOutcome(success ? SecurityAuditLog.AuditOutcome.SUCCESS : SecurityAuditLog.AuditOutcome.FAILURE);
        auditLog.setRiskLevel(success ? SecurityAuditLog.RiskLevel.LOW : SecurityAuditLog.RiskLevel.HIGH);

        // Add MFA details
        Map<String, Object> details = new HashMap<>();
        details.put("mfaMethod", mfaMethod);
        details.put("mfaResult", success ? "success" : "failure");
        setAuditDetails(auditLog, details);

        saveAuditLog(auditLog);
        log.info("Logged MFA event for user: {} - {} ({})", username, success ? "success" : "failure", mfaMethod);
    }

    /**
     * Create base audit log with common fields.
     */
    private SecurityAuditLog createBaseAuditLog(SecurityAuditLog.SecurityEventType eventType,
            SecurityAuditLog.EventCategory eventCategory,
            String description) {
        SecurityAuditLog auditLog = new SecurityAuditLog();
        auditLog.setEventType(eventType);
        auditLog.setEventCategory(eventCategory);
        auditLog.setEventDescription(description);
        auditLog.setTimestamp(LocalDateTime.now());
        auditLog.setServerTimestamp(LocalDateTime.now());

        // Set user context
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated()) {
            auditLog.setUsername(auth.getName());
            // Extract user ID if available
            UUID userId = extractUserId(auth);
            if (userId != null) {
                auditLog.setUserId(userId);
            }
        }

        // Set tenant context
        UUID organizationId = TenantSecurityContext.getCurrentTenant();
        if (organizationId != null) {
            auditLog.setOrganizationId(organizationId);
        }

        // Set request context
        setRequestContext(auditLog);

        return auditLog;
    }

    /**
     * Set request context information.
     */
    private void setRequestContext(SecurityAuditLog auditLog) {
        try {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder
                    .getRequestAttributes();

            if (attributes != null) {
                HttpServletRequest request = attributes.getRequest();

                auditLog.setIpAddress(getClientIpAddress(request));
                auditLog.setUserAgent(request.getHeader("User-Agent"));
                auditLog.setSessionId(request.getSession(false) != null ? request.getSession().getId() : null);

                // Set request ID if available
                String requestId = request.getHeader("X-Request-ID");
                if (requestId != null) {
                    auditLog.setRequestId(requestId);
                }

                // Set correlation ID if available
                String correlationId = request.getHeader("X-Correlation-ID");
                if (correlationId != null) {
                    auditLog.setCorrelationId(correlationId);
                }
            }
        } catch (Exception e) {
            log.debug("Could not set request context for audit log", e);
        }
    }

    /**
     * Get client IP address from request.
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String[] headerNames = {
                "X-Forwarded-For",
                "X-Real-IP",
                "Proxy-Client-IP",
                "WL-Proxy-Client-IP",
                "HTTP_X_FORWARDED_FOR",
                "HTTP_X_FORWARDED",
                "HTTP_X_CLUSTER_CLIENT_IP",
                "HTTP_CLIENT_IP",
                "HTTP_FORWARDED_FOR",
                "HTTP_FORWARDED",
                "HTTP_VIA",
                "REMOTE_ADDR"
        };

        for (String header : headerNames) {
            String ip = request.getHeader(header);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                // Handle comma-separated IPs
                if (ip.contains(",")) {
                    ip = ip.split(",")[0].trim();
                }
                return ip;
            }
        }

        return request.getRemoteAddr();
    }

    /**
     * Extract user ID from authentication.
     */
    private UUID extractUserId(Authentication auth) {
        try {
            if (auth.getDetails() instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> details = (Map<String, Object>) auth.getDetails();
                String userId = (String) details.get("userId");
                if (userId != null) {
                    return UUID.fromString(userId);
                }
            }

            // Try to parse principal name as UUID
            String principalName = auth.getName();
            if (principalName != null) {
                return UUID.fromString(principalName);
            }
        } catch (Exception e) {
            log.debug("Could not extract user ID from authentication", e);
        }

        return null;
    }

    /**
     * Set audit details as JSON.
     */
    private void setAuditDetails(SecurityAuditLog auditLog, Map<String, Object> details) {
        try {
            auditLog.setDetails(objectMapper.writeValueAsString(details));
        } catch (Exception e) {
            log.warn("Failed to serialize audit details", e);
        }
    }

    /**
     * Determine risk level based on anomaly score.
     */
    private SecurityAuditLog.RiskLevel determineRiskLevel(double anomalyScore) {
        if (anomalyScore >= 0.8) {
            return SecurityAuditLog.RiskLevel.CRITICAL;
        } else if (anomalyScore >= 0.6) {
            return SecurityAuditLog.RiskLevel.HIGH;
        } else if (anomalyScore >= 0.4) {
            return SecurityAuditLog.RiskLevel.MEDIUM;
        } else {
            return SecurityAuditLog.RiskLevel.LOW;
        }
    }

    /**
     * Save audit log with error handling.
     */
    private void saveAuditLog(SecurityAuditLog auditLog) {
        try {
            auditLogRepository.save(auditLog);
        } catch (Exception e) {
            log.error("Failed to save audit log: {}", e.getMessage(), e);
            // Could implement fallback logging mechanism here
        }
    }
    
    /**
     * Log OAuth2 client registration event.
     */
    @Async
    @Transactional
    public void logClientRegistration(String clientId, String registeredBy) {
        SecurityAuditLog auditLog = createBaseAuditLog(
                SecurityAuditLog.SecurityEventType.OAUTH2_CLIENT_REGISTERED,
                SecurityAuditLog.EventCategory.ADMINISTRATION,
                String.format("OAuth2 client registered: %s", clientId));
        
        auditLog.setResourceType("oauth2_client");
        auditLog.setResourceId(clientId);
        auditLog.setAction("register");
        auditLog.setOutcome(SecurityAuditLog.AuditOutcome.SUCCESS);
        auditLog.setRiskLevel(SecurityAuditLog.RiskLevel.LOW);
        
        Map<String, Object> details = new HashMap<>();
        details.put("clientId", clientId);
        details.put("registeredBy", registeredBy);
        setAuditDetails(auditLog, details);
        
        saveAuditLog(auditLog);
        log.info("Logged OAuth2 client registration: {}", clientId);
    }
    
    /**
     * Log OAuth2 client update event.
     */
    @Async
    @Transactional
    public void logClientUpdate(String clientId, String updatedBy) {
        SecurityAuditLog auditLog = createBaseAuditLog(
                SecurityAuditLog.SecurityEventType.OAUTH2_CLIENT_UPDATED,
                SecurityAuditLog.EventCategory.ADMINISTRATION,
                String.format("OAuth2 client updated: %s", clientId));
        
        auditLog.setResourceType("oauth2_client");
        auditLog.setResourceId(clientId);
        auditLog.setAction("update");
        auditLog.setOutcome(SecurityAuditLog.AuditOutcome.SUCCESS);
        auditLog.setRiskLevel(SecurityAuditLog.RiskLevel.LOW);
        
        Map<String, Object> details = new HashMap<>();
        details.put("clientId", clientId);
        details.put("updatedBy", updatedBy);
        setAuditDetails(auditLog, details);
        
        saveAuditLog(auditLog);
        log.info("Logged OAuth2 client update: {}", clientId);
    }
    
    /**
     * Log OAuth2 client secret regeneration event.
     */
    @Async
    @Transactional
    public void logClientSecretRegeneration(String clientId, String regeneratedBy) {
        SecurityAuditLog auditLog = createBaseAuditLog(
                SecurityAuditLog.SecurityEventType.OAUTH2_CLIENT_SECRET_REGENERATED,
                SecurityAuditLog.EventCategory.ADMINISTRATION,
                String.format("OAuth2 client secret regenerated: %s", clientId));
        
        auditLog.setResourceType("oauth2_client");
        auditLog.setResourceId(clientId);
        auditLog.setAction("regenerate_secret");
        auditLog.setOutcome(SecurityAuditLog.AuditOutcome.SUCCESS);
        auditLog.setRiskLevel(SecurityAuditLog.RiskLevel.MEDIUM);
        
        Map<String, Object> details = new HashMap<>();
        details.put("clientId", clientId);
        details.put("regeneratedBy", regeneratedBy);
        setAuditDetails(auditLog, details);
        
        saveAuditLog(auditLog);
        log.warn("Logged OAuth2 client secret regeneration: {}", clientId);
    }
    
    /**
     * Log OAuth2 client deactivation event.
     */
    @Async
    @Transactional
    public void logClientDeactivation(String clientId, String deactivatedBy) {
        SecurityAuditLog auditLog = createBaseAuditLog(
                SecurityAuditLog.SecurityEventType.OAUTH2_CLIENT_DEACTIVATED,
                SecurityAuditLog.EventCategory.ADMINISTRATION,
                String.format("OAuth2 client deactivated: %s", clientId));
        
        auditLog.setResourceType("oauth2_client");
        auditLog.setResourceId(clientId);
        auditLog.setAction("deactivate");
        auditLog.setOutcome(SecurityAuditLog.AuditOutcome.SUCCESS);
        auditLog.setRiskLevel(SecurityAuditLog.RiskLevel.MEDIUM);
        
        Map<String, Object> details = new HashMap<>();
        details.put("clientId", clientId);
        details.put("deactivatedBy", deactivatedBy);
        setAuditDetails(auditLog, details);
        
        saveAuditLog(auditLog);
        log.warn("Logged OAuth2 client deactivation: {}", clientId);
    }
    
    /**
     * Log OAuth2 client reactivation event.
     */
    @Async
    @Transactional
    public void logClientReactivation(String clientId, String reactivatedBy) {
        SecurityAuditLog auditLog = createBaseAuditLog(
                SecurityAuditLog.SecurityEventType.OAUTH2_CLIENT_REACTIVATED,
                SecurityAuditLog.EventCategory.ADMINISTRATION,
                String.format("OAuth2 client reactivated: %s", clientId));
        
        auditLog.setResourceType("oauth2_client");
        auditLog.setResourceId(clientId);
        auditLog.setAction("reactivate");
        auditLog.setOutcome(SecurityAuditLog.AuditOutcome.SUCCESS);
        auditLog.setRiskLevel(SecurityAuditLog.RiskLevel.LOW);
        
        Map<String, Object> details = new HashMap<>();
        details.put("clientId", clientId);
        details.put("reactivatedBy", reactivatedBy);
        setAuditDetails(auditLog, details);
        
        saveAuditLog(auditLog);
        log.info("Logged OAuth2 client reactivation: {}", clientId);
    }
}