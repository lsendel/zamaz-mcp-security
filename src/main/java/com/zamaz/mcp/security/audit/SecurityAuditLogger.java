package com.zamaz.mcp.security.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zamaz.mcp.common.logging.LogContext;
import com.zamaz.mcp.common.logging.StructuredLogger;
import com.zamaz.mcp.security.model.McpUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Security Audit Logger
 * Provides comprehensive security event logging with structured format
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class SecurityAuditLogger {

    private final ObjectMapper objectMapper;
    private final StructuredLogger structuredLogger;
    
    @Value("${spring.application.name:mcp-service}")
    private String applicationName;
    
    @Value("${spring.profiles.active:development}")
    private String environment;
    
    // Security event types
    public enum SecurityEventType {
        AUTHENTICATION_SUCCESS,
        AUTHENTICATION_FAILURE,
        AUTHORIZATION_SUCCESS,
        AUTHORIZATION_FAILURE,
        PERMISSION_DENIED,
        ROLE_DENIED,
        SUSPICIOUS_ACTIVITY,
        SECURITY_VIOLATION,
        SESSION_CREATED,
        SESSION_EXPIRED,
        PASSWORD_CHANGED,
        ACCOUNT_LOCKED,
        ACCOUNT_UNLOCKED,
        PRIVILEGE_ESCALATION_ATTEMPT,
        DATA_ACCESS,
        SENSITIVE_OPERATION,
        SECURITY_CONFIGURATION_CHANGED,
        
        // User Management Events
        USER_REGISTERED,
        USER_REGISTRATION_FAILED,
        USER_OPERATION_FAILED,
        ACCOUNT_DEACTIVATED,
        
        // OAuth2 Events
        OAUTH2_LOGIN_SUCCESS,
        OAUTH2_LOGIN_FAILED,
        OAUTH2_ACCOUNT_LINKED,
        OAUTH2_ACCOUNT_UNLINKED,
        OAUTH2_PROVIDER_ERROR,
        OAUTH2_TOKEN_REFRESH,
        OAUTH2_AUTHORIZATION_CODE_RECEIVED,
        OAUTH2_USER_INFO_RETRIEVED
    }
    
    // Risk levels
    public enum RiskLevel {
        LOW, MEDIUM, HIGH, CRITICAL
    }
    
    /**
     * Log a comprehensive audit event (NEW METHOD)
     */
    public CompletableFuture<Void> logAuditEvent(AuditEvent auditEvent) {
        return CompletableFuture.runAsync(() -> {
            try {
                // Enrich with current context
                enrichAuditEvent(auditEvent);
                
                // Calculate risk score
                auditEvent.calculateRiskScore();
                
                // Set event category
                auditEvent.withEventCategory();
                
                // Convert to log context
                LogContext logContext = convertToLogContext(auditEvent);
                
                // Log based on severity
                String message = auditEvent.getDescription() != null ? 
                    auditEvent.getDescription() : 
                    auditEvent.getEventType().getDescription();
                
                switch (auditEvent.getSeverity()) {
                    case CRITICAL:
                        structuredLogger.error(SecurityAuditLogger.class.getName(), message, logContext);
                        break;
                    case HIGH:
                        structuredLogger.warn(SecurityAuditLogger.class.getName(), message, logContext);
                        break;
                    case MEDIUM:
                        structuredLogger.info(SecurityAuditLogger.class.getName(), message, logContext);
                        break;
                    case LOW:
                        structuredLogger.debug(SecurityAuditLogger.class.getName(), message, logContext);
                        break;
                }
                
                // Log raw JSON for external systems
                log.info("AUDIT_EVENT: {}", auditEvent.toJson());
                
            } catch (Exception e) {
                log.error("Failed to log audit event", e);
            }
        });
    }
    
    /**
     * Log a security event with full context (LEGACY METHOD - MAINTAINED FOR COMPATIBILITY)
     */
    public void logSecurityEvent(SecurityEventType eventType, RiskLevel riskLevel, 
                                String description, Map<String, Object> additionalData) {
        try {
            SecurityAuditEvent event = SecurityAuditEvent.builder()
                .timestamp(Instant.now())
                .eventType(eventType)
                .riskLevel(riskLevel)
                .description(description)
                .userId(getCurrentUserId())
                .organizationId(getCurrentOrganizationId())
                .sessionId(getCurrentSessionId())
                .userAgent(getCurrentUserAgent())
                .clientIp(getCurrentClientIp())
                .additionalData(additionalData != null ? additionalData : new HashMap<>())
                .build();
            
            String jsonEvent = objectMapper.writeValueAsString(event);
            
            // Log based on risk level
            switch (riskLevel) {
                case CRITICAL:
                    log.error("[SECURITY-CRITICAL] {}", jsonEvent);
                    break;
                case HIGH:
                    log.warn("[SECURITY-HIGH] {}", jsonEvent);
                    break;
                case MEDIUM:
                    log.warn("[SECURITY-MEDIUM] {}", jsonEvent);
                    break;
                case LOW:
                    log.info("[SECURITY-LOW] {}", jsonEvent);
                    break;
            }
            
        } catch (Exception e) {
            log.error("Failed to log security event: {}", e.getMessage(), e);
        }
    }
    
    /**
     * Log authentication success
     */
    public void logAuthenticationSuccess(String userId, String method) {
        Map<String, Object> data = Map.of(
            "authMethod", method,
            "success", true
        );
        logSecurityEvent(SecurityEventType.AUTHENTICATION_SUCCESS, RiskLevel.LOW,
            "User authenticated successfully", data);
    }
    
    /**
     * Log authentication failure
     */
    public void logAuthenticationFailure(String userId, String method, String reason) {
        Map<String, Object> data = Map.of(
            "authMethod", method,
            "reason", reason,
            "success", false
        );
        logSecurityEvent(SecurityEventType.AUTHENTICATION_FAILURE, RiskLevel.MEDIUM,
            "Authentication failed: " + reason, data);
    }
    
    /**
     * Log authorization failure
     */
    public void logAuthorizationFailure(String resource, String permission, String reason) {
        Map<String, Object> data = Map.of(
            "resource", resource,
            "permission", permission,
            "reason", reason
        );
        logSecurityEvent(SecurityEventType.AUTHORIZATION_FAILURE, RiskLevel.MEDIUM,
            "Authorization failed for resource: " + resource, data);
    }
    
    /**
     * Log permission denied
     */
    public void logPermissionDenied(String permission, String resource) {
        Map<String, Object> data = Map.of(
            "permission", permission,
            "resource", resource
        );
        logSecurityEvent(SecurityEventType.PERMISSION_DENIED, RiskLevel.MEDIUM,
            "Permission denied: " + permission, data);
    }
    
    /**
     * Log suspicious activity
     */
    public void logSuspiciousActivity(String activity, String details) {
        Map<String, Object> data = Map.of(
            "activity", activity,
            "details", details
        );
        logSecurityEvent(SecurityEventType.SUSPICIOUS_ACTIVITY, RiskLevel.HIGH,
            "Suspicious activity detected: " + activity, data);
    }
    
    /**
     * Log security violation
     */
    public void logSecurityViolation(String violation, String source) {
        Map<String, Object> data = Map.of(
            "violation", violation,
            "source", source
        );
        logSecurityEvent(SecurityEventType.SECURITY_VIOLATION, RiskLevel.HIGH,
            "Security violation: " + violation, data);
    }
    
    /**
     * Log privilege escalation attempt
     */
    public void logPrivilegeEscalationAttempt(String attemptedAction, String currentRole) {
        Map<String, Object> data = Map.of(
            "attemptedAction", attemptedAction,
            "currentRole", currentRole
        );
        logSecurityEvent(SecurityEventType.PRIVILEGE_ESCALATION_ATTEMPT, RiskLevel.CRITICAL,
            "Privilege escalation attempt detected", data);
    }
    
    /**
     * Log sensitive operation
     */
    public void logSensitiveOperation(String operation, String resource) {
        Map<String, Object> data = Map.of(
            "operation", operation,
            "resource", resource
        );
        logSecurityEvent(SecurityEventType.SENSITIVE_OPERATION, RiskLevel.MEDIUM,
            "Sensitive operation performed: " + operation, data);
    }
    
    /**
     * Log data access
     */
    public void logDataAccess(String dataType, String operation, String resourceId) {
        Map<String, Object> data = Map.of(
            "dataType", dataType,
            "operation", operation,
            "resourceId", resourceId
        );
        logSecurityEvent(SecurityEventType.DATA_ACCESS, RiskLevel.LOW,
            "Data access: " + operation + " on " + dataType, data);
    }
    
    /**
     * Log security configuration change
     */
    public void logSecurityConfigurationChange(String configType, String change) {
        Map<String, Object> data = Map.of(
            "configType", configType,
            "change", change
        );
        logSecurityEvent(SecurityEventType.SECURITY_CONFIGURATION_CHANGED, RiskLevel.HIGH,
            "Security configuration changed: " + configType, data);
    }
    
    // Helper methods to extract context
    private String getCurrentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof McpUser) {
            return ((McpUser) auth.getPrincipal()).getId();
        }
        return "anonymous";
    }
    
    private String getCurrentOrganizationId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof McpUser) {
            return ((McpUser) auth.getPrincipal()).getCurrentOrganizationId();
        }
        return null;
    }
    
    private String getCurrentSessionId() {
        // This would be extracted from the security context or request
        // Implementation depends on session management strategy
        return "session-" + System.currentTimeMillis();
    }
    
    private String getCurrentUserAgent() {
        // This would be extracted from the current HTTP request
        // Implementation depends on web context availability
        return "unknown";
    }
    
    private String getCurrentClientIp() {
        ServletRequestAttributes attributes = 
            (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes != null) {
            return getClientIpAddress(attributes.getRequest());
        }
        return "unknown";
    }
    
    /**
     * Enhanced methods for comprehensive audit events
     */
    
    /**
     * Enrich audit event with current context
     */
    private void enrichAuditEvent(AuditEvent auditEvent) {
        // Add current authentication context
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && auditEvent.getActor() != null) {
            auditEvent.getActor().setUsername(auth.getName());
            if (auth.getAuthorities() != null) {
                auditEvent.getActor().setRoles(auth.getAuthorities().stream()
                    .map(a -> a.getAuthority())
                    .toArray(String[]::new));
            }
        }
        
        // Add current request context
        ServletRequestAttributes attributes = 
            (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes != null && auditEvent.getContext() != null) {
            HttpServletRequest request = attributes.getRequest();
            auditEvent.getContext().setHttpMethod(request.getMethod());
            auditEvent.getContext().setHttpPath(request.getRequestURI());
            auditEvent.getContext().setRequestId(request.getHeader("X-Request-ID"));
            
            // Add IP address to actor
            if (auditEvent.getActor() != null) {
                auditEvent.getActor().setIpAddress(getClientIpAddress(request));
                auditEvent.getActor().setUserAgent(request.getHeader("User-Agent"));
            }
        }
        
        // Add correlation IDs
        if (auditEvent.getCorrelationId() == null) {
            auditEvent.setCorrelationId(java.util.UUID.randomUUID().toString());
        }
        
        // Set source system info
        auditEvent.setSourceSystem(applicationName);
        auditEvent.setSourceComponent("security-audit");
    }
    
    /**
     * Convert audit event to log context
     */
    private LogContext convertToLogContext(AuditEvent auditEvent) {
        LogContext.LogContextBuilder builder = LogContext.builder()
            .operation(auditEvent.getEventType().name())
            .component("audit")
            .correlationId(auditEvent.getCorrelationId())
            .traceId(auditEvent.getTraceId())
            .spanId(auditEvent.getSpanId())
            .duration(auditEvent.getDuration());
        
        if (auditEvent.getActor() != null) {
            builder.userId(auditEvent.getActor().getUserId())
                .organizationId(auditEvent.getActor().getOrganizationId())
                .sessionId(auditEvent.getActor().getSessionId());
        }
        
        if (auditEvent.getTarget() != null) {
            builder.resourceType(auditEvent.getTarget().getResourceType())
                .resourceId(auditEvent.getTarget().getResourceId());
        }
        
        if (auditEvent.getContext() != null) {
            builder.statusCode(auditEvent.getContext().getHttpStatusCode());
        }
        
        LogContext context = builder.build();
        
        // Add all details as metadata
        if (auditEvent.getDetails() != null) {
            auditEvent.getDetails().forEach(context::addMetadata);
        }
        
        // Add audit-specific metadata
        context.addMetadata("eventType", auditEvent.getEventType().name());
        context.addMetadata("eventCategory", auditEvent.getEventCategory());
        context.addMetadata("outcome", auditEvent.getOutcome().name());
        context.addMetadata("severity", auditEvent.getSeverity().name());
        context.addMetadata("riskScore", auditEvent.getRiskScore());
        
        if (auditEvent.getTags() != null) {
            context.addMetadata("tags", String.join(",", auditEvent.getTags()));
        }
        
        return context;
    }
    
    /**
     * Get client IP address from request
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String[] headers = {
            "X-Forwarded-For",
            "X-Real-IP",
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP"
        };
        
        for (String header : headers) {
            String ip = request.getHeader(header);
            if (ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip)) {
                return ip.split(",")[0].trim();
            }
        }
        
        return request.getRemoteAddr();
    }
}
