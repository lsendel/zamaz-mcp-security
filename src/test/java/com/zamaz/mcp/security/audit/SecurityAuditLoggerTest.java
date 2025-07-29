package com.zamaz.mcp.security.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zamaz.mcp.security.model.McpUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityAuditLoggerTest {

    @Mock
    private Logger logger;

    @Mock
    private SecurityContext securityContext;

    @Captor
    private ArgumentCaptor<String> logCaptor;

    private SecurityAuditLogger auditLogger;
    private ObjectMapper objectMapper;
    private McpUser testUser;

    private static final String TEST_USER_ID = "user123";
    private static final String TEST_USERNAME = "testuser";
    private static final String TEST_ORG_ID = "org123";

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        auditLogger = new SecurityAuditLogger();
        
        // Use reflection to set the mocked logger
        try {
            java.lang.reflect.Field loggerField = SecurityAuditLogger.class.getDeclaredField("auditLog");
            loggerField.setAccessible(true);
            loggerField.set(auditLogger, logger);
        } catch (Exception e) {
            fail("Failed to inject mock logger: " + e.getMessage());
        }
        
        testUser = createTestUser();
        SecurityContextHolder.setContext(securityContext);
    }

    @Test
    void logSecurityEvent_WithAuthentication_ShouldIncludeUserDetails() {
        // Given
        authenticateUser();
        Map<String, Object> details = Map.of("action", "test_action", "resource", "test_resource");

        // When
        auditLogger.logSecurityEvent(
            SecurityAuditLogger.SecurityEventType.AUTHORIZATION_SUCCESS,
            SecurityAuditLogger.RiskLevel.LOW,
            "Test authorization success",
            details
        );

        // Then
        verify(logger).info(logCaptor.capture());
        String logMessage = logCaptor.getValue();
        
        assertTrue(logMessage.contains("\"eventType\":\"AUTHORIZATION_SUCCESS\""));
        assertTrue(logMessage.contains("\"riskLevel\":\"LOW\""));
        assertTrue(logMessage.contains("\"message\":\"Test authorization success\""));
        assertTrue(logMessage.contains("\"userId\":\"" + TEST_USER_ID + "\""));
        assertTrue(logMessage.contains("\"username\":\"" + TEST_USERNAME + "\""));
        assertTrue(logMessage.contains("\"organizationId\":\"" + TEST_ORG_ID + "\""));
        assertTrue(logMessage.contains("\"action\":\"test_action\""));
        assertTrue(logMessage.contains("\"resource\":\"test_resource\""));
    }

    @Test
    void logSecurityEvent_WithoutAuthentication_ShouldLogAnonymous() {
        // Given
        when(securityContext.getAuthentication()).thenReturn(null);
        
        // When
        auditLogger.logSecurityEvent(
            SecurityAuditLogger.SecurityEventType.AUTHENTICATION_FAILURE,
            SecurityAuditLogger.RiskLevel.MEDIUM,
            "Anonymous authentication failure",
            null
        );

        // Then
        verify(logger).warn(logCaptor.capture());
        String logMessage = logCaptor.getValue();
        
        assertTrue(logMessage.contains("\"eventType\":\"AUTHENTICATION_FAILURE\""));
        assertTrue(logMessage.contains("\"userId\":\"anonymous\""));
        assertTrue(logMessage.contains("\"username\":\"anonymous\""));
    }

    @Test
    void logAuthenticationSuccess_ShouldLogCorrectly() {
        // Given
        authenticateUser();
        String ipAddress = "192.168.1.100";
        String userAgent = "Mozilla/5.0";

        // When
        auditLogger.logAuthenticationSuccess(ipAddress, userAgent);

        // Then
        verify(logger).info(logCaptor.capture());
        String logMessage = logCaptor.getValue();
        
        assertTrue(logMessage.contains("\"eventType\":\"AUTHENTICATION_SUCCESS\""));
        assertTrue(logMessage.contains("\"riskLevel\":\"LOW\""));
        assertTrue(logMessage.contains("\"clientIp\":\"" + ipAddress + "\""));
        assertTrue(logMessage.contains("\"userAgent\":\"" + userAgent + "\""));
    }

    @Test
    void logAuthenticationFailure_ShouldLogAsWarning() {
        // Given
        String username = "faileduser";
        String ipAddress = "192.168.1.100";
        String reason = "Invalid credentials";

        // When
        auditLogger.logAuthenticationFailure(username, ipAddress, reason);

        // Then
        verify(logger).warn(logCaptor.capture());
        String logMessage = logCaptor.getValue();
        
        assertTrue(logMessage.contains("\"eventType\":\"AUTHENTICATION_FAILURE\""));
        assertTrue(logMessage.contains("\"riskLevel\":\"MEDIUM\""));
        assertTrue(logMessage.contains("\"attemptedUsername\":\"" + username + "\""));
        assertTrue(logMessage.contains("\"clientIp\":\"" + ipAddress + "\""));
        assertTrue(logMessage.contains("\"reason\":\"" + reason + "\""));
    }

    @Test
    void logAuthorizationFailure_ShouldLogAsWarning() {
        // Given
        authenticateUser();
        String resource = "/api/admin/users";
        String requiredPermission = "ADMIN_ACCESS";

        // When
        auditLogger.logAuthorizationFailure(resource, requiredPermission);

        // Then
        verify(logger).warn(logCaptor.capture());
        String logMessage = logCaptor.getValue();
        
        assertTrue(logMessage.contains("\"eventType\":\"AUTHORIZATION_FAILURE\""));
        assertTrue(logMessage.contains("\"riskLevel\":\"MEDIUM\""));
        assertTrue(logMessage.contains("\"resource\":\"" + resource + "\""));
        assertTrue(logMessage.contains("\"requiredPermission\":\"" + requiredPermission + "\""));
    }

    @Test
    void logPermissionDenied_ShouldLogCorrectly() {
        // Given
        authenticateUser();
        String permission = "DELETE_USER";
        String method = "deleteUser";

        // When
        auditLogger.logPermissionDenied(permission, method);

        // Then
        verify(logger).warn(logCaptor.capture());
        String logMessage = logCaptor.getValue();
        
        assertTrue(logMessage.contains("\"eventType\":\"PERMISSION_DENIED\""));
        assertTrue(logMessage.contains("\"permission\":\"" + permission + "\""));
        assertTrue(logMessage.contains("\"method\":\"" + method + "\""));
    }

    @Test
    void logRoleDenied_ShouldLogCorrectly() {
        // Given
        authenticateUser();
        String role = "ADMIN";
        String method = "adminOperation";

        // When
        auditLogger.logRoleDenied(role, method);

        // Then
        verify(logger).warn(logCaptor.capture());
        String logMessage = logCaptor.getValue();
        
        assertTrue(logMessage.contains("\"eventType\":\"ROLE_DENIED\""));
        assertTrue(logMessage.contains("\"role\":\"" + role + "\""));
        assertTrue(logMessage.contains("\"method\":\"" + method + "\""));
    }

    @Test
    void logSuspiciousActivity_ShouldLogAsError() {
        // Given
        authenticateUser();
        String activityType = "SQL_INJECTION_ATTEMPT";
        Map<String, Object> details = Map.of(
            "query", "'; DROP TABLE users; --",
            "endpoint", "/api/search"
        );

        // When
        auditLogger.logSuspiciousActivity(activityType, details);

        // Then
        verify(logger).error(logCaptor.capture());
        String logMessage = logCaptor.getValue();
        
        assertTrue(logMessage.contains("\"eventType\":\"SUSPICIOUS_ACTIVITY\""));
        assertTrue(logMessage.contains("\"riskLevel\":\"HIGH\""));
        assertTrue(logMessage.contains("\"activityType\":\"" + activityType + "\""));
        assertTrue(logMessage.contains("\"query\":\"'; DROP TABLE users; --\""));
    }

    @Test
    void logSecurityViolation_ShouldLogAsCritical() {
        // Given
        String violationType = "UNAUTHORIZED_DATA_ACCESS";
        Map<String, Object> details = Map.of(
            "dataType", "SENSITIVE_PII",
            "recordCount", 1000
        );

        // When
        auditLogger.logSecurityViolation(violationType, details);

        // Then
        verify(logger).error(logCaptor.capture());
        String logMessage = logCaptor.getValue();
        
        assertTrue(logMessage.contains("\"eventType\":\"SECURITY_VIOLATION\""));
        assertTrue(logMessage.contains("\"riskLevel\":\"CRITICAL\""));
        assertTrue(logMessage.contains("\"violationType\":\"" + violationType + "\""));
        assertTrue(logMessage.contains("\"recordCount\":1000"));
    }

    @Test
    void logPrivilegeEscalationAttempt_ShouldLogAsCritical() {
        // Given
        authenticateUser();
        String attemptedRole = "SUPER_ADMIN";
        String currentRole = "USER";

        // When
        auditLogger.logPrivilegeEscalationAttempt(attemptedRole, currentRole);

        // Then
        verify(logger).error(logCaptor.capture());
        String logMessage = logCaptor.getValue();
        
        assertTrue(logMessage.contains("\"eventType\":\"PRIVILEGE_ESCALATION_ATTEMPT\""));
        assertTrue(logMessage.contains("\"riskLevel\":\"CRITICAL\""));
        assertTrue(logMessage.contains("\"attemptedRole\":\"" + attemptedRole + "\""));
        assertTrue(logMessage.contains("\"currentRole\":\"" + currentRole + "\""));
    }

    @Test
    void logSessionCreated_ShouldLogSessionInfo() {
        // Given
        authenticateUser();
        String sessionId = "session123";
        String ipAddress = "192.168.1.100";

        // When
        auditLogger.logSessionCreated(sessionId, ipAddress);

        // Then
        verify(logger).info(logCaptor.capture());
        String logMessage = logCaptor.getValue();
        
        assertTrue(logMessage.contains("\"eventType\":\"SESSION_CREATED\""));
        assertTrue(logMessage.contains("\"sessionId\":\"" + sessionId + "\""));
        assertTrue(logMessage.contains("\"clientIp\":\"" + ipAddress + "\""));
    }

    @Test
    void logSessionExpired_ShouldLogSessionInfo() {
        // Given
        String sessionId = "session123";
        String reason = "TIMEOUT";

        // When
        auditLogger.logSessionExpired(sessionId, reason);

        // Then
        verify(logger).info(logCaptor.capture());
        String logMessage = logCaptor.getValue();
        
        assertTrue(logMessage.contains("\"eventType\":\"SESSION_EXPIRED\""));
        assertTrue(logMessage.contains("\"sessionId\":\"" + sessionId + "\""));
        assertTrue(logMessage.contains("\"reason\":\"" + reason + "\""));
    }

    @Test
    void logPasswordChanged_ShouldNotLogPassword() {
        // Given
        authenticateUser();

        // When
        auditLogger.logPasswordChanged();

        // Then
        verify(logger).info(logCaptor.capture());
        String logMessage = logCaptor.getValue();
        
        assertTrue(logMessage.contains("\"eventType\":\"PASSWORD_CHANGED\""));
        assertTrue(logMessage.contains("Password changed for user"));
        // Ensure no password is logged
        assertFalse(logMessage.toLowerCase().contains("password"));
    }

    @Test
    void logApiRateLimitExceeded_ShouldLogDetails() {
        // Given
        authenticateUser();
        String endpoint = "/api/data";
        int limit = 100;
        int attempts = 150;

        // When
        auditLogger.logApiRateLimitExceeded(endpoint, limit, attempts);

        // Then
        verify(logger).warn(logCaptor.capture());
        String logMessage = logCaptor.getValue();
        
        assertTrue(logMessage.contains("\"eventType\":\"API_RATE_LIMIT_EXCEEDED\""));
        assertTrue(logMessage.contains("\"endpoint\":\"" + endpoint + "\""));
        assertTrue(logMessage.contains("\"limit\":" + limit));
        assertTrue(logMessage.contains("\"attempts\":" + attempts));
    }

    @Test
    void logDataAccess_ShouldLogDataDetails() {
        // Given
        authenticateUser();
        String dataType = "USER_PROFILE";
        String operation = "READ";
        int recordCount = 50;

        // When
        auditLogger.logDataAccess(dataType, operation, recordCount);

        // Then
        verify(logger).info(logCaptor.capture());
        String logMessage = logCaptor.getValue();
        
        assertTrue(logMessage.contains("\"eventType\":\"DATA_ACCESS\""));
        assertTrue(logMessage.contains("\"dataType\":\"" + dataType + "\""));
        assertTrue(logMessage.contains("\"operation\":\"" + operation + "\""));
        assertTrue(logMessage.contains("\"recordCount\":" + recordCount));
    }

    @Test
    void logConfigurationChanged_ShouldLogChanges() {
        // Given
        authenticateUser();
        String setting = "MAX_LOGIN_ATTEMPTS";
        String oldValue = "3";
        String newValue = "5";

        // When
        auditLogger.logConfigurationChanged(setting, oldValue, newValue);

        // Then
        verify(logger).warn(logCaptor.capture());
        String logMessage = logCaptor.getValue();
        
        assertTrue(logMessage.contains("\"eventType\":\"CONFIGURATION_CHANGED\""));
        assertTrue(logMessage.contains("\"setting\":\"" + setting + "\""));
        assertTrue(logMessage.contains("\"oldValue\":\"" + oldValue + "\""));
        assertTrue(logMessage.contains("\"newValue\":\"" + newValue + "\""));
    }

    @Test
    void logServiceStarted_ShouldLogServiceInfo() {
        // Given
        String serviceName = "AuthenticationService";
        String version = "1.0.0";

        // When
        auditLogger.logServiceStarted(serviceName, version);

        // Then
        verify(logger).info(logCaptor.capture());
        String logMessage = logCaptor.getValue();
        
        assertTrue(logMessage.contains("\"eventType\":\"SERVICE_STARTED\""));
        assertTrue(logMessage.contains("\"serviceName\":\"" + serviceName + "\""));
        assertTrue(logMessage.contains("\"version\":\"" + version + "\""));
    }

    @Test
    void logServiceStopped_ShouldLogServiceInfo() {
        // Given
        String serviceName = "AuthenticationService";
        String reason = "SHUTDOWN";

        // When
        auditLogger.logServiceStopped(serviceName, reason);

        // Then
        verify(logger).info(logCaptor.capture());
        String logMessage = logCaptor.getValue();
        
        assertTrue(logMessage.contains("\"eventType\":\"SERVICE_STOPPED\""));
        assertTrue(logMessage.contains("\"serviceName\":\"" + serviceName + "\""));
        assertTrue(logMessage.contains("\"reason\":\"" + reason + "\""));
    }

    private McpUser createTestUser() {
        McpUser user = new McpUser();
        user.setId(TEST_USER_ID);
        user.setUsername(TEST_USERNAME);
        user.setEmail("test@example.com");
        user.setCurrentOrganizationId(TEST_ORG_ID);
        user.setOrganizationIds(Collections.singletonList(TEST_ORG_ID));
        return user;
    }

    private void authenticateUser() {
        Authentication authentication = new UsernamePasswordAuthenticationToken(testUser, null);
        when(securityContext.getAuthentication()).thenReturn(authentication);
    }
}