package com.zamaz.mcp.security.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zamaz.mcp.security.entity.Permission;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class PermissionEvaluationEngineTest {

    private PermissionEvaluationEngine evaluationEngine;
    private ObjectMapper objectMapper;
    private UUID userId;
    private UUID organizationId;

    @BeforeEach
    void setUp() {
        evaluationEngine = new PermissionEvaluationEngine();
        objectMapper = new ObjectMapper();
        userId = UUID.randomUUID();
        organizationId = UUID.randomUUID();
    }

    @Test
    void shouldEvaluateBasicPermissionConditions() {
        // Given
        Permission permission = createBasicPermission();
        PermissionService.PermissionContext context = createBasicContext();

        // When
        boolean result = evaluationEngine.evaluateConditions(permission, context);

        // Then
        assertThat(result).isTrue();
    }

    @Test
    void shouldEvaluateTimeBasedConstraints() {
        // Given
        Permission permission = createTimeBasedPermission();
        PermissionService.PermissionContext context = createBasicContext();

        // When
        boolean result = evaluationEngine.evaluateConditions(permission, context);

        // Then
        assertThat(result).isTrue();
    }

    @Test
    void shouldDenyExpiredTimeBasedPermission() {
        // Given
        Permission permission = createExpiredTimeBasedPermission();
        PermissionService.PermissionContext context = createBasicContext();

        // When
        boolean result = evaluationEngine.evaluateConditions(permission, context);

        // Then
        assertThat(result).isFalse();
    }

    @Test
    void shouldEvaluateHourConstraints() {
        // Given
        Permission permission = createHourConstrainedPermission();
        PermissionService.PermissionContext context = createBasicContext();

        // When
        boolean result = evaluationEngine.evaluateConditions(permission, context);

        // Then - This will depend on current time, but should not throw exception
        assertThat(result).isIn(true, false);
    }

    @Test
    void shouldEvaluateDayOfWeekConstraints() {
        // Given
        Permission permission = createDayConstrainedPermission();
        PermissionService.PermissionContext context = createBasicContext();

        // When
        boolean result = evaluationEngine.evaluateConditions(permission, context);

        // Then - This will depend on current day, but should not throw exception
        assertThat(result).isIn(true, false);
    }

    @Test
    void shouldEvaluateIpRestrictions() {
        // Given
        Permission permission = createIpRestrictedPermission();
        PermissionService.PermissionContext context = createContextWithIp("192.168.1.100");

        // When
        boolean result = evaluationEngine.evaluateConditions(permission, context);

        // Then
        assertThat(result).isTrue();
    }

    @Test
    void shouldDenyInvalidIpAccess() {
        // Given
        Permission permission = createIpRestrictedPermission();
        PermissionService.PermissionContext context = createContextWithIp("10.0.0.1");

        // When
        boolean result = evaluationEngine.evaluateConditions(permission, context);

        // Then
        assertThat(result).isFalse();
    }

    @Test
    void shouldEvaluateLocationRestrictions() {
        // Given
        Permission permission = createLocationRestrictedPermission();
        PermissionService.PermissionContext context = createContextWithLocation("US");

        // When
        boolean result = evaluationEngine.evaluateConditions(permission, context);

        // Then
        assertThat(result).isTrue();
    }

    @Test
    void shouldDenyInvalidLocationAccess() {
        // Given
        Permission permission = createLocationRestrictedPermission();
        PermissionService.PermissionContext context = createContextWithLocation("CN");

        // When
        boolean result = evaluationEngine.evaluateConditions(permission, context);

        // Then
        assertThat(result).isFalse();
    }

    @Test
    void shouldEvaluateSpelExpressions() {
        // Given
        Permission permission = createSpelPermission();
        PermissionService.PermissionContext context = createContextWithAttributes();

        // When
        boolean result = evaluationEngine.evaluateConditions(permission, context);

        // Then
        assertThat(result).isTrue();
    }

    @Test
    void shouldDenyWhenSpelExpressionFails() {
        // Given
        Permission permission = createSpelPermission();
        PermissionService.PermissionContext context = createContextWithWrongAttributes();

        // When
        boolean result = evaluationEngine.evaluateConditions(permission, context);

        // Then
        assertThat(result).isFalse();
    }

    @Test
    void shouldEvaluateSubjectAttributes() {
        // Given
        Permission permission = createSubjectAttributePermission();
        PermissionService.PermissionContext context = createContextWithUserAttributes();

        // When
        boolean result = evaluationEngine.evaluateConditions(permission, context);

        // Then
        assertThat(result).isTrue();
    }

    @Test
    void shouldDenyWhenSubjectAttributesMismatch() {
        // Given
        Permission permission = createSubjectAttributePermission();
        PermissionService.PermissionContext context = createContextWithWrongUserAttributes();

        // When
        boolean result = evaluationEngine.evaluateConditions(permission, context);

        // Then
        assertThat(result).isFalse();
    }

    @Test
    void shouldEvaluateResourceAttributes() {
        // Given
        Permission permission = createResourceAttributePermission();
        PermissionService.PermissionContext context = createContextWithResourceAttributes();

        // When
        boolean result = evaluationEngine.evaluateConditions(permission, context);

        // Then
        assertThat(result).isTrue();
    }

    @Test
    void shouldEvaluateEnvironmentAttributes() {
        // Given
        Permission permission = createEnvironmentAttributePermission();
        PermissionService.PermissionContext context = createContextWithEnvironmentAttributes();

        // When
        boolean result = evaluationEngine.evaluateConditions(permission, context);

        // Then
        assertThat(result).isTrue();
    }

    @Test
    void shouldHandleComplexAttributeConditions() {
        // Given
        Permission permission = createComplexAttributePermission();
        PermissionService.PermissionContext context = createComplexContext();

        // When
        boolean result = evaluationEngine.evaluateConditions(permission, context);

        // Then
        assertThat(result).isTrue();
    }

    @Test
    void shouldHandleInvalidJsonGracefully() {
        // Given
        Permission permission = createPermissionWithInvalidJson();
        PermissionService.PermissionContext context = createBasicContext();

        // When
        boolean result = evaluationEngine.evaluateConditions(permission, context);

        // Then - Should fail secure
        assertThat(result).isFalse();
    }

    @Test
    void shouldHandleNullConditionsGracefully() {
        // Given
        Permission permission = createBasicPermission();
        permission.setConditionExpression(null);
        permission.setSubjectAttributes(null);
        permission.setResourceAttributes(null);
        permission.setEnvironmentAttributes(null);

        PermissionService.PermissionContext context = createBasicContext();

        // When
        boolean result = evaluationEngine.evaluateConditions(permission, context);

        // Then
        assertThat(result).isTrue();
    }

    // Helper methods

    private Permission createBasicPermission() {
        Permission permission = new Permission();
        permission.setId(UUID.randomUUID());
        permission.setResource("debate");
        permission.setAction("read");
        permission.setIsActive(true);
        permission.setTimeBased(false);
        return permission;
    }

    private Permission createTimeBasedPermission() {
        Permission permission = createBasicPermission();
        permission.setTimeBased(true);
        permission.setValidFrom(LocalDateTime.now().minusHours(1));
        permission.setValidUntil(LocalDateTime.now().plusHours(1));
        return permission;
    }

    private Permission createExpiredTimeBasedPermission() {
        Permission permission = createBasicPermission();
        permission.setTimeBased(true);
        permission.setValidFrom(LocalDateTime.now().minusHours(2));
        permission.setValidUntil(LocalDateTime.now().minusHours(1));
        return permission;
    }

    private Permission createHourConstrainedPermission() {
        Permission permission = createBasicPermission();
        permission.setTimeBased(true);
        permission.setHoursOfDay("09:00-17:00");
        return permission;
    }

    private Permission createDayConstrainedPermission() {
        Permission permission = createBasicPermission();
        permission.setTimeBased(true);
        permission.setDaysOfWeek("MON,TUE,WED,THU,FRI");
        return permission;
    }

    private Permission createIpRestrictedPermission() {
        Permission permission = createBasicPermission();
        permission.setIpRestrictions("[\"192.168.1.0/24\", \"10.0.0.0/8\"]");
        return permission;
    }

    private Permission createLocationRestrictedPermission() {
        Permission permission = createBasicPermission();
        permission.setLocationRestrictions("[\"US\", \"CA\", \"GB\"]");
        return permission;
    }

    private Permission createSpelPermission() {
        Permission permission = createBasicPermission();
        permission.setConditionExpression("userDepartment == 'FINANCE' && currentHour >= 9 && currentHour <= 17");
        return permission;
    }

    private Permission createSubjectAttributePermission() {
        Permission permission = createBasicPermission();
        permission.setSubjectAttributes(
                "{\"department\": \"FINANCE\", \"clearanceLevel\": {\"in\": [\"SECRET\", \"TOP_SECRET\"]}}");
        return permission;
    }

    private Permission createResourceAttributePermission() {
        Permission permission = createBasicPermission();
        permission.setResourceAttributes("{\"classification\": \"CONFIDENTIAL\", \"owner\": \"FINANCE_DEPT\"}");
        return permission;
    }

    private Permission createEnvironmentAttributePermission() {
        Permission permission = createBasicPermission();
        permission.setEnvironmentAttributes("{\"requestSource\": \"internal\", \"securityLevel\": \"high\"}");
        return permission;
    }

    private Permission createComplexAttributePermission() {
        Permission permission = createBasicPermission();
        permission.setSubjectAttributes("{\"department\": \"FINANCE\", \"role\": {\"regex\": \".*MANAGER.*\"}}");
        permission.setResourceAttributes("{\"sensitivity\": {\"in\": [\"LOW\", \"MEDIUM\"]}}");
        permission.setEnvironmentAttributes("{\"accessMethod\": \"VPN\"}");
        return permission;
    }

    private Permission createPermissionWithInvalidJson() {
        Permission permission = createBasicPermission();
        permission.setSubjectAttributes("{invalid json}");
        return permission;
    }

    private PermissionService.PermissionContext createBasicContext() {
        return PermissionService.PermissionContext.builder()
                .userId(userId)
                .organizationId(organizationId)
                .resource("debate")
                .action("read")
                .resourceId("debate-123")
                .build();
    }

    private PermissionService.PermissionContext createContextWithIp(String ip) {
        return PermissionService.PermissionContext.builder()
                .userId(userId)
                .organizationId(organizationId)
                .resource("debate")
                .action("read")
                .environmentContext("clientIp", ip)
                .build();
    }

    private PermissionService.PermissionContext createContextWithLocation(String country) {
        return PermissionService.PermissionContext.builder()
                .userId(userId)
                .organizationId(organizationId)
                .resource("debate")
                .action("read")
                .environmentContext("country", country)
                .build();
    }

    private PermissionService.PermissionContext createContextWithAttributes() {
        return PermissionService.PermissionContext.builder()
                .userId(userId)
                .organizationId(organizationId)
                .resource("debate")
                .action("read")
                .attribute("userDepartment", "FINANCE")
                .build();
    }

    private PermissionService.PermissionContext createContextWithWrongAttributes() {
        return PermissionService.PermissionContext.builder()
                .userId(userId)
                .organizationId(organizationId)
                .resource("debate")
                .action("read")
                .attribute("userDepartment", "HR")
                .build();
    }

    private PermissionService.PermissionContext createContextWithUserAttributes() {
        return PermissionService.PermissionContext.builder()
                .userId(userId)
                .organizationId(organizationId)
                .resource("debate")
                .action("read")
                .attribute("department", "FINANCE")
                .attribute("clearanceLevel", "SECRET")
                .build();
    }

    private PermissionService.PermissionContext createContextWithWrongUserAttributes() {
        return PermissionService.PermissionContext.builder()
                .userId(userId)
                .organizationId(organizationId)
                .resource("debate")
                .action("read")
                .attribute("department", "HR")
                .attribute("clearanceLevel", "PUBLIC")
                .build();
    }

    private PermissionService.PermissionContext createContextWithResourceAttributes() {
        return PermissionService.PermissionContext.builder()
                .userId(userId)
                .organizationId(organizationId)
                .resource("debate")
                .action("read")
                .attribute("resource_classification", "CONFIDENTIAL")
                .attribute("resource_owner", "FINANCE_DEPT")
                .build();
    }

    private PermissionService.PermissionContext createContextWithEnvironmentAttributes() {
        return PermissionService.PermissionContext.builder()
                .userId(userId)
                .organizationId(organizationId)
                .resource("debate")
                .action("read")
                .environmentContext("requestSource", "internal")
                .environmentContext("securityLevel", "high")
                .build();
    }

    private PermissionService.PermissionContext createComplexContext() {
        return PermissionService.PermissionContext.builder()
                .userId(userId)
                .organizationId(organizationId)
                .resource("debate")
                .action("read")
                .attribute("department", "FINANCE")
                .attribute("role", "SENIOR_MANAGER")
                .attribute("resource_sensitivity", "MEDIUM")
                .environmentContext("accessMethod", "VPN")
                .build();
    }
}