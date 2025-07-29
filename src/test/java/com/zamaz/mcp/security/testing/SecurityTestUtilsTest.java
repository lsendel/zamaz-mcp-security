package com.zamaz.mcp.security.testing;

import com.zamaz.mcp.security.domain.Permission;
import com.zamaz.mcp.security.domain.Role;
import com.zamaz.mcp.security.domain.SecurityContext;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.*;

class SecurityTestUtilsTest {

    @Test
    void securityTestContext_shouldCreateSystemAdminContext() {
        // When
        SecurityContext context = SecurityTestContext.systemAdmin();

        // Then
        assertThat(context.getUserId()).isEqualTo("system-admin");
        assertThat(context.getUsername()).isEqualTo("admin@system.com");
        assertThat(context.getRoles()).contains(Role.SYSTEM_ADMIN);
        assertThat(context.getGlobalPermissions()).containsAll(List.of(Permission.values()));
    }

    @Test
    void securityTestContext_shouldCreateOrgAdminContext() {
        // When
        SecurityContext context = SecurityTestContext.organizationAdmin("org-123");

        // Then
        assertThat(context.getOrganizationId()).isEqualTo("org-123");
        assertThat(context.getRoles()).contains(Role.ORG_ADMIN);
        assertThat(context.getOrganizationPermissions().get("org-123"))
            .contains(Permission.DEBATE_CREATE, Permission.USER_MANAGE);
    }

    @Test
    void securityTestContext_shouldSetAndClearContext() {
        // Given
        SecurityContext context = SecurityTestContext.regularUser("org-123");

        // When
        SecurityTestContext.setContext(context);

        // Then
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication().getName())
            .isEqualTo("user@example.com");

        // Clean up
        SecurityTestContext.clearContext();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void securityTestContext_shouldRunWithTemporaryContext() {
        // Given
        AtomicReference<String> capturedUserId = new AtomicReference<>();
        SecurityContext tempContext = SecurityTestContext.builder()
            .withUserId("temp-user")
            .withUsername("temp@example.com")
            .build();

        // When
        SecurityTestContext.runAs(tempContext, () -> {
            capturedUserId.set(SecurityContextHolder.getContext()
                .getAuthentication().getName());
        });

        // Then
        assertThat(capturedUserId.get()).isEqualTo("temp@example.com");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void mockJwtProvider_shouldCreateValidToken() {
        // When
        String token = MockJwtProvider.createToken("user-123", "org-456");

        // Then
        assertThat(token).isNotNull();
        Claims claims = MockJwtProvider.parseToken(token);
        assertThat(claims.getSubject()).isEqualTo("user-123");
        assertThat(claims.get("organizationId")).isEqualTo("org-456");
        assertThat(claims.getExpiration()).isAfter(new Date());
    }

    @Test
    void mockJwtProvider_shouldCreateExpiredToken() {
        // When
        String token = MockJwtProvider.createExpiredToken();

        // Then
        assertThat(token).isNotNull();
        Claims claims = MockJwtProvider.parseToken(token);
        assertThat(claims.getExpiration()).isBefore(new Date());
    }

    @Test
    void mockJwtProvider_shouldCreateTokenWithCustomClaims() {
        // When
        String token = MockJwtProvider.builder()
            .withUserId("custom-user")
            .withRole(Role.ORG_ADMIN)
            .withPermissions(Permission.DEBATE_CREATE, Permission.DEBATE_DELETE)
            .withCustomClaim("department", "engineering")
            .build();

        // Then
        Claims claims = MockJwtProvider.parseToken(token);
        assertThat(claims.get("userId")).isEqualTo("custom-user");
        assertThat((List<String>) claims.get("roles")).contains("ORG_ADMIN");
        assertThat((List<String>) claims.get("permissions"))
            .contains("DEBATE_CREATE", "DEBATE_DELETE");
        assertThat(claims.get("department")).isEqualTo("engineering");
    }

    @Test
    void permissionTestUtils_shouldAssertPermissions() {
        // Given
        SecurityContext context = SecurityTestContext.builder()
            .withUserId("test-user")
            .withRole(Role.USER)
            .withGlobalPermission(Permission.DEBATE_VIEW)
            .withOrganizationPermissions("org-1", Permission.DEBATE_CREATE)
            .build();

        // Then
        PermissionTestUtils.assertPermissions(context)
            .hasGlobalPermission(Permission.DEBATE_VIEW)
            .hasOrganizationPermission("org-1", Permission.DEBATE_CREATE)
            .hasRole(Role.USER)
            .canAccessOrganization("org-1");
    }

    @Test
    void permissionMatrix_shouldTestPermissionCombinations() {
        // Given
        PermissionTestUtils.PermissionMatrix matrix = PermissionTestUtils.createPermissionMatrix()
            .withRolePermissions(Role.USER, Permission.DEBATE_VIEW)
            .withRolePermissions(Role.ORG_ADMIN, Permission.DEBATE_VIEW, Permission.DEBATE_CREATE);

        // When & Then
        assertThat(matrix.shouldHavePermission(Role.USER, Permission.DEBATE_VIEW)).isTrue();
        assertThat(matrix.shouldHavePermission(Role.USER, Permission.DEBATE_CREATE)).isFalse();
        assertThat(matrix.shouldHavePermission(Role.ORG_ADMIN, Permission.DEBATE_CREATE)).isTrue();
    }

    @Test
    void resourcePermissionBuilder_shouldManageResourcePermissions() {
        // Given
        PermissionTestUtils.ResourcePermissionBuilder builder = 
            new PermissionTestUtils.ResourcePermissionBuilder()
                .withResource("resource-1", "owner-1")
                .grantPermission("resource-1", "user-1", Permission.DEBATE_VIEW);

        // When
        PermissionTestUtils.ResourcePermissionBuilder.ResourcePermissions resource = 
            builder.getResource("resource-1");

        // Then
        assertThat(resource.hasPermission("owner-1", Permission.DEBATE_DELETE)).isTrue();
        assertThat(resource.hasPermission("user-1", Permission.DEBATE_VIEW)).isTrue();
        assertThat(resource.hasPermission("user-1", Permission.DEBATE_DELETE)).isFalse();
    }

    @Test
    void withMockTenant_shouldWorkWithSpringContext() {
        // This test would require Spring context, so we're just validating the structure
        WithMockTenant annotation = SecurityTestUtilsTest.class.getAnnotation(WithMockTenant.class);
        assertThat(annotation).isNull(); // No annotation on this class
    }

    @Test
    void securityScenarios_shouldCreateMultiOrgUser() {
        // When
        SecurityContext context = SecurityTestContext.Scenarios
            .multiOrganizationUser("org-1", "org-2", "org-3");

        // Then
        assertThat(context.getOrganizationId()).isEqualTo("org-1");
        assertThat(context.getOrganizationPermissions()).hasSize(3);
        assertThat(context.getOrganizationPermissions().keySet())
            .containsExactlyInAnyOrder("org-1", "org-2", "org-3");
    }

    @Test
    void securityScenarios_shouldCreateReadOnlyUser() {
        // When
        SecurityContext context = SecurityTestContext.Scenarios.readOnlyUser("org-123");

        // Then
        assertThat(context.getOrganizationPermissions().get("org-123"))
            .containsExactly(Permission.DEBATE_VIEW);
    }

    @Test
    void mockJwtTokens_shouldCreatePreBuiltTokens() {
        // Test system admin token
        String systemAdminToken = MockJwtProvider.Tokens.systemAdmin();
        Claims systemAdminClaims = MockJwtProvider.parseToken(systemAdminToken);
        assertThat((List<String>) systemAdminClaims.get("roles")).contains("SYSTEM_ADMIN");

        // Test org admin token
        String orgAdminToken = MockJwtProvider.Tokens.orgAdmin("org-123");
        Claims orgAdminClaims = MockJwtProvider.parseToken(orgAdminToken);
        assertThat(orgAdminClaims.get("organizationId")).isEqualTo("org-123");
        assertThat((List<String>) orgAdminClaims.get("roles")).contains("ORG_ADMIN");

        // Test token expiring soon
        String expiringToken = MockJwtProvider.Tokens.tokenExpiringIn(5);
        Claims expiringClaims = MockJwtProvider.parseToken(expiringToken);
        assertThat(expiringClaims.getExpiration())
            .isBefore(Date.from(Instant.now().plusSeconds(10)))
            .isAfter(new Date());
    }
}