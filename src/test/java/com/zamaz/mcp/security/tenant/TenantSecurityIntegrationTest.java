package com.zamaz.mcp.security.tenant;

import com.zamaz.mcp.security.entity.Permission;
import com.zamaz.mcp.security.entity.Role;
import com.zamaz.mcp.security.entity.User;
import com.zamaz.mcp.security.repository.PermissionRepository;
import com.zamaz.mcp.security.repository.UserRoleRepository;
import com.zamaz.mcp.security.service.PermissionService;
import com.zamaz.mcp.security.tenant.TenantSecurityContext.TenantSecurityException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class TenantSecurityIntegrationTest {

    private UUID tenant1Id;
    private UUID tenant2Id;
    private UUID user1Id;
    private UUID user2Id;

    @BeforeEach
    void setUp() {
        tenant1Id = UUID.randomUUID();
        tenant2Id = UUID.randomUUID();
        user1Id = UUID.randomUUID();
        user2Id = UUID.randomUUID();
    }

    @AfterEach
    void tearDown() {
        TenantSecurityContext.clear();
    }

    @Test
    void shouldIsolateTenantContexts() {
        // Given - no tenant context initially
        assertThat(TenantSecurityContext.hasTenant()).isFalse();

        // When - set tenant 1 context
        TenantSecurityContext.setCurrentTenant(tenant1Id, "Tenant 1");

        // Then - tenant 1 context is active
        assertThat(TenantSecurityContext.hasTenant()).isTrue();
        assertThat(TenantSecurityContext.getCurrentTenant()).isEqualTo(tenant1Id);
        assertThat(TenantSecurityContext.getCurrentTenantName()).isEqualTo("Tenant 1");
        assertThat(TenantSecurityContext.isCurrentTenant(tenant1Id)).isTrue();
        assertThat(TenantSecurityContext.isCurrentTenant(tenant2Id)).isFalse();
    }

    @Test
    void shouldValidateTenantAccess() {
        // Given - tenant 1 context
        TenantSecurityContext.setCurrentTenant(tenant1Id);

        // When/Then - validation passes for correct tenant
        TenantSecurityContext.validateTenant(tenant1Id);

        // When/Then - validation fails for different tenant
        assertThatThrownBy(() -> TenantSecurityContext.validateTenant(tenant2Id))
                .isInstanceOf(TenantSecurityException.class)
                .hasMessageContaining("Tenant mismatch");
    }

    @Test
    void shouldExecuteInTenantContext() {
        // Given - no initial tenant context
        assertThat(TenantSecurityContext.hasTenant()).isFalse();

        // When - execute in tenant context
        String result = TenantSecurityContext.executeInTenantContext(tenant1Id, () -> {
            assertThat(TenantSecurityContext.getCurrentTenant()).isEqualTo(tenant1Id);
            return "executed";
        });

        // Then - result is correct and context is cleared
        assertThat(result).isEqualTo("executed");
        assertThat(TenantSecurityContext.hasTenant()).isFalse();
    }

    @Test
    void shouldHandleNestedTenantContexts() {
        // Given - tenant 1 context
        TenantSecurityContext.setCurrentTenant(tenant1Id, "Tenant 1");

        // When - execute in different tenant context
        String result = TenantSecurityContext.executeInTenantContext(tenant2Id, () -> {
            // Inner context should be tenant 2
            assertThat(TenantSecurityContext.getCurrentTenant()).isEqualTo(tenant2Id);

            return TenantSecurityContext.executeInTenantContext(tenant1Id, () -> {
                // Nested context should be tenant 1
                assertThat(TenantSecurityContext.getCurrentTenant()).isEqualTo(tenant1Id);
                return "nested";
            });
        });

        // Then - original context is restored
        assertThat(result).isEqualTo("nested");
        assertThat(TenantSecurityContext.getCurrentTenant()).isEqualTo(tenant1Id);
        assertThat(TenantSecurityContext.getCurrentTenantName()).isEqualTo("Tenant 1");
    }

    @Test
    void shouldClearTenantContext() {
        // Given - tenant context is set
        TenantSecurityContext.setCurrentTenant(tenant1Id, "Tenant 1");
        assertThat(TenantSecurityContext.hasTenant()).isTrue();

        // When - clear context
        TenantSecurityContext.clear();

        // Then - context is cleared
        assertThat(TenantSecurityContext.hasTenant()).isFalse();
        assertThat(TenantSecurityContext.getCurrentTenant()).isNull();
        assertThat(TenantSecurityContext.getCurrentTenantName()).isNull();
    }

    @Test
    void shouldProvideContextSummary() {
        // Given - no tenant context
        String noContextSummary = TenantSecurityContext.getContextSummary();
        assertThat(noContextSummary).isEqualTo("No tenant context");

        // When - set tenant context without name
        TenantSecurityContext.setCurrentTenant(tenant1Id);
        String contextWithoutName = TenantSecurityContext.getContextSummary();
        assertThat(contextWithoutName).contains(tenant1Id.toString());

        // When - set tenant context with name
        TenantSecurityContext.setCurrentTenant(tenant1Id, "Tenant 1");
        String contextWithName = TenantSecurityContext.getContextSummary();
        assertThat(contextWithName).contains(tenant1Id.toString());
        assertThat(contextWithName).contains("Tenant 1");
    }

    @Test
    void shouldHandleTenantSecurityInfo() {
        // Given - comprehensive tenant security info
        TenantSecurityContext.TenantSecurityInfo securityInfo = new TenantSecurityContext.TenantSecurityInfo(
                tenant1Id,
                "Tenant 1",
                true,
                java.util.Set.of("POLICY_A", "POLICY_B"),
                java.util.Map.of("maxUsers", 100, "region", "US"));

        // When - set security info
        TenantSecurityContext.setTenantSecurityInfo(securityInfo);

        // Then - all information is available
        assertThat(TenantSecurityContext.getCurrentTenant()).isEqualTo(tenant1Id);
        assertThat(TenantSecurityContext.getCurrentTenantName()).isEqualTo("Tenant 1");

        TenantSecurityContext.TenantSecurityInfo retrievedInfo = TenantSecurityContext.getTenantSecurityInfo();

        assertThat(retrievedInfo).isNotNull();
        assertThat(retrievedInfo.getTenantId()).isEqualTo(tenant1Id);
        assertThat(retrievedInfo.getTenantName()).isEqualTo("Tenant 1");
        assertThat(retrievedInfo.isActive()).isTrue();
        assertThat(retrievedInfo.hasSecurityPolicy("POLICY_A")).isTrue();
        assertThat(retrievedInfo.hasSecurityPolicy("POLICY_C")).isFalse();
        assertThat(retrievedInfo.getSecurityAttribute("maxUsers")).isEqualTo(100);
        assertThat(retrievedInfo.getSecurityAttribute("region")).isEqualTo("US");
    }

    @Test
    void shouldThrowExceptionForInvalidTenantOperations() {
        // When/Then - validate tenant without context
        assertThatThrownBy(() -> TenantSecurityContext.validateTenant(tenant1Id))
                .isInstanceOf(TenantSecurityException.class)
                .hasMessageContaining("No tenant context set");
    }

    @Test
    void shouldHandleExceptionsInTenantContext() {
        // Given - no initial context
        assertThat(TenantSecurityContext.hasTenant()).isFalse();

        // When/Then - exception in tenant context should not affect cleanup
        assertThatThrownBy(() -> {
            TenantSecurityContext.executeInTenantContext(tenant1Id, () -> {
                assertThat(TenantSecurityContext.getCurrentTenant()).isEqualTo(tenant1Id);
                throw new RuntimeException("Test exception");
            });
        }).isInstanceOf(RuntimeException.class);

        // Context should still be cleared
        assertThat(TenantSecurityContext.hasTenant()).isFalse();
    }
}