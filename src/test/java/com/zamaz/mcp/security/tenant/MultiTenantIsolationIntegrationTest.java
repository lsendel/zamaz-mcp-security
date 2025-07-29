package com.zamaz.mcp.security.tenant;

import com.zamaz.mcp.security.entity.*;
import com.zamaz.mcp.security.repository.*;
import com.zamaz.mcp.security.service.PermissionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Integration tests for multi-tenant security isolation.
 * Verifies that organizations cannot access each other's data or resources.
 */
@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@Transactional
class MultiTenantIsolationIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15")
            .withDatabaseName("auth_test")
            .withUsername("test")
            .withPassword("test");

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PermissionRepository permissionRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Autowired
    private PermissionService permissionService;

    private UUID org1Id;
    private UUID org2Id;
    private UUID user1Id;
    private UUID user2Id;

    @BeforeEach
    void setUp() {
        org1Id = UUID.randomUUID();
        org2Id = UUID.randomUUID();
        user1Id = UUID.randomUUID();
        user2Id = UUID.randomUUID();

        // Create users in different organizations
        createTestData();
    }

    @Test
    void shouldIsolateUsersByOrganization() {
        // Set tenant context for org1
        TenantSecurityContext.setCurrentTenant(org1Id);

        // Should find user1 (same org)
        List<User> org1Users = userRepository.findAll();
        assertThat(org1Users).hasSize(1);
        assertThat(org1Users.get(0).getId()).isEqualTo(user1Id);

        // Set tenant context for org2
        TenantSecurityContext.setCurrentTenant(org2Id);

        // Should find user2 (same org)
        List<User> org2Users = userRepository.findAll();
        assertThat(org2Users).hasSize(1);
        assertThat(org2Users.get(0).getId()).isEqualTo(user2Id);

        TenantSecurityContext.clear();
    }

    @Test
    void shouldPreventCrossTenantDataAccess() {
        // Set tenant context for org1
        TenantSecurityContext.setCurrentTenant(org1Id);

        // Try to access user from org2 - should fail
        assertThat(userRepository.findById(user2Id)).isEmpty();

        // Set tenant context for org2
        TenantSecurityContext.setCurrentTenant(org2Id);

        // Try to access user from org1 - should fail
        assertThat(userRepository.findById(user1Id)).isEmpty();

        TenantSecurityContext.clear();
    }

    @Test
    void shouldEnforcePermissionIsolation() {
        // User1 should not have permissions in org2
        boolean hasPermission = permissionService.hasPermission(user1Id, org2Id, "debate", "read");
        assertThat(hasPermission).isFalse();

        // User2 should not have permissions in org1
        hasPermission = permissionService.hasPermission(user2Id, org1Id, "debate", "read");
        assertThat(hasPermission).isFalse();

        // Users should have permissions in their own org
        hasPermission = permissionService.hasPermission(user1Id, org1Id, "debate", "read");
        assertThat(hasPermission).isTrue();

        hasPermission = permissionService.hasPermission(user2Id, org2Id, "debate", "read");
        assertThat(hasPermission).isTrue();
    }

    @Test
    void shouldValidateTenantOwnership() {
        // Create entity in org1 context
        TenantSecurityContext.setCurrentTenant(org1Id);

        User newUser = new User();
        newUser.setEmail("test@org1.com");
        newUser.setPasswordHash("hash");

        // Should succeed - same tenant
        User savedUser = userRepository.save(newUser);
        assertThat(savedUser.getId()).isNotNull();

        // Switch to org2 context
        TenantSecurityContext.setCurrentTenant(org2Id);

        // Should not be able to access user from org1
        assertThat(userRepository.findById(savedUser.getId())).isEmpty();

        TenantSecurityContext.clear();
    }

    @Test
    void shouldPreventTenantViolations() {
        // Set tenant context for org1
        TenantSecurityContext.setCurrentTenant(org1Id);

        // Try to validate against org2 - should throw exception
        assertThatThrownBy(() -> TenantSecurityContext.validateTenant(org2Id))
                .isInstanceOf(TenantSecurityContext.TenantSecurityException.class)
                .hasMessageContaining("Tenant mismatch");

        TenantSecurityContext.clear();
    }

    @Test
    void shouldExecuteInTenantContext() {
        // Execute code in org1 context
        String result = TenantSecurityContext.executeInTenantContext(org1Id, () -> {
            assertThat(TenantSecurityContext.getCurrentTenant()).isEqualTo(org1Id);
            return "org1-result";
        });

        assertThat(result).isEqualTo("org1-result");
        assertThat(TenantSecurityContext.getCurrentTenant()).isNull();

        // Execute code in org2 context
        result = TenantSecurityContext.executeInTenantContext(org2Id, () -> {
            assertThat(TenantSecurityContext.getCurrentTenant()).isEqualTo(org2Id);
            return "org2-result";
        });

        assertThat(result).isEqualTo("org2-result");
        assertThat(TenantSecurityContext.getCurrentTenant()).isNull();
    }

    @Test
    void shouldHandleNestedTenantContexts() {
        // Set initial context
        TenantSecurityContext.setCurrentTenant(org1Id);
        assertThat(TenantSecurityContext.getCurrentTenant()).isEqualTo(org1Id);

        // Execute in different context
        TenantSecurityContext.executeInTenantContext(org2Id, () -> {
            assertThat(TenantSecurityContext.getCurrentTenant()).isEqualTo(org2Id);
            return null;
        });

        // Should restore original context
        assertThat(TenantSecurityContext.getCurrentTenant()).isEqualTo(org1Id);

        TenantSecurityContext.clear();
    }

    @Test
    void shouldIsolateRolesByOrganization() {
        // Set tenant context for org1
        TenantSecurityContext.setCurrentTenant(org1Id);

        List<Role> org1Roles = roleRepository.findAll();
        assertThat(org1Roles).hasSize(1);
        assertThat(org1Roles.get(0).getOrganizationId()).isEqualTo(org1Id);

        // Set tenant context for org2
        TenantSecurityContext.setCurrentTenant(org2Id);

        List<Role> org2Roles = roleRepository.findAll();
        assertThat(org2Roles).hasSize(1);
        assertThat(org2Roles.get(0).getOrganizationId()).isEqualTo(org2Id);

        TenantSecurityContext.clear();
    }

    @Test
    void shouldPreventCrossTenantRoleAssignment() {
        // Try to assign role from org2 to user in org1
        TenantSecurityContext.setCurrentTenant(org1Id);

        // Get org2 role (should not be accessible)
        TenantSecurityContext.setCurrentTenant(org2Id);
        List<Role> org2Roles = roleRepository.findAll();
        Role org2Role = org2Roles.get(0);

        // Switch back to org1
        TenantSecurityContext.setCurrentTenant(org1Id);

        // Try to create user role assignment - should fail validation
        UserRole userRole = new UserRole();
        userRole.setUserId(user1Id);
        userRole.setRole(org2Role);
        userRole.setOrganizationId(org1Id);

        // This should fail due to tenant mismatch
        assertThatThrownBy(() -> userRoleRepository.save(userRole))
                .isInstanceOf(Exception.class);

        TenantSecurityContext.clear();
    }

    private void createTestData() {
        // Create users
        User user1 = new User();
        user1.setId(user1Id);
        user1.setEmail("user1@org1.com");
        user1.setPasswordHash("hash1");
        user1.setIsActive(true);
        user1.setEmailVerified(true);

        User user2 = new User();
        user2.setId(user2Id);
        user2.setEmail("user2@org2.com");
        user2.setPasswordHash("hash2");
        user2.setIsActive(true);
        user2.setEmailVerified(true);

        // Create roles
        Role role1 = new Role();
        role1.setName("USER");
        role1.setOrganizationId(org1Id);
        role1.setIsActive(true);

        Role role2 = new Role();
        role2.setName("USER");
        role2.setOrganizationId(org2Id);
        role2.setIsActive(true);

        // Create permissions
        Permission permission1 = new Permission();
        permission1.setResource("debate");
        permission1.setAction("read");
        permission1.setOrganizationId(org1Id);
        permission1.setIsActive(true);

        Permission permission2 = new Permission();
        permission2.setResource("debate");
        permission2.setAction("read");
        permission2.setOrganizationId(org2Id);
        permission2.setIsActive(true);

        // Save in appropriate tenant contexts
        TenantSecurityContext.setCurrentTenant(org1Id);
        userRepository.save(user1);
        roleRepository.save(role1);
        permissionRepository.save(permission1);

        // Create user role assignment
        UserRole userRole1 = new UserRole();
        userRole1.setUserId(user1Id);
        userRole1.setRole(role1);
        userRole1.setOrganizationId(org1Id);
        userRole1.setIsActive(true);
        userRole1.setAssignmentStatus(UserRole.AssignmentStatus.ACTIVE);
        userRoleRepository.save(userRole1);

        // Create role permission assignment
        RolePermission rolePermission1 = new RolePermission();
        rolePermission1.setRole(role1);
        rolePermission1.setPermission(permission1);
        rolePermission1.setIsActive(true);

        TenantSecurityContext.setCurrentTenant(org2Id);
        userRepository.save(user2);
        roleRepository.save(role2);
        permissionRepository.save(permission2);

        // Create user role assignment
        UserRole userRole2 = new UserRole();
        userRole2.setUserId(user2Id);
        userRole2.setRole(role2);
        userRole2.setOrganizationId(org2Id);
        userRole2.setIsActive(true);
        userRole2.setAssignmentStatus(UserRole.AssignmentStatus.ACTIVE);
        userRoleRepository.save(userRole2);

        // Create role permission assignment
        RolePermission rolePermission2 = new RolePermission();
        rolePermission2.setRole(role2);
        rolePermission2.setPermission(permission2);
        rolePermission2.setIsActive(true);

        TenantSecurityContext.clear();
    }
}