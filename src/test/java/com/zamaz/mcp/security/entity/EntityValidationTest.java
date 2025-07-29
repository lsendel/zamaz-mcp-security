package com.zamaz.mcp.security.entity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Test class to validate the enhanced user and role data models.
 * Tests entity creation, relationships, and business logic methods.
 */
class EntityValidationTest {

    private User testUser;
    private Role testRole;
    private Permission testPermission;

    @BeforeEach
    void setUp() {
        // Create test user with MFA and audit fields
        testUser = new User();
        testUser.setId(UUID.randomUUID());
        testUser.setEmail("test@example.com");
        testUser.setPasswordHash("$2a$10$hashedPassword");
        testUser.setFirstName("Test");
        testUser.setLastName("User");
        testUser.setEmailVerified(true);
        testUser.setMfaEnabled(false);
        testUser.setAccountLocked(false);
        testUser.setFailedLoginAttempts(0);
        testUser.setIsActive(true);
        testUser.setCreatedAt(LocalDateTime.now());
        testUser.setUpdatedAt(LocalDateTime.now());

        // Create test role with hierarchical support
        testRole = new Role();
        testRole.setId(UUID.randomUUID());
        testRole.setName("TEST_ROLE");
        testRole.setDescription("Test role for validation");
        testRole.setOrganizationId(UUID.randomUUID());
        testRole.setIsSystemRole(false);
        testRole.setHierarchyLevel(1);
        testRole.setRoleType(Role.RoleType.FUNCTIONAL);
        testRole.setIsActive(true);
        testRole.setCreatedAt(LocalDateTime.now());
        testRole.setUpdatedAt(LocalDateTime.now());

        // Create test permission with resource-based access
        testPermission = new Permission();
        testPermission.setId(UUID.randomUUID());
        testPermission.setResource("debate");
        testPermission.setAction("read");
        testPermission.setDescription("Read access to debates");
        testPermission.setOrganizationId(UUID.randomUUID());
        testPermission.setPermissionType(Permission.PermissionType.RESOURCE_BASED);
        testPermission.setPermissionScope(Permission.PermissionScope.ORGANIZATION);
        testPermission.setIsActive(true);
        testPermission.setCreatedAt(LocalDateTime.now());
        testPermission.setUpdatedAt(LocalDateTime.now());
    }

    @Test
    void testUserEntityCreation() {
        assertNotNull(testUser.getId());
        assertEquals("test@example.com", testUser.getEmail());
        assertEquals("Test User", testUser.getFullName());
        assertTrue(testUser.isEnabled());
        assertTrue(testUser.isAccountNonLocked());
        assertTrue(testUser.isCredentialsNonExpired());
        assertTrue(testUser.isAccountNonExpired());
    }

    @Test
    void testUserMfaSupport() {
        assertFalse(testUser.getMfaEnabled());

        // Enable MFA
        testUser.setMfaEnabled(true);
        testUser.setMfaSecret("TESTSECRET123");
        testUser.setMfaBackupCodes("[\"code1\", \"code2\", \"code3\"]");

        assertTrue(testUser.getMfaEnabled());
        assertEquals("TESTSECRET123", testUser.getMfaSecret());
        assertNotNull(testUser.getMfaBackupCodes());
    }

    @Test
    void testUserAccountLocking() {
        assertTrue(testUser.isAccountNonLocked());

        // Lock account
        testUser.lockAccount("Security violation");

        assertFalse(testUser.isAccountNonLocked());
        assertEquals("Security violation", testUser.getAccountLockReason());
        assertNotNull(testUser.getAccountLockedAt());

        // Unlock account
        testUser.unlockAccount();

        assertTrue(testUser.isAccountNonLocked());
        assertNull(testUser.getAccountLockReason());
        assertEquals(0, testUser.getFailedLoginAttempts());
    }

    @Test
    void testUserFailedLoginAttempts() {
        assertEquals(0, testUser.getFailedLoginAttempts());

        // Increment failed attempts
        testUser.incrementFailedLoginAttempts();
        testUser.incrementFailedLoginAttempts();

        assertEquals(2, testUser.getFailedLoginAttempts());
        assertNotNull(testUser.getLastFailedLoginAt());

        // Reset attempts
        testUser.resetFailedLoginAttempts();

        assertEquals(0, testUser.getFailedLoginAttempts());
        assertNull(testUser.getLastFailedLoginAt());
    }

    @Test
    void testRoleEntityCreation() {
        assertNotNull(testRole.getId());
        assertEquals("TEST_ROLE", testRole.getName());
        assertEquals(1, testRole.getHierarchyLevel());
        assertEquals(Role.RoleType.FUNCTIONAL, testRole.getRoleType());
        assertTrue(testRole.isEffective());
        assertFalse(testRole.getIsSystemRole());
    }

    @Test
    void testRoleHierarchy() {
        // Create parent role
        Role parentRole = new Role();
        parentRole.setId(UUID.randomUUID());
        parentRole.setName("PARENT_ROLE");
        parentRole.setHierarchyLevel(2);
        parentRole.setIsActive(true);

        // Test role management capabilities
        assertTrue(parentRole.canManageRole(testRole));
        assertFalse(testRole.canManageRole(parentRole));
    }

    @Test
    void testRoleEffectiveness() {
        assertTrue(testRole.isEffective());

        // Set future effective date
        testRole.setEffectiveFrom(LocalDateTime.now().plusDays(1));
        assertFalse(testRole.isEffective());

        // Set past effective date
        testRole.setEffectiveFrom(LocalDateTime.now().minusDays(1));
        assertTrue(testRole.isEffective());

        // Set expiration date
        testRole.setEffectiveUntil(LocalDateTime.now().minusHours(1));
        assertFalse(testRole.isEffective());
    }

    @Test
    void testPermissionEntityCreation() {
        assertNotNull(testPermission.getId());
        assertEquals("debate", testPermission.getResource());
        assertEquals("read", testPermission.getAction());
        assertEquals(Permission.PermissionType.RESOURCE_BASED, testPermission.getPermissionType());
        assertEquals(Permission.PermissionScope.ORGANIZATION, testPermission.getPermissionScope());
        assertTrue(testPermission.isEffective());
        assertTrue(testPermission.isAllow());
    }

    @Test
    void testPermissionMatching() {
        UUID orgId = testPermission.getOrganizationId();

        // Test exact match
        assertTrue(testPermission.matches("debate", "read", null, orgId));

        // Test resource mismatch
        assertFalse(testPermission.matches("user", "read", null, orgId));

        // Test action mismatch
        assertFalse(testPermission.matches("debate", "write", null, orgId));

        // Test organization mismatch
        assertFalse(testPermission.matches("debate", "read", null, UUID.randomUUID()));
    }

    @Test
    void testPermissionWithResourceId() {
        testPermission.setResourceId("debate123");
        UUID orgId = testPermission.getOrganizationId();

        // Test with matching resource ID
        assertTrue(testPermission.matches("debate", "read", "debate123", orgId));

        // Test with different resource ID
        assertFalse(testPermission.matches("debate", "read", "debate456", orgId));

        // Test without resource ID
        assertFalse(testPermission.matches("debate", "read", null, orgId));
    }

    @Test
    void testPermissionEffectiveness() {
        assertTrue(testPermission.isEffective());

        // Deactivate permission
        testPermission.setIsActive(false);
        assertFalse(testPermission.isEffective());

        // Reactivate and test time-based constraints
        testPermission.setIsActive(true);
        testPermission.setTimeBased(true);
        testPermission.setValidFrom(LocalDateTime.now().plusHours(1));

        assertFalse(testPermission.isEffective());

        // Set valid time range
        testPermission.setValidFrom(LocalDateTime.now().minusHours(1));
        testPermission.setValidUntil(LocalDateTime.now().plusHours(1));

        assertTrue(testPermission.isEffective());
    }

    @Test
    void testUserRoleAssociation() {
        UserRole userRole = new UserRole();
        userRole.setId(UUID.randomUUID());
        userRole.setUser(testUser);
        userRole.setRole(testRole);
        userRole.setOrganizationId(testRole.getOrganizationId());
        userRole.setAssignmentType(UserRole.AssignmentType.DIRECT);
        userRole.setAssignmentStatus(UserRole.AssignmentStatus.ACTIVE);
        userRole.setIsActive(true);
        userRole.setGrantedAt(LocalDateTime.now());

        assertTrue(userRole.isEffective());
        assertFalse(userRole.isExpired());
        assertFalse(userRole.isDelegated());

        // Test expiration
        userRole.setExpiresAt(LocalDateTime.now().minusHours(1));
        assertFalse(userRole.isEffective());
        assertTrue(userRole.isExpired());
    }

    @Test
    void testUserPermissionAssociation() {
        UserPermission userPermission = new UserPermission();
        userPermission.setId(UUID.randomUUID());
        userPermission.setUser(testUser);
        userPermission.setPermission(testPermission);
        userPermission.setOrganizationId(testPermission.getOrganizationId());
        userPermission.setAssignmentType(UserPermission.AssignmentType.DIRECT);
        userPermission.setIsActive(true);
        userPermission.setGrantedAt(LocalDateTime.now());

        assertTrue(userPermission.isEffective());
        assertFalse(userPermission.isExpired());
        assertFalse(userPermission.isDelegated());

        // Test usage tracking
        assertEquals(0L, userPermission.getUsageCount());
        userPermission.recordUsage();
        assertEquals(1L, userPermission.getUsageCount());
        assertNotNull(userPermission.getLastUsedAt());
    }

    @Test
    void testRolePermissionAssociation() {
        RolePermission rolePermission = new RolePermission();
        rolePermission.setId(UUID.randomUUID());
        rolePermission.setRole(testRole);
        rolePermission.setPermission(testPermission);
        rolePermission.setIsActive(true);
        rolePermission.setGrantedAt(LocalDateTime.now());

        assertTrue(rolePermission.isEffective());

        // Test revocation
        rolePermission.revoke("admin", "No longer needed");
        assertFalse(rolePermission.getIsActive());
        assertNotNull(rolePermission.getRevokedAt());
        assertEquals("admin", rolePermission.getRevokedBy());
        assertEquals("No longer needed", rolePermission.getRevocationReason());
    }

    @Test
    void testSecurityAuditLog() {
        SecurityAuditLog auditLog = new SecurityAuditLog();
        auditLog.setId(UUID.randomUUID());
        auditLog.setEventType(SecurityAuditLog.SecurityEventType.LOGIN_SUCCESS);
        auditLog.setEventCategory(SecurityAuditLog.EventCategory.AUTHENTICATION);
        auditLog.setUser(testUser);
        auditLog.setOrganizationId(UUID.randomUUID());
        auditLog.setOutcome(SecurityAuditLog.AuditOutcome.SUCCESS);
        auditLog.setRiskLevel(SecurityAuditLog.RiskLevel.LOW);
        auditLog.setIpAddress("192.168.1.1");
        auditLog.setTimestamp(LocalDateTime.now());

        assertFalse(auditLog.isHighRisk());
        assertFalse(auditLog.isSecurityEvent());
        assertFalse(auditLog.isFailureEvent());
        assertFalse(auditLog.requiresAlert());

        // Test high-risk event
        auditLog.setRiskLevel(SecurityAuditLog.RiskLevel.CRITICAL);
        auditLog.setEventType(SecurityAuditLog.SecurityEventType.SUSPICIOUS_ACTIVITY);
        auditLog.setAnomalyDetected(true);

        assertTrue(auditLog.isHighRisk());
        assertTrue(auditLog.isSecurityEvent());
        assertTrue(auditLog.requiresAlert());
    }
}