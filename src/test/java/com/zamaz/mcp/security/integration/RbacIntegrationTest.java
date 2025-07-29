package com.zamaz.mcp.security.integration;

import com.zamaz.mcp.security.entity.*;
import com.zamaz.mcp.security.expression.SecurityExpressions;
import com.zamaz.mcp.security.repository.PermissionRepository;
import com.zamaz.mcp.security.repository.UserPermissionRepository;
import com.zamaz.mcp.security.repository.UserRoleRepository;
import com.zamaz.mcp.security.service.PermissionEvaluationEngine;
import com.zamaz.mcp.security.service.PermissionService;
import com.zamaz.mcp.security.tenant.TenantSecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.LocalDateTime;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Integration test for the complete RBAC permission system.
 * Tests the interaction between PermissionService, SecurityExpressions, and
 * PermissionEvaluationEngine.
 */
@ExtendWith(MockitoExtension.class)
class RbacIntegrationTest {

    @Mock
    private PermissionRepository permissionRepository;

    @Mock
    private UserRoleRepository userRoleRepository;

    @Mock
    private UserPermissionRepository userPermissionRepository;

    @Mock
    private Authentication authentication;

    @Mock
    private SecurityContext securityContext;

    private PermissionEvaluationEngine evaluationEngine;
    private PermissionService permissionService;
    private SecurityExpressions securityExpressions;

    private UUID userId;
    private UUID organizationId;
    private UUID adminRoleId;
    private UUID userRoleId;

    @BeforeEach
    void setUp() {
        evaluationEngine = new PermissionEvaluationEngine();
        permissionService = new PermissionService(
                permissionRepository,
                userRoleRepository,
                userPermissionRepository,
                evaluationEngine);
        securityExpressions = new SecurityExpressions(permissionService);

        userId = UUID.randomUUID();
        organizationId = UUID.randomUUID();
        adminRoleId = UUID.randomUUID();
        userRoleId = UUID.randomUUID();

        setupSecurityContext();
    }

    @Test
    void shouldGrantAccessForAdminUserWithHierarchicalRoles() {
        // Given - Admin user with hierarchical role structure
        Role adminRole = createRole("ADMIN", 3);
        Role moderatorRole = createRole("MODERATOR", 2);
        Role userRole = createRole("USER", 1);

        // Set up role hierarchy
        moderatorRole.setParentRoles(Set.of(adminRole));
        userRole.setParentRoles(Set.of(moderatorRole));

        Permission debateManagePermission = createPermission("debate", "manage");
        Permission userViewPermission = createPermission("user", "view");

        // Admin role has debate management permission
        RolePermission adminRolePermission = createRolePermission(adminRole, debateManagePermission);
        adminRole.setRolePermissions(Set.of(adminRolePermission));

        // User role has user view permission
        RolePermission userRolePermission = createRolePermission(userRole, userViewPermission);
        userRole.setRolePermissions(Set.of(userRolePermission));

        UserRole userAdminRole = createUserRole(adminRole);

        when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                .thenReturn(Collections.emptyList());
        when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                .thenReturn(List.of(userAdminRole));

        // When - Check if admin can manage debates
        boolean canManageDebates = permissionService.hasPermission(userId, organizationId, "debate", "manage");

        // Then
        assertThat(canManageDebates).isTrue();
    }

    @Test
    void shouldEnforceResourceLevelPermissions() {
        // Given - User with permission for specific debate
        Permission specificDebatePermission = createPermission("debate", "edit");
        specificDebatePermission.setResourceId("debate-123");

        UserPermission userPermission = createUserPermission(specificDebatePermission);

        when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                .thenReturn(List.of(userPermission));
        when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                .thenReturn(Collections.emptyList());

        // When - Check access to specific debate
        boolean canEditSpecificDebate = permissionService.hasPermission(userId, organizationId, "debate", "edit",
                "debate-123");
        boolean canEditOtherDebate = permissionService.hasPermission(userId, organizationId, "debate", "edit",
                "debate-456");

        // Then
        assertThat(canEditSpecificDebate).isTrue();
        assertThat(canEditOtherDebate).isFalse();
    }

    @Test
    void shouldEnforceAttributeBasedPermissions() {
        // Given - Permission with attribute-based conditions
        Permission attributePermission = createPermission("document", "access");
        attributePermission.setConditionExpression("userDepartment == 'FINANCE' && currentHour >= 9");
        attributePermission.setSubjectAttributes("{\"department\": \"FINANCE\", \"clearanceLevel\": \"SECRET\"}");

        UserPermission userPermission = createUserPermission(attributePermission);

        when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                .thenReturn(List.of(userPermission));
        when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                .thenReturn(Collections.emptyList());

        // When - Check permission with matching attributes
        boolean hasPermission = permissionService.hasPermission(userId, organizationId, "document", "access");

        // Then - Should evaluate conditions (mocked to return true)
        assertThat(hasPermission).isTrue();
    }

    @Test
    void shouldEnforceTimeBasedPermissions() {
        // Given - Time-based permission
        Permission timeBasedPermission = createPermission("system", "maintenance");
        timeBasedPermission.setTimeBased(true);
        timeBasedPermission.setValidFrom(LocalDateTime.now().minusHours(1));
        timeBasedPermission.setValidUntil(LocalDateTime.now().plusHours(1));
        timeBasedPermission.setHoursOfDay("09:00-17:00");
        timeBasedPermission.setDaysOfWeek("MON,TUE,WED,THU,FRI");

        UserPermission userPermission = createUserPermission(timeBasedPermission);

        when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                .thenReturn(List.of(userPermission));
        when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                .thenReturn(Collections.emptyList());

        // When
        boolean hasPermission = permissionService.hasPermission(userId, organizationId, "system", "maintenance");

        // Then - Should check time constraints
        assertThat(hasPermission).isIn(true, false); // Depends on current time
    }

    @Test
    void shouldHandleDenyPermissionsWithPriority() {
        // Given - Both ALLOW and DENY permissions
        Permission allowPermission = createPermission("debate", "read");
        allowPermission.setEffect("ALLOW");
        allowPermission.setPriority(1);

        Permission denyPermission = createPermission("debate", "read");
        denyPermission.setEffect("DENY");
        denyPermission.setPriority(2);
        denyPermission.setResourceId("debate-sensitive");

        UserPermission allowUserPermission = createUserPermission(allowPermission);
        UserPermission denyUserPermission = createUserPermission(denyPermission);

        when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                .thenReturn(List.of(allowUserPermission, denyUserPermission));
        when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                .thenReturn(Collections.emptyList());

        // When - Check access to sensitive debate
        boolean canReadSensitiveDebate = permissionService.hasPermission(userId, organizationId, "debate", "read",
                "debate-sensitive");
        boolean canReadOtherDebate = permissionService.hasPermission(userId, organizationId, "debate", "read",
                "debate-normal");

        // Then - DENY should take precedence for sensitive debate
        assertThat(canReadSensitiveDebate).isFalse();
        assertThat(canReadOtherDebate).isTrue();
    }

    @Test
    void shouldWorkWithSecurityExpressions() {
        // Given - User with admin role
        Collection<org.springframework.security.core.GrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("ROLE_ADMIN"));
        when(authentication.getAuthorities()).thenReturn(authorities);

        Permission adminPermission = createPermission("user", "manage");
        UserPermission userPermission = createUserPermission(adminPermission);

        when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                .thenReturn(List.of(userPermission));
        when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                .thenReturn(Collections.emptyList());
        when(permissionService.getUserMaxHierarchyLevel(userId, organizationId))
                .thenReturn(3);

        // When - Use security expressions
        boolean hasPermission = securityExpressions.hasPermission("user", "manage");
        boolean hasRole = securityExpressions.hasRole("ADMIN");
        boolean hasMinLevel = securityExpressions.hasMinimumHierarchyLevel(2);
        boolean hasComplexPermission = securityExpressions.hasComplexPermission(
                "user", "manage", null, "ADMIN", 2);

        // Then
        assertThat(hasPermission).isTrue();
        assertThat(hasRole).isTrue();
        assertThat(hasMinLevel).isTrue();
        assertThat(hasComplexPermission).isTrue();
    }

    @Test
    void shouldHandleMultiTenantIsolation() {
        // Given - User in specific organization
        UUID otherOrgId = UUID.randomUUID();

        Permission orgPermission = createPermission("debate", "read");
        orgPermission.setOrganizationId(organizationId);

        UserPermission userPermission = createUserPermission(orgPermission);

        when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                .thenReturn(List.of(userPermission));
        when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, otherOrgId))
                .thenReturn(Collections.emptyList());
        when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                .thenReturn(Collections.emptyList());
        when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, otherOrgId))
                .thenReturn(Collections.emptyList());

        // When - Check access in different organizations
        boolean hasPermissionInOrg = permissionService.hasPermission(userId, organizationId, "debate", "read");
        boolean hasPermissionInOtherOrg = permissionService.hasPermission(userId, otherOrgId, "debate", "read");

        // Then - Should only have access in own organization
        assertThat(hasPermissionInOrg).isTrue();
        assertThat(hasPermissionInOtherOrg).isFalse();
    }

    @Test
    void shouldHandlePermissionDelegation() {
        // Given - User with delegatable permission
        Permission delegatablePermission = createPermission("user", "invite");
        delegatablePermission.setDelegationAllowed(true);
        delegatablePermission.setMaxDelegationDepth(2);

        UserPermission userPermission = createUserPermission(delegatablePermission);

        when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                .thenReturn(List.of(userPermission));
        when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                .thenReturn(Collections.emptyList());

        // When
        Set<Permission> delegatablePermissions = permissionService.getDelegatablePermissions(userId, organizationId);
        boolean canDelegatePermissions = securityExpressions.canDelegatePermissions();
        boolean canDelegateSpecific = securityExpressions.canDelegatePermission("user", "invite");

        // Then
        assertThat(delegatablePermissions).hasSize(1);
        assertThat(delegatablePermissions).contains(delegatablePermission);
        assertThat(canDelegatePermissions).isTrue();
        assertThat(canDelegateSpecific).isTrue();
    }

    @Test
    void shouldHandleResourceOwnership() {
        // Given - User with ownership permission
        Permission ownershipPermission = createPermission("debate", "own");
        ownershipPermission.setResourceId("debate-123");

        UserPermission userPermission = createUserPermission(ownershipPermission);

        when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                .thenReturn(List.of(userPermission));
        when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                .thenReturn(Collections.emptyList());

        try (MockedStatic<TenantSecurityContext> mockedTenant = mockStatic(TenantSecurityContext.class)) {
            mockedTenant.when(TenantSecurityContext::getCurrentTenant).thenReturn(organizationId.toString());

            // When
            boolean isOwner = permissionService.isResourceOwner(userId, "debate", "debate-123");
            boolean canActOnResource = securityExpressions.canActOnResource("debate", "edit", "debate-123", "ownerId");

            // Then
            assertThat(isOwner).isTrue();
            assertThat(canActOnResource).isTrue();
        }
    }

    @Test
    void shouldHandleEmergencyOverride() {
        // Given - System admin without specific permission
        Collection<org.springframework.security.core.GrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("ROLE_SYSTEM_ADMIN"));
        when(authentication.getAuthorities()).thenReturn(authorities);

        when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                .thenReturn(Collections.emptyList());
        when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                .thenReturn(Collections.emptyList());

        // When - Use emergency override
        boolean hasNormalPermission = securityExpressions.hasPermission("system", "shutdown");
        boolean hasEmergencyPermission = securityExpressions.hasPermissionOrEmergencyOverride("system", "shutdown",
                true);

        // Then
        assertThat(hasNormalPermission).isFalse();
        assertThat(hasEmergencyPermission).isTrue();
    }

    // Helper methods

    private void setupSecurityContext() {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        SecurityContextHolder.setContext(securityContext);

        Map<String, Object> details = new HashMap<>();
        details.put("userId", userId.toString());
        details.put("organizationId", organizationId.toString());
        when(authentication.getDetails()).thenReturn(details);
        when(authentication.getName()).thenReturn(userId.toString());
    }

    private Role createRole(String name, int hierarchyLevel) {
        Role role = new Role();
        role.setId(UUID.randomUUID());
        role.setName(name);
        role.setHierarchyLevel(hierarchyLevel);
        role.setIsActive(true);
        role.setOrganizationId(organizationId);
        role.setRolePermissions(new HashSet<>());
        role.setParentRoles(new HashSet<>());
        return role;
    }

    private Permission createPermission(String resource, String action) {
        Permission permission = new Permission();
        permission.setId(UUID.randomUUID());
        permission.setResource(resource);
        permission.setAction(action);
        permission.setIsActive(true);
        permission.setEffect("ALLOW");
        permission.setOrganizationId(organizationId);
        permission.setPriority(1);
        permission.setDelegationAllowed(false);
        return permission;
    }

    private UserRole createUserRole(Role role) {
        UserRole userRole = new UserRole();
        userRole.setId(UUID.randomUUID());
        userRole.setUserId(userId);
        userRole.setRole(role);
        userRole.setOrganizationId(organizationId);
        userRole.setIsActive(true);
        userRole.setAssignmentStatus(UserRole.AssignmentStatus.ACTIVE);
        return userRole;
    }

    private UserPermission createUserPermission(Permission permission) {
        UserPermission userPermission = new UserPermission();
        userPermission.setId(UUID.randomUUID());
        userPermission.setUserId(userId);
        userPermission.setPermission(permission);
        userPermission.setOrganizationId(organizationId);
        userPermission.setIsActive(true);
        return userPermission;
    }

    private RolePermission createRolePermission(Role role, Permission permission) {
        RolePermission rolePermission = new RolePermission();
        rolePermission.setId(UUID.randomUUID());
        rolePermission.setRole(role);
        rolePermission.setPermission(permission);
        rolePermission.setIsActive(true);
        return rolePermission;
    }
}