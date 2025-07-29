package com.zamaz.mcp.security.expression;

import com.zamaz.mcp.security.entity.Permission;
import com.zamaz.mcp.security.service.PermissionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityExpressionsTest {

    @Mock
    private PermissionService permissionService;

    @Mock
    private Authentication authentication;

    @Mock
    private SecurityContext securityContext;

    private SecurityExpressions securityExpressions;

    private UUID userId;
    private UUID organizationId;

    @BeforeEach
    void setUp() {
        securityExpressions = new SecurityExpressions(permissionService);
        userId = UUID.randomUUID();
        organizationId = UUID.randomUUID();

        // Setup security context
        when(securityContext.getAuthentication()).thenReturn(authentication);
        SecurityContextHolder.setContext(securityContext);

        // Setup authentication details
        Map<String, Object> details = new HashMap<>();
        details.put("userId", userId.toString());
        details.put("organizationId", organizationId.toString());
        when(authentication.getDetails()).thenReturn(details);
        when(authentication.getName()).thenReturn(userId.toString());
    }

    @Test
    void shouldGrantPermissionWhenUserHasPermission() {
        // Given
        when(permissionService.hasPermission(userId, organizationId, "debate", "read"))
                .thenReturn(true);

        // When
        boolean hasPermission = securityExpressions.hasPermission("debate", "read");

        // Then
        assertThat(hasPermission).isTrue();
    }

    @Test
    void shouldDenyPermissionWhenUserLacksPermission() {
        // Given
        when(permissionService.hasPermission(userId, organizationId, "debate", "write"))
                .thenReturn(false);

        // When
        boolean hasPermission = securityExpressions.hasPermission("debate", "write");

        // Then
        assertThat(hasPermission).isFalse();
    }

    @Test
    void shouldGrantPermissionOnSpecificResource() {
        // Given
        when(permissionService.hasPermission(userId, organizationId, "debate", "edit", "debate-123"))
                .thenReturn(true);

        // When
        boolean hasPermission = securityExpressions.hasPermissionOnResource("debate", "edit", "debate-123");

        // Then
        assertThat(hasPermission).isTrue();
    }

    @Test
    void shouldGrantAnyPermissionWhenUserHasOne() {
        // Given
        when(permissionService.hasAnyPermission(userId, organizationId, "debate", "read", "write"))
                .thenReturn(true);

        // When
        boolean hasAnyPermission = securityExpressions.hasAnyPermission("debate", "read", "write");

        // Then
        assertThat(hasAnyPermission).isTrue();
    }

    @Test
    void shouldGrantAllPermissionsWhenUserHasAll() {
        // Given
        when(permissionService.hasAllPermissions(userId, organizationId, "debate", "read", "write"))
                .thenReturn(true);

        // When
        boolean hasAllPermissions = securityExpressions.hasAllPermissions("debate", "read", "write");

        // Then
        assertThat(hasAllPermissions).isTrue();
    }

    @Test
    void shouldGrantOwnerOrPermissionWhenUserIsOwner() {
        // Given
        when(permissionService.isResourceOwner(userId, "debate", "debate-123"))
                .thenReturn(true);

        // When
        boolean canAct = securityExpressions.isOwnerOrHasPermission("debate", "edit", "debate-123");

        // Then
        assertThat(canAct).isTrue();
    }

    @Test
    void shouldGrantOwnerOrPermissionWhenUserHasPermission() {
        // Given
        when(permissionService.isResourceOwner(userId, "debate", "debate-123"))
                .thenReturn(false);
        when(permissionService.hasPermission(userId, organizationId, "debate", "edit", "debate-123"))
                .thenReturn(true);

        // When
        boolean canAct = securityExpressions.isOwnerOrHasPermission("debate", "edit", "debate-123");

        // Then
        assertThat(canAct).isTrue();
    }

    @Test
    void shouldCheckSameOrganization() {
        // Given
        UUID targetUserId = UUID.randomUUID();
        when(permissionService.isUserInOrganization(targetUserId, organizationId))
                .thenReturn(true);

        // When
        boolean isSameOrg = securityExpressions.isSameOrganization(targetUserId.toString());

        // Then
        assertThat(isSameOrg).isTrue();
    }

    @Test
    void shouldCheckUserManagementCapability() {
        // Given
        UUID targetUserId = UUID.randomUUID();
        when(permissionService.canManageUser(userId, targetUserId, organizationId))
                .thenReturn(true);

        // When
        boolean canManage = securityExpressions.canManageUser(targetUserId.toString());

        // Then
        assertThat(canManage).isTrue();
    }

    @Test
    void shouldCheckRoleBasedAccess() {
        // Given
        Collection<GrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("ROLE_ADMIN"),
                new SimpleGrantedAuthority("ROLE_USER"));
        when(authentication.getAuthorities()).thenReturn(authorities);

        // When
        boolean hasAdminRole = securityExpressions.hasRole("ADMIN");
        boolean hasUserRole = securityExpressions.hasRole("USER");
        boolean hasModeratorRole = securityExpressions.hasRole("MODERATOR");

        // Then
        assertThat(hasAdminRole).isTrue();
        assertThat(hasUserRole).isTrue();
        assertThat(hasModeratorRole).isFalse();
    }

    @Test
    void shouldCheckAnyRole() {
        // Given
        Collection<GrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("ROLE_USER"));
        when(authentication.getAuthorities()).thenReturn(authorities);

        // When
        boolean hasAnyRole = securityExpressions.hasAnyRole("ADMIN", "USER", "MODERATOR");

        // Then
        assertThat(hasAnyRole).isTrue();
    }

    @Test
    void shouldCheckMinimumHierarchyLevel() {
        // Given
        when(permissionService.getUserMaxHierarchyLevel(userId, organizationId))
                .thenReturn(3);

        // When
        boolean hasMinLevel = securityExpressions.hasMinimumHierarchyLevel(2);
        boolean hasHighLevel = securityExpressions.hasMinimumHierarchyLevel(4);

        // Then
        assertThat(hasMinLevel).isTrue();
        assertThat(hasHighLevel).isFalse();
    }

    @Test
    void shouldCheckSystemAdminRole() {
        // Given
        Collection<GrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("ROLE_SYSTEM_ADMIN"));
        when(authentication.getAuthorities()).thenReturn(authorities);

        // When
        boolean isSystemAdmin = securityExpressions.isSystemAdmin();

        // Then
        assertThat(isSystemAdmin).isTrue();
    }

    @Test
    void shouldCheckOrganizationAdminRole() {
        // Given
        Collection<GrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("ROLE_ORG_ADMIN"));
        when(authentication.getAuthorities()).thenReturn(authorities);

        // When
        boolean isOrgAdmin = securityExpressions.isOrganizationAdmin();

        // Then
        assertThat(isOrgAdmin).isTrue();
    }

    @Test
    void shouldCheckOrganizationAccess() {
        // Given
        when(permissionService.isUserInOrganization(userId, organizationId))
                .thenReturn(true);

        // When
        boolean canAccess = securityExpressions.canAccessOrganization(organizationId.toString());

        // Then
        assertThat(canAccess).isTrue();
    }

    @Test
    void shouldCheckResourceInUserOrganization() {
        // When
        boolean isInOrg = securityExpressions.isResourceInUserOrganization(organizationId.toString());

        // Then
        assertThat(isInOrg).isTrue();
    }

    @Test
    void shouldCheckDelegationCapability() {
        // Given
        Set<Permission> delegatablePermissions = Set.of(createPermission("user", "invite"));
        when(permissionService.getDelegatablePermissions(userId, organizationId))
                .thenReturn(delegatablePermissions);

        // When
        boolean canDelegate = securityExpressions.canDelegatePermissions();

        // Then
        assertThat(canDelegate).isTrue();
    }

    @Test
    void shouldHandleComplexPermissionCheck() {
        // Given
        when(permissionService.hasPermission(userId, organizationId, "debate", "moderate", "debate-123"))
                .thenReturn(true);
        when(permissionService.getUserMaxHierarchyLevel(userId, organizationId))
                .thenReturn(2);

        Collection<GrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("ROLE_MODERATOR"));
        when(authentication.getAuthorities()).thenReturn(authorities);

        // When
        boolean hasComplexPermission = securityExpressions.hasComplexPermission(
                "debate", "moderate", "debate-123", "MODERATOR", 1);

        // Then
        assertThat(hasComplexPermission).isTrue();
    }

    @Test
    void shouldHandlePermissionWithAttributes() {
        // Given
        Map<String, Object> userAttributes = Map.of("department", "FINANCE");
        Map<String, Object> resourceAttributes = Map.of("classification", "CONFIDENTIAL");

        when(permissionService.hasPermission(userId, organizationId, "document", "access", "doc-123"))
                .thenReturn(true);

        // When
        boolean hasPermission = securityExpressions.hasPermissionWithAttributes(
                "document", "access", "doc-123", userAttributes, resourceAttributes);

        // Then
        assertThat(hasPermission).isTrue();
    }

    @Test
    void shouldHandleTimeBasedPermissions() {
        // Given
        when(permissionService.hasPermission(userId, organizationId, "system", "maintenance"))
                .thenReturn(true);

        // When - during business hours
        boolean hasPermissionDuringHours = securityExpressions.hasPermissionAtTime(
                "system", "maintenance", "09:00-17:00");

        // Then
        assertThat(hasPermissionDuringHours).isTrue();
    }

    @Test
    void shouldHandleLocationBasedPermissions() {
        // Given
        when(permissionService.hasPermission(userId, organizationId, "sensitive", "access"))
                .thenReturn(true);

        // When
        boolean hasPermissionFromLocation = securityExpressions.hasPermissionFromLocation(
                "sensitive", "access", "192.168.1.100");

        // Then
        assertThat(hasPermissionFromLocation).isTrue();
    }

    @Test
    void shouldHandleResourceOwnershipOrPermission() {
        // Given
        when(permissionService.isResourceOwner(userId, "debate", "debate-123"))
                .thenReturn(true);

        // When
        boolean canAct = securityExpressions.canActOnResource("debate", "edit", "debate-123", "ownerId");

        // Then
        assertThat(canAct).isTrue();
    }

    @Test
    void shouldHandlePatternBasedPermissions() {
        // Given
        when(permissionService.hasPermission(userId, organizationId, "debate", "read"))
                .thenReturn(true);

        // When
        boolean hasPermission = securityExpressions.hasPermissionOnPattern("debate:org1:*", "read");

        // Then
        assertThat(hasPermission).isTrue();
    }

    @Test
    void shouldCheckElevatedPrivileges() {
        // Given
        Collection<GrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("ROLE_SYSTEM_ADMIN"));
        when(authentication.getAuthorities()).thenReturn(authorities);

        // When
        boolean hasElevatedPrivileges = securityExpressions.hasElevatedPrivileges();

        // Then
        assertThat(hasElevatedPrivileges).isTrue();
    }

    @Test
    void shouldHandleEmergencyOverride() {
        // Given
        when(permissionService.hasPermission(userId, organizationId, "system", "shutdown"))
                .thenReturn(false);

        Collection<GrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("ROLE_SYSTEM_ADMIN"));
        when(authentication.getAuthorities()).thenReturn(authorities);

        // When
        boolean hasPermissionWithOverride = securityExpressions.hasPermissionOrEmergencyOverride(
                "system", "shutdown", true);

        // Then
        assertThat(hasPermissionWithOverride).isTrue();
    }

    @Test
    void shouldCheckSpecificPermissionDelegation() {
        // Given
        Set<Permission> delegatablePermissions = Set.of(
                createPermission("user", "invite"),
                createPermission("debate", "moderate"));
        when(permissionService.getDelegatablePermissions(userId, organizationId))
                .thenReturn(delegatablePermissions);

        // When
        boolean canDelegateInvite = securityExpressions.canDelegatePermission("user", "invite");
        boolean canDelegateDelete = securityExpressions.canDelegatePermission("user", "delete");

        // Then
        assertThat(canDelegateInvite).isTrue();
        assertThat(canDelegateDelete).isFalse();
    }

    @Test
    void shouldHandleContextualPermissions() {
        // Given
        Map<String, Object> context = Map.of(
                "requestSource", "internal",
                "riskLevel", "low");
        when(permissionService.hasPermission(userId, organizationId, "api", "access"))
                .thenReturn(true);

        // When
        boolean hasContextualPermission = securityExpressions.hasContextualPermission(
                "api", "access", context);

        // Then
        assertThat(hasContextualPermission).isTrue();
    }

    @Test
    void shouldReturnFalseWhenNoAuthentication() {
        // Given
        SecurityContextHolder.clearContext();

        // When
        boolean hasPermission = securityExpressions.hasPermission("debate", "read");

        // Then
        assertThat(hasPermission).isFalse();
    }

    @Test
    void shouldHandleNullOrganizationId() {
        // Given
        Map<String, Object> details = new HashMap<>();
        details.put("userId", userId.toString());
        // No organizationId in details
        when(authentication.getDetails()).thenReturn(details);

        // When
        boolean isSameOrg = securityExpressions.isSameOrganization(UUID.randomUUID().toString());

        // Then
        assertThat(isSameOrg).isFalse();
    }

    // Helper methods

    private Permission createPermission(String resource, String action) {
        Permission permission = new Permission();
        permission.setId(UUID.randomUUID());
        permission.setResource(resource);
        permission.setAction(action);
        permission.setIsActive(true);
        permission.setDelegationAllowed(true);
        return permission;
    }
}