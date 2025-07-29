package com.zamaz.mcp.security.service;

import com.zamaz.mcp.security.entity.*;
import com.zamaz.mcp.security.repository.PermissionRepository;
import com.zamaz.mcp.security.repository.UserPermissionRepository;
import com.zamaz.mcp.security.repository.UserRoleRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PermissionServiceTest {

        @Mock
        private PermissionRepository permissionRepository;

        @Mock
        private UserRoleRepository userRoleRepository;

        @Mock
        private UserPermissionRepository userPermissionRepository;

        @Mock
        private PermissionEvaluationEngine permissionEvaluationEngine;

        private PermissionService permissionService;

        private UUID userId;
        private UUID organizationId;
        private UUID roleId;
        private UUID permissionId;

        @BeforeEach
        void setUp() {
                permissionService = new PermissionService(
                                permissionRepository,
                                userRoleRepository,
                                userPermissionRepository,
                                permissionEvaluationEngine);

                userId = UUID.randomUUID();
                organizationId = UUID.randomUUID();
                roleId = UUID.randomUUID();
                permissionId = UUID.randomUUID();
        }

        @Test
        void shouldGrantPermissionWhenUserHasDirectPermission() {
                // Given
                Permission permission = createPermission("debate", "read");
                UserPermission userPermission = createUserPermission(permission);

                when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(List.of(userPermission));
                when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(Collections.emptyList());
                when(permissionEvaluationEngine.evaluateConditions(eq(permission), any()))
                                .thenReturn(true);

                // When
                boolean hasPermission = permissionService.hasPermission(userId, organizationId, "debate", "read");

                // Then
                assertThat(hasPermission).isTrue();
        }

        @Test
        void shouldGrantPermissionWhenUserHasRoleBasedPermission() {
                // Given
                Permission permission = createPermission("debate", "write");
                Role role = createRole("MODERATOR");
                RolePermission rolePermission = createRolePermission(role, permission);
                UserRole userRole = createUserRole(role);

                role.setRolePermissions(Set.of(rolePermission));

                when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(Collections.emptyList());
                when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(List.of(userRole));
                when(permissionEvaluationEngine.evaluateConditions(eq(permission), any()))
                                .thenReturn(true);

                // When
                boolean hasPermission = permissionService.hasPermission(userId, organizationId, "debate", "write");

                // Then
                assertThat(hasPermission).isTrue();
        }

        @Test
        void shouldDenyPermissionWhenUserHasNoPermission() {
                // Given
                when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(Collections.emptyList());
                when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(Collections.emptyList());

                // When
                boolean hasPermission = permissionService.hasPermission(userId, organizationId, "debate", "delete");

                // Then
                assertThat(hasPermission).isFalse();
        }

        @Test
        void shouldDenyPermissionWhenConditionsNotMet() {
                // Given
                Permission permission = createPermission("debate", "read");
                UserPermission userPermission = createUserPermission(permission);

                when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(List.of(userPermission));
                when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(Collections.emptyList());
                when(permissionEvaluationEngine.evaluateConditions(eq(permission), any()))
                                .thenReturn(false);

                // When
                boolean hasPermission = permissionService.hasPermission(userId, organizationId, "debate", "read");

                // Then
                assertThat(hasPermission).isFalse();
        }

        @Test
        void shouldGrantPermissionForSpecificResourceInstance() {
                // Given
                Permission permission = createPermission("debate", "edit");
                permission.setResourceId("debate-123");
                UserPermission userPermission = createUserPermission(permission);

                when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(List.of(userPermission));
                when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(Collections.emptyList());
                when(permissionEvaluationEngine.evaluateConditions(eq(permission), any()))
                                .thenReturn(true);

                // When
                boolean hasPermission = permissionService.hasPermission(userId, organizationId, "debate", "edit",
                                "debate-123");

                // Then
                assertThat(hasPermission).isTrue();
        }

        @Test
        void shouldDenyPermissionForDifferentResourceInstance() {
                // Given
                Permission permission = createPermission("debate", "edit");
                permission.setResourceId("debate-123");
                UserPermission userPermission = createUserPermission(permission);

                when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(List.of(userPermission));
                when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(Collections.emptyList());

                // When
                boolean hasPermission = permissionService.hasPermission(userId, organizationId, "debate", "edit",
                                "debate-456");

                // Then
                assertThat(hasPermission).isFalse();
        }

        @Test
        void shouldHandleHierarchicalRoles() {
                // Given
                Permission permission = createPermission("user", "manage");
                Role parentRole = createRole("ADMIN");
                Role childRole = createRole("MODERATOR");

                parentRole.setHierarchyLevel(2);
                childRole.setHierarchyLevel(1);
                childRole.setParentRoles(Set.of(parentRole));

                RolePermission rolePermission = createRolePermission(parentRole, permission);
                parentRole.setRolePermissions(Set.of(rolePermission));

                UserRole userRole = createUserRole(childRole);

                when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(Collections.emptyList());
                when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(List.of(userRole));
                when(permissionEvaluationEngine.evaluateConditions(eq(permission), any()))
                                .thenReturn(true);

                // When
                boolean hasPermission = permissionService.hasPermission(userId, organizationId, "user", "manage");

                // Then
                assertThat(hasPermission).isTrue();
        }

        @Test
        void shouldReturnUserEffectivePermissions() {
                // Given
                Permission directPermission = createPermission("debate", "read");
                Permission rolePermission = createPermission("user", "view");

                UserPermission userPermission = createUserPermission(directPermission);

                Role role = createRole("USER");
                RolePermission rolePerm = createRolePermission(role, rolePermission);
                role.setRolePermissions(Set.of(rolePerm));
                UserRole userRole = createUserRole(role);

                when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(List.of(userPermission));
                when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(List.of(userRole));

                // When
                Set<Permission> permissions = permissionService.getUserEffectivePermissions(userId, organizationId);

                // Then
                assertThat(permissions).hasSize(2);
                assertThat(permissions).contains(directPermission, rolePermission);
        }

        @Test
        void shouldCheckUserInOrganization() {
                // Given
                when(userRoleRepository.existsByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(true);

                // When
                boolean isInOrganization = permissionService.isUserInOrganization(userId, organizationId);

                // Then
                assertThat(isInOrganization).isTrue();
        }

        @Test
        void shouldGetUserMaxHierarchyLevel() {
                // Given
                Role role1 = createRole("USER");
                role1.setHierarchyLevel(1);
                Role role2 = createRole("ADMIN");
                role2.setHierarchyLevel(3);

                UserRole userRole1 = createUserRole(role1);
                UserRole userRole2 = createUserRole(role2);

                when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(List.of(userRole1, userRole2));

                // When
                int maxLevel = permissionService.getUserMaxHierarchyLevel(userId, organizationId);

                // Then
                assertThat(maxLevel).isEqualTo(3);
        }

        @Test
        void shouldHandleAttributeBasedPermissions() {
                // Given
                Permission permission = createPermission("document", "access");
                permission.setConditionExpression("userDepartment == 'FINANCE'");
                permission.setSubjectAttributes("{\"department\": \"FINANCE\"}");

                UserPermission userPermission = createUserPermission(permission);

                when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(List.of(userPermission));
                when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(Collections.emptyList());
                when(permissionEvaluationEngine.evaluateConditions(eq(permission), any()))
                                .thenReturn(true);

                // When
                boolean hasPermission = permissionService.hasPermission(userId, organizationId, "document", "access");

                // Then
                assertThat(hasPermission).isTrue();
        }

        @Test
        void shouldDenyPermissionWhenAttributeConditionsNotMet() {
                // Given
                Permission permission = createPermission("document", "access");
                permission.setConditionExpression("userDepartment == 'FINANCE'");
                permission.setSubjectAttributes("{\"department\": \"FINANCE\"}");

                UserPermission userPermission = createUserPermission(permission);

                when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(List.of(userPermission));
                when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(Collections.emptyList());
                when(permissionEvaluationEngine.evaluateConditions(eq(permission), any()))
                                .thenReturn(false);

                // When
                boolean hasPermission = permissionService.hasPermission(userId, organizationId, "document", "access");

                // Then
                assertThat(hasPermission).isFalse();
        }

        @Test
        void shouldHandleDenyPermissions() {
                // Given
                Permission allowPermission = createPermission("debate", "read");
                allowPermission.setEffect("ALLOW");
                allowPermission.setPriority(1);

                Permission denyPermission = createPermission("debate", "read");
                denyPermission.setEffect("DENY");
                denyPermission.setPriority(2);
                denyPermission.setResourceId("debate-123");

                UserPermission userPermission1 = createUserPermission(allowPermission);
                UserPermission userPermission2 = createUserPermission(denyPermission);

                when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(List.of(userPermission1, userPermission2));
                when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(Collections.emptyList());
                when(permissionEvaluationEngine.evaluateConditions(any(), any()))
                                .thenReturn(true);

                // When - should deny access to specific resource due to DENY permission
                boolean hasPermission = permissionService.hasPermission(userId, organizationId, "debate", "read",
                                "debate-123");

                // Then
                assertThat(hasPermission).isFalse();
        }

        @Test
        void shouldHandleResourcePatternMatching() {
                // Given
                Permission permission = createPermission("debate", "read");
                permission.setResourcePattern("debate:org1:*");

                UserPermission userPermission = createUserPermission(permission);

                when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(List.of(userPermission));
                when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(Collections.emptyList());
                when(permissionEvaluationEngine.evaluateConditions(eq(permission), any()))
                                .thenReturn(true);

                // When
                boolean hasPermission = permissionService.hasPermission(userId, organizationId, "debate", "read",
                                "debate:org1:123");

                // Then
                assertThat(hasPermission).isTrue();
        }

        @Test
        void shouldHandleTimeBasedPermissions() {
                // Given
                Permission permission = createPermission("system", "maintenance");
                permission.setTimeBased(true);
                permission.setValidFrom(LocalDateTime.now().minusHours(1));
                permission.setValidUntil(LocalDateTime.now().plusHours(1));
                permission.setHoursOfDay("09:00-17:00");

                UserPermission userPermission = createUserPermission(permission);

                when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(List.of(userPermission));
                when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(Collections.emptyList());
                when(permissionEvaluationEngine.evaluateConditions(eq(permission), any()))
                                .thenReturn(true);

                // When
                boolean hasPermission = permissionService.hasPermission(userId, organizationId, "system",
                                "maintenance");

                // Then
                assertThat(hasPermission).isTrue();
        }

        @Test
        void shouldHandleCanManageUserHierarchy() {
                // Given
                Role managerRole = createRole("MANAGER");
                managerRole.setHierarchyLevel(3);

                Role userRole = createRole("USER");
                userRole.setHierarchyLevel(1);

                UUID targetUserId = UUID.randomUUID();

                when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(List.of(createUserRole(managerRole)));
                when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(targetUserId, organizationId))
                                .thenReturn(List.of(createUserRole(userRole)));

                // When
                boolean canManage = permissionService.canManageUser(userId, targetUserId, organizationId);

                // Then
                assertThat(canManage).isTrue();
        }

        @Test
        void shouldDenyManageUserWhenSameHierarchyLevel() {
                // Given
                Role role = createRole("MANAGER");
                role.setHierarchyLevel(2);

                UUID targetUserId = UUID.randomUUID();

                when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(List.of(createUserRole(role)));
                when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(targetUserId, organizationId))
                                .thenReturn(List.of(createUserRole(role)));

                // When
                boolean canManage = permissionService.canManageUser(userId, targetUserId, organizationId);

                // Then
                assertThat(canManage).isFalse();
        }

        @Test
        void shouldGetDelegatablePermissions() {
                // Given
                Permission delegatablePermission = createPermission("user", "invite");
                delegatablePermission.setDelegationAllowed(true);

                Permission nonDelegatablePermission = createPermission("system", "admin");
                nonDelegatablePermission.setDelegationAllowed(false);

                UserPermission userPermission1 = createUserPermission(delegatablePermission);
                UserPermission userPermission2 = createUserPermission(nonDelegatablePermission);

                when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(List.of(userPermission1, userPermission2));
                when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(Collections.emptyList());

                // When
                Set<Permission> delegatablePermissions = permissionService.getDelegatablePermissions(userId,
                                organizationId);

                // Then
                assertThat(delegatablePermissions).hasSize(1);
                assertThat(delegatablePermissions).contains(delegatablePermission);
        }

        @Test
        void shouldHandleMultiplePermissionChecks() {
                // Given
                Permission readPermission = createPermission("debate", "read");
                Permission writePermission = createPermission("debate", "write");

                UserPermission userPermission1 = createUserPermission(readPermission);
                UserPermission userPermission2 = createUserPermission(writePermission);

                when(userPermissionRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(List.of(userPermission1, userPermission2));
                when(userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId))
                                .thenReturn(Collections.emptyList());
                when(permissionEvaluationEngine.evaluateConditions(any(), any()))
                                .thenReturn(true);

                // When - check if user has any of the permissions
                boolean hasAnyPermission = permissionService.hasAnyPermission(userId, organizationId, "debate", "read",
                                "delete");

                // Then
                assertThat(hasAnyPermission).isTrue();

                // When - check if user has all permissions
                boolean hasAllPermissions = permissionService.hasAllPermissions(userId, organizationId, "debate",
                                "read", "write");

                // Then
                assertThat(hasAllPermissions).isTrue();

                // When - check if user has all permissions (including one they don't have)
                boolean hasAllIncludingMissing = permissionService.hasAllPermissions(userId, organizationId, "debate",
                                "read", "write", "delete");

                // Then
                assertThat(hasAllIncludingMissing).isFalse();
        }

        // Helper methods

        private Permission createPermission(String resource, String action) {
                Permission permission = new Permission();
                permission.setId(permissionId);
                permission.setResource(resource);
                permission.setAction(action);
                permission.setIsActive(true);
                permission.setEffect("ALLOW");
                permission.setOrganizationId(organizationId);
                return permission;
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

        private Role createRole(String name) {
                Role role = new Role();
                role.setId(roleId);
                role.setName(name);
                role.setIsActive(true);
                role.setOrganizationId(organizationId);
                role.setRolePermissions(new HashSet<>());
                role.setParentRoles(new HashSet<>());
                return role;
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

        private RolePermission createRolePermission(Role role, Permission permission) {
                RolePermission rolePermission = new RolePermission();
                rolePermission.setId(UUID.randomUUID());
                rolePermission.setRole(role);
                rolePermission.setPermission(permission);
                rolePermission.setIsActive(true);
                return rolePermission;
        }
}