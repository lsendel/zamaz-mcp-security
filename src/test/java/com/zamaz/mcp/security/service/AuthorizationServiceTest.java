package com.zamaz.mcp.security.service;

import com.zamaz.mcp.security.model.ContextPermission;
import com.zamaz.mcp.security.model.McpUser;
import com.zamaz.mcp.security.model.Permission;
import com.zamaz.mcp.security.model.Role;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Authorization Service Tests")
class AuthorizationServiceTest {

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthorizationService authorizationService;

    private McpUser testUser;
    private McpUser systemAdminUser;
    private McpUser orgAdminUser;
    
    private String testOrgId;
    private String testResourceId;
    private String testContextId;
    
    private Permission debateCreatePermission;
    private Permission debateReadPermission;
    private Permission contextEditPermission;
    
    private Role userRole;
    private Role adminRole;
    private Role systemAdminRole;
    private Role orgAdminRole;

    @BeforeEach
    void setUp() {
        testOrgId = "org-123";
        testResourceId = "resource-456";
        testContextId = "context-789";
        
        // Create permissions
        debateCreatePermission = new Permission();
        debateCreatePermission.setName("debate:create");
        
        debateReadPermission = new Permission();
        debateReadPermission.setName("debate:read");
        
        contextEditPermission = new Permission();
        contextEditPermission.setName("context:edit");
        
        // Create roles
        userRole = new Role();
        userRole.setName("USER");
        userRole.setPermissions(Set.of(debateReadPermission));
        
        adminRole = new Role();
        adminRole.setName("ADMIN");
        adminRole.setPermissions(Set.of(debateCreatePermission, debateReadPermission, contextEditPermission));
        
        systemAdminRole = new Role();
        systemAdminRole.setName("SYSTEM_ADMIN");
        
        orgAdminRole = new Role();
        orgAdminRole.setName("ORG_ADMIN");
        orgAdminRole.setPermissions(Set.of(debateCreatePermission, debateReadPermission));
        
        // Create test users
        setupTestUser();
        setupSystemAdminUser();
        setupOrgAdminUser();
    }

    private void setupTestUser() {
        testUser = spy(new McpUser());
        testUser.setId("user-123");
        testUser.setUsername("testuser");
        testUser.setOrganizationIds(Arrays.asList(testOrgId));
        
        // Mock global permissions and roles
        when(testUser.getGlobalPermissions()).thenReturn(Set.of(debateReadPermission));
        when(testUser.getGlobalRoles()).thenReturn(Set.of(userRole));
        when(testUser.hasRole("USER")).thenReturn(true);
        when(testUser.hasRole("ADMIN")).thenReturn(false);
        when(testUser.hasRole("SYSTEM_ADMIN")).thenReturn(false);
        
        // Mock organization-specific permissions and roles
        when(testUser.getOrganizationPermissions(testOrgId)).thenReturn(Set.of(debateCreatePermission));
        when(testUser.getOrganizationRoles(testOrgId)).thenReturn(Set.of(adminRole));
        when(testUser.hasOrganizationRole(testOrgId, "ADMIN")).thenReturn(true);
        when(testUser.hasOrganizationRole(testOrgId, "ORG_ADMIN")).thenReturn(false);
        
        // Mock context permissions
        ContextPermission contextPerm = new ContextPermission();
        contextPerm.setContextId(testContextId);
        contextPerm.setPermission(contextEditPermission);
        when(testUser.getContextPermissions()).thenReturn(Set.of(contextPerm));
    }

    private void setupSystemAdminUser() {
        systemAdminUser = spy(new McpUser());
        systemAdminUser.setId("admin-123");
        systemAdminUser.setUsername("sysadmin");
        
        when(systemAdminUser.hasRole("SYSTEM_ADMIN")).thenReturn(true);
        when(systemAdminUser.getGlobalRoles()).thenReturn(Set.of(systemAdminRole));
    }

    private void setupOrgAdminUser() {
        orgAdminUser = spy(new McpUser());
        orgAdminUser.setId("orgadmin-123");
        orgAdminUser.setUsername("orgadmin");
        orgAdminUser.setOrganizationIds(Arrays.asList(testOrgId));
        
        when(orgAdminUser.hasRole("SYSTEM_ADMIN")).thenReturn(false);
        when(orgAdminUser.hasOrganizationRole(testOrgId, "ORG_ADMIN")).thenReturn(true);
        when(orgAdminUser.getOrganizationIds()).thenReturn(Arrays.asList(testOrgId));
    }

    @Nested
    @DisplayName("Permission Checking Tests")
    class PermissionCheckingTests {

        @Test
        @DisplayName("Should grant permission to system admin for any permission")
        void shouldGrantPermissionToSystemAdmin() {
            // When & Then
            assertThat(authorizationService.hasPermission(systemAdminUser, "any:permission", testOrgId))
                .isTrue();
            assertThat(authorizationService.hasPermission(systemAdminUser, "debate:create", null))
                .isTrue();
        }

        @Test
        @DisplayName("Should grant organization-specific permission")
        void shouldGrantOrganizationSpecificPermission() {
            // When & Then
            assertThat(authorizationService.hasPermission(testUser, "debate:create", testOrgId))
                .isTrue();
        }

        @Test
        @DisplayName("Should grant global permission")
        void shouldGrantGlobalPermission() {
            // When & Then
            assertThat(authorizationService.hasPermission(testUser, "debate:read", null))
                .isTrue();
            assertThat(authorizationService.hasPermission(testUser, "debate:read", testOrgId))
                .isTrue();
        }

        @Test
        @DisplayName("Should deny permission when user lacks both global and org permissions")
        void shouldDenyPermissionWhenUserLacksPermissions() {
            // Given
            String nonExistentPermission = "nonexistent:permission";
            
            // When & Then
            assertThat(authorizationService.hasPermission(testUser, nonExistentPermission, testOrgId))
                .isFalse();
            assertThat(authorizationService.hasPermission(testUser, nonExistentPermission, null))
                .isFalse();
        }

        @Test
        @DisplayName("Should deny org permission for different organization")
        void shouldDenyOrgPermissionForDifferentOrganization() {
            // Given
            String differentOrgId = "different-org-id";
            when(testUser.getOrganizationPermissions(differentOrgId)).thenReturn(Set.of());
            
            // When & Then
            assertThat(authorizationService.hasPermission(testUser, "debate:create", differentOrgId))
                .isFalse();
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = {" ", "\t"})
        @DisplayName("Should handle null and empty permissions gracefully")
        void shouldHandleNullAndEmptyPermissions(String permission) {
            // When & Then
            assertThat(authorizationService.hasPermission(testUser, permission, testOrgId))
                .isFalse();
        }
    }

    @Nested
    @DisplayName("Role Checking Tests")
    class RoleCheckingTests {

        @Test
        @DisplayName("Should grant organization-specific role")
        void shouldGrantOrganizationSpecificRole() {
            // When & Then
            assertThat(authorizationService.hasRole(testUser, "ADMIN", testOrgId))
                .isTrue();
        }

        @Test
        @DisplayName("Should grant global role")
        void shouldGrantGlobalRole() {
            // When & Then
            assertThat(authorizationService.hasRole(testUser, "USER", null))
                .isTrue();
            assertThat(authorizationService.hasRole(testUser, "USER", testOrgId))
                .isTrue();
        }

        @Test
        @DisplayName("Should deny role when user lacks both global and org roles")
        void shouldDenyRoleWhenUserLacksRoles() {
            // Given
            when(testUser.hasRole("SUPER_ADMIN")).thenReturn(false);
            when(testUser.getOrganizationRoles(testOrgId)).thenReturn(Set.of(userRole));
            
            // When & Then
            assertThat(authorizationService.hasRole(testUser, "SUPER_ADMIN", testOrgId))
                .isFalse();
        }

        @Test
        @DisplayName("Should deny org role for different organization")
        void shouldDenyOrgRoleForDifferentOrganization() {
            // Given
            String differentOrgId = "different-org-id";
            when(testUser.getOrganizationRoles(differentOrgId)).thenReturn(Set.of());
            
            // When & Then
            assertThat(authorizationService.hasRole(testUser, "ADMIN", differentOrgId))
                .isFalse();
        }

        @Test
        @DisplayName("Should handle role hierarchy correctly")
        void shouldHandleRoleHierarchyCorrectly() {
            // Given - ADMIN role in org should not grant SYSTEM_ADMIN
            // When & Then
            assertThat(authorizationService.hasRole(testUser, "SYSTEM_ADMIN", testOrgId))
                .isFalse();
        }
    }

    @Nested
    @DisplayName("Organization Access Tests")
    class OrganizationAccessTests {

        @Test
        @DisplayName("Should grant organization access to member")
        void shouldGrantOrganizationAccessToMember() {
            // When & Then
            assertThat(authorizationService.hasOrganizationAccess(testUser, testOrgId))
                .isTrue();
        }

        @Test
        @DisplayName("Should grant organization access to system admin")
        void shouldGrantOrganizationAccessToSystemAdmin() {
            // When & Then
            assertThat(authorizationService.hasOrganizationAccess(systemAdminUser, testOrgId))
                .isTrue();
            assertThat(authorizationService.hasOrganizationAccess(systemAdminUser, "any-org-id"))
                .isTrue();
        }

        @Test
        @DisplayName("Should deny organization access to non-member")
        void shouldDenyOrganizationAccessToNonMember() {
            // Given
            String nonMemberOrgId = "non-member-org";
            
            // When & Then
            assertThat(authorizationService.hasOrganizationAccess(testUser, nonMemberOrgId))
                .isFalse();
        }

        @Test
        @DisplayName("Should handle null organization ID")
        void shouldHandleNullOrganizationId() {
            // When & Then
            assertThat(authorizationService.hasOrganizationAccess(testUser, null))
                .isFalse();
        }
    }

    @Nested
    @DisplayName("Resource Ownership Tests")
    class ResourceOwnershipTests {

        @Test
        @DisplayName("Should grant ownership to resource owner")
        void shouldGrantOwnershipToResourceOwner() {
            // When & Then
            assertThat(authorizationService.hasResourceOwnership(testUser, testUser.getId()))
                .isTrue();
        }

        @Test
        @DisplayName("Should deny ownership to non-owner")
        void shouldDenyOwnershipToNonOwner() {
            // Given
            String differentUserId = "different-user-id";
            
            // When & Then
            assertThat(authorizationService.hasResourceOwnership(testUser, differentUserId))
                .isFalse();
        }

        @Test
        @DisplayName("Should handle null resource owner ID")
        void shouldHandleNullResourceOwnerId() {
            // When & Then
            assertThat(authorizationService.hasResourceOwnership(testUser, null))
                .isFalse();
        }
    }

    @Nested
    @DisplayName("Context Permission Tests")
    class ContextPermissionTests {

        @Test
        @DisplayName("Should grant context permission when user has it")
        void shouldGrantContextPermissionWhenUserHasIt() {
            // When & Then
            assertThat(authorizationService.hasContextPermission(testUser, testContextId, "context:edit"))
                .isTrue();
        }

        @Test
        @DisplayName("Should deny context permission when user lacks it")
        void shouldDenyContextPermissionWhenUserLacksIt() {
            // When & Then
            assertThat(authorizationService.hasContextPermission(testUser, testContextId, "context:delete"))
                .isFalse();
        }

        @Test
        @DisplayName("Should deny context permission for different context")
        void shouldDenyContextPermissionForDifferentContext() {
            // Given
            String differentContextId = "different-context-id";
            
            // When & Then
            assertThat(authorizationService.hasContextPermission(testUser, differentContextId, "context:edit"))
                .isFalse();
        }

        @Test
        @DisplayName("Should handle empty context permissions")
        void shouldHandleEmptyContextPermissions() {
            // Given
            when(testUser.getContextPermissions()).thenReturn(Set.of());
            
            // When & Then
            assertThat(authorizationService.hasContextPermission(testUser, testContextId, "context:edit"))
                .isFalse();
        }
    }

    @Nested
    @DisplayName("Resource Access Tests")
    class ResourceAccessTests {

        @Test
        @DisplayName("Should grant resource access to system admin")
        void shouldGrantResourceAccessToSystemAdmin() {
            // When & Then
            assertThat(authorizationService.hasResourceAccess(systemAdminUser, testResourceId, testOrgId))
                .isTrue();
        }

        @Test
        @DisplayName("Should grant resource access to org admin")
        void shouldGrantResourceAccessToOrgAdmin() {
            // When & Then
            assertThat(authorizationService.hasResourceAccess(orgAdminUser, testResourceId, testOrgId))
                .isTrue();
        }

        @Test
        @DisplayName("Should grant resource access to organization member")
        void shouldGrantResourceAccessToOrganizationMember() {
            // When & Then
            assertThat(authorizationService.hasResourceAccess(testUser, testResourceId, testOrgId))
                .isTrue();
        }

        @Test
        @DisplayName("Should deny resource access to non-member")
        void shouldDenyResourceAccessToNonMember() {
            // Given
            String nonMemberOrgId = "non-member-org";
            
            // When & Then
            assertThat(authorizationService.hasResourceAccess(testUser, testResourceId, nonMemberOrgId))
                .isFalse();
        }

        @Test
        @DisplayName("Should handle null organization ID in resource access")
        void shouldHandleNullOrganizationIdInResourceAccess() {
            // When & Then - without org context, only system admins should have access
            assertThat(authorizationService.hasResourceAccess(testUser, testResourceId, null))
                .isFalse();
            assertThat(authorizationService.hasResourceAccess(systemAdminUser, testResourceId, null))
                .isTrue();
        }
    }

    @Nested
    @DisplayName("User Permissions Aggregation Tests")
    class UserPermissionsAggregationTests {

        @Test
        @DisplayName("Should aggregate global and organization permissions")
        void shouldAggregateGlobalAndOrganizationPermissions() {
            // When
            Set<Permission> permissions = authorizationService.getUserPermissions(testUser, testOrgId);
            
            // Then
            assertThat(permissions).hasSize(2);
            assertThat(permissions).contains(debateReadPermission, debateCreatePermission);
        }

        @Test
        @DisplayName("Should return only global permissions when no organization specified")
        void shouldReturnOnlyGlobalPermissionsWhenNoOrganizationSpecified() {
            // When
            Set<Permission> permissions = authorizationService.getUserPermissions(testUser, null);
            
            // Then
            assertThat(permissions).hasSize(1);
            assertThat(permissions).contains(debateReadPermission);
        }

        @Test
        @DisplayName("Should handle user with no permissions")
        void shouldHandleUserWithNoPermissions() {
            // Given
            McpUser emptyUser = spy(new McpUser());
            when(emptyUser.getGlobalPermissions()).thenReturn(Set.of());
            when(emptyUser.getOrganizationPermissions(testOrgId)).thenReturn(Set.of());
            
            // When
            Set<Permission> permissions = authorizationService.getUserPermissions(emptyUser, testOrgId);
            
            // Then
            assertThat(permissions).isEmpty();
        }
    }

    @Nested
    @DisplayName("Edge Cases and Error Handling")
    class EdgeCasesAndErrorHandling {

        @Test
        @DisplayName("Should handle null user gracefully")
        void shouldHandleNullUserGracefully() {
            // When & Then
            assertThatThrownBy(() -> authorizationService.hasPermission(null, "any:permission", testOrgId))
                .isInstanceOf(NullPointerException.class);
        }

        @Test
        @DisplayName("Should handle user with null organization IDs")
        void shouldHandleUserWithNullOrganizationIds() {
            // Given
            McpUser userWithNullOrgs = spy(new McpUser());
            when(userWithNullOrgs.getOrganizationIds()).thenReturn(null);
            when(userWithNullOrgs.hasRole("SYSTEM_ADMIN")).thenReturn(false);
            
            // When & Then
            assertThatThrownBy(() -> authorizationService.hasOrganizationAccess(userWithNullOrgs, testOrgId))
                .isInstanceOf(NullPointerException.class);
        }

        @Test
        @DisplayName("Should handle user with null permissions collections")
        void shouldHandleUserWithNullPermissionsCollections() {
            // Given
            McpUser userWithNullPerms = spy(new McpUser());
            when(userWithNullPerms.hasRole("SYSTEM_ADMIN")).thenReturn(false);
            when(userWithNullPerms.getGlobalPermissions()).thenReturn(null);
            when(userWithNullPerms.getOrganizationPermissions(testOrgId)).thenReturn(null);
            
            // When & Then
            assertThatThrownBy(() -> authorizationService.hasPermission(userWithNullPerms, "any:permission", testOrgId))
                .isInstanceOf(NullPointerException.class);
        }

        @Test
        @DisplayName("Should handle concurrent access scenarios")
        void shouldHandleConcurrentAccessScenarios() {
            // This test ensures thread safety for authorization checks
            // Given
            List<Thread> threads = new ArrayList<>();
            List<Boolean> results = Collections.synchronizedList(new ArrayList<>());
            
            // When - multiple threads checking permissions simultaneously
            for (int i = 0; i < 10; i++) {
                Thread thread = new Thread(() -> {
                    boolean result = authorizationService.hasPermission(testUser, "debate:read", testOrgId);
                    results.add(result);
                });
                threads.add(thread);
                thread.start();
            }
            
            // Wait for all threads to complete
            threads.forEach(thread -> {
                try {
                    thread.join();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
            
            // Then - all results should be consistent
            assertThat(results).hasSize(10);
            assertThat(results).allMatch(result -> result); // All should be true
        }

        @Test
        @DisplayName("Should handle malformed permission names")
        void shouldHandleMalformedPermissionNames() {
            // Given
            String[] malformedPermissions = {
                "invalid-permission-format",
                "permission:",
                ":permission",
                "per:mis:sion:too:many:colons",
                "permission with spaces",
                "permission\nwith\nnewlines"
            };
            
            // When & Then
            for (String permission : malformedPermissions) {
                assertThat(authorizationService.hasPermission(testUser, permission, testOrgId))
                    .isFalse();
            }
        }
    }
}