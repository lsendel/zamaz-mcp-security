package com.zamaz.mcp.security.testing;

import com.zamaz.mcp.security.domain.Permission;
import com.zamaz.mcp.security.domain.Role;
import com.zamaz.mcp.security.domain.SecurityContext;
import com.zamaz.mcp.security.service.AuthorizationService;
import org.assertj.core.api.AbstractAssert;
import org.assertj.core.api.Assertions;

import java.util.*;
import java.util.function.Consumer;

/**
 * Utilities for testing RBAC (Role-Based Access Control) and permissions.
 */
public class PermissionTestUtils {

    /**
     * Creates a permission matrix for testing different role/permission combinations.
     */
    public static PermissionMatrix createPermissionMatrix() {
        return new PermissionMatrix();
    }

    /**
     * Asserts permissions for a security context.
     */
    public static PermissionAssert assertPermissions(SecurityContext context) {
        return new PermissionAssert(context);
    }

    /**
     * Tests a permission check against multiple contexts.
     */
    public static void testPermissionAcrossContexts(
            AuthorizationService authService,
            Permission permission,
            Map<SecurityContext, Boolean> expectedResults) {
        
        expectedResults.forEach((context, expected) -> {
            SecurityTestContext.runAs(context, () -> {
                boolean hasPermission = authService.hasPermission(permission);
                Assertions.assertThat(hasPermission)
                    .as("Permission %s for context %s", permission, context.getUserId())
                    .isEqualTo(expected);
            });
        });
    }

    /**
     * Matrix for testing permissions across different roles and contexts.
     */
    public static class PermissionMatrix {
        private final Map<Role, Set<Permission>> rolePermissions = new HashMap<>();
        private final Map<String, Map<String, Set<Permission>>> contextPermissions = new HashMap<>();

        public PermissionMatrix withRolePermissions(Role role, Permission... permissions) {
            rolePermissions.computeIfAbsent(role, k -> new HashSet<>())
                .addAll(Arrays.asList(permissions));
            return this;
        }

        public PermissionMatrix withContextPermissions(String context, String resource, Permission... permissions) {
            contextPermissions.computeIfAbsent(context, k -> new HashMap<>())
                .computeIfAbsent(resource, k -> new HashSet<>())
                .addAll(Arrays.asList(permissions));
            return this;
        }

        public boolean shouldHavePermission(Role role, Permission permission) {
            return rolePermissions.getOrDefault(role, Collections.emptySet())
                .contains(permission);
        }

        public boolean shouldHavePermission(String context, String resource, Permission permission) {
            return contextPermissions.getOrDefault(context, Collections.emptyMap())
                .getOrDefault(resource, Collections.emptySet())
                .contains(permission);
        }

        public void testAllCombinations(Consumer<TestCase> testExecutor) {
            // Test role-based permissions
            for (Role role : Role.values()) {
                for (Permission permission : Permission.values()) {
                    boolean expected = shouldHavePermission(role, permission);
                    testExecutor.accept(new TestCase(role, permission, expected));
                }
            }
        }

        public static class TestCase {
            public final Role role;
            public final Permission permission;
            public final boolean expected;

            public TestCase(Role role, Permission permission, boolean expected) {
                this.role = role;
                this.permission = permission;
                this.expected = expected;
            }
        }
    }

    /**
     * Assertions for permission testing.
     */
    public static class PermissionAssert extends AbstractAssert<PermissionAssert, SecurityContext> {

        public PermissionAssert(SecurityContext actual) {
            super(actual, PermissionAssert.class);
        }

        public PermissionAssert hasGlobalPermission(Permission permission) {
            isNotNull();
            Assertions.assertThat(actual.getGlobalPermissions())
                .as("Global permissions")
                .contains(permission);
            return this;
        }

        public PermissionAssert doesNotHaveGlobalPermission(Permission permission) {
            isNotNull();
            Assertions.assertThat(actual.getGlobalPermissions())
                .as("Global permissions")
                .doesNotContain(permission);
            return this;
        }

        public PermissionAssert hasOrganizationPermission(String orgId, Permission permission) {
            isNotNull();
            Set<Permission> orgPerms = actual.getOrganizationPermissions().get(orgId);
            Assertions.assertThat(orgPerms)
                .as("Organization permissions for " + orgId)
                .isNotNull()
                .contains(permission);
            return this;
        }

        public PermissionAssert hasRole(Role role) {
            isNotNull();
            Assertions.assertThat(actual.getRoles())
                .as("Roles")
                .contains(role);
            return this;
        }

        public PermissionAssert hasExactlyRoles(Role... roles) {
            isNotNull();
            Assertions.assertThat(actual.getRoles())
                .as("Roles")
                .containsExactlyInAnyOrder(roles);
            return this;
        }

        public PermissionAssert canAccessOrganization(String orgId) {
            isNotNull();
            boolean canAccess = actual.getOrganizationId() != null && 
                               actual.getOrganizationId().equals(orgId) ||
                               actual.getOrganizationPermissions().containsKey(orgId);
            Assertions.assertThat(canAccess)
                .as("Can access organization " + orgId)
                .isTrue();
            return this;
        }

        public PermissionAssert isSystemAdmin() {
            return hasRole(Role.SYSTEM_ADMIN);
        }

        public PermissionAssert isOrgAdmin() {
            return hasRole(Role.ORG_ADMIN);
        }

        public PermissionAssert hasPermissionCount(int count) {
            isNotNull();
            int totalPerms = actual.getGlobalPermissions().size() +
                           actual.getOrganizationPermissions().values().stream()
                               .mapToInt(Set::size)
                               .sum() +
                           actual.getContextPermissions().values().stream()
                               .mapToInt(Set::size)
                               .sum();
            Assertions.assertThat(totalPerms)
                .as("Total permission count")
                .isEqualTo(count);
            return this;
        }
    }

    /**
     * Helper to create test scenarios for permission inheritance.
     */
    public static class PermissionHierarchyTest {
        private final List<HierarchyLevel> levels = new ArrayList<>();

        public PermissionHierarchyTest withLevel(String name, Permission... permissions) {
            levels.add(new HierarchyLevel(name, new HashSet<>(Arrays.asList(permissions))));
            return this;
        }

        public void testInheritance(Consumer<HierarchyTestCase> testExecutor) {
            for (int i = 0; i < levels.size(); i++) {
                Set<Permission> expectedPermissions = new HashSet<>();
                for (int j = 0; j <= i; j++) {
                    expectedPermissions.addAll(levels.get(j).permissions);
                }
                testExecutor.accept(new HierarchyTestCase(
                    levels.get(i).name,
                    expectedPermissions
                ));
            }
        }

        public static class HierarchyLevel {
            public final String name;
            public final Set<Permission> permissions;

            public HierarchyLevel(String name, Set<Permission> permissions) {
                this.name = name;
                this.permissions = permissions;
            }
        }

        public static class HierarchyTestCase {
            public final String level;
            public final Set<Permission> expectedPermissions;

            public HierarchyTestCase(String level, Set<Permission> expectedPermissions) {
                this.level = level;
                this.expectedPermissions = expectedPermissions;
            }
        }
    }

    /**
     * Creates test data for resource-based permissions.
     */
    public static class ResourcePermissionBuilder {
        private final Map<String, ResourcePermissions> resources = new HashMap<>();

        public ResourcePermissionBuilder withResource(String resourceId, String ownerId) {
            resources.put(resourceId, new ResourcePermissions(resourceId, ownerId));
            return this;
        }

        public ResourcePermissionBuilder grantPermission(String resourceId, String userId, Permission... permissions) {
            resources.get(resourceId).userPermissions
                .computeIfAbsent(userId, k -> new HashSet<>())
                .addAll(Arrays.asList(permissions));
            return this;
        }

        public ResourcePermissions getResource(String resourceId) {
            return resources.get(resourceId);
        }

        public static class ResourcePermissions {
            public final String resourceId;
            public final String ownerId;
            public final Map<String, Set<Permission>> userPermissions = new HashMap<>();

            public ResourcePermissions(String resourceId, String ownerId) {
                this.resourceId = resourceId;
                this.ownerId = ownerId;
            }

            public boolean hasPermission(String userId, Permission permission) {
                if (userId.equals(ownerId)) {
                    return true; // Owners have all permissions
                }
                return userPermissions.getOrDefault(userId, Collections.emptySet())
                    .contains(permission);
            }
        }
    }
}