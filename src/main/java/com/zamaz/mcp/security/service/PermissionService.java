package com.zamaz.mcp.security.service;

import com.zamaz.mcp.security.entity.*;
import com.zamaz.mcp.security.repository.PermissionRepository;
import com.zamaz.mcp.security.repository.UserPermissionRepository;
import com.zamaz.mcp.security.repository.UserRoleRepository;
import com.zamaz.mcp.security.tenant.TenantSecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Permission Service with resource-level and instance-level permission
 * checking.
 * Implements fine-grained RBAC with attribute-based access control support.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class PermissionService {

    private final PermissionRepository permissionRepository;
    private final UserRoleRepository userRoleRepository;
    private final UserPermissionRepository userPermissionRepository;
    private final PermissionEvaluationEngine permissionEvaluationEngine;

    /**
     * Check if user has permission for a resource and action.
     */
    @Cacheable(value = "permissions", key = "#userId + ':' + #organizationId + ':' + #resource + ':' + #action")
    public boolean hasPermission(UUID userId, UUID organizationId, String resource, String action) {
        return hasPermission(userId, organizationId, resource, action, null);
    }

    /**
     * Check if user has permission for a specific resource instance.
     */
    @Cacheable(value = "permissions", key = "#userId + ':' + #organizationId + ':' + #resource + ':' + #action + ':' + #resourceId")
    public boolean hasPermission(UUID userId, UUID organizationId, String resource, String action, String resourceId) {
        log.debug("Checking permission for user {} in org {} for {}:{} on resource {}",
                userId, organizationId, resource, action, resourceId);

        try {
            // Get all effective permissions for the user
            Set<Permission> userPermissions = getUserEffectivePermissions(userId, organizationId);

            // Evaluate permissions with context
            PermissionContext context = PermissionContext.builder()
                    .userId(userId)
                    .organizationId(organizationId)
                    .resource(resource)
                    .action(action)
                    .resourceId(resourceId)
                    .build();

            return evaluatePermissions(userPermissions, context);

        } catch (Exception e) {
            log.error("Error checking permission for user {} on {}:{}", userId, resource, action, e);
            return false; // Fail secure
        }
    }

    /**
     * Check if user has any of the specified permissions.
     */
    public boolean hasAnyPermission(UUID userId, UUID organizationId, String resource, String... actions) {
        for (String action : actions) {
            if (hasPermission(userId, organizationId, resource, action)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if user has all of the specified permissions.
     */
    public boolean hasAllPermissions(UUID userId, UUID organizationId, String resource, String... actions) {
        for (String action : actions) {
            if (!hasPermission(userId, organizationId, resource, action)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Get all effective permissions for a user (direct + role-based).
     */
    @Cacheable(value = "userPermissions", key = "#userId + ':' + #organizationId")
    public Set<Permission> getUserEffectivePermissions(UUID userId, UUID organizationId) {
        Set<Permission> allPermissions = new HashSet<>();

        // Get direct user permissions
        List<UserPermission> directPermissions = userPermissionRepository
                .findEffectiveByUserIdAndOrganizationId(userId, organizationId);

        allPermissions.addAll(directPermissions.stream()
                .map(UserPermission::getPermission)
                .collect(Collectors.toSet()));

        // Get role-based permissions
        List<UserRole> userRoles = userRoleRepository
                .findEffectiveByUserIdAndOrganizationId(userId, organizationId);

        for (UserRole userRole : userRoles) {
            Set<Permission> rolePermissions = getRoleEffectivePermissions(userRole.getRole());
            allPermissions.addAll(rolePermissions);
        }

        log.debug("Found {} effective permissions for user {} in organization {}",
                allPermissions.size(), userId, organizationId);

        return allPermissions;
    }

    /**
     * Get all effective permissions for a role (including inherited).
     */
    @Cacheable(value = "rolePermissions", key = "#role.id")
    public Set<Permission> getRoleEffectivePermissions(Role role) {
        Set<Permission> allPermissions = new HashSet<>();
        Set<Role> processedRoles = new HashSet<>();

        collectRolePermissions(role, allPermissions, processedRoles);

        return allPermissions;
    }

    /**
     * Recursively collect permissions from role hierarchy.
     */
    private void collectRolePermissions(Role role, Set<Permission> permissions, Set<Role> processedRoles) {
        if (processedRoles.contains(role) || !role.isEffective()) {
            return;
        }

        processedRoles.add(role);

        // Add direct role permissions
        role.getRolePermissions().stream()
                .filter(RolePermission::isEffective)
                .map(RolePermission::getPermission)
                .filter(Permission::isEffective)
                .forEach(permissions::add);

        // Add permissions from parent roles
        for (Role parentRole : role.getParentRoles()) {
            collectRolePermissions(parentRole, permissions, processedRoles);
        }
    }

    /**
     * Evaluate permissions against context with ABAC support.
     */
    private boolean evaluatePermissions(Set<Permission> permissions, PermissionContext context) {
        List<Permission> matchingPermissions = permissions.stream()
                .filter(p -> p.matches(context.getResource(), context.getAction(),
                        context.getResourceId(), context.getOrganizationId()))
                .sorted(Comparator.comparing(Permission::getPriority).reversed())
                .collect(Collectors.toList());

        if (matchingPermissions.isEmpty()) {
            log.debug("No matching permissions found for {}:{}", context.getResource(), context.getAction());
            return false;
        }

        // Evaluate permissions in priority order (DENY takes precedence)
        for (Permission permission : matchingPermissions) {
            if (permission.isDeny()) {
                log.debug("DENY permission found: {}", permission.getFullPermissionString());
                return false;
            }

            if (permission.isAllow()) {
                // Check additional conditions if present
                if (permissionEvaluationEngine.evaluateConditions(permission, context)) {
                    log.debug("ALLOW permission granted: {}", permission.getFullPermissionString());
                    return true;
                }
            }
        }

        log.debug("No ALLOW permissions matched conditions for {}:{}", context.getResource(), context.getAction());
        return false;
    }

    /**
     * Check if user owns a specific resource.
     */
    public boolean isResourceOwner(UUID userId, String resourceType, String resourceId) {
        log.debug("Checking resource ownership for user {} on {}:{}", userId, resourceType, resourceId);

        try {
            // Check for ownership permissions
            UUID currentTenant = null;
            if (TenantSecurityContext.getCurrentTenant() != null) {
                try {
                    currentTenant = UUID.fromString(TenantSecurityContext.getCurrentTenant());
                } catch (IllegalArgumentException e) {
                    log.warn("Invalid tenant ID format: {}", TenantSecurityContext.getCurrentTenant());
                }
            }
            Set<Permission> userPermissions = getUserEffectivePermissions(userId, currentTenant);

            // Look for ownership-specific permissions
            return userPermissions.stream()
                    .anyMatch(p -> p.getResource().equals(resourceType) &&
                            p.getAction().equals("own") &&
                            (p.getResourceId() == null || p.getResourceId().equals(resourceId)) &&
                            p.isEffective());
        } catch (Exception e) {
            log.error("Error checking resource ownership: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Check if user is in the specified organization.
     */
    public boolean isUserInOrganization(UUID userId, UUID organizationId) {
        return userRoleRepository.existsByUserIdAndOrganizationId(userId, organizationId);
    }

    /**
     * Get user's roles in an organization.
     */
    @Cacheable(value = "userRoles", key = "#userId + ':' + #organizationId")
    public Set<Role> getUserRoles(UUID userId, UUID organizationId) {
        return userRoleRepository.findEffectiveByUserIdAndOrganizationId(userId, organizationId)
                .stream()
                .map(UserRole::getRole)
                .collect(Collectors.toSet());
    }

    /**
     * Get user's highest hierarchy level in an organization.
     */
    public int getUserMaxHierarchyLevel(UUID userId, UUID organizationId) {
        return getUserRoles(userId, organizationId).stream()
                .mapToInt(Role::getHierarchyLevel)
                .max()
                .orElse(0);
    }

    /**
     * Check if user can manage another user (based on hierarchy).
     */
    public boolean canManageUser(UUID managerId, UUID targetUserId, UUID organizationId) {
        int managerLevel = getUserMaxHierarchyLevel(managerId, organizationId);
        int targetLevel = getUserMaxHierarchyLevel(targetUserId, organizationId);

        return managerLevel > targetLevel;
    }

    /**
     * Get permissions that can be delegated by a user.
     */
    public Set<Permission> getDelegatablePermissions(UUID userId, UUID organizationId) {
        return getUserEffectivePermissions(userId, organizationId).stream()
                .filter(Permission::canDelegate)
                .collect(Collectors.toSet());
    }

    /**
     * Permission evaluation context.
     */
    public static class PermissionContext {
        private UUID userId;
        private UUID organizationId;
        private String resource;
        private String action;
        private String resourceId;
        private Map<String, Object> attributes = new HashMap<>();
        private Map<String, Object> environmentContext = new HashMap<>();

        // Builder pattern
        public static PermissionContextBuilder builder() {
            return new PermissionContextBuilder();
        }

        // Getters
        public UUID getUserId() {
            return userId;
        }

        public UUID getOrganizationId() {
            return organizationId;
        }

        public String getResource() {
            return resource;
        }

        public String getAction() {
            return action;
        }

        public String getResourceId() {
            return resourceId;
        }

        public Map<String, Object> getAttributes() {
            return attributes;
        }

        public Map<String, Object> getEnvironmentContext() {
            return environmentContext;
        }

        public static class PermissionContextBuilder {
            private PermissionContext context = new PermissionContext();

            public PermissionContextBuilder userId(UUID userId) {
                context.userId = userId;
                return this;
            }

            public PermissionContextBuilder organizationId(UUID organizationId) {
                context.organizationId = organizationId;
                return this;
            }

            public PermissionContextBuilder resource(String resource) {
                context.resource = resource;
                return this;
            }

            public PermissionContextBuilder action(String action) {
                context.action = action;
                return this;
            }

            public PermissionContextBuilder resourceId(String resourceId) {
                context.resourceId = resourceId;
                return this;
            }

            public PermissionContextBuilder attribute(String key, Object value) {
                context.attributes.put(key, value);
                return this;
            }

            public PermissionContextBuilder environmentContext(String key, Object value) {
                context.environmentContext.put(key, value);
                return this;
            }

            public PermissionContext build() {
                return context;
            }
        }
    }
}