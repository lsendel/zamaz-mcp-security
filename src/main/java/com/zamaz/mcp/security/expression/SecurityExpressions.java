package com.zamaz.mcp.security.expression;

import com.zamaz.mcp.security.entity.Permission;
import com.zamaz.mcp.security.service.PermissionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Custom security expressions for @PreAuthorize annotations with SpEL support.
 * Provides fine-grained permission checking methods for use in method security.
 */
@Component("securityExpressions")
@RequiredArgsConstructor
@Slf4j
public class SecurityExpressions {

    private final PermissionService permissionService;

    /**
     * Check if current user has permission for resource and action.
     */
    public boolean hasPermission(String resource, String action) {
        Authentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }

        UUID userId = extractUserId(auth);
        UUID organizationId = extractOrganizationId(auth);

        return permissionService.hasPermission(userId, organizationId, resource, action);
    }

    /**
     * Check if current user has permission for specific resource instance.
     */
    public boolean hasPermissionOnResource(String resource, String action, String resourceId) {
        Authentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }

        UUID userId = extractUserId(auth);
        UUID organizationId = extractOrganizationId(auth);

        return permissionService.hasPermission(userId, organizationId, resource, action, resourceId);
    }

    /**
     * Check if current user has any of the specified permissions.
     */
    public boolean hasAnyPermission(String resource, String... actions) {
        Authentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }

        UUID userId = extractUserId(auth);
        UUID organizationId = extractOrganizationId(auth);

        return permissionService.hasAnyPermission(userId, organizationId, resource, actions);
    }

    /**
     * Check if current user has all of the specified permissions.
     */
    public boolean hasAllPermissions(String resource, String... actions) {
        Authentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }

        UUID userId = extractUserId(auth);
        UUID organizationId = extractOrganizationId(auth);

        return permissionService.hasAllPermissions(userId, organizationId, resource, actions);
    }

    /**
     * Check if current user owns the resource or has permission.
     */
    public boolean isOwnerOrHasPermission(String resource, String action, String resourceId) {
        Authentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }

        UUID userId = extractUserId(auth);
        UUID organizationId = extractOrganizationId(auth);

        // Check if user owns the resource
        if (permissionService.isResourceOwner(userId, resource, resourceId)) {
            return true;
        }

        // Check if user has explicit permission
        return permissionService.hasPermission(userId, organizationId, resource, action, resourceId);
    }

    /**
     * Check if current user is in the same organization as target user.
     */
    public boolean isSameOrganization(String targetUserId) {
        Authentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }

        UUID organizationId = extractOrganizationId(auth);
        if (organizationId == null) {
            return false;
        }

        return permissionService.isUserInOrganization(UUID.fromString(targetUserId), organizationId);
    }

    /**
     * Check if current user can manage target user (hierarchy-based).
     */
    public boolean canManageUser(String targetUserId) {
        Authentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }

        UUID managerId = extractUserId(auth);
        UUID organizationId = extractOrganizationId(auth);

        return permissionService.canManageUser(managerId, UUID.fromString(targetUserId), organizationId);
    }

    /**
     * Check if current user has role in current organization.
     */
    public boolean hasRole(String roleName) {
        Authentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }

        return auth.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals("ROLE_" + roleName.toUpperCase()));
    }

    /**
     * Check if current user has any of the specified roles.
     */
    public boolean hasAnyRole(String... roleNames) {
        Authentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }

        for (String roleName : roleNames) {
            if (hasRole(roleName)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if current user has minimum hierarchy level.
     */
    public boolean hasMinimumHierarchyLevel(int minimumLevel) {
        Authentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }

        UUID userId = extractUserId(auth);
        UUID organizationId = extractOrganizationId(auth);

        int userLevel = permissionService.getUserMaxHierarchyLevel(userId, organizationId);
        return userLevel >= minimumLevel;
    }

    /**
     * Check if current user is system admin.
     */
    public boolean isSystemAdmin() {
        return hasRole("SYSTEM_ADMIN") || hasRole("SUPER_ADMIN");
    }

    /**
     * Check if current user is organization admin.
     */
    public boolean isOrganizationAdmin() {
        return hasAnyRole("ORG_ADMIN", "ORGANIZATION_ADMIN", "ADMIN");
    }

    /**
     * Check if current user can access organization.
     */
    public boolean canAccessOrganization(String organizationId) {
        Authentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }

        UUID userId = extractUserId(auth);
        return permissionService.isUserInOrganization(userId, UUID.fromString(organizationId));
    }

    /**
     * Check if resource belongs to current user's organization.
     */
    public boolean isResourceInUserOrganization(String resourceOrganizationId) {
        Authentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }

        UUID userOrganizationId = extractOrganizationId(auth);
        if (userOrganizationId == null) {
            return false;
        }

        return userOrganizationId.toString().equals(resourceOrganizationId);
    }

    /**
     * Check if current user can delegate permissions.
     */
    public boolean canDelegatePermissions() {
        Authentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }

        UUID userId = extractUserId(auth);
        UUID organizationId = extractOrganizationId(auth);

        return !permissionService.getDelegatablePermissions(userId, organizationId).isEmpty();
    }

    /**
     * Complex permission check with multiple conditions.
     */
    public boolean hasComplexPermission(String resource, String action, String resourceId,
            String requiredRole, int minimumHierarchyLevel) {
        if (!hasPermissionOnResource(resource, action, resourceId)) {
            return false;
        }

        if (requiredRole != null && !hasRole(requiredRole)) {
            return false;
        }

        return hasMinimumHierarchyLevel(minimumHierarchyLevel);
    }

    /**
     * Check permission with attribute-based conditions.
     */
    public boolean hasPermissionWithAttributes(String resource, String action, String resourceId,
            Map<String, Object> userAttributes, Map<String, Object> resourceAttributes) {
        Authentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }

        UUID userId = extractUserId(auth);
        UUID organizationId = extractOrganizationId(auth);

        // Create enhanced permission context with attributes
        PermissionService.PermissionContext context = PermissionService.PermissionContext.builder()
                .userId(userId)
                .organizationId(organizationId)
                .resource(resource)
                .action(action)
                .resourceId(resourceId)
                .build();

        // Add user attributes
        if (userAttributes != null) {
            userAttributes.forEach(context.getAttributes()::put);
        }

        // Add resource attributes
        if (resourceAttributes != null) {
            resourceAttributes.forEach((key, value) -> context.getAttributes().put("resource_" + key, value));
        }

        return permissionService.hasPermission(userId, organizationId, resource, action, resourceId);
    }

    /**
     * Check permission with time-based constraints.
     */
    public boolean hasPermissionAtTime(String resource, String action, String timeConstraint) {
        if (!hasPermission(resource, action)) {
            return false;
        }

        // Parse time constraint (e.g., "09:00-17:00", "MON-FRI")
        return evaluateTimeConstraint(timeConstraint);
    }

    /**
     * Check permission with IP-based restrictions.
     */
    public boolean hasPermissionFromLocation(String resource, String action, String clientIp) {
        Authentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }

        UUID userId = extractUserId(auth);
        UUID organizationId = extractOrganizationId(auth);

        // Create context with IP information
        PermissionService.PermissionContext context = PermissionService.PermissionContext.builder()
                .userId(userId)
                .organizationId(organizationId)
                .resource(resource)
                .action(action)
                .environmentContext("clientIp", clientIp)
                .build();

        return permissionService.hasPermission(userId, organizationId, resource, action);
    }

    /**
     * Check if user can perform action based on resource ownership or permission.
     */
    public boolean canActOnResource(String resource, String action, String resourceId, String ownerField) {
        Authentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }

        UUID userId = extractUserId(auth);
        UUID organizationId = extractOrganizationId(auth);

        // Check ownership first
        if (permissionService.isResourceOwner(userId, resource, resourceId)) {
            return true;
        }

        // Check explicit permission
        return permissionService.hasPermission(userId, organizationId, resource, action, resourceId);
    }

    /**
     * Check permission with dynamic resource pattern.
     */
    public boolean hasPermissionOnPattern(String resourcePattern, String action) {
        Authentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }

        UUID userId = extractUserId(auth);
        UUID organizationId = extractOrganizationId(auth);

        // Extract resource type from pattern
        String resourceType = resourcePattern.split(":")[0];

        return permissionService.hasPermission(userId, organizationId, resourceType, action);
    }

    /**
     * Check if user has elevated privileges (admin or system roles).
     */
    public boolean hasElevatedPrivileges() {
        return isSystemAdmin() || isOrganizationAdmin() || hasMinimumHierarchyLevel(3);
    }

    /**
     * Check permission with emergency override capability.
     */
    public boolean hasPermissionOrEmergencyOverride(String resource, String action, boolean emergencyMode) {
        if (hasPermission(resource, action)) {
            return true;
        }

        // Allow emergency override for system admins
        return emergencyMode && isSystemAdmin();
    }

    /**
     * Check if user can delegate specific permission.
     */
    public boolean canDelegatePermission(String resource, String action) {
        Authentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }

        UUID userId = extractUserId(auth);
        UUID organizationId = extractOrganizationId(auth);

        Set<Permission> delegatablePermissions = permissionService.getDelegatablePermissions(userId, organizationId);

        return delegatablePermissions.stream()
                .anyMatch(p -> p.getResource().equals(resource) && p.getAction().equals(action));
    }

    /**
     * Check permission with context-aware evaluation.
     */
    public boolean hasContextualPermission(String resource, String action, Map<String, Object> context) {
        Authentication auth = getCurrentAuthentication();
        if (auth == null) {
            return false;
        }

        UUID userId = extractUserId(auth);
        UUID organizationId = extractOrganizationId(auth);

        // Create permission context with additional context data
        PermissionService.PermissionContext permContext = PermissionService.PermissionContext.builder()
                .userId(userId)
                .organizationId(organizationId)
                .resource(resource)
                .action(action)
                .build();

        // Add context attributes
        if (context != null) {
            context.forEach(permContext.getEnvironmentContext()::put);
        }

        return permissionService.hasPermission(userId, organizationId, resource, action);
    }

    // Helper methods

    private Authentication getCurrentAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    private UUID extractUserId(Authentication auth) {
        try {
            // Extract user ID from JWT token or principal
            if (auth.getDetails() instanceof java.util.Map) {
                @SuppressWarnings("unchecked")
                java.util.Map<String, Object> details = (java.util.Map<String, Object>) auth.getDetails();
                String userId = (String) details.get("userId");
                if (userId != null) {
                    return UUID.fromString(userId);
                }
            }

            // Fallback to principal name if it's a UUID
            String principalName = auth.getName();
            if (principalName != null) {
                return UUID.fromString(principalName);
            }
        } catch (Exception e) {
            log.debug("Could not extract user ID from authentication: {}", e.getMessage());
        }

        return null;
    }

    private UUID extractOrganizationId(Authentication auth) {
        try {
            // Extract organization ID from JWT token or details
            if (auth.getDetails() instanceof java.util.Map) {
                @SuppressWarnings("unchecked")
                java.util.Map<String, Object> details = (java.util.Map<String, Object>) auth.getDetails();
                String organizationId = (String) details.get("organizationId");
                if (organizationId != null) {
                    return UUID.fromString(organizationId);
                }
            }
        } catch (Exception e) {
            log.debug("Could not extract organization ID from authentication: {}", e.getMessage());
        }

        return null;
    }

    /**
     * Evaluate time-based constraints.
     */
    private boolean evaluateTimeConstraint(String timeConstraint) {
        try {
            LocalDateTime now = LocalDateTime.now();

            if (timeConstraint.contains("-") && timeConstraint.contains(":")) {
                // Time range constraint (e.g., "09:00-17:00")
                String[] parts = timeConstraint.split("-");
                if (parts.length == 2) {
                    LocalTime startTime = LocalTime.parse(parts[0]);
                    LocalTime endTime = LocalTime.parse(parts[1]);
                    LocalTime currentTime = now.toLocalTime();

                    if (startTime.isBefore(endTime)) {
                        // Same day range
                        return !currentTime.isBefore(startTime) && !currentTime.isAfter(endTime);
                    } else {
                        // Overnight range (e.g., 22:00-06:00)
                        return !currentTime.isBefore(startTime) || !currentTime.isAfter(endTime);
                    }
                }
            } else if (timeConstraint.contains("-") && timeConstraint.length() == 7) {
                // Day range constraint (e.g., "MON-FRI")
                String[] parts = timeConstraint.split("-");
                if (parts.length == 2) {
                    String currentDay = now.getDayOfWeek().name().substring(0, 3).toUpperCase();
                    String startDay = parts[0].toUpperCase();
                    String endDay = parts[1].toUpperCase();

                    // Simple day range check (would need more sophisticated logic for proper day
                    // ranges)
                    return currentDay.equals(startDay) || currentDay.equals(endDay) ||
                            (startDay.equals("MON") && endDay.equals("FRI") &&
                                    !currentDay.equals("SAT") && !currentDay.equals("SUN"));
                }
            }

            return true; // Allow access if constraint format is not recognized
        } catch (Exception e) {
            log.warn("Invalid time constraint format: {}", timeConstraint);
            return true; // Allow access on invalid format
        }
    }
}