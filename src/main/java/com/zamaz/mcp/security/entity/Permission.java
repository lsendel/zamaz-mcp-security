package com.zamaz.mcp.security.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Enhanced Permission entity with resource-based and attribute-based
 * permissions.
 * Supports fine-grained access control with contextual conditions and resource
 * scoping.
 */
@Entity
@Table(name = "permissions", uniqueConstraints = {
        @UniqueConstraint(name = "uk_permissions_resource_action_org", columnNames = { "resource", "action",
                "organizationId" })
}, indexes = {
        @Index(name = "idx_permissions_resource", columnList = "resource"),
        @Index(name = "idx_permissions_action", columnList = "action"),
        @Index(name = "idx_permissions_organization", columnList = "organizationId"),
        @Index(name = "idx_permissions_resource_id", columnList = "resourceId"),
        @Index(name = "idx_permissions_active", columnList = "isActive"),
        @Index(name = "idx_permissions_system", columnList = "isSystemPermission")
})
@Data
@EqualsAndHashCode(exclude = { "rolePermissions", "userPermissions" })
@ToString(exclude = { "rolePermissions", "userPermissions" })
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // Core Permission Definition
    @Column(nullable = false, length = 100)
    private String resource; // e.g., "debate", "organization", "user", "system"

    @Column(nullable = false, length = 50)
    private String action; // e.g., "create", "read", "update", "delete", "manage", "execute"

    @Column(length = 500)
    private String description;

    @Column(name = "display_name", length = 200)
    private String displayName;

    // Resource Scoping
    @Column(name = "resource_id", length = 255)
    private String resourceId; // Specific resource instance ID for instance-level permissions

    @Column(name = "resource_pattern", length = 500)
    private String resourcePattern; // Pattern matching for multiple resources (e.g., "debate:*", "user:org1:*")

    @Column(name = "organization_id")
    private UUID organizationId; // null for global/system permissions

    // Permission Type and Scope
    @Enumerated(EnumType.STRING)
    @Column(name = "permission_type", nullable = false, length = 50)
    private PermissionType permissionType = PermissionType.RESOURCE_BASED;

    @Enumerated(EnumType.STRING)
    @Column(name = "permission_scope", nullable = false, length = 50)
    private PermissionScope permissionScope = PermissionScope.INSTANCE;

    @Column(name = "is_system_permission", nullable = false)
    private Boolean isSystemPermission = false;

    // Attribute-Based Access Control (ABAC)
    @Column(name = "condition_expression", columnDefinition = "TEXT")
    private String conditionExpression; // SpEL expression for conditional permissions

    @Column(name = "subject_attributes", columnDefinition = "jsonb")
    private String subjectAttributes; // JSON object defining required subject attributes

    @Column(name = "resource_attributes", columnDefinition = "jsonb")
    private String resourceAttributes; // JSON object defining required resource attributes

    @Column(name = "environment_attributes", columnDefinition = "jsonb")
    private String environmentAttributes; // JSON object defining environmental conditions

    // Permission Constraints
    @Column(name = "time_based", nullable = false)
    private Boolean timeBased = false;

    @Column(name = "valid_from")
    private LocalDateTime validFrom;

    @Column(name = "valid_until")
    private LocalDateTime validUntil;

    @Column(name = "days_of_week", length = 20)
    private String daysOfWeek; // e.g., "MON,TUE,WED,THU,FRI"

    @Column(name = "hours_of_day", length = 50)
    private String hoursOfDay; // e.g., "09:00-17:00"

    @Column(name = "ip_restrictions", columnDefinition = "TEXT")
    private String ipRestrictions; // JSON array of allowed IP ranges

    @Column(name = "location_restrictions", columnDefinition = "TEXT")
    private String locationRestrictions; // JSON array of allowed locations/countries

    // Permission Metadata
    @Column(name = "priority", nullable = false)
    private Integer priority = 0; // Higher priority permissions override lower ones

    @Column(name = "effect", nullable = false, length = 10)
    private String effect = "ALLOW"; // ALLOW or DENY

    @Column(name = "delegation_allowed", nullable = false)
    private Boolean delegationAllowed = false;

    @Column(name = "max_delegation_depth")
    private Integer maxDelegationDepth = 1;

    // Permission Categories and Tags
    @Column(name = "category", length = 100)
    private String category; // e.g., "admin", "user", "api", "system"

    @Column(name = "tags", columnDefinition = "TEXT")
    private String tags; // JSON array of tags for grouping and filtering

    @Column(name = "risk_level", length = 20)
    private String riskLevel = "LOW"; // LOW, MEDIUM, HIGH, CRITICAL

    // Status and Lifecycle
    @Column(name = "is_active", nullable = false)
    private Boolean isActive = true;

    @Column(name = "requires_approval", nullable = false)
    private Boolean requiresApproval = false;

    @Column(name = "auto_expire_days")
    private Integer autoExpireDays;

    // Audit Fields
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @Column(name = "created_by", length = 255)
    private String createdBy;

    @Column(name = "updated_by", length = 255)
    private String updatedBy;

    // Relationships
    @OneToMany(mappedBy = "permission", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private Set<RolePermission> rolePermissions = new HashSet<>();

    @OneToMany(mappedBy = "permission", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private Set<UserPermission> userPermissions = new HashSet<>();

    // Enums
    public enum PermissionType {
        RESOURCE_BASED, // Traditional resource-action permissions
        ATTRIBUTE_BASED, // ABAC permissions with conditions
        ROLE_BASED, // Permissions tied to specific roles
        TIME_BASED, // Permissions with time constraints
        LOCATION_BASED, // Permissions with location constraints
        CONTEXT_BASED // Permissions based on request context
    }

    public enum PermissionScope {
        GLOBAL, // Global permissions across all organizations
        ORGANIZATION, // Organization-scoped permissions
        INSTANCE, // Instance-level permissions for specific resources
        PATTERN // Pattern-based permissions for multiple resources
    }

    // Helper Methods
    public boolean isEffective() {
        LocalDateTime now = LocalDateTime.now();

        if (!isActive) {
            return false;
        }

        if (timeBased) {
            if (validFrom != null && now.isBefore(validFrom)) {
                return false;
            }

            if (validUntil != null && now.isAfter(validUntil)) {
                return false;
            }

            // Check day of week constraints
            if (daysOfWeek != null && !daysOfWeek.isEmpty()) {
                String currentDay = now.getDayOfWeek().name().substring(0, 3);
                if (!daysOfWeek.contains(currentDay)) {
                    return false;
                }
            }

            // Check hour constraints
            if (hoursOfDay != null && !hoursOfDay.isEmpty()) {
                // Implementation would check if current time falls within allowed hours
                // This is a simplified check - full implementation would parse time ranges
                int currentHour = now.getHour();
                // Simplified check - would need proper time range parsing
            }
        }

        return true;
    }

    public boolean matches(String resource, String action, String resourceId, UUID organizationId) {
        if (!isEffective()) {
            return false;
        }

        // Check resource match
        if (!this.resource.equals(resource)) {
            return false;
        }

        // Check action match
        if (!this.action.equals(action) && !"*".equals(this.action)) {
            return false;
        }

        // Check resource ID match
        if (this.resourceId != null) {
            if (resourceId == null || !this.resourceId.equals(resourceId)) {
                return false;
            }
        }

        // Check resource pattern match
        if (this.resourcePattern != null && resourceId != null) {
            if (!matchesPattern(this.resourcePattern, resourceId)) {
                return false;
            }
        }

        // Check organization scope
        if (this.organizationId != null) {
            if (organizationId == null || !this.organizationId.equals(organizationId)) {
                return false;
            }
        }

        return true;
    }

    private boolean matchesPattern(String pattern, String value) {
        // Simple pattern matching - could be enhanced with regex or glob patterns
        if (pattern.endsWith("*")) {
            String prefix = pattern.substring(0, pattern.length() - 1);
            return value.startsWith(prefix);
        }
        return pattern.equals(value);
    }

    public boolean isAllow() {
        return "ALLOW".equals(effect);
    }

    public boolean isDeny() {
        return "DENY".equals(effect);
    }

    public String getFullPermissionString() {
        StringBuilder sb = new StringBuilder();
        sb.append(resource).append(":").append(action);

        if (resourceId != null) {
            sb.append(":").append(resourceId);
        } else if (resourcePattern != null) {
            sb.append(":").append(resourcePattern);
        }

        if (organizationId != null) {
            sb.append("@").append(organizationId);
        }

        return sb.toString();
    }

    public boolean canDelegate() {
        return delegationAllowed && isActive && isEffective();
    }
}