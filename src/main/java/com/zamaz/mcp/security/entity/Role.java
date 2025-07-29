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
 * Enhanced Role entity with hierarchical role support and organization scoping.
 * Supports role inheritance, delegation, and fine-grained permission
 * management.
 */
@Entity
@Table(name = "roles", uniqueConstraints = {
        @UniqueConstraint(name = "uk_roles_name_org", columnNames = { "name", "organizationId" })
}, indexes = {
        @Index(name = "idx_roles_name", columnList = "name"),
        @Index(name = "idx_roles_organization", columnList = "organizationId"),
        @Index(name = "idx_roles_active", columnList = "isActive"),
        @Index(name = "idx_roles_system", columnList = "isSystemRole"),
        @Index(name = "idx_roles_hierarchy_level", columnList = "hierarchyLevel")
})
@Data
@EqualsAndHashCode(exclude = { "parentRoles", "childRoles", "rolePermissions", "userRoles" })
@ToString(exclude = { "parentRoles", "childRoles", "rolePermissions", "userRoles" })
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(length = 500)
    private String description;

    @Column(name = "display_name", length = 200)
    private String displayName;

    // Organization Scoping
    @Column(name = "organization_id")
    private UUID organizationId; // null for global/system roles

    @Column(name = "is_system_role", nullable = false)
    private Boolean isSystemRole = false;

    @Column(name = "is_default_role", nullable = false)
    private Boolean isDefaultRole = false;

    // Role Hierarchy
    @Column(name = "hierarchy_level", nullable = false)
    private Integer hierarchyLevel = 0; // 0 = lowest level, higher numbers = higher authority

    @Column(name = "max_hierarchy_level")
    private Integer maxHierarchyLevel; // Maximum level this role can manage

    // Role Type and Category
    @Enumerated(EnumType.STRING)
    @Column(name = "role_type", nullable = false, length = 50)
    private RoleType roleType = RoleType.FUNCTIONAL;

    @Column(name = "role_category", length = 100)
    private String roleCategory; // e.g., "admin", "user", "service", "api"

    // Role Constraints
    @Column(name = "max_users")
    private Integer maxUsers; // Maximum number of users that can have this role

    @Column(name = "requires_approval", nullable = false)
    private Boolean requiresApproval = false;

    @Column(name = "auto_expire_days")
    private Integer autoExpireDays; // Role assignment auto-expires after N days

    @Column(name = "delegation_allowed", nullable = false)
    private Boolean delegationAllowed = false;

    @Column(name = "max_delegation_depth")
    private Integer maxDelegationDepth = 1;

    // Role Status
    @Column(name = "is_active", nullable = false)
    private Boolean isActive = true;

    @Column(name = "effective_from")
    private LocalDateTime effectiveFrom;

    @Column(name = "effective_until")
    private LocalDateTime effectiveUntil;

    // Role Metadata
    @Column(name = "role_metadata", columnDefinition = "jsonb")
    private String roleMetadata; // JSON object for additional role properties

    @Column(name = "access_patterns", columnDefinition = "jsonb")
    private String accessPatterns; // JSON array of access pattern definitions

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

    // Hierarchical Relationships
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "role_hierarchy", joinColumns = @JoinColumn(name = "child_role_id"), inverseJoinColumns = @JoinColumn(name = "parent_role_id"), indexes = {
            @Index(name = "idx_role_hierarchy_child", columnList = "child_role_id"),
            @Index(name = "idx_role_hierarchy_parent", columnList = "parent_role_id")
    })
    private Set<Role> parentRoles = new HashSet<>();

    @ManyToMany(mappedBy = "parentRoles", fetch = FetchType.LAZY)
    private Set<Role> childRoles = new HashSet<>();

    // Permission Relationships
    @OneToMany(mappedBy = "role", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private Set<RolePermission> rolePermissions = new HashSet<>();

    // User Relationships
    @OneToMany(mappedBy = "role", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private Set<UserRole> userRoles = new HashSet<>();

    // Role Types
    public enum RoleType {
        SYSTEM, // System-level roles (e.g., SUPER_ADMIN)
        ORGANIZATIONAL, // Organization-level roles (e.g., ORG_ADMIN)
        FUNCTIONAL, // Functional roles (e.g., DEBATE_MODERATOR)
        TEMPORARY, // Temporary roles with expiration
        DELEGATED // Delegated roles from other users
    }

    // Helper Methods
    public boolean isEffective() {
        LocalDateTime now = LocalDateTime.now();

        if (!isActive) {
            return false;
        }

        if (effectiveFrom != null && now.isBefore(effectiveFrom)) {
            return false;
        }

        if (effectiveUntil != null && now.isAfter(effectiveUntil)) {
            return false;
        }

        return true;
    }

    public boolean canManageRole(Role otherRole) {
        if (!isActive || !isEffective()) {
            return false;
        }

        // System roles can manage all roles
        if (isSystemRole && roleType == RoleType.SYSTEM) {
            return true;
        }

        // Check hierarchy level
        if (maxHierarchyLevel != null && otherRole.getHierarchyLevel() > maxHierarchyLevel) {
            return false;
        }

        // Check organization scope
        if (organizationId != null && !organizationId.equals(otherRole.getOrganizationId())) {
            return false;
        }

        return hierarchyLevel > otherRole.getHierarchyLevel();
    }

    public boolean canDelegate() {
        return delegationAllowed && isActive && isEffective();
    }

    public boolean isParentOf(Role childRole) {
        return childRoles.contains(childRole);
    }

    public boolean isChildOf(Role parentRole) {
        return parentRoles.contains(parentRole);
    }

    public Set<Role> getAllParentRoles() {
        Set<Role> allParents = new HashSet<>();
        collectParentRoles(this, allParents);
        return allParents;
    }

    public Set<Role> getAllChildRoles() {
        Set<Role> allChildren = new HashSet<>();
        collectChildRoles(this, allChildren);
        return allChildren;
    }

    private void collectParentRoles(Role role, Set<Role> collected) {
        for (Role parent : role.getParentRoles()) {
            if (!collected.contains(parent)) {
                collected.add(parent);
                collectParentRoles(parent, collected);
            }
        }
    }

    private void collectChildRoles(Role role, Set<Role> collected) {
        for (Role child : role.getChildRoles()) {
            if (!collected.contains(child)) {
                collected.add(child);
                collectChildRoles(child, collected);
            }
        }
    }

    public String getQualifiedName() {
        if (organizationId != null) {
            return organizationId + ":" + name;
        }
        return name;
    }
}