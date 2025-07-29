package com.zamaz.mcp.security.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * User-Permission association entity for direct permission assignments.
 * Supports direct permission grants to users with temporal and contextual
 * constraints.
 */
@Entity
@Table(name = "user_permissions", indexes = {
        @Index(name = "idx_user_permissions_user", columnList = "userId"),
        @Index(name = "idx_user_permissions_permission", columnList = "permissionId"),
        @Index(name = "idx_user_permissions_organization", columnList = "organizationId"),
        @Index(name = "idx_user_permissions_active", columnList = "isActive"),
        @Index(name = "idx_user_permissions_granted_by", columnList = "grantedBy")
})
@Data
@EqualsAndHashCode(exclude = { "user", "permission" })
@ToString(exclude = { "user", "permission" })
public class UserPermission {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // Core Relationship
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "user_id", insertable = false, updatable = false)
    private UUID userId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "permission_id", nullable = false)
    private Permission permission;

    @Column(name = "permission_id", insertable = false, updatable = false)
    private UUID permissionId;

    // Organization Context
    @Column(name = "organization_id")
    private UUID organizationId; // Permission assignment within specific organization

    // Assignment Type and Status
    @Enumerated(EnumType.STRING)
    @Column(name = "assignment_type", nullable = false, length = 50)
    private AssignmentType assignmentType = AssignmentType.DIRECT;

    @Column(name = "is_active", nullable = false)
    private Boolean isActive = true;

    // Contextual Constraints
    @Column(name = "conditions", columnDefinition = "TEXT")
    private String conditions; // SpEL expression for conditional permission activation

    @Column(name = "context_attributes", columnDefinition = "jsonb")
    private String contextAttributes; // JSON object with additional context

    @Column(name = "resource_constraints", columnDefinition = "jsonb")
    private String resourceConstraints; // JSON object defining resource-specific constraints

    // Temporal Constraints
    @Column(name = "effective_from")
    private LocalDateTime effectiveFrom;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @Column(name = "auto_renew", nullable = false)
    private Boolean autoRenew = false;

    @Column(name = "renewal_period_days")
    private Integer renewalPeriodDays;

    // Assignment Metadata
    @Column(name = "assignment_reason", length = 500)
    private String assignmentReason;

    @Column(name = "emergency_grant", nullable = false)
    private Boolean emergencyGrant = false;

    @Column(name = "requires_justification", nullable = false)
    private Boolean requiresJustification = false;

    @Column(name = "justification", length = 1000)
    private String justification;

    // Delegation Support
    @Column(name = "is_delegated", nullable = false)
    private Boolean isDelegated = false;

    @Column(name = "delegated_from", length = 255)
    private String delegatedFrom; // User ID who delegated this permission

    @Column(name = "delegation_depth", nullable = false)
    private Integer delegationDepth = 0;

    @Column(name = "delegation_expires_at")
    private LocalDateTime delegationExpiresAt;

    // Audit Fields
    @CreationTimestamp
    @Column(name = "granted_at", nullable = false, updatable = false)
    private LocalDateTime grantedAt;

    @Column(name = "granted_by", length = 255)
    private String grantedBy;

    @Column(name = "revoked_at")
    private LocalDateTime revokedAt;

    @Column(name = "revoked_by", length = 255)
    private String revokedBy;

    @Column(name = "revocation_reason", length = 500)
    private String revocationReason;

    @Column(name = "last_used_at")
    private LocalDateTime lastUsedAt;

    @Column(name = "usage_count", nullable = false)
    private Long usageCount = 0L;

    // Enums
    public enum AssignmentType {
        DIRECT, // Directly assigned to user
        DELEGATED, // Delegated from another user
        TEMPORARY, // Temporary assignment
        EMERGENCY, // Emergency grant
        CONDITIONAL // Conditional assignment based on attributes
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

        if (expiresAt != null && now.isAfter(expiresAt)) {
            return false;
        }

        if (isDelegated && delegationExpiresAt != null && now.isAfter(delegationExpiresAt)) {
            return false;
        }

        return true;
    }

    public boolean isExpired() {
        LocalDateTime now = LocalDateTime.now();
        return expiresAt != null && now.isAfter(expiresAt);
    }

    public boolean isDelegationExpired() {
        LocalDateTime now = LocalDateTime.now();
        return isDelegated && delegationExpiresAt != null && now.isAfter(delegationExpiresAt);
    }

    public boolean canRenew() {
        return autoRenew && renewalPeriodDays != null && renewalPeriodDays > 0;
    }

    public void renew() {
        if (canRenew()) {
            LocalDateTime now = LocalDateTime.now();
            this.expiresAt = now.plusDays(renewalPeriodDays);
        }
    }

    public void revoke(String revokedBy, String reason) {
        this.isActive = false;
        this.revokedAt = LocalDateTime.now();
        this.revokedBy = revokedBy;
        this.revocationReason = reason;
    }

    public void recordUsage() {
        this.lastUsedAt = LocalDateTime.now();
        this.usageCount++;
    }
}