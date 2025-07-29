package com.zamaz.mcp.security.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * User-Role association entity with temporal and contextual constraints.
 * Supports role assignment with expiration, approval workflows, and delegation
 * tracking.
 */
@Entity
@Table(name = "user_roles", indexes = {
        @Index(name = "idx_user_roles_user", columnList = "userId"),
        @Index(name = "idx_user_roles_role", columnList = "roleId"),
        @Index(name = "idx_user_roles_organization", columnList = "organizationId"),
        @Index(name = "idx_user_roles_active", columnList = "isActive"),
        @Index(name = "idx_user_roles_expires", columnList = "expiresAt"),
        @Index(name = "idx_user_roles_granted_by", columnList = "grantedBy")
})
@Data
@EqualsAndHashCode(exclude = { "user", "role" })
@ToString(exclude = { "user", "role" })
public class UserRole {

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
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;

    @Column(name = "role_id", insertable = false, updatable = false)
    private UUID roleId;

    // Organization Context
    @Column(name = "organization_id")
    private UUID organizationId; // Role assignment within specific organization

    // Assignment Type and Status
    @Enumerated(EnumType.STRING)
    @Column(name = "assignment_type", nullable = false, length = 50)
    private AssignmentType assignmentType = AssignmentType.DIRECT;

    @Enumerated(EnumType.STRING)
    @Column(name = "assignment_status", nullable = false, length = 50)
    private AssignmentStatus assignmentStatus = AssignmentStatus.ACTIVE;

    @Column(name = "is_active", nullable = false)
    private Boolean isActive = true;

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

    @Column(name = "assignment_context", columnDefinition = "jsonb")
    private String assignmentContext; // JSON object with additional context

    @Column(name = "conditions", columnDefinition = "TEXT")
    private String conditions; // SpEL expression for conditional role activation

    // Approval and Workflow
    @Column(name = "requires_approval", nullable = false)
    private Boolean requiresApproval = false;

    @Column(name = "approval_status", length = 50)
    private String approvalStatus; // PENDING, APPROVED, REJECTED

    @Column(name = "approved_by", length = 255)
    private String approvedBy;

    @Column(name = "approved_at")
    private LocalDateTime approvedAt;

    @Column(name = "approval_comments", length = 1000)
    private String approvalComments;

    // Delegation Support
    @Column(name = "is_delegated", nullable = false)
    private Boolean isDelegated = false;

    @Column(name = "delegated_from", length = 255)
    private String delegatedFrom; // User ID who delegated this role

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
        INHERITED, // Inherited from parent role
        DELEGATED, // Delegated from another user
        TEMPORARY, // Temporary assignment
        CONDITIONAL // Conditional assignment based on attributes
    }

    public enum AssignmentStatus {
        ACTIVE, // Currently active
        INACTIVE, // Temporarily inactive
        EXPIRED, // Assignment has expired
        REVOKED, // Assignment was revoked
        PENDING, // Pending approval
        SUSPENDED // Temporarily suspended
    }

    // Helper Methods
    public boolean isEffective() {
        LocalDateTime now = LocalDateTime.now();

        if (!isActive || assignmentStatus != AssignmentStatus.ACTIVE) {
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

        if (requiresApproval && !"APPROVED".equals(approvalStatus)) {
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
            this.assignmentStatus = AssignmentStatus.ACTIVE;
        }
    }

    public void revoke(String revokedBy, String reason) {
        this.isActive = false;
        this.assignmentStatus = AssignmentStatus.REVOKED;
        this.revokedAt = LocalDateTime.now();
        this.revokedBy = revokedBy;
        this.revocationReason = reason;
    }

    public void suspend(String reason) {
        this.assignmentStatus = AssignmentStatus.SUSPENDED;
        this.revocationReason = reason;
    }

    public void activate() {
        this.isActive = true;
        this.assignmentStatus = AssignmentStatus.ACTIVE;
        this.revokedAt = null;
        this.revokedBy = null;
        this.revocationReason = null;
    }

    public void recordUsage() {
        this.lastUsedAt = LocalDateTime.now();
        this.usageCount++;
    }

    public boolean isPendingApproval() {
        return requiresApproval && "PENDING".equals(approvalStatus);
    }

    public void approve(String approvedBy, String comments) {
        this.approvalStatus = "APPROVED";
        this.approvedBy = approvedBy;
        this.approvedAt = LocalDateTime.now();
        this.approvalComments = comments;
        this.assignmentStatus = AssignmentStatus.ACTIVE;
    }

    public void reject(String rejectedBy, String comments) {
        this.approvalStatus = "REJECTED";
        this.approvedBy = rejectedBy;
        this.approvedAt = LocalDateTime.now();
        this.approvalComments = comments;
        this.assignmentStatus = AssignmentStatus.INACTIVE;
    }
}