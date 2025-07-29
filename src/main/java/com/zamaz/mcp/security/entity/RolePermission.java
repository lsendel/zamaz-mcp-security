package com.zamaz.mcp.security.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Role-Permission association entity with contextual constraints.
 * Supports permission assignment to roles with conditions and temporal
 * constraints.
 */
@Entity
@Table(name = "role_permissions", indexes = {
        @Index(name = "idx_role_permissions_role", columnList = "roleId"),
        @Index(name = "idx_role_permissions_permission", columnList = "permissionId"),
        @Index(name = "idx_role_permissions_active", columnList = "isActive"),
        @Index(name = "idx_role_permissions_granted_by", columnList = "grantedBy")
})
@Data
@EqualsAndHashCode(exclude = { "role", "permission" })
@ToString(exclude = { "role", "permission" })
public class RolePermission {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // Core Relationship
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;

    @Column(name = "role_id", insertable = false, updatable = false)
    private UUID roleId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "permission_id", nullable = false)
    private Permission permission;

    @Column(name = "permission_id", insertable = false, updatable = false)
    private UUID permissionId;

    // Assignment Context
    @Column(name = "is_active", nullable = false)
    private Boolean isActive = true;

    @Column(name = "conditions", columnDefinition = "TEXT")
    private String conditions; // SpEL expression for conditional permission activation

    @Column(name = "context_attributes", columnDefinition = "jsonb")
    private String contextAttributes; // JSON object with additional context

    // Temporal Constraints
    @Column(name = "effective_from")
    private LocalDateTime effectiveFrom;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

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

        return true;
    }

    public void revoke(String revokedBy, String reason) {
        this.isActive = false;
        this.revokedAt = LocalDateTime.now();
        this.revokedBy = revokedBy;
        this.revocationReason = reason;
    }
}