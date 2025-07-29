package com.zamaz.mcp.security.repository;

import com.zamaz.mcp.security.entity.UserPermission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface UserPermissionRepository extends JpaRepository<UserPermission, UUID> {

    /**
     * Find all user permissions for a user in an organization.
     */
    List<UserPermission> findByUserIdAndOrganizationId(UUID userId, UUID organizationId);

    /**
     * Find effective user permissions (active and not expired).
     */
    @Query("SELECT up FROM UserPermission up WHERE up.userId = :userId AND " +
            "(up.organizationId = :organizationId OR up.organizationId IS NULL) AND " +
            "up.isActive = true AND " +
            "(up.effectiveFrom IS NULL OR up.effectiveFrom <= CURRENT_TIMESTAMP) AND " +
            "(up.expiresAt IS NULL OR up.expiresAt >= CURRENT_TIMESTAMP) AND " +
            "(up.isDelegated = false OR up.delegationExpiresAt IS NULL OR up.delegationExpiresAt >= CURRENT_TIMESTAMP)")
    List<UserPermission> findEffectiveByUserIdAndOrganizationId(@Param("userId") UUID userId,
            @Param("organizationId") UUID organizationId);

    /**
     * Find all user permissions for a user across all organizations.
     */
    List<UserPermission> findByUserId(UUID userId);

    /**
     * Find all users with a specific permission.
     */
    List<UserPermission> findByPermissionId(UUID permissionId);

    /**
     * Find user permissions by assignment type.
     */
    List<UserPermission> findByUserIdAndAssignmentType(UUID userId, UserPermission.AssignmentType assignmentType);

    /**
     * Find delegated permissions for a user.
     */
    List<UserPermission> findByUserIdAndIsDelegatedTrue(UUID userId);

    /**
     * Find permissions delegated by a user.
     */
    List<UserPermission> findByDelegatedFrom(String delegatedFrom);

    /**
     * Find expired user permissions.
     */
    @Query("SELECT up FROM UserPermission up WHERE up.expiresAt < CURRENT_TIMESTAMP AND up.isActive = true")
    List<UserPermission> findExpiredPermissions();

    /**
     * Find emergency grants.
     */
    List<UserPermission> findByEmergencyGrantTrueAndIsActiveTrue();

    /**
     * Find permissions requiring justification.
     */
    List<UserPermission> findByRequiresJustificationTrueAndJustificationIsNull();

    /**
     * Check if user has specific permission.
     */
    boolean existsByUserIdAndPermissionIdAndOrganizationId(UUID userId, UUID permissionId, UUID organizationId);

    /**
     * Find permissions that can be renewed.
     */
    @Query("SELECT up FROM UserPermission up WHERE up.autoRenew = true AND " +
            "up.expiresAt BETWEEN CURRENT_TIMESTAMP AND (CURRENT_TIMESTAMP + INTERVAL '7 days')")
    List<UserPermission> findPermissionsForRenewal();

    /**
     * Count active permissions for a user.
     */
    @Query("SELECT COUNT(up) FROM UserPermission up WHERE up.userId = :userId AND up.isActive = true")
    long countActivePermissionsByUserId(@Param("userId") UUID userId);

    /**
     * Find user permissions by granted by.
     */
    List<UserPermission> findByGrantedBy(String grantedBy);

    /**
     * Find high-usage permissions.
     */
    @Query("SELECT up FROM UserPermission up WHERE up.usageCount > :threshold ORDER BY up.usageCount DESC")
    List<UserPermission> findHighUsagePermissions(@Param("threshold") long threshold);
}