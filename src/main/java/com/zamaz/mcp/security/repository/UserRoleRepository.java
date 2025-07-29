package com.zamaz.mcp.security.repository;

import com.zamaz.mcp.security.entity.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRole, UUID> {

    /**
     * Find all user roles for a user in an organization.
     */
    List<UserRole> findByUserIdAndOrganizationId(UUID userId, UUID organizationId);

    /**
     * Find effective user roles (active and not expired).
     */
    @Query("SELECT ur FROM UserRole ur WHERE ur.userId = :userId AND " +
            "(ur.organizationId = :organizationId OR ur.organizationId IS NULL) AND " +
            "ur.isActive = true AND ur.assignmentStatus = 'ACTIVE' AND " +
            "(ur.effectiveFrom IS NULL OR ur.effectiveFrom <= CURRENT_TIMESTAMP) AND " +
            "(ur.expiresAt IS NULL OR ur.expiresAt >= CURRENT_TIMESTAMP) AND " +
            "(ur.isDelegated = false OR ur.delegationExpiresAt IS NULL OR ur.delegationExpiresAt >= CURRENT_TIMESTAMP)")
    List<UserRole> findEffectiveByUserIdAndOrganizationId(@Param("userId") UUID userId,
            @Param("organizationId") UUID organizationId);

    /**
     * Find all user roles for a user across all organizations.
     */
    List<UserRole> findByUserId(UUID userId);

    /**
     * Find all users with a specific role.
     */
    List<UserRole> findByRoleId(UUID roleId);

    /**
     * Find user roles by assignment type.
     */
    List<UserRole> findByUserIdAndAssignmentType(UUID userId, UserRole.AssignmentType assignmentType);

    /**
     * Find delegated roles for a user.
     */
    List<UserRole> findByUserIdAndIsDelegatedTrue(UUID userId);

    /**
     * Find roles delegated by a user.
     */
    List<UserRole> findByDelegatedFrom(String delegatedFrom);

    /**
     * Find expired user roles.
     */
    @Query("SELECT ur FROM UserRole ur WHERE ur.expiresAt < CURRENT_TIMESTAMP AND ur.isActive = true")
    List<UserRole> findExpiredRoles();

    /**
     * Find roles pending approval.
     */
    List<UserRole> findByRequiresApprovalTrueAndApprovalStatus(String approvalStatus);

    /**
     * Check if user has role in organization.
     */
    boolean existsByUserIdAndRoleIdAndOrganizationId(UUID userId, UUID roleId, UUID organizationId);

    /**
     * Check if user is in organization.
     */
    boolean existsByUserIdAndOrganizationId(UUID userId, UUID organizationId);

    /**
     * Find roles that can be renewed.
     */
    @Query("SELECT ur FROM UserRole ur WHERE ur.autoRenew = true AND " +
            "ur.expiresAt BETWEEN CURRENT_TIMESTAMP AND (CURRENT_TIMESTAMP + INTERVAL '7 days')")
    List<UserRole> findRolesForRenewal();

    /**
     * Count active roles for a user.
     */
    @Query("SELECT COUNT(ur) FROM UserRole ur WHERE ur.userId = :userId AND ur.isActive = true")
    long countActiveRolesByUserId(@Param("userId") UUID userId);

    /**
     * Find user roles by granted by.
     */
    List<UserRole> findByGrantedBy(String grantedBy);
}