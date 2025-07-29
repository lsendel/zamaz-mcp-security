package com.zamaz.mcp.security.repository;

import com.zamaz.mcp.security.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, UUID> {

    /**
     * Find permission by resource, action, and organization.
     */
    Optional<Permission> findByResourceAndActionAndOrganizationId(String resource, String action, UUID organizationId);

    /**
     * Find all permissions for a resource.
     */
    List<Permission> findByResourceAndIsActiveTrue(String resource);

    /**
     * Find all permissions for an organization.
     */
    List<Permission> findByOrganizationIdAndIsActiveTrue(UUID organizationId);

    /**
     * Find all system permissions.
     */
    List<Permission> findByIsSystemPermissionTrueAndIsActiveTrue();

    /**
     * Find permissions by category.
     */
    List<Permission> findByCategoryAndIsActiveTrue(String category);

    /**
     * Find permissions by risk level.
     */
    List<Permission> findByRiskLevelAndIsActiveTrue(String riskLevel);

    /**
     * Find permissions that match resource pattern.
     */
    @Query("SELECT p FROM Permission p WHERE p.isActive = true AND " +
            "(p.resource = :resource OR p.resourcePattern LIKE :pattern)")
    List<Permission> findByResourceOrPattern(@Param("resource") String resource,
            @Param("pattern") String pattern);

    /**
     * Find effective permissions (active and within validity period).
     */
    @Query("SELECT p FROM Permission p WHERE p.isActive = true AND " +
            "(p.validFrom IS NULL OR p.validFrom <= CURRENT_TIMESTAMP) AND " +
            "(p.validUntil IS NULL OR p.validUntil >= CURRENT_TIMESTAMP)")
    List<Permission> findEffectivePermissions();

    /**
     * Find permissions that can be delegated.
     */
    List<Permission> findByDelegationAllowedTrueAndIsActiveTrue();

    /**
     * Check if permission exists for resource and action.
     */
    boolean existsByResourceAndActionAndOrganizationId(String resource, String action, UUID organizationId);

    /**
     * Find permissions requiring approval.
     */
    List<Permission> findByRequiresApprovalTrueAndIsActiveTrue();

    /**
     * Find high-risk permissions.
     */
    @Query("SELECT p FROM Permission p WHERE p.isActive = true AND p.riskLevel IN ('HIGH', 'CRITICAL')")
    List<Permission> findHighRiskPermissions();
}