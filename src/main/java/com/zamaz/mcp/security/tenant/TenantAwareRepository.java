package com.zamaz.mcp.security.tenant;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.jpa.domain.Specification;

import jakarta.persistence.criteria.Predicate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Base class for tenant-aware repositories with automatic organization
 * filtering.
 * Provides common methods for multi-tenant data access with security isolation.
 */
@Slf4j
public abstract class TenantAwareRepository {

    /**
     * Create a specification that filters by current tenant.
     */
    protected static <T> Specification<T> withCurrentTenant() {
        return (root, query, criteriaBuilder) -> {
            UUID currentTenant = TenantSecurityContext.getCurrentTenant();
            if (currentTenant == null) {
                log.warn("No tenant context set for query filtering");
                // Return a predicate that matches nothing for security
                return criteriaBuilder.disjunction();
            }

            return criteriaBuilder.equal(root.get("organizationId"), currentTenant);
        };
    }

    /**
     * Create a specification that filters by specific tenant.
     */
    protected static <T> Specification<T> withTenant(UUID tenantId) {
        return (root, query, criteriaBuilder) -> {
            if (tenantId == null) {
                return criteriaBuilder.disjunction(); // No matches
            }
            return criteriaBuilder.equal(root.get("organizationId"), tenantId);
        };
    }

    /**
     * Create a specification that allows global (system-level) records or current
     * tenant.
     */
    protected static <T> Specification<T> withCurrentTenantOrGlobal() {
        return (root, query, criteriaBuilder) -> {
            UUID currentTenant = TenantSecurityContext.getCurrentTenant();
            if (currentTenant == null) {
                // Only allow global records if no tenant context
                return criteriaBuilder.isNull(root.get("organizationId"));
            }

            return criteriaBuilder.or(
                    criteriaBuilder.equal(root.get("organizationId"), currentTenant),
                    criteriaBuilder.isNull(root.get("organizationId")));
        };
    }

    /**
     * Create a specification for active records in current tenant.
     */
    protected static <T> Specification<T> withCurrentTenantAndActive() {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            // Tenant filter
            UUID currentTenant = TenantSecurityContext.getCurrentTenant();
            if (currentTenant == null) {
                return criteriaBuilder.disjunction();
            }
            predicates.add(criteriaBuilder.equal(root.get("organizationId"), currentTenant));

            // Active filter
            predicates.add(criteriaBuilder.equal(root.get("isActive"), true));

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }

    /**
     * Create a specification for effective records (active and within validity
     * period).
     */
    protected static <T> Specification<T> withCurrentTenantAndEffective() {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            // Tenant filter
            UUID currentTenant = TenantSecurityContext.getCurrentTenant();
            if (currentTenant == null) {
                return criteriaBuilder.disjunction();
            }
            predicates.add(criteriaBuilder.equal(root.get("organizationId"), currentTenant));

            // Active filter
            predicates.add(criteriaBuilder.equal(root.get("isActive"), true));

            // Effective date filters
            java.time.LocalDateTime now = java.time.LocalDateTime.now();

            // effectiveFrom <= now OR effectiveFrom IS NULL
            predicates.add(criteriaBuilder.or(
                    criteriaBuilder.lessThanOrEqualTo(root.get("effectiveFrom"), now),
                    criteriaBuilder.isNull(root.get("effectiveFrom"))));

            // expiresAt > now OR expiresAt IS NULL
            predicates.add(criteriaBuilder.or(
                    criteriaBuilder.greaterThan(root.get("expiresAt"), now),
                    criteriaBuilder.isNull(root.get("expiresAt"))));

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }

    /**
     * Validate that an entity belongs to the current tenant.
     */
    protected void validateTenantOwnership(Object entity) {
        UUID currentTenant = TenantSecurityContext.getCurrentTenant();
        if (currentTenant == null) {
            throw new TenantSecurityContext.TenantSecurityException("No tenant context for ownership validation");
        }

        UUID entityTenant = extractTenantId(entity);
        if (entityTenant != null && !currentTenant.equals(entityTenant)) {
            throw new TenantSecurityContext.TenantSecurityException(
                    String.format("Entity belongs to different tenant: entity=%s, current=%s",
                            entityTenant, currentTenant));
        }
    }

    /**
     * Set the tenant ID on an entity before saving.
     */
    protected void setTenantId(Object entity) {
        UUID currentTenant = TenantSecurityContext.getCurrentTenant();
        if (currentTenant == null) {
            log.warn("No tenant context when setting tenant ID on entity: {}", entity.getClass().getSimpleName());
            return;
        }

        try {
            // Use reflection to set organizationId field
            java.lang.reflect.Field field = findOrganizationIdField(entity.getClass());
            if (field != null) {
                field.setAccessible(true);
                field.set(entity, currentTenant);
                log.debug("Set tenant ID {} on entity {}", currentTenant, entity.getClass().getSimpleName());
            }
        } catch (Exception e) {
            log.error("Failed to set tenant ID on entity", e);
        }
    }

    /**
     * Extract tenant ID from an entity.
     */
    private UUID extractTenantId(Object entity) {
        try {
            java.lang.reflect.Field field = findOrganizationIdField(entity.getClass());
            if (field != null) {
                field.setAccessible(true);
                return (UUID) field.get(entity);
            }
        } catch (Exception e) {
            log.debug("Could not extract tenant ID from entity: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Find the organizationId field in an entity class.
     */
    private java.lang.reflect.Field findOrganizationIdField(Class<?> entityClass) {
        Class<?> currentClass = entityClass;
        while (currentClass != null) {
            try {
                return currentClass.getDeclaredField("organizationId");
            } catch (NoSuchFieldException e) {
                currentClass = currentClass.getSuperclass();
            }
        }
        return null;
    }

    /**
     * Create a tenant-safe save operation.
     */
    protected <T> T tenantSafeSave(T entity, java.util.function.Function<T, T> saveFunction) {
        // Set tenant ID if not already set
        if (extractTenantId(entity) == null) {
            setTenantId(entity);
        } else {
            // Validate ownership if tenant ID is already set
            validateTenantOwnership(entity);
        }

        return saveFunction.apply(entity);
    }

    /**
     * Create a tenant-safe update operation.
     */
    protected <T> T tenantSafeUpdate(T entity, java.util.function.Function<T, T> updateFunction) {
        // Always validate ownership for updates
        validateTenantOwnership(entity);
        return updateFunction.apply(entity);
    }

    /**
     * Create a tenant-safe delete operation.
     */
    protected void tenantSafeDelete(Object entity, Runnable deleteFunction) {
        // Validate ownership before deletion
        validateTenantOwnership(entity);
        deleteFunction.run();
    }

    /**
     * Log tenant-aware operation.
     */
    protected void logTenantOperation(String operation, Object entity) {
        if (log.isDebugEnabled()) {
            UUID currentTenant = TenantSecurityContext.getCurrentTenant();
            log.debug("Tenant operation: {} on {} for tenant: {}",
                    operation, entity.getClass().getSimpleName(), currentTenant);
        }
    }
}