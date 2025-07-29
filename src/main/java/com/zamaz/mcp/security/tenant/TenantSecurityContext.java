package com.zamaz.mcp.security.tenant;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * Thread-local tenant security context for multi-tenant isolation.
 * Manages the current tenant/organization context for security operations.
 */
@Component
@Slf4j
public class TenantSecurityContext {

    private static final ThreadLocal<UUID> currentTenant = new ThreadLocal<>();
    private static final ThreadLocal<String> currentTenantName = new ThreadLocal<>();
    private static final ThreadLocal<TenantSecurityInfo> tenantSecurityInfo = new ThreadLocal<>();

    /**
     * Set the current tenant ID for the thread.
     */
    public static void setCurrentTenant(UUID tenantId) {
        currentTenant.set(tenantId);
        log.debug("Set current tenant to: {}", tenantId);
    }

    /**
     * Set the current tenant with additional information.
     */
    public static void setCurrentTenant(UUID tenantId, String tenantName) {
        currentTenant.set(tenantId);
        currentTenantName.set(tenantName);
        log.debug("Set current tenant to: {} ({})", tenantId, tenantName);
    }

    /**
     * Set comprehensive tenant security information.
     */
    public static void setTenantSecurityInfo(TenantSecurityInfo info) {
        tenantSecurityInfo.set(info);
        currentTenant.set(info.getTenantId());
        currentTenantName.set(info.getTenantName());
        log.debug("Set tenant security info for: {} ({})", info.getTenantId(), info.getTenantName());
    }

    /**
     * Get the current tenant ID.
     */
    public static UUID getCurrentTenant() {
        return currentTenant.get();
    }

    /**
     * Get the current tenant name.
     */
    public static String getCurrentTenantName() {
        return currentTenantName.get();
    }

    /**
     * Get comprehensive tenant security information.
     */
    public static TenantSecurityInfo getTenantSecurityInfo() {
        return tenantSecurityInfo.get();
    }

    /**
     * Check if a tenant is currently set.
     */
    public static boolean hasTenant() {
        return currentTenant.get() != null;
    }

    /**
     * Check if the specified tenant ID matches the current tenant.
     */
    public static boolean isCurrentTenant(UUID tenantId) {
        UUID current = currentTenant.get();
        return current != null && current.equals(tenantId);
    }

    /**
     * Validate that the current tenant matches the required tenant.
     */
    public static void validateTenant(UUID requiredTenantId) throws TenantSecurityException {
        UUID current = currentTenant.get();

        if (current == null) {
            throw new TenantSecurityException("No tenant context set");
        }

        if (!current.equals(requiredTenantId)) {
            throw new TenantSecurityException(
                    String.format("Tenant mismatch: current=%s, required=%s", current, requiredTenantId));
        }
    }

    /**
     * Execute code within a specific tenant context.
     */
    public static <T> T executeInTenantContext(UUID tenantId, TenantContextCallback<T> callback) {
        UUID previousTenant = currentTenant.get();
        String previousTenantName = currentTenantName.get();
        TenantSecurityInfo previousInfo = tenantSecurityInfo.get();

        try {
            setCurrentTenant(tenantId);
            return callback.execute();
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            throw new RuntimeException("Error executing in tenant context", e);
        } finally {
            // Restore previous context
            currentTenant.set(previousTenant);
            currentTenantName.set(previousTenantName);
            tenantSecurityInfo.set(previousInfo);
        }
    }

    /**
     * Execute code within a specific tenant context with full info.
     */
    public static <T> T executeInTenantContext(TenantSecurityInfo info, TenantContextCallback<T> callback) {
        UUID previousTenant = currentTenant.get();
        String previousTenantName = currentTenantName.get();
        TenantSecurityInfo previousInfo = tenantSecurityInfo.get();

        try {
            setTenantSecurityInfo(info);
            return callback.execute();
        } catch (Exception e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            throw new RuntimeException("Error executing in tenant context", e);
        } finally {
            // Restore previous context
            currentTenant.set(previousTenant);
            currentTenantName.set(previousTenantName);
            tenantSecurityInfo.set(previousInfo);
        }
    }

    /**
     * Clear the current tenant context.
     */
    public static void clear() {
        UUID tenant = currentTenant.get();
        if (tenant != null) {
            log.debug("Clearing tenant context for: {}", tenant);
        }

        currentTenant.remove();
        currentTenantName.remove();
        tenantSecurityInfo.remove();
    }

    /**
     * Get tenant context summary for logging.
     */
    public static String getContextSummary() {
        UUID tenant = currentTenant.get();
        String name = currentTenantName.get();

        if (tenant == null) {
            return "No tenant context";
        }

        if (name != null) {
            return String.format("Tenant: %s (%s)", tenant, name);
        }

        return String.format("Tenant: %s", tenant);
    }

    /**
     * Callback interface for tenant context execution.
     */
    @FunctionalInterface
    public interface TenantContextCallback<T> {
        T execute() throws Exception;
    }

    /**
     * Tenant security information holder.
     */
    public static class TenantSecurityInfo {
        private final UUID tenantId;
        private final String tenantName;
        private final boolean isActive;
        private final java.util.Set<String> securityPolicies;
        private final java.util.Map<String, Object> securityAttributes;

        public TenantSecurityInfo(UUID tenantId, String tenantName, boolean isActive,
                java.util.Set<String> securityPolicies,
                java.util.Map<String, Object> securityAttributes) {
            this.tenantId = tenantId;
            this.tenantName = tenantName;
            this.isActive = isActive;
            this.securityPolicies = securityPolicies != null ? securityPolicies : java.util.Collections.emptySet();
            this.securityAttributes = securityAttributes != null ? securityAttributes
                    : java.util.Collections.emptyMap();
        }

        // Getters
        public UUID getTenantId() {
            return tenantId;
        }

        public String getTenantName() {
            return tenantName;
        }

        public boolean isActive() {
            return isActive;
        }

        public java.util.Set<String> getSecurityPolicies() {
            return securityPolicies;
        }

        public java.util.Map<String, Object> getSecurityAttributes() {
            return securityAttributes;
        }

        public boolean hasSecurityPolicy(String policy) {
            return securityPolicies.contains(policy);
        }

        public Object getSecurityAttribute(String key) {
            return securityAttributes.get(key);
        }

        @Override
        public String toString() {
            return String.format("TenantSecurityInfo{id=%s, name='%s', active=%s}",
                    tenantId, tenantName, isActive);
        }
    }

    /**
     * Exception thrown for tenant security violations.
     */
    public static class TenantSecurityException extends RuntimeException {
        public TenantSecurityException(String message) {
            super(message);
        }

        public TenantSecurityException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}