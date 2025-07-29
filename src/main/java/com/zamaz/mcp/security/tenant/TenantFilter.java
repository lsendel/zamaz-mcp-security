package com.zamaz.mcp.security.tenant;

import com.zamaz.mcp.security.tenant.TenantSecurityContext.TenantSecurityException;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.UUID;

/**
 * Tenant filter to extract and set organization context from JWT tokens.
 * Ensures proper tenant isolation by setting the tenant context for each
 * request.
 */
@Component
@Order(1)
@RequiredArgsConstructor
@Slf4j
public class TenantFilter implements Filter {

    private static final String ORGANIZATION_ID_HEADER = "X-Organization-ID";
    private static final String ORGANIZATION_ID_CLAIM = "organizationId";
    private static final String ORGANIZATION_NAME_CLAIM = "organizationName";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        try {
            // Extract tenant information
            TenantInfo tenantInfo = extractTenantInfo(httpRequest);

            if (tenantInfo != null) {
                // Validate tenant access for authenticated users
                validateTenantAccess(tenantInfo);

                // Set tenant context
                TenantSecurityContext.setCurrentTenant(tenantInfo.getTenantId(), tenantInfo.getTenantName());

                // Add tenant info to response headers for debugging
                if (log.isDebugEnabled()) {
                    httpResponse.setHeader("X-Current-Tenant", tenantInfo.getTenantId().toString());
                }

                log.debug("Set tenant context: {}", tenantInfo);
            } else {
                log.debug("No tenant information found in request");
            }

            // Continue with the filter chain
            chain.doFilter(request, response);

        } catch (TenantSecurityException e) {
            log.warn("Tenant security violation: {}", e.getMessage());
            httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
            httpResponse.getWriter().write("{\"error\":\"tenant_violation\",\"message\":\"" + e.getMessage() + "\"}");
            return;

        } catch (Exception e) {
            log.error("Error processing tenant filter", e);
            httpResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            httpResponse.getWriter().write("{\"error\":\"internal_error\",\"message\":\"Tenant processing failed\"}");
            return;

        } finally {
            // Always clear tenant context after request
            TenantSecurityContext.clear();
        }
    }

    /**
     * Extract tenant information from the request.
     */
    private TenantInfo extractTenantInfo(HttpServletRequest request) {
        // Try to extract from JWT token first
        TenantInfo jwtTenantInfo = extractTenantFromJWT();
        if (jwtTenantInfo != null) {
            return jwtTenantInfo;
        }

        // Try to extract from header
        TenantInfo headerTenantInfo = extractTenantFromHeader(request);
        if (headerTenantInfo != null) {
            return headerTenantInfo;
        }

        // Try to extract from path parameter
        TenantInfo pathTenantInfo = extractTenantFromPath(request);
        if (pathTenantInfo != null) {
            return pathTenantInfo;
        }

        return null;
    }

    /**
     * Extract tenant information from JWT token.
     */
    private TenantInfo extractTenantFromJWT() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication instanceof JwtAuthenticationToken jwtAuth) {
                Jwt jwt = jwtAuth.getToken();

                String organizationIdStr = jwt.getClaimAsString(ORGANIZATION_ID_CLAIM);
                if (organizationIdStr != null) {
                    UUID organizationId = UUID.fromString(organizationIdStr);
                    String organizationName = jwt.getClaimAsString(ORGANIZATION_NAME_CLAIM);

                    return new TenantInfo(organizationId, organizationName, "jwt");
                }
            }
        } catch (Exception e) {
            log.debug("Could not extract tenant from JWT: {}", e.getMessage());
        }

        return null;
    }

    /**
     * Extract tenant information from request header.
     */
    private TenantInfo extractTenantFromHeader(HttpServletRequest request) {
        try {
            String organizationHeader = request.getHeader(ORGANIZATION_ID_HEADER);
            if (organizationHeader != null && !organizationHeader.trim().isEmpty()) {
                UUID organizationId = UUID.fromString(organizationHeader.trim());
                return new TenantInfo(organizationId, null, "header");
            }
        } catch (Exception e) {
            log.debug("Could not extract tenant from header: {}", e.getMessage());
        }

        return null;
    }

    /**
     * Extract tenant information from request path.
     */
    private TenantInfo extractTenantFromPath(HttpServletRequest request) {
        try {
            String requestURI = request.getRequestURI();

            // Look for patterns like /api/v1/organizations/{orgId}/...
            if (requestURI.contains("/organizations/")) {
                String[] pathParts = requestURI.split("/");
                for (int i = 0; i < pathParts.length - 1; i++) {
                    if ("organizations".equals(pathParts[i]) && i + 1 < pathParts.length) {
                        String orgIdStr = pathParts[i + 1];
                        try {
                            UUID organizationId = UUID.fromString(orgIdStr);
                            return new TenantInfo(organizationId, null, "path");
                        } catch (IllegalArgumentException e) {
                            // Not a valid UUID, continue
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.debug("Could not extract tenant from path: {}", e.getMessage());
        }

        return null;
    }

    /**
     * Validate tenant access for the current user.
     */
    private void validateTenantAccess(TenantInfo tenantInfo) throws TenantSecurityException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new TenantSecurityException("No authenticated user for tenant access");
        }

        // Additional validation logic could be added here
        // For example, checking if the user has access to the specified organization

        log.debug("Validated tenant access for user: {} to tenant: {}",
                authentication.getName(), tenantInfo.getTenantId());
    }

    /**
     * Tenant information holder.
     */
    private static class TenantInfo {
        private final UUID tenantId;
        private final String tenantName;
        private final String source;

        public TenantInfo(UUID tenantId, String tenantName, String source) {
            this.tenantId = tenantId;
            this.tenantName = tenantName;
            this.source = source;
        }

        public UUID getTenantId() {
            return tenantId;
        }

        public String getTenantName() {
            return tenantName;
        }

        public String getSource() {
            return source;
        }

        @Override
        public String toString() {
            return String.format("TenantInfo{id=%s, name='%s', source='%s'}",
                    tenantId, tenantName, source);
        }
    }
}