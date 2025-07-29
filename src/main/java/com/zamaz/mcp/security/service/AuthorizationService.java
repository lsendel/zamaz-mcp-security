package com.zamaz.mcp.security.service;

import com.zamaz.mcp.security.model.McpUser;
import com.zamaz.mcp.security.model.Permission;
import com.zamaz.mcp.security.model.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Service for handling authorization logic including permissions and roles.
 * Implements organization-based access control and context-level permissions.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthorizationService {
    
    private final JwtService jwtService;
    
    /**
     * Check if user has required permission for an organization.
     * 
     * @param user The authenticated user
     * @param permission The required permission (e.g., "debate:create")
     * @param organizationId The organization ID (nullable)
     * @return true if user has permission
     */
    public boolean hasPermission(McpUser user, String permission, String organizationId) {
        log.debug("Checking permission '{}' for user '{}' in organization '{}'", 
                permission, user.getId(), organizationId);
        
        // System admin has all permissions
        if (user.hasRole("SYSTEM_ADMIN")) {
            log.debug("User has SYSTEM_ADMIN role, granting permission");
            return true;
        }
        
        // Check organization-specific permissions
        if (organizationId != null) {
            Set<Permission> orgPermissions = user.getOrganizationPermissions(organizationId);
            boolean hasOrgPermission = orgPermissions.stream()
                    .anyMatch(p -> p.getName().equals(permission));
            
            if (hasOrgPermission) {
                log.debug("User has organization-specific permission");
                return true;
            }
        }
        
        // Check global permissions
        Set<Permission> globalPermissions = user.getGlobalPermissions();
        boolean hasGlobalPermission = globalPermissions.stream()
                .anyMatch(p -> p.getName().equals(permission));
        
        if (hasGlobalPermission) {
            log.debug("User has global permission");
            return true;
        }
        
        log.debug("User does not have required permission");
        return false;
    }
    
    /**
     * Check if user has required role in an organization.
     * 
     * @param user The authenticated user
     * @param role The required role (e.g., "ADMIN", "USER")
     * @param organizationId The organization ID (nullable)
     * @return true if user has role
     */
    public boolean hasRole(McpUser user, String role, String organizationId) {
        log.debug("Checking role '{}' for user '{}' in organization '{}'", 
                role, user.getId(), organizationId);
        
        // Check organization-specific roles
        if (organizationId != null) {
            Set<Role> orgRoles = user.getOrganizationRoles(organizationId);
            boolean hasOrgRole = orgRoles.stream()
                    .anyMatch(r -> r.getName().equals(role));
            
            if (hasOrgRole) {
                log.debug("User has organization-specific role");
                return true;
            }
        }
        
        // Check global roles
        boolean hasGlobalRole = user.hasRole(role);
        
        if (hasGlobalRole) {
            log.debug("User has global role");
            return true;
        }
        
        log.debug("User does not have required role");
        return false;
    }
    
    /**
     * Check if user has access to a specific organization.
     * 
     * @param user The authenticated user
     * @param organizationId The organization ID
     * @return true if user has access
     */
    public boolean hasOrganizationAccess(McpUser user, String organizationId) {
        log.debug("Checking organization access for user '{}' to organization '{}'", 
                user.getId(), organizationId);
        
        // System admin has access to all organizations
        if (user.hasRole("SYSTEM_ADMIN")) {
            return true;
        }
        
        // Check if user is member of organization
        return user.getOrganizationIds().contains(organizationId);
    }
    
    /**
     * Check if user owns a specific resource.
     * 
     * @param user The authenticated user
     * @param resourceOwnerId The ID of the resource owner
     * @return true if user owns the resource
     */
    public boolean hasResourceOwnership(McpUser user, String resourceOwnerId) {
        log.debug("Checking resource ownership for user '{}' on resource owned by '{}'", 
                user.getId(), resourceOwnerId);
        
        return user.getId().equals(resourceOwnerId);
    }
    
    /**
     * Check context-level permissions for a user.
     * 
     * @param user The authenticated user
     * @param contextId The context ID
     * @param permission The required permission
     * @return true if user has context-level permission
     */
    public boolean hasContextPermission(McpUser user, String contextId, String permission) {
        log.debug("Checking context permission '{}' for user '{}' on context '{}'", 
                permission, user.getId(), contextId);
        
        // Context-level permissions are stored in user's context permissions
        return user.getContextPermissions().stream()
                .anyMatch(cp -> cp.getContextId().equals(contextId) && 
                              cp.getPermission().getName().equals(permission));
    }
    
    /**
     * Get all permissions for a user in a specific organization.
     * 
     * @param user The authenticated user
     * @param organizationId The organization ID
     * @return Set of permissions
     */
    public Set<Permission> getUserPermissions(McpUser user, String organizationId) {
        Set<Permission> permissions = user.getGlobalPermissions();
        
        if (organizationId != null) {
            permissions.addAll(user.getOrganizationPermissions(organizationId));
        }
        
        return permissions;
    }
    
    /**
     * Check if user has access to a specific resource.
     * 
     * @param user The authenticated user
     * @param resourceId The resource ID
     * @param organizationId The organization ID
     * @return true if user has access to the resource
     */
    public boolean hasResourceAccess(McpUser user, String resourceId, String organizationId) {
        log.debug("Checking resource access for user '{}' on resource '{}' in organization '{}'", 
                user.getId(), resourceId, organizationId);
        
        // System admin has access to all resources
        if (user.hasRole("SYSTEM_ADMIN")) {
            return true;
        }
        
        // Organization admin has access to all resources in their organization
        if (organizationId != null && user.hasOrganizationRole(organizationId, "ORG_ADMIN")) {
            return true;
        }
        
        // Check specific resource permissions (would typically check a database)
        // For now, we'll allow access if user belongs to the organization
        return organizationId != null && user.getOrganizationIds().contains(organizationId);
    }
}