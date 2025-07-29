package com.zamaz.mcp.security.rbac;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service for managing roles and permissions
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RoleService {
    
    // In-memory storage for demo purposes
    // In production, this would be backed by a database
    private final Map<String, Set<Role>> userRoles = new ConcurrentHashMap<>();
    private final Map<String, Map<String, String>> resourceOwners = new ConcurrentHashMap<>();
    
    /**
     * Get all roles for a user in an organization
     */
    public Set<Role> getUserRoles(UUID userId, UUID organizationId) {
        String key = buildUserRoleKey(userId, organizationId);
        Set<Role> roles = userRoles.get(key);
        
        if (roles == null || roles.isEmpty()) {
            // Default to USER role if no roles assigned
            log.debug("No roles found for user {}, assigning default USER role", userId);
            return EnumSet.of(Role.USER);
        }
        
        return EnumSet.copyOf(roles);
    }
    
    /**
     * Assign a role to a user in an organization
     */
    public void assignRole(UUID userId, UUID organizationId, Role role) {
        String key = buildUserRoleKey(userId, organizationId);
        userRoles.computeIfAbsent(key, k -> EnumSet.noneOf(Role.class)).add(role);
        
        log.info("Assigned role {} to user {} in organization {}", 
            role, userId, organizationId);
    }
    
    /**
     * Remove a role from a user in an organization
     */
    public void removeRole(UUID userId, UUID organizationId, Role role) {
        String key = buildUserRoleKey(userId, organizationId);
        Set<Role> roles = userRoles.get(key);
        
        if (roles != null) {
            roles.remove(role);
            if (roles.isEmpty()) {
                userRoles.remove(key);
            }
        }
        
        log.info("Removed role {} from user {} in organization {}", 
            role, userId, organizationId);
    }
    
    /**
     * Check if a user has a specific role
     */
    public boolean hasRole(UUID userId, UUID organizationId, Role role) {
        Set<Role> roles = getUserRoles(userId, organizationId);
        return roles.contains(role);
    }
    
    /**
     * Check if a user is the owner of a resource
     */
    public boolean isResourceOwner(UUID userId, String resourceType, String resourceId) {
        Map<String, String> owners = resourceOwners.get(resourceType);
        if (owners == null) {
            return false;
        }
        
        String ownerId = owners.get(resourceId);
        return userId.toString().equals(ownerId);
    }
    
    /**
     * Set the owner of a resource
     */
    public void setResourceOwner(String resourceType, String resourceId, UUID ownerId) {
        resourceOwners.computeIfAbsent(resourceType, k -> new ConcurrentHashMap<>())
                     .put(resourceId, ownerId.toString());
        
        log.debug("Set owner of {} {} to {}", resourceType, resourceId, ownerId);
    }
    
    /**
     * Get all permissions for a user based on their roles
     */
    public Set<Permission> getUserPermissions(UUID userId, UUID organizationId) {
        Set<Role> roles = getUserRoles(userId, organizationId);
        Set<Permission> permissions = EnumSet.noneOf(Permission.class);
        
        for (Role role : roles) {
            permissions.addAll(role.getPermissions());
        }
        
        return permissions;
    }
    
    /**
     * Initialize default roles for a new organization
     */
    public void initializeOrganizationRoles(UUID organizationId, UUID ownerId) {
        // Assign ORGANIZATION_OWNER role to the creator
        assignRole(ownerId, organizationId, Role.ORGANIZATION_OWNER);
        
        log.info("Initialized organization {} with owner {}", organizationId, ownerId);
    }
    
    /**
     * Get all users with a specific role in an organization
     */
    public List<UUID> getUsersWithRole(UUID organizationId, Role role) {
        List<UUID> users = new ArrayList<>();
        
        userRoles.forEach((key, roles) -> {
            if (roles.contains(role) && key.contains(organizationId.toString())) {
                String userId = key.split(":")[0];
                users.add(UUID.fromString(userId));
            }
        });
        
        return users;
    }
    
    private String buildUserRoleKey(UUID userId, UUID organizationId) {
        return userId.toString() + ":" + organizationId.toString();
    }
}