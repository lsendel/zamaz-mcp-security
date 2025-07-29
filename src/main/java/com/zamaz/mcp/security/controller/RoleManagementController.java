package com.zamaz.mcp.security.controller;

import com.zamaz.mcp.security.entity.Role;
import com.zamaz.mcp.security.entity.Permission;
import com.zamaz.mcp.security.service.RoleManagementService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Role and permission management endpoints with organization-scoped access.
 */
@RestController
@RequestMapping("/api/v1/roles")
@RequiredArgsConstructor
@Slf4j
public class RoleManagementController {

    private final RoleManagementService roleManagementService;

    /**
     * Get all roles in the current organization.
     */
    @GetMapping
    @PreAuthorize("@securityExpressions.hasPermission('role', 'read')")
    public ResponseEntity<Page<RoleDto>> getRoles(Pageable pageable) {
        Page<Role> roles = roleManagementService.getRoles(pageable);
        Page<RoleDto> roleDtos = roles.map(this::convertToDto);
        return ResponseEntity.ok(roleDtos);
    }

    /**
     * Get role by ID.
     */
    @GetMapping("/{roleId}")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('role', 'read', #roleId)")
    public ResponseEntity<RoleDto> getRole(@PathVariable UUID roleId) {
        Role role = roleManagementService.getRole(roleId);
        return ResponseEntity.ok(convertToDto(role));
    }

    /**
     * Create new role.
     */
    @PostMapping
    @PreAuthorize("@securityExpressions.hasPermission('role', 'create')")
    public ResponseEntity<RoleDto> createRole(@Valid @RequestBody CreateRoleRequest request) {
        Role role = roleManagementService.createRole(request);
        return ResponseEntity.ok(convertToDto(role));
    }

    /**
     * Update role.
     */
    @PutMapping("/{roleId}")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('role', 'update', #roleId)")
    public ResponseEntity<RoleDto> updateRole(@PathVariable UUID roleId,
            @Valid @RequestBody UpdateRoleRequest request) {
        Role role = roleManagementService.updateRole(roleId, request);
        return ResponseEntity.ok(convertToDto(role));
    }

    /**
     * Delete role.
     */
    @DeleteMapping("/{roleId}")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('role', 'delete', #roleId)")
    public ResponseEntity<Void> deleteRole(@PathVariable UUID roleId) {
        roleManagementService.deleteRole(roleId);
        return ResponseEntity.noContent().build();
    }

    /**
     * Get role permissions.
     */
    @GetMapping("/{roleId}/permissions")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('role', 'read', #roleId)")
    public ResponseEntity<Set<PermissionDto>> getRolePermissions(@PathVariable UUID roleId) {
        Set<Permission> permissions = roleManagementService.getRolePermissions(roleId);
        Set<PermissionDto> permissionDtos = permissions.stream()
                .map(this::convertPermissionToDto)
                .collect(java.util.stream.Collectors.toSet());
        return ResponseEntity.ok(permissionDtos);
    }

    /**
     * Assign permission to role.
     */
    @PostMapping("/{roleId}/permissions/{permissionId}")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('role', 'manage', #roleId)")
    public ResponseEntity<Void> assignPermissionToRole(@PathVariable UUID roleId, @PathVariable UUID permissionId) {
        roleManagementService.assignPermissionToRole(roleId, permissionId);
        return ResponseEntity.ok().build();
    }

    /**
     * Remove permission from role.
     */
    @DeleteMapping("/{roleId}/permissions/{permissionId}")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('role', 'manage', #roleId)")
    public ResponseEntity<Void> removePermissionFromRole(@PathVariable UUID roleId, @PathVariable UUID permissionId) {
        roleManagementService.removePermissionFromRole(roleId, permissionId);
        return ResponseEntity.ok().build();
    }

    /**
     * Get role hierarchy (parent roles).
     */
    @GetMapping("/{roleId}/parents")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('role', 'read', #roleId)")
    public ResponseEntity<Set<RoleDto>> getParentRoles(@PathVariable UUID roleId) {
        Set<Role> parentRoles = roleManagementService.getParentRoles(roleId);
        Set<RoleDto> roleDtos = parentRoles.stream()
                .map(this::convertToDto)
                .collect(java.util.stream.Collectors.toSet());
        return ResponseEntity.ok(roleDtos);
    }

    /**
     * Get role hierarchy (child roles).
     */
    @GetMapping("/{roleId}/children")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('role', 'read', #roleId)")
    public ResponseEntity<Set<RoleDto>> getChildRoles(@PathVariable UUID roleId) {
        Set<Role> childRoles = roleManagementService.getChildRoles(roleId);
        Set<RoleDto> roleDtos = childRoles.stream()
                .map(this::convertToDto)
                .collect(java.util.stream.Collectors.toSet());
        return ResponseEntity.ok(roleDtos);
    }

    /**
     * Add parent role (role inheritance).
     */
    @PostMapping("/{roleId}/parents/{parentRoleId}")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('role', 'manage', #roleId)")
    public ResponseEntity<Void> addParentRole(@PathVariable UUID roleId, @PathVariable UUID parentRoleId) {
        roleManagementService.addParentRole(roleId, parentRoleId);
        return ResponseEntity.ok().build();
    }

    /**
     * Remove parent role.
     */
    @DeleteMapping("/{roleId}/parents/{parentRoleId}")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('role', 'manage', #roleId)")
    public ResponseEntity<Void> removeParentRole(@PathVariable UUID roleId, @PathVariable UUID parentRoleId) {
        roleManagementService.removeParentRole(roleId, parentRoleId);
        return ResponseEntity.ok().build();
    }

    private RoleDto convertToDto(Role role) {
        RoleDto dto = new RoleDto();
        dto.setId(role.getId());
        dto.setName(role.getName());
        dto.setDescription(role.getDescription());
        dto.setDisplayName(role.getDisplayName());
        dto.setHierarchyLevel(role.getHierarchyLevel());
        dto.setRoleType(role.getRoleType().name());
        dto.setRoleCategory(role.getRoleCategory());
        dto.setIsActive(role.getIsActive());
        dto.setIsSystemRole(role.getIsSystemRole());
        dto.setDelegationAllowed(role.getDelegationAllowed());
        dto.setCreatedAt(role.getCreatedAt());
        return dto;
    }

    private PermissionDto convertPermissionToDto(Permission permission) {
        PermissionDto dto = new PermissionDto();
        dto.setId(permission.getId());
        dto.setResource(permission.getResource());
        dto.setAction(permission.getAction());
        dto.setDescription(permission.getDescription());
        dto.setDisplayName(permission.getDisplayName());
        dto.setResourceId(permission.getResourceId());
        dto.setResourcePattern(permission.getResourcePattern());
        dto.setPermissionType(permission.getPermissionType().name());
        dto.setPermissionScope(permission.getPermissionScope().name());
        dto.setRiskLevel(permission.getRiskLevel());
        dto.setIsActive(permission.getIsActive());
        return dto;
    }

    // DTOs
    public static class RoleDto {
        private UUID id;
        private String name;
        private String description;
        private String displayName;
        private Integer hierarchyLevel;
        private String roleType;
        private String roleCategory;
        private Boolean isActive;
        private Boolean isSystemRole;
        private Boolean delegationAllowed;
        private java.time.LocalDateTime createdAt;

        // Getters and setters
        public UUID getId() {
            return id;
        }

        public void setId(UUID id) {
            this.id = id;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public String getDisplayName() {
            return displayName;
        }

        public void setDisplayName(String displayName) {
            this.displayName = displayName;
        }

        public Integer getHierarchyLevel() {
            return hierarchyLevel;
        }

        public void setHierarchyLevel(Integer hierarchyLevel) {
            this.hierarchyLevel = hierarchyLevel;
        }

        public String getRoleType() {
            return roleType;
        }

        public void setRoleType(String roleType) {
            this.roleType = roleType;
        }

        public String getRoleCategory() {
            return roleCategory;
        }

        public void setRoleCategory(String roleCategory) {
            this.roleCategory = roleCategory;
        }

        public Boolean getIsActive() {
            return isActive;
        }

        public void setIsActive(Boolean isActive) {
            this.isActive = isActive;
        }

        public Boolean getIsSystemRole() {
            return isSystemRole;
        }

        public void setIsSystemRole(Boolean isSystemRole) {
            this.isSystemRole = isSystemRole;
        }

        public Boolean getDelegationAllowed() {
            return delegationAllowed;
        }

        public void setDelegationAllowed(Boolean delegationAllowed) {
            this.delegationAllowed = delegationAllowed;
        }

        public java.time.LocalDateTime getCreatedAt() {
            return createdAt;
        }

        public void setCreatedAt(java.time.LocalDateTime createdAt) {
            this.createdAt = createdAt;
        }
    }

    public static class PermissionDto {
        private UUID id;
        private String resource;
        private String action;
        private String description;
        private String displayName;
        private String resourceId;
        private String resourcePattern;
        private String permissionType;
        private String permissionScope;
        private String riskLevel;
        private Boolean isActive;

        // Getters and setters
        public UUID getId() {
            return id;
        }

        public void setId(UUID id) {
            this.id = id;
        }

        public String getResource() {
            return resource;
        }

        public void setResource(String resource) {
            this.resource = resource;
        }

        public String getAction() {
            return action;
        }

        public void setAction(String action) {
            this.action = action;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public String getDisplayName() {
            return displayName;
        }

        public void setDisplayName(String displayName) {
            this.displayName = displayName;
        }

        public String getResourceId() {
            return resourceId;
        }

        public void setResourceId(String resourceId) {
            this.resourceId = resourceId;
        }

        public String getResourcePattern() {
            return resourcePattern;
        }

        public void setResourcePattern(String resourcePattern) {
            this.resourcePattern = resourcePattern;
        }

        public String getPermissionType() {
            return permissionType;
        }

        public void setPermissionType(String permissionType) {
            this.permissionType = permissionType;
        }

        public String getPermissionScope() {
            return permissionScope;
        }

        public void setPermissionScope(String permissionScope) {
            this.permissionScope = permissionScope;
        }

        public String getRiskLevel() {
            return riskLevel;
        }

        public void setRiskLevel(String riskLevel) {
            this.riskLevel = riskLevel;
        }

        public Boolean getIsActive() {
            return isActive;
        }

        public void setIsActive(Boolean isActive) {
            this.isActive = isActive;
        }
    }

    public static class CreateRoleRequest {
        private String name;
        private String description;
        private String displayName;
        private Integer hierarchyLevel;
        private String roleCategory;

        // Getters and setters
        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public String getDisplayName() {
            return displayName;
        }

        public void setDisplayName(String displayName) {
            this.displayName = displayName;
        }

        public Integer getHierarchyLevel() {
            return hierarchyLevel;
        }

        public void setHierarchyLevel(Integer hierarchyLevel) {
            this.hierarchyLevel = hierarchyLevel;
        }

        public String getRoleCategory() {
            return roleCategory;
        }

        public void setRoleCategory(String roleCategory) {
            this.roleCategory = roleCategory;
        }
    }

    public static class UpdateRoleRequest {
        private String description;
        private String displayName;
        private String roleCategory;
        private Boolean isActive;

        // Getters and setters
        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public String getDisplayName() {
            return displayName;
        }

        public void setDisplayName(String displayName) {
            this.displayName = displayName;
        }

        public String getRoleCategory() {
            return roleCategory;
        }

        public void setRoleCategory(String roleCategory) {
            this.roleCategory = roleCategory;
        }

        public Boolean getIsActive() {
            return isActive;
        }

        public void setIsActive(Boolean isActive) {
            this.isActive = isActive;
        }
    }
}