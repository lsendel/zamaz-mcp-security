package com.zamaz.mcp.security.rbac;

import java.util.Set;
import java.util.EnumSet;

/**
 * Predefined roles with associated permissions
 * Follows principle of least privilege
 */
public enum Role {
    
    // System roles
    SYSTEM_ADMIN("System Administrator", EnumSet.allOf(Permission.class)),
    
    // Organization roles
    ORGANIZATION_OWNER("Organization Owner", EnumSet.of(
        Permission.ORGANIZATION_READ,
        Permission.ORGANIZATION_UPDATE,
        Permission.ORGANIZATION_MANAGE_USERS,
        Permission.DEBATE_CREATE,
        Permission.DEBATE_READ,
        Permission.DEBATE_UPDATE,
        Permission.DEBATE_DELETE,
        Permission.DEBATE_MODERATE,
        Permission.DEBATE_VIEW_ANALYTICS,
        Permission.LLM_USE_PREMIUM,
        Permission.LLM_CONFIGURE,
        Permission.LLM_VIEW_USAGE,
        Permission.TEMPLATE_CREATE,
        Permission.TEMPLATE_READ,
        Permission.TEMPLATE_UPDATE,
        Permission.TEMPLATE_DELETE,
        Permission.TEMPLATE_SHARE,
        Permission.RAG_CREATE_KB,
        Permission.RAG_QUERY,
        Permission.RAG_MANAGE_DOCUMENTS,
        Permission.RAG_VIEW_ANALYTICS
    )),
    
    ORGANIZATION_ADMIN("Organization Administrator", EnumSet.of(
        Permission.ORGANIZATION_READ,
        Permission.ORGANIZATION_UPDATE,
        Permission.ORGANIZATION_MANAGE_USERS,
        Permission.DEBATE_CREATE,
        Permission.DEBATE_READ,
        Permission.DEBATE_UPDATE,
        Permission.DEBATE_MODERATE,
        Permission.DEBATE_VIEW_ANALYTICS,
        Permission.LLM_USE_PREMIUM,
        Permission.LLM_VIEW_USAGE,
        Permission.TEMPLATE_CREATE,
        Permission.TEMPLATE_READ,
        Permission.TEMPLATE_UPDATE,
        Permission.TEMPLATE_SHARE,
        Permission.RAG_CREATE_KB,
        Permission.RAG_QUERY,
        Permission.RAG_MANAGE_DOCUMENTS
    )),
    
    // Debate-specific roles
    DEBATE_MODERATOR("Debate Moderator", EnumSet.of(
        Permission.ORGANIZATION_READ,
        Permission.DEBATE_CREATE,
        Permission.DEBATE_READ,
        Permission.DEBATE_UPDATE,
        Permission.DEBATE_MODERATE,
        Permission.DEBATE_VIEW_ANALYTICS,
        Permission.LLM_USE_BASIC,
        Permission.TEMPLATE_READ,
        Permission.TEMPLATE_CREATE,
        Permission.RAG_QUERY
    )),
    
    DEBATE_PARTICIPANT("Debate Participant", EnumSet.of(
        Permission.ORGANIZATION_READ,
        Permission.DEBATE_READ,
        Permission.DEBATE_PARTICIPATE,
        Permission.LLM_USE_BASIC,
        Permission.TEMPLATE_READ,
        Permission.RAG_QUERY
    )),
    
    // Content roles
    CONTENT_CREATOR("Content Creator", EnumSet.of(
        Permission.ORGANIZATION_READ,
        Permission.DEBATE_CREATE,
        Permission.DEBATE_READ,
        Permission.DEBATE_PARTICIPATE,
        Permission.LLM_USE_BASIC,
        Permission.TEMPLATE_CREATE,
        Permission.TEMPLATE_READ,
        Permission.TEMPLATE_UPDATE,
        Permission.TEMPLATE_SHARE,
        Permission.RAG_CREATE_KB,
        Permission.RAG_QUERY,
        Permission.RAG_MANAGE_DOCUMENTS
    )),
    
    // Basic user role
    USER("User", EnumSet.of(
        Permission.ORGANIZATION_READ,
        Permission.DEBATE_READ,
        Permission.DEBATE_PARTICIPATE,
        Permission.LLM_USE_BASIC,
        Permission.TEMPLATE_READ,
        Permission.RAG_QUERY
    )),
    
    // Read-only role
    VIEWER("Viewer", EnumSet.of(
        Permission.ORGANIZATION_READ,
        Permission.DEBATE_READ,
        Permission.TEMPLATE_READ
    ));
    
    private final String displayName;
    private final Set<Permission> permissions;
    
    Role(String displayName, Set<Permission> permissions) {
        this.displayName = displayName;
        this.permissions = EnumSet.copyOf(permissions);
    }
    
    public String getDisplayName() {
        return displayName;
    }
    
    public Set<Permission> getPermissions() {
        return EnumSet.copyOf(permissions);
    }
    
    public boolean hasPermission(Permission permission) {
        return permissions.contains(permission);
    }
    
    public boolean hasAnyPermission(Permission... permissions) {
        for (Permission permission : permissions) {
            if (this.permissions.contains(permission)) {
                return true;
            }
        }
        return false;
    }
    
    public boolean hasAllPermissions(Permission... permissions) {
        for (Permission permission : permissions) {
            if (!this.permissions.contains(permission)) {
                return false;
            }
        }
        return true;
    }
}