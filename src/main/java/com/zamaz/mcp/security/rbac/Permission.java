package com.zamaz.mcp.security.rbac;

/**
 * System permissions for fine-grained access control
 */
public enum Permission {
    
    // Organization permissions
    ORGANIZATION_CREATE("organization:create"),
    ORGANIZATION_READ("organization:read"),
    ORGANIZATION_UPDATE("organization:update"),
    ORGANIZATION_DELETE("organization:delete"),
    ORGANIZATION_MANAGE_USERS("organization:manage_users"),
    
    // Debate permissions
    DEBATE_CREATE("debate:create"),
    DEBATE_READ("debate:read"),
    DEBATE_UPDATE("debate:update"),
    DEBATE_DELETE("debate:delete"),
    DEBATE_MODERATE("debate:moderate"),
    DEBATE_PARTICIPATE("debate:participate"),
    DEBATE_VIEW_ANALYTICS("debate:view_analytics"),
    
    // LLM permissions
    LLM_USE_BASIC("llm:use_basic"),
    LLM_USE_PREMIUM("llm:use_premium"),
    LLM_CONFIGURE("llm:configure"),
    LLM_VIEW_USAGE("llm:view_usage"),
    LLM_MANAGE_PROVIDERS("llm:manage_providers"),
    
    // Template permissions
    TEMPLATE_CREATE("template:create"),
    TEMPLATE_READ("template:read"),
    TEMPLATE_UPDATE("template:update"),
    TEMPLATE_DELETE("template:delete"),
    TEMPLATE_SHARE("template:share"),
    TEMPLATE_LIST("template:list"),
    
    // Context permissions
    CONTEXT_CREATE("context:create"),
    CONTEXT_READ("context:read"),
    CONTEXT_UPDATE("context:update"),
    CONTEXT_DELETE("context:delete"),
    CONTEXT_SHARE("context:share"),
    
    // RAG permissions
    RAG_CREATE_KB("rag:create_kb"),
    RAG_QUERY("rag:query"),
    RAG_MANAGE_DOCUMENTS("rag:manage_documents"),
    RAG_VIEW_ANALYTICS("rag:view_analytics"),
    
    // System permissions
    SYSTEM_ADMIN("system:admin"),
    SYSTEM_MONITOR("system:monitor"),
    SYSTEM_CONFIGURE("system:configure");
    
    private final String permission;
    
    Permission(String permission) {
        this.permission = permission;
    }
    
    public String getPermission() {
        return permission;
    }
    
    @Override
    public String toString() {
        return permission;
    }
}