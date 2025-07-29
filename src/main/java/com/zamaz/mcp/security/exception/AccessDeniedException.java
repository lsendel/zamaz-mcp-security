package com.zamaz.mcp.security.exception;

/**
 * Exception thrown when access is denied to a resource or operation
 */
public class AccessDeniedException extends RuntimeException {
    
    private final String resource;
    private final String action;
    private final String userId;
    
    public AccessDeniedException(String message) {
        super(message);
        this.resource = null;
        this.action = null;
        this.userId = null;
    }
    
    public AccessDeniedException(String message, Throwable cause) {
        super(message, cause);
        this.resource = null;
        this.action = null;
        this.userId = null;
    }
    
    public AccessDeniedException(String message, String resource, String action, String userId) {
        super(message);
        this.resource = resource;
        this.action = action;
        this.userId = userId;
    }
    
    public String getResource() {
        return resource;
    }
    
    public String getAction() {
        return action;
    }
    
    public String getUserId() {
        return userId;
    }
}