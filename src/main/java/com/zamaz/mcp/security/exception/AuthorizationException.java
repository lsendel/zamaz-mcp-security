package com.zamaz.mcp.security.exception;

/**
 * Exception thrown when authorization checks fail.
 * Indicates that a user does not have the required permissions or roles.
 */
public class AuthorizationException extends RuntimeException {
    
    public AuthorizationException(String message) {
        super(message);
    }
    
    public AuthorizationException(String message, Throwable cause) {
        super(message, cause);
    }
}