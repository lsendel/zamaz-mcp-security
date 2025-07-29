package com.zamaz.mcp.security.exception;

/**
 * Exception thrown when OAuth2 client registration or management operations fail.
 */
public class ClientRegistrationException extends RuntimeException {
    
    private String errorCode;
    
    public ClientRegistrationException(String message) {
        super(message);
        this.errorCode = "CLIENT_REGISTRATION_ERROR";
    }
    
    public ClientRegistrationException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
    }
    
    public ClientRegistrationException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = "CLIENT_REGISTRATION_ERROR";
    }
    
    public ClientRegistrationException(String message, String errorCode, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }
    
    public String getErrorCode() {
        return errorCode;
    }
}