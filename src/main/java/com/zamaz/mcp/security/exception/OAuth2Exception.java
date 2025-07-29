package com.zamaz.mcp.security.exception;

/**
 * OAuth2 specific exception for handling OAuth2 errors according to RFC 6749.
 */
public class OAuth2Exception extends RuntimeException {
    
    private final String error;
    private final String errorDescription;
    private final String errorUri;
    private final int httpStatus;
    
    public OAuth2Exception(String error, String errorDescription) {
        this(error, errorDescription, null, 400);
    }
    
    public OAuth2Exception(String error, String errorDescription, String errorUri) {
        this(error, errorDescription, errorUri, 400);
    }
    
    public OAuth2Exception(String error, String errorDescription, String errorUri, int httpStatus) {
        super(errorDescription);
        this.error = error;
        this.errorDescription = errorDescription;
        this.errorUri = errorUri;
        this.httpStatus = httpStatus;
    }
    
    /**
     * Common OAuth2 error codes
     */
    public static class ErrorCodes {
        public static final String INVALID_REQUEST = "invalid_request";
        public static final String UNAUTHORIZED_CLIENT = "unauthorized_client";
        public static final String ACCESS_DENIED = "access_denied";
        public static final String UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
        public static final String INVALID_SCOPE = "invalid_scope";
        public static final String SERVER_ERROR = "server_error";
        public static final String TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";
        public static final String INVALID_CLIENT = "invalid_client";
        public static final String INVALID_GRANT = "invalid_grant";
        public static final String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
    }
    
    // Getters
    public String getError() { return error; }
    public String getErrorDescription() { return errorDescription; }
    public String getErrorUri() { return errorUri; }
    public int getHttpStatus() { return httpStatus; }
}