package com.zamaz.mcp.security.session;

/**
 * Session Type
 * Defines different types of user sessions
 */
public enum SessionType {
    STANDARD,     // Regular user session
    REMEMBER_ME,  // Extended session with "remember me" option
    API,          // API-only session
    ADMIN,        // Administrative session with enhanced security
    TEMPORARY     // Short-lived session for specific operations
}
