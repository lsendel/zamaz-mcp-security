package com.zamaz.mcp.security.service;

import com.zamaz.mcp.security.model.McpUser;

/**
 * Service interface for loading user details.
 * Used by authentication components to retrieve user information.
 */
public interface UserDetailsService {
    
    /**
     * Load a user by their unique identifier.
     * 
     * @param userId The user's unique identifier
     * @return The user details, or null if not found
     */
    McpUser loadUserById(String userId);
    
    /**
     * Load a user by their username.
     * 
     * @param username The user's username
     * @return The user details, or null if not found
     */
    McpUser loadUserByUsername(String username);
    
    /**
     * Load a user by their email address.
     * 
     * @param email The user's email address
     * @return The user details, or null if not found
     */
    McpUser loadUserByEmail(String email);
    
    /**
     * Check if a user exists.
     * 
     * @param userId The user's unique identifier
     * @return true if the user exists, false otherwise
     */
    boolean userExists(String userId);
    
    /**
     * Update user's last login timestamp and related information.
     * 
     * @param userId The user's unique identifier
     * @param ipAddress The IP address used for login
     */
    void updateLastLogin(String userId, String ipAddress);
}