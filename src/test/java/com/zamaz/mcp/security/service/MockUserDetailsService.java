package com.zamaz.mcp.security.service;

import com.zamaz.mcp.security.model.McpUser;
import org.springframework.boot.test.context.TestComponent;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Mock implementation of UserDetailsService for testing.
 * Provides an in-memory user store for unit and integration tests.
 */
@TestComponent
public class MockUserDetailsService implements UserDetailsService {
    
    private final Map<String, McpUser> userStore = new ConcurrentHashMap<>();
    
    public MockUserDetailsService() {
        // Initialize with some test users
        initializeTestUsers();
    }
    
    @Override
    public McpUser loadUserById(String userId) {
        return userStore.get(userId);
    }
    
    @Override
    public McpUser loadUserByUsername(String username) {
        return userStore.values().stream()
                .filter(user -> username.equals(user.getUsername()))
                .findFirst()
                .orElse(null);
    }
    
    @Override
    public McpUser loadUserByEmail(String email) {
        return userStore.values().stream()
                .filter(user -> email.equals(user.getEmail()))
                .findFirst()
                .orElse(null);
    }
    
    @Override
    public boolean userExists(String userId) {
        return userStore.containsKey(userId);
    }
    
    @Override
    public void updateLastLogin(String userId, String ipAddress) {
        McpUser user = userStore.get(userId);
        if (user != null) {
            user.setLastLoginAt(new Date());
            user.setLastLoginIp(ipAddress);
        }
    }
    
    /**
     * Add a user to the mock store.
     */
    public void addUser(McpUser user) {
        userStore.put(user.getId(), user);
    }
    
    /**
     * Remove a user from the mock store.
     */
    public void removeUser(String userId) {
        userStore.remove(userId);
    }
    
    /**
     * Clear all users from the mock store.
     */
    public void clearUsers() {
        userStore.clear();
    }
    
    /**
     * Reset the store to initial test users.
     */
    public void reset() {
        clearUsers();
        initializeTestUsers();
    }
    
    private void initializeTestUsers() {
        // Test user 1 - Regular user
        McpUser user1 = new McpUser();
        user1.setId("user1");
        user1.setUsername("testuser1");
        user1.setEmail("testuser1@example.com");
        user1.setOrganizationIds(Arrays.asList("org1", "org2"));
        user1.setCurrentOrganizationId("org1");
        user1.setRoles(Collections.singletonList("ROLE_USER"));
        userStore.put(user1.getId(), user1);
        
        // Test user 2 - Admin user
        McpUser user2 = new McpUser();
        user2.setId("user2");
        user2.setUsername("adminuser");
        user2.setEmail("admin@example.com");
        user2.setOrganizationIds(Arrays.asList("org1"));
        user2.setCurrentOrganizationId("org1");
        user2.setRoles(Arrays.asList("ROLE_USER", "ROLE_ADMIN"));
        userStore.put(user2.getId(), user2);
        
        // Test user 3 - Multi-org user
        McpUser user3 = new McpUser();
        user3.setId("user3");
        user3.setUsername("multiorguser");
        user3.setEmail("multiorg@example.com");
        user3.setOrganizationIds(Arrays.asList("org1", "org2", "org3"));
        user3.setCurrentOrganizationId("org2");
        user3.setRoles(Collections.singletonList("ROLE_USER"));
        userStore.put(user3.getId(), user3);
    }
}