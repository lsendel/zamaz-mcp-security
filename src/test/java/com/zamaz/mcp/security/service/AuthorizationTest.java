package com.zamaz.mcp.security.service;

import com.zamaz.mcp.security.model.McpUser;
import com.zamaz.mcp.security.model.Role;
import com.zamaz.mcp.security.model.Permission;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Simple unit tests for authorization logic (no Spring context required)
 */
class AuthorizationTest {
    
    @Test
    void testPermissionMatching() {
        // Test exact match
        Permission p1 = Permission.fromString("debate:create");
        assertTrue(p1.matches("debate:create"));
        assertFalse(p1.matches("debate:read"));
        
        // Test wildcard match
        Permission p2 = new Permission("debate:*", "debate:*", "All debate permissions", "debate", "*");
        assertTrue(p2.matches("debate:create"));
        assertTrue(p2.matches("debate:read"));
        assertFalse(p2.matches("context:create"));
    }
    
    @Test
    void testRoleHasPermission() {
        // Create permissions
        Permission createPermission = Permission.fromString("debate:create");
        Permission readPermission = Permission.fromString("debate:read");
        
        // Create role with permissions
        Role debateManager = new Role("DEBATE_MANAGER", "DEBATE_MANAGER", "Debate Manager", 
                Set.of(createPermission, readPermission), false);
        
        // Test role has permissions
        assertTrue(debateManager.hasPermission("debate:create"));
        assertTrue(debateManager.hasPermission("debate:read"));
        assertFalse(debateManager.hasPermission("debate:delete"));
    }
    
    @Test
    void testUserHasRole() {
        // Create roles
        Role adminRole = new Role("ADMIN", "ADMIN", "Administrator", Set.of(), false);
        Role userRole = new Role("USER", "USER", "Regular User", Set.of(), false);
        
        // Create user with roles
        McpUser user = new McpUser();
        user.setId(UUID.randomUUID().toString());
        user.setUsername("testuser");
        user.setGlobalRoles(Set.of(adminRole, userRole));
        user.setCurrentOrganizationId(UUID.randomUUID().toString());
        
        // Test user has roles
        assertTrue(user.hasRole("ADMIN"));
        assertTrue(user.hasRole("USER"));
        assertFalse(user.hasRole("GUEST"));
    }
    
    @Test
    void testSystemRoleConstants() {
        // Test that system role constants are defined
        assertEquals("SYSTEM_ADMIN", Role.SystemRoles.SYSTEM_ADMIN);
        assertEquals("ORG_ADMIN", Role.SystemRoles.ORG_ADMIN);
        assertEquals("USER", Role.SystemRoles.USER);
        assertEquals("MODERATOR", Role.SystemRoles.MODERATOR);
        assertEquals("VIEWER", Role.SystemRoles.VIEWER);
    }
    
    @Test
    void testPermissionFromString() {
        // Test permission parsing
        Permission perm = Permission.fromString("context:update");
        assertEquals("context:update", perm.getName());
        assertEquals("context", perm.getService());
        assertEquals("update", perm.getAction());
        assertEquals("Permission to update context", perm.getDescription());
        
        // Test invalid format
        assertThrows(IllegalArgumentException.class, () -> {
            Permission.fromString("invalid-format");
        });
    }
}