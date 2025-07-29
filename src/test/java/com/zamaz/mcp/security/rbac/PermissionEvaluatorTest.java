package com.zamaz.mcp.security.rbac;

import com.zamaz.mcp.security.context.SecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for PermissionEvaluator
 */
@ExtendWith(MockitoExtension.class)
class PermissionEvaluatorTest {
    
    @Mock
    private RoleService roleService;
    
    @InjectMocks
    private PermissionEvaluator permissionEvaluator;
    
    private SecurityContext context;
    private UUID userId;
    private UUID organizationId;
    
    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID();
        organizationId = UUID.randomUUID();
        context = new SecurityContext();
        context.setUserId(userId.toString());
        context.setOrganizationId(organizationId.toString());
    }
    
    @Test
    void testHasPermission_SystemAdmin_AlwaysGranted() {
        context.setSystemAdmin(true);
        
        boolean result = permissionEvaluator.hasPermission(context, Permission.DEBATE_CREATE);
        
        assertTrue(result);
        verify(roleService, never()).getUserRoles(any(), any());
    }
    
    @Test
    void testHasPermission_UserWithPermission_Granted() {
        Set<Role> userRoles = EnumSet.of(Role.DEBATE_MODERATOR);
        when(roleService.getUserRoles(userId, organizationId)).thenReturn(userRoles);
        
        boolean result = permissionEvaluator.hasPermission(context, Permission.DEBATE_MODERATE);
        
        assertTrue(result);
    }
    
    @Test
    void testHasPermission_UserWithoutPermission_Denied() {
        Set<Role> userRoles = EnumSet.of(Role.VIEWER);
        when(roleService.getUserRoles(userId, organizationId)).thenReturn(userRoles);
        
        boolean result = permissionEvaluator.hasPermission(context, Permission.DEBATE_CREATE);
        
        assertFalse(result);
    }
    
    @Test
    void testHasAnyPermission_HasOnePermission_Granted() {
        Set<Role> userRoles = EnumSet.of(Role.DEBATE_PARTICIPANT);
        when(roleService.getUserRoles(userId, organizationId)).thenReturn(userRoles);
        
        boolean result = permissionEvaluator.hasAnyPermission(context, 
            Permission.DEBATE_CREATE, Permission.DEBATE_PARTICIPATE);
        
        assertTrue(result);
    }
    
    @Test
    void testHasAllPermissions_MissingOnePermission_Denied() {
        Set<Role> userRoles = EnumSet.of(Role.DEBATE_PARTICIPANT);
        when(roleService.getUserRoles(userId, organizationId)).thenReturn(userRoles);
        
        boolean result = permissionEvaluator.hasAllPermissions(context, 
            Permission.DEBATE_READ, Permission.DEBATE_CREATE);
        
        assertFalse(result);
    }
}