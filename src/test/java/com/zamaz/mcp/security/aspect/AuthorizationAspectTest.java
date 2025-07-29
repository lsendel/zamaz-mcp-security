package com.zamaz.mcp.security.aspect;

import com.zamaz.mcp.security.annotation.RequiresPermission;
import com.zamaz.mcp.security.annotation.RequiresRole;
import com.zamaz.mcp.security.audit.SecurityAuditLogger;
import com.zamaz.mcp.security.exception.AuthorizationException;
import com.zamaz.mcp.security.model.McpUser;
import com.zamaz.mcp.security.rbac.Permission;
import com.zamaz.mcp.security.rbac.Role;
import com.zamaz.mcp.security.service.AuthorizationService;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorizationAspectTest {

    @Mock
    private AuthorizationService authorizationService;

    @Mock
    private SecurityAuditLogger auditLogger;

    @Mock
    private JoinPoint joinPoint;

    @Mock
    private MethodSignature methodSignature;

    @Mock
    private SecurityContext securityContext;

    @InjectMocks
    private AuthorizationAspect authorizationAspect;

    private McpUser testUser;
    private static final String TEST_ORG_ID = "org123";
    private static final String TEST_USER_ID = "user123";

    @BeforeEach
    void setUp() {
        testUser = new McpUser();
        testUser.setId(TEST_USER_ID);
        testUser.setUsername("testuser");
        testUser.setCurrentOrganizationId(TEST_ORG_ID);
        testUser.setOrganizationIds(Collections.singletonList(TEST_ORG_ID));

        SecurityContextHolder.setContext(securityContext);
    }

    @Test
    void checkPermission_WithValidPermission_ShouldPass() throws NoSuchMethodException {
        // Given
        Authentication authentication = new UsernamePasswordAuthenticationToken(testUser, null);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        
        Method method = TestService.class.getMethod("methodWithPermission", String.class);
        RequiresPermission annotation = method.getAnnotation(RequiresPermission.class);
        
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getName()).thenReturn("methodWithPermission");
        when(methodSignature.getParameterNames()).thenReturn(new String[]{"organizationId"});
        when(joinPoint.getArgs()).thenReturn(new Object[]{TEST_ORG_ID});
        
        when(authorizationService.hasOrganizationAccess(testUser, TEST_ORG_ID)).thenReturn(true);
        when(authorizationService.hasPermission(testUser, Permission.DEBATE_CREATE.getPermission(), TEST_ORG_ID))
                .thenReturn(true);

        // When
        authorizationAspect.checkPermission(joinPoint, annotation);

        // Then
        verify(authorizationService).hasOrganizationAccess(testUser, TEST_ORG_ID);
        verify(authorizationService).hasPermission(testUser, Permission.DEBATE_CREATE.getPermission(), TEST_ORG_ID);
        verify(auditLogger).logSecurityEvent(
                eq(SecurityAuditLogger.SecurityEventType.AUTHORIZATION_SUCCESS),
                eq(SecurityAuditLogger.RiskLevel.LOW),
                anyString(),
                any(Map.class)
        );
    }

    @Test
    void checkPermission_WithoutAuthentication_ShouldThrowException() throws NoSuchMethodException {
        // Given
        when(securityContext.getAuthentication()).thenReturn(null);
        
        Method method = TestService.class.getMethod("methodWithPermission", String.class);
        RequiresPermission annotation = method.getAnnotation(RequiresPermission.class);
        
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getName()).thenReturn("methodWithPermission");

        // When & Then
        AuthorizationException exception = assertThrows(
                AuthorizationException.class,
                () -> authorizationAspect.checkPermission(joinPoint, annotation)
        );
        assertEquals("User not authenticated", exception.getMessage());
    }

    @Test
    void checkPermission_WithoutRequiredPermission_ShouldThrowException() throws NoSuchMethodException {
        // Given
        Authentication authentication = new UsernamePasswordAuthenticationToken(testUser, null);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        
        Method method = TestService.class.getMethod("methodWithPermission", String.class);
        RequiresPermission annotation = method.getAnnotation(RequiresPermission.class);
        
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getName()).thenReturn("methodWithPermission");
        when(methodSignature.getParameterNames()).thenReturn(new String[]{"organizationId"});
        when(joinPoint.getArgs()).thenReturn(new Object[]{TEST_ORG_ID});
        
        when(authorizationService.hasOrganizationAccess(testUser, TEST_ORG_ID)).thenReturn(true);
        when(authorizationService.hasPermission(testUser, Permission.DEBATE_CREATE.getPermission(), TEST_ORG_ID))
                .thenReturn(false);

        // When & Then
        AuthorizationException exception = assertThrows(
                AuthorizationException.class,
                () -> authorizationAspect.checkPermission(joinPoint, annotation)
        );
        
        verify(auditLogger).logPermissionDenied(anyString(), eq("methodWithPermission"));
    }

    @Test
    void checkPermission_WithAnyOfPermissions_ShouldPassIfOneMatches() throws NoSuchMethodException {
        // Given
        Authentication authentication = new UsernamePasswordAuthenticationToken(testUser, null);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        
        Method method = TestService.class.getMethod("methodWithAnyOfPermissions", String.class);
        RequiresPermission annotation = method.getAnnotation(RequiresPermission.class);
        
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getName()).thenReturn("methodWithAnyOfPermissions");
        when(methodSignature.getParameterNames()).thenReturn(new String[]{"organizationId"});
        when(joinPoint.getArgs()).thenReturn(new Object[]{TEST_ORG_ID});
        
        when(authorizationService.hasOrganizationAccess(testUser, TEST_ORG_ID)).thenReturn(true);
        when(authorizationService.hasPermission(testUser, Permission.DEBATE_READ.getPermission(), TEST_ORG_ID))
                .thenReturn(false);
        when(authorizationService.hasPermission(testUser, Permission.DEBATE_UPDATE.getPermission(), TEST_ORG_ID))
                .thenReturn(true);

        // When
        authorizationAspect.checkPermission(joinPoint, annotation);

        // Then
        verify(authorizationService).hasPermission(testUser, Permission.DEBATE_READ.getPermission(), TEST_ORG_ID);
        verify(authorizationService).hasPermission(testUser, Permission.DEBATE_UPDATE.getPermission(), TEST_ORG_ID);
        verify(auditLogger).logSecurityEvent(
                eq(SecurityAuditLogger.SecurityEventType.AUTHORIZATION_SUCCESS),
                any(),
                anyString(),
                any()
        );
    }

    @Test
    void checkPermission_WithResourceAccess_ShouldCheckResourcePermission() throws NoSuchMethodException {
        // Given
        Authentication authentication = new UsernamePasswordAuthenticationToken(testUser, null);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        
        Method method = TestService.class.getMethod("methodWithResourcePermission", String.class, String.class);
        RequiresPermission annotation = method.getAnnotation(RequiresPermission.class);
        
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getName()).thenReturn("methodWithResourcePermission");
        when(methodSignature.getParameterNames()).thenReturn(new String[]{"organizationId", "resourceId"});
        when(joinPoint.getArgs()).thenReturn(new Object[]{TEST_ORG_ID, "resource123"});
        
        when(authorizationService.hasOrganizationAccess(testUser, TEST_ORG_ID)).thenReturn(true);
        when(authorizationService.hasPermission(testUser, Permission.DEBATE_UPDATE.getPermission(), TEST_ORG_ID))
                .thenReturn(true);
        when(authorizationService.hasResourceAccess(testUser, "resource123", TEST_ORG_ID))
                .thenReturn(true);

        // When
        authorizationAspect.checkPermission(joinPoint, annotation);

        // Then
        verify(authorizationService).hasResourceAccess(testUser, "resource123", TEST_ORG_ID);
    }

    @Test
    void checkRole_WithValidRole_ShouldPass() throws NoSuchMethodException {
        // Given
        Authentication authentication = new UsernamePasswordAuthenticationToken(testUser, null);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        
        Method method = TestService.class.getMethod("methodWithRole", String.class);
        RequiresRole annotation = method.getAnnotation(RequiresRole.class);
        
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getName()).thenReturn("methodWithRole");
        when(methodSignature.getParameterNames()).thenReturn(new String[]{"organizationId"});
        when(joinPoint.getArgs()).thenReturn(new Object[]{TEST_ORG_ID});
        
        when(authorizationService.hasRole(testUser, Role.ORGANIZATION_ADMIN, TEST_ORG_ID))
                .thenReturn(true);

        // When
        authorizationAspect.checkRole(joinPoint, annotation);

        // Then
        verify(authorizationService).hasRole(testUser, Role.ORGANIZATION_ADMIN, TEST_ORG_ID);
    }

    @Test
    void checkRole_WithoutRequiredRole_ShouldThrowException() throws NoSuchMethodException {
        // Given
        Authentication authentication = new UsernamePasswordAuthenticationToken(testUser, null);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        
        Method method = TestService.class.getMethod("methodWithRole", String.class);
        RequiresRole annotation = method.getAnnotation(RequiresRole.class);
        
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getName()).thenReturn("methodWithRole");
        when(methodSignature.getParameterNames()).thenReturn(new String[]{"organizationId"});
        when(joinPoint.getArgs()).thenReturn(new Object[]{TEST_ORG_ID});
        
        when(authorizationService.hasRole(testUser, Role.ORGANIZATION_ADMIN, TEST_ORG_ID))
                .thenReturn(false);

        // When & Then
        AuthorizationException exception = assertThrows(
                AuthorizationException.class,
                () -> authorizationAspect.checkRole(joinPoint, annotation)
        );
        assertTrue(exception.getMessage().contains("ORGANIZATION_ADMIN"));
    }

    @Test
    void checkPermission_WithoutOrganizationAccess_ShouldThrowException() throws NoSuchMethodException {
        // Given
        Authentication authentication = new UsernamePasswordAuthenticationToken(testUser, null);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        
        Method method = TestService.class.getMethod("methodWithPermission", String.class);
        RequiresPermission annotation = method.getAnnotation(RequiresPermission.class);
        
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getName()).thenReturn("methodWithPermission");
        when(methodSignature.getParameterNames()).thenReturn(new String[]{"organizationId"});
        when(joinPoint.getArgs()).thenReturn(new Object[]{TEST_ORG_ID});
        
        when(authorizationService.hasOrganizationAccess(testUser, TEST_ORG_ID)).thenReturn(false);

        // When & Then
        AuthorizationException exception = assertThrows(
                AuthorizationException.class,
                () -> authorizationAspect.checkPermission(joinPoint, annotation)
        );
        assertTrue(exception.getMessage().contains("organization"));
    }

    @Test
    void extractOrganizationId_FromUserContext_WhenNotInParams() throws NoSuchMethodException {
        // Given
        Authentication authentication = new UsernamePasswordAuthenticationToken(testUser, null);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        
        Method method = TestService.class.getMethod("methodWithoutOrgParam");
        RequiresPermission annotation = method.getAnnotation(RequiresPermission.class);
        
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getName()).thenReturn("methodWithoutOrgParam");
        when(methodSignature.getParameterNames()).thenReturn(new String[]{});
        when(joinPoint.getArgs()).thenReturn(new Object[]{});
        
        when(authorizationService.hasOrganizationAccess(testUser, TEST_ORG_ID)).thenReturn(true);
        when(authorizationService.hasPermission(testUser, Permission.DEBATE_CREATE.getPermission(), TEST_ORG_ID))
                .thenReturn(true);

        // When
        authorizationAspect.checkPermission(joinPoint, annotation);

        // Then - Should use organization from user context
        verify(authorizationService).hasOrganizationAccess(testUser, TEST_ORG_ID);
    }

    // Test service class for annotations
    private static class TestService {
        @RequiresPermission(value = Permission.DEBATE_CREATE, requireOrganization = true)
        public void methodWithPermission(String organizationId) {}
        
        @RequiresPermission(
            value = Permission.DEBATE_READ, 
            anyOf = {Permission.DEBATE_READ, Permission.DEBATE_UPDATE},
            requireOrganization = true
        )
        public void methodWithAnyOfPermissions(String organizationId) {}
        
        @RequiresPermission(value = Permission.DEBATE_UPDATE, resourceParam = "resourceId", requireOrganization = true)
        public void methodWithResourcePermission(String organizationId, String resourceId) {}
        
        @RequiresRole(value = Role.ORGANIZATION_ADMIN, organizationScope = true)
        public void methodWithRole(String organizationId) {}
        
        @RequiresPermission(value = Permission.DEBATE_CREATE, requireOrganization = true)
        public void methodWithoutOrgParam() {}
    }
}