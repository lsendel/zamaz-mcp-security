package com.zamaz.mcp.security.integration;

import com.zamaz.mcp.security.annotation.RequiresPermission;
import com.zamaz.mcp.security.annotation.RequiresRole;
import com.zamaz.mcp.security.aspect.AuthorizationAspect;
import com.zamaz.mcp.security.audit.SecurityAuditLogger;
import com.zamaz.mcp.security.config.TestSecurityConfiguration;
import com.zamaz.mcp.security.exception.AuthorizationException;
import com.zamaz.mcp.security.model.McpUser;
import com.zamaz.mcp.security.rbac.Permission;
import com.zamaz.mcp.security.rbac.Role;
import com.zamaz.mcp.security.service.AuthorizationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.test.context.ActiveProfiles;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@SpringBootTest
@ActiveProfiles("test")
class SecurityAnnotationIntegrationTest {

    @Autowired
    private TestSecuredService securedService;

    @MockBean
    private AuthorizationService authorizationService;

    @MockBean
    private SecurityAuditLogger auditLogger;

    private McpUser testUser;
    private static final String TEST_ORG_ID = "org123";
    private static final String TEST_USER_ID = "user123";

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        
        testUser = new McpUser();
        testUser.setId(TEST_USER_ID);
        testUser.setUsername("testuser");
        testUser.setCurrentOrganizationId(TEST_ORG_ID);
        testUser.setOrganizationIds(Collections.singletonList(TEST_ORG_ID));
        
        reset(authorizationService, auditLogger);
    }

    @Test
    void requiresPermission_WithValidPermission_ShouldAllowAccess() {
        // Given
        authenticateUser();
        when(authorizationService.hasOrganizationAccess(testUser, TEST_ORG_ID)).thenReturn(true);
        when(authorizationService.hasPermission(testUser, Permission.DEBATE_CREATE.getPermission(), TEST_ORG_ID))
                .thenReturn(true);

        // When
        String result = securedService.createDebate(TEST_ORG_ID, "Test Debate");

        // Then
        assertEquals("Debate created: Test Debate", result);
        verify(authorizationService).hasPermission(testUser, Permission.DEBATE_CREATE.getPermission(), TEST_ORG_ID);
    }

    @Test
    void requiresPermission_WithoutPermission_ShouldThrowException() {
        // Given
        authenticateUser();
        when(authorizationService.hasOrganizationAccess(testUser, TEST_ORG_ID)).thenReturn(true);
        when(authorizationService.hasPermission(testUser, Permission.DEBATE_CREATE.getPermission(), TEST_ORG_ID))
                .thenReturn(false);

        // When & Then
        assertThrows(AuthorizationException.class, 
                () -> securedService.createDebate(TEST_ORG_ID, "Test Debate"));
        
        verify(auditLogger).logPermissionDenied(anyString(), eq("createDebate"));
    }

    @Test
    void requiresPermission_WithAnyOfPermissions_ShouldAllowIfOneMatches() {
        // Given
        authenticateUser();
        when(authorizationService.hasOrganizationAccess(testUser, TEST_ORG_ID)).thenReturn(true);
        when(authorizationService.hasPermission(testUser, Permission.DEBATE_READ.getPermission(), TEST_ORG_ID))
                .thenReturn(false);
        when(authorizationService.hasPermission(testUser, Permission.DEBATE_UPDATE.getPermission(), TEST_ORG_ID))
                .thenReturn(true);

        // When
        String result = securedService.readOrUpdateDebate(TEST_ORG_ID, "debate123");

        // Then
        assertEquals("Debate accessed: debate123", result);
    }

    @Test
    void requiresRole_WithValidRole_ShouldAllowAccess() {
        // Given
        authenticateUser();
        when(authorizationService.hasRole(testUser, Role.ORGANIZATION_ADMIN, TEST_ORG_ID))
                .thenReturn(true);

        // When
        String result = securedService.adminOperation(TEST_ORG_ID);

        // Then
        assertEquals("Admin operation completed", result);
        verify(authorizationService).hasRole(testUser, Role.ORGANIZATION_ADMIN, TEST_ORG_ID);
    }

    @Test
    void requiresRole_WithoutRole_ShouldThrowException() {
        // Given
        authenticateUser();
        when(authorizationService.hasRole(testUser, Role.ORGANIZATION_ADMIN, TEST_ORG_ID))
                .thenReturn(false);

        // When & Then
        assertThrows(AuthorizationException.class, 
                () -> securedService.adminOperation(TEST_ORG_ID));
    }

    @Test
    void requiresPermission_WithResourceAccess_ShouldCheckResource() {
        // Given
        authenticateUser();
        String resourceId = "resource123";
        when(authorizationService.hasOrganizationAccess(testUser, TEST_ORG_ID)).thenReturn(true);
        when(authorizationService.hasPermission(testUser, Permission.DEBATE_UPDATE.getPermission(), TEST_ORG_ID))
                .thenReturn(true);
        when(authorizationService.hasResourceAccess(testUser, resourceId, TEST_ORG_ID))
                .thenReturn(true);

        // When
        String result = securedService.updateResource(TEST_ORG_ID, resourceId, "Updated content");

        // Then
        assertEquals("Resource updated: resource123", result);
        verify(authorizationService).hasResourceAccess(testUser, resourceId, TEST_ORG_ID);
    }

    @Test
    void requiresPermission_WithoutAuthentication_ShouldThrowException() {
        // Given - No authentication

        // When & Then
        assertThrows(AuthorizationException.class, 
                () -> securedService.createDebate(TEST_ORG_ID, "Test Debate"));
    }

    @Test
    void multipleAnnotations_ShouldCheckBoth() {
        // Given
        authenticateUser();
        when(authorizationService.hasRole(testUser, Role.SUPER_ADMIN, null)).thenReturn(true);
        when(authorizationService.hasOrganizationAccess(testUser, TEST_ORG_ID)).thenReturn(true);
        when(authorizationService.hasPermission(testUser, Permission.SYSTEM_ADMIN.getPermission(), TEST_ORG_ID))
                .thenReturn(true);

        // When
        String result = securedService.superAdminOperation(TEST_ORG_ID);

        // Then
        assertEquals("Super admin operation completed", result);
        verify(authorizationService).hasRole(testUser, Role.SUPER_ADMIN, null);
        verify(authorizationService).hasPermission(testUser, Permission.SYSTEM_ADMIN.getPermission(), TEST_ORG_ID);
    }

    @Test
    void publicMethod_ShouldNotRequireAuthentication() {
        // Given - No authentication

        // When
        String result = securedService.publicOperation();

        // Then
        assertEquals("Public operation completed", result);
        verifyNoInteractions(authorizationService);
    }

    private void authenticateUser() {
        UsernamePasswordAuthenticationToken authentication = 
                new UsernamePasswordAuthenticationToken(testUser, null, testUser.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @Configuration
    @EnableAspectJAutoProxy
    @Import({TestSecurityConfiguration.class, AuthorizationAspect.class})
    static class TestConfig {
        
        @Bean
        public TestSecuredService testSecuredService() {
            return new TestSecuredService();
        }
    }

    @Service
    static class TestSecuredService {
        
        @RequiresPermission(value = Permission.DEBATE_CREATE, requireOrganization = true)
        public String createDebate(String organizationId, String debateName) {
            return "Debate created: " + debateName;
        }
        
        @RequiresPermission(
            value = Permission.DEBATE_READ,
            anyOf = {Permission.DEBATE_READ, Permission.DEBATE_UPDATE},
            requireOrganization = true
        )
        public String readOrUpdateDebate(String organizationId, String debateId) {
            return "Debate accessed: " + debateId;
        }
        
        @RequiresRole(value = Role.ORGANIZATION_ADMIN, organizationScope = true)
        public String adminOperation(String organizationId) {
            return "Admin operation completed";
        }
        
        @RequiresPermission(
            value = Permission.DEBATE_UPDATE,
            resourceParam = "resourceId",
            requireOrganization = true
        )
        public String updateResource(String organizationId, String resourceId, String content) {
            return "Resource updated: " + resourceId;
        }
        
        @RequiresRole(Role.SUPER_ADMIN)
        @RequiresPermission(value = Permission.SYSTEM_ADMIN, requireOrganization = true)
        public String superAdminOperation(String organizationId) {
            return "Super admin operation completed";
        }
        
        public String publicOperation() {
            return "Public operation completed";
        }
    }
}