package com.zamaz.mcp.security.aspect;

import com.zamaz.mcp.security.annotation.RequiresPermission;
import com.zamaz.mcp.security.annotation.RequiresRole;
import com.zamaz.mcp.security.exception.AuthorizationException;
import com.zamaz.mcp.security.model.McpUser;
import com.zamaz.mcp.security.service.AuthorizationService;
import com.zamaz.mcp.security.audit.SecurityAuditLogger;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.util.Arrays;

/**
 * Aspect for handling authorization checks on annotated methods.
 * Intercepts calls to methods annotated with @RequiresPermission or @RequiresRole.
 */
@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class AuthorizationAspect {
    
    private final AuthorizationService authorizationService;
    private final SecurityAuditLogger auditLogger;
    
    /**
     * Intercept methods annotated with @RequiresPermission.
     */
    @Before("@annotation(requiresPermission)")
    public void checkPermission(JoinPoint joinPoint, RequiresPermission requiresPermission) {
        log.debug("Checking permission: {} for method: {}", 
                requiresPermission.value(), joinPoint.getSignature().getName());
        
        McpUser user = getCurrentUser();
        if (user == null) {
            throw new AuthorizationException("User not authenticated");
        }
        
        String organizationId = extractOrganizationId(joinPoint, requiresPermission.requireOrganization());
        
        // Check organization access if required
        if (requiresPermission.requireOrganization() && organizationId != null) {
            if (!authorizationService.hasOrganizationAccess(user, organizationId)) {
                throw new AuthorizationException("User does not have access to organization: " + organizationId);
            }
        }
        
        // Check permissions
        com.zamaz.mcp.security.rbac.Permission[] permissions = requiresPermission.value();
        boolean hasPermission = false;
        
        if (requiresPermission.anyOf().length > 0) {
            // Check if user has ANY of the specified permissions
            for (com.zamaz.mcp.security.rbac.Permission permission : requiresPermission.anyOf()) {
                if (authorizationService.hasPermission(user, permission.getPermission(), organizationId)) {
                    hasPermission = true;
                    break;
                }
            }
        } else {
            // Check if user has ALL the specified permissions
            hasPermission = true;
            for (com.zamaz.mcp.security.rbac.Permission permission : permissions) {
                if (!authorizationService.hasPermission(user, permission.getPermission(), organizationId)) {
                    hasPermission = false;
                    break;
                }
            }
        }
        
        if (!hasPermission) {
            // Audit authorization failure
            String permissionNames = java.util.Arrays.stream(permissions)
                .map(p -> p.getPermission())
                .collect(java.util.stream.Collectors.joining(\", \"));
            auditLogger.logPermissionDenied(permissionNames, joinPoint.getSignature().getName());
            
            throw new AuthorizationException(requiresPermission.message());
        }
        
        // Audit successful authorization
        auditLogger.logSecurityEvent(SecurityAuditLogger.SecurityEventType.AUTHORIZATION_SUCCESS, 
            SecurityAuditLogger.RiskLevel.LOW,
            \"Permission check passed\", 
            java.util.Map.of(\"method\", joinPoint.getSignature().getName()));
        
        // Check resource-specific permissions if needed
        if (!requiresPermission.resourceParam().isEmpty()) {
            String resourceId = extractResourceId(joinPoint, requiresPermission.resourceParam());
            if (resourceId != null && !authorizationService.hasResourceAccess(user, resourceId, organizationId)) {
                throw new AuthorizationException("User does not have access to the resource");
            }
        }
        
        log.debug("Permission check passed for user: {}", user.getId());
    }
    
    /**
     * Intercept methods annotated with @RequiresRole.
     */
    @Before("@annotation(requiresRole)")
    public void checkRole(JoinPoint joinPoint, RequiresRole requiresRole) {
        log.debug("Checking role: {} for method: {}", 
                requiresRole.value(), joinPoint.getSignature().getName());
        
        McpUser user = getCurrentUser();
        if (user == null) {
            throw new AuthorizationException("User not authenticated");
        }
        
        String organizationId = extractOrganizationId(joinPoint, requiresRole.organizationScope());
        
        // Check role
        if (!authorizationService.hasRole(user, requiresRole.value(), organizationId)) {
            throw new AuthorizationException("User does not have required role: " + requiresRole.value());
        }
        
        log.debug("Role check passed for user: {}", user.getId());
    }
    
    /**
     * Get the current authenticated user.
     */
    private McpUser getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        
        Object principal = authentication.getPrincipal();
        if (principal instanceof McpUser) {
            return (McpUser) principal;
        }
        
        return null;
    }
    
    /**
     * Extract organization ID from method parameters.
     * Looks for parameters named "organizationId" or of type containing "organization".
     */
    private String extractOrganizationId(JoinPoint joinPoint, boolean required) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        String[] paramNames = signature.getParameterNames();
        Object[] args = joinPoint.getArgs();
        
        for (int i = 0; i < paramNames.length; i++) {
            String paramName = paramNames[i];
            if (paramName.equals("organizationId") || paramName.equals("orgId")) {
                return (String) args[i];
            }
        }
        
        // If not found but required, try to get from user context
        if (required) {
            McpUser user = getCurrentUser();
            if (user != null) {
                return user.getCurrentOrganizationId();
            }
        }
        
        return null;
    }
    
    /**
     * Extract resource owner ID from method parameters.
     * Looks for parameters named "userId", "ownerId", or "createdBy".
     */
    private String extractResourceOwnerId(JoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        String[] paramNames = signature.getParameterNames();
        Object[] args = joinPoint.getArgs();
        
        for (int i = 0; i < paramNames.length; i++) {
            String paramName = paramNames[i];
            if (paramName.equals("userId") || paramName.equals("ownerId") || paramName.equals("createdBy")) {
                return (String) args[i];
            }
        }
        
        return null;
    }
    
    /**
     * Extract resource ID from method parameters by parameter name.
     */
    private String extractResourceId(JoinPoint joinPoint, String paramName) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        String[] paramNames = signature.getParameterNames();
        Object[] args = joinPoint.getArgs();
        
        for (int i = 0; i < paramNames.length; i++) {
            if (paramNames[i].equals(paramName)) {
                Object arg = args[i];
                return arg != null ? arg.toString() : null;
            }
        }
        
        return null;
    }
}