package com.zamaz.mcp.security.rbac;

import com.zamaz.mcp.security.annotation.RequiresPermission;
import com.zamaz.mcp.security.context.SecurityContext;
import com.zamaz.mcp.security.context.SecurityContextHolder;
import com.zamaz.mcp.security.exception.AccessDeniedException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.util.Arrays;

/**
 * Aspect for handling @RequiresPermission annotation
 */
@Aspect
@Component
@Order(1)
@RequiredArgsConstructor
@Slf4j
public class RequiresPermissionAspect {
    
    private final PermissionEvaluator permissionEvaluator;
    private final SecurityContextHolder securityContextHolder;
    
    @Around("@annotation(com.zamaz.mcp.security.annotation.RequiresPermission)")
    public Object checkPermission(ProceedingJoinPoint joinPoint) throws Throwable {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        RequiresPermission annotation = method.getAnnotation(RequiresPermission.class);
        
        if (annotation == null) {
            return joinPoint.proceed();
        }
        
        SecurityContext context = securityContextHolder.getContext();
        if (context == null) {
            throw new AccessDeniedException("No security context available");
        }
        
        // Check permissions
        boolean hasPermission = false;
        
        if (annotation.anyOf().length > 0) {
            // Check if user has ANY of the specified permissions
            hasPermission = permissionEvaluator.hasAnyPermission(context, annotation.anyOf());
        } else {
            // Check if user has ALL the specified permissions
            hasPermission = permissionEvaluator.hasAllPermissions(context, annotation.value());
        }
        
        if (!hasPermission) {
            String permissionList = annotation.anyOf().length > 0 
                ? Arrays.toString(annotation.anyOf())
                : Arrays.toString(annotation.value());
                
            log.warn("Access denied for user {} to method {} - missing permissions: {}", 
                context.getUserId(), method.getName(), permissionList);
                
            throw new AccessDeniedException(annotation.message());
        }
        
        // Check resource-specific permissions if needed
        if (!annotation.resourceParam().isEmpty()) {
            String resourceId = extractResourceId(joinPoint, annotation.resourceParam());
            if (resourceId != null) {
                // Additional resource-level checks can be performed here
                log.debug("Checking resource-level permissions for resource: {}", resourceId);
            }
        }
        
        log.debug("Permission granted for user {} to access method {}", 
            context.getUserId(), method.getName());
        
        return joinPoint.proceed();
    }
    
    private String extractResourceId(ProceedingJoinPoint joinPoint, String paramName) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        String[] parameterNames = signature.getParameterNames();
        Object[] args = joinPoint.getArgs();
        
        for (int i = 0; i < parameterNames.length; i++) {
            if (parameterNames[i].equals(paramName)) {
                Object arg = args[i];
                return arg != null ? arg.toString() : null;
            }
        }
        
        return null;
    }
}