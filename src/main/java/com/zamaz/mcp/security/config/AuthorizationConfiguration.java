package com.zamaz.mcp.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

/**
 * Configuration class for authorization system.
 * Enables AspectJ auto-proxying for authorization annotations.
 */
@Configuration
@EnableAspectJAutoProxy
public class AuthorizationConfiguration {
    
    // Configuration is handled by annotations and auto-configuration
}