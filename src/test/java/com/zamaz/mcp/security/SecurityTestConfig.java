package com.zamaz.mcp.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

/**
 * Test configuration for security module tests
 */
@SpringBootApplication
@ComponentScan(basePackages = "com.zamaz.mcp.security")
public class SecurityTestConfig {
    
    public static void main(String[] args) {
        SpringApplication.run(SecurityTestConfig.class, args);
    }
}