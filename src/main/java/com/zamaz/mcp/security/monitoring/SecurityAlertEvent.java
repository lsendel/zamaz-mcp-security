package com.zamaz.mcp.security.monitoring;

import org.springframework.context.ApplicationEvent;

/**
 * Spring application event for security alerts.
 * Published when a security alert is triggered.
 */
public class SecurityAlertEvent extends ApplicationEvent {
    
    private final SecurityAlert alert;
    
    public SecurityAlertEvent(SecurityAlert alert) {
        super(alert);
        this.alert = alert;
    }
    
    public SecurityAlert getAlert() {
        return alert;
    }
}