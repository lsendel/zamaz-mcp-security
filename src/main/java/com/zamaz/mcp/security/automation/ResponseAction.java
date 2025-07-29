package com.zamaz.mcp.security.automation;

import lombok.Data;

import java.time.Instant;
import java.util.Map;

/**
 * Response Action
 * Represents a specific action taken in response to a security incident
 */
@Data
public class ResponseAction {
    private String type;
    private String description;
    private Instant timestamp;
    private Map<String, String> parameters;
    private boolean automated;
}
