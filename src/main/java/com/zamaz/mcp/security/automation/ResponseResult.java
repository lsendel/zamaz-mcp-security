package com.zamaz.mcp.security.automation;

import lombok.Data;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Response Result
 * Represents the result of an automated security response
 */
@Data
public class ResponseResult {
    private String incidentId;
    private Instant timestamp;
    private boolean success;
    private String error;
    private List<ResponseAction> actionsPerformed = new ArrayList<>();
    
    public void addAction(String type, String description) {
        ResponseAction action = new ResponseAction();
        action.setType(type);
        action.setDescription(description);
        action.setTimestamp(Instant.now());
        actionsPerformed.add(action);
    }
}
