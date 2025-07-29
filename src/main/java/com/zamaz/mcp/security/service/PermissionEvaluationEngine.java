package com.zamaz.mcp.security.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zamaz.mcp.security.entity.Permission;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.List;
import java.util.Map;

/**
 * Permission evaluation engine that handles complex conditions and
 * attribute-based access control.
 * Supports SpEL expressions, time-based constraints, and environmental
 * conditions.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class PermissionEvaluationEngine {

    private final ExpressionParser expressionParser = new SpelExpressionParser();
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Evaluate all conditions for a permission against the given context.
     */
    public boolean evaluateConditions(Permission permission, PermissionService.PermissionContext context) {
        try {
            // Check time-based constraints
            if (permission.getTimeBased() && !evaluateTimeConstraints(permission)) {
                log.debug("Time constraints not met for permission: {}", permission.getId());
                return false;
            }

            // Check IP restrictions
            if (permission.getIpRestrictions() != null && !evaluateIpRestrictions(permission, context)) {
                log.debug("IP restrictions not met for permission: {}", permission.getId());
                return false;
            }

            // Check location restrictions
            if (permission.getLocationRestrictions() != null && !evaluateLocationRestrictions(permission, context)) {
                log.debug("Location restrictions not met for permission: {}", permission.getId());
                return false;
            }

            // Check SpEL condition expression
            if (permission.getConditionExpression() != null && !evaluateSpelExpression(permission, context)) {
                log.debug("SpEL condition not met for permission: {}", permission.getId());
                return false;
            }

            // Check attribute-based conditions
            if (!evaluateAttributeConditions(permission, context)) {
                log.debug("Attribute conditions not met for permission: {}", permission.getId());
                return false;
            }

            return true;

        } catch (Exception e) {
            log.error("Error evaluating permission conditions for permission {}: {}", permission.getId(),
                    e.getMessage());
            return false; // Fail secure
        }
    }

    /**
     * Evaluate time-based constraints.
     */
    private boolean evaluateTimeConstraints(Permission permission) {
        LocalDateTime now = LocalDateTime.now();

        // Check validity period
        if (permission.getValidFrom() != null && now.isBefore(permission.getValidFrom())) {
            return false;
        }

        if (permission.getValidUntil() != null && now.isAfter(permission.getValidUntil())) {
            return false;
        }

        // Check day of week constraints
        if (permission.getDaysOfWeek() != null && !permission.getDaysOfWeek().isEmpty()) {
            String currentDay = now.getDayOfWeek().name().substring(0, 3).toUpperCase();
            if (!permission.getDaysOfWeek().toUpperCase().contains(currentDay)) {
                return false;
            }
        }

        // Check hour constraints
        if (permission.getHoursOfDay() != null && !permission.getHoursOfDay().isEmpty()) {
            return evaluateHourConstraints(permission.getHoursOfDay(), now.toLocalTime());
        }

        return true;
    }

    /**
     * Evaluate hour constraints (e.g., "09:00-17:00").
     */
    private boolean evaluateHourConstraints(String hoursOfDay, LocalTime currentTime) {
        try {
            String[] parts = hoursOfDay.split("-");
            if (parts.length != 2) {
                return true; // Invalid format, allow access
            }

            LocalTime startTime = LocalTime.parse(parts[0]);
            LocalTime endTime = LocalTime.parse(parts[1]);

            if (startTime.isBefore(endTime)) {
                // Same day range
                return !currentTime.isBefore(startTime) && !currentTime.isAfter(endTime);
            } else {
                // Overnight range (e.g., 22:00-06:00)
                return !currentTime.isBefore(startTime) || !currentTime.isAfter(endTime);
            }
        } catch (Exception e) {
            log.warn("Invalid hour constraint format: {}", hoursOfDay);
            return true; // Allow access on invalid format
        }
    }

    /**
     * Evaluate IP restrictions.
     */
    private boolean evaluateIpRestrictions(Permission permission, PermissionService.PermissionContext context) {
        try {
            String clientIp = (String) context.getEnvironmentContext().get("clientIp");
            if (clientIp == null) {
                return false; // No IP information available
            }

            List<String> allowedIpRanges = objectMapper.readValue(
                    permission.getIpRestrictions(),
                    new TypeReference<List<String>>() {
                    });

            return allowedIpRanges.stream().anyMatch(range -> isIpInRange(clientIp, range));

        } catch (Exception e) {
            log.error("Error evaluating IP restrictions: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Check if IP is in the specified range.
     */
    private boolean isIpInRange(String ip, String range) {
        // Simplified IP range checking - would need proper CIDR implementation
        if (range.equals("*") || range.equals(ip)) {
            return true;
        }

        if (range.contains("/")) {
            // CIDR notation - simplified check
            String[] parts = range.split("/");
            String networkIp = parts[0];
            // Would need proper CIDR calculation here
            return ip.startsWith(networkIp.substring(0, networkIp.lastIndexOf(".")));
        }

        return false;
    }

    /**
     * Evaluate location restrictions.
     */
    private boolean evaluateLocationRestrictions(Permission permission, PermissionService.PermissionContext context) {
        try {
            String userCountry = (String) context.getEnvironmentContext().get("country");
            if (userCountry == null) {
                return false; // No location information available
            }

            List<String> allowedCountries = objectMapper.readValue(
                    permission.getLocationRestrictions(),
                    new TypeReference<List<String>>() {
                    });

            return allowedCountries.contains("*") || allowedCountries.contains(userCountry);

        } catch (Exception e) {
            log.error("Error evaluating location restrictions: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Evaluate SpEL expression conditions.
     */
    private boolean evaluateSpelExpression(Permission permission, PermissionService.PermissionContext context) {
        try {
            Expression expression = expressionParser.parseExpression(permission.getConditionExpression());
            EvaluationContext evaluationContext = createEvaluationContext(context);

            Object result = expression.getValue(evaluationContext);
            return Boolean.TRUE.equals(result);

        } catch (Exception e) {
            log.error("Error evaluating SpEL expression '{}': {}", permission.getConditionExpression(), e.getMessage());
            return false;
        }
    }

    /**
     * Create SpEL evaluation context with available variables.
     */
    private EvaluationContext createEvaluationContext(PermissionService.PermissionContext context) {
        StandardEvaluationContext evaluationContext = new StandardEvaluationContext();

        // Add context variables
        evaluationContext.setVariable("userId", context.getUserId());
        evaluationContext.setVariable("organizationId", context.getOrganizationId());
        evaluationContext.setVariable("resource", context.getResource());
        evaluationContext.setVariable("action", context.getAction());
        evaluationContext.setVariable("resourceId", context.getResourceId());

        // Add user attributes
        context.getAttributes().forEach(evaluationContext::setVariable);

        // Add environment context
        context.getEnvironmentContext().forEach(evaluationContext::setVariable);

        // Add time-related variables
        LocalDateTime now = LocalDateTime.now();
        evaluationContext.setVariable("now", now);
        evaluationContext.setVariable("currentHour", now.getHour());
        evaluationContext.setVariable("currentDay", now.getDayOfWeek().name());

        return evaluationContext;
    }

    /**
     * Evaluate attribute-based conditions.
     */
    private boolean evaluateAttributeConditions(Permission permission, PermissionService.PermissionContext context) {
        try {
            // Check subject attributes
            if (permission.getSubjectAttributes() != null && !evaluateSubjectAttributes(permission, context)) {
                return false;
            }

            // Check resource attributes
            if (permission.getResourceAttributes() != null && !evaluateResourceAttributes(permission, context)) {
                return false;
            }

            // Check environment attributes
            if (permission.getEnvironmentAttributes() != null && !evaluateEnvironmentAttributes(permission, context)) {
                return false;
            }

            return true;

        } catch (Exception e) {
            log.error("Error evaluating attribute conditions: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Evaluate subject (user) attributes.
     */
    private boolean evaluateSubjectAttributes(Permission permission, PermissionService.PermissionContext context) {
        try {
            Map<String, Object> requiredAttributes = objectMapper.readValue(
                    permission.getSubjectAttributes(),
                    new TypeReference<Map<String, Object>>() {
                    });

            return requiredAttributes.entrySet().stream()
                    .allMatch(entry -> {
                        Object userValue = context.getAttributes().get(entry.getKey());
                        return matchesAttributeValue(userValue, entry.getValue());
                    });

        } catch (Exception e) {
            log.error("Error evaluating subject attributes: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Evaluate resource attributes.
     */
    private boolean evaluateResourceAttributes(Permission permission, PermissionService.PermissionContext context) {
        try {
            Map<String, Object> requiredAttributes = objectMapper.readValue(
                    permission.getResourceAttributes(),
                    new TypeReference<Map<String, Object>>() {
                    });

            // Resource attributes would typically be loaded from the resource itself
            // This is a simplified implementation
            return requiredAttributes.entrySet().stream()
                    .allMatch(entry -> {
                        Object resourceValue = context.getAttributes().get("resource_" + entry.getKey());
                        return matchesAttributeValue(resourceValue, entry.getValue());
                    });

        } catch (Exception e) {
            log.error("Error evaluating resource attributes: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Evaluate environment attributes.
     */
    private boolean evaluateEnvironmentAttributes(Permission permission, PermissionService.PermissionContext context) {
        try {
            Map<String, Object> requiredAttributes = objectMapper.readValue(
                    permission.getEnvironmentAttributes(),
                    new TypeReference<Map<String, Object>>() {
                    });

            return requiredAttributes.entrySet().stream()
                    .allMatch(entry -> {
                        Object envValue = context.getEnvironmentContext().get(entry.getKey());
                        return matchesAttributeValue(envValue, entry.getValue());
                    });

        } catch (Exception e) {
            log.error("Error evaluating environment attributes: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Check if an attribute value matches the required value.
     */
    private boolean matchesAttributeValue(Object actualValue, Object requiredValue) {
        if (actualValue == null && requiredValue == null) {
            return true;
        }

        if (actualValue == null || requiredValue == null) {
            return false;
        }

        // Handle different comparison types
        if (requiredValue instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> condition = (Map<String, Object>) requiredValue;

            if (condition.containsKey("equals")) {
                return actualValue.equals(condition.get("equals"));
            }

            if (condition.containsKey("in")) {
                @SuppressWarnings("unchecked")
                List<Object> values = (List<Object>) condition.get("in");
                return values.contains(actualValue);
            }

            if (condition.containsKey("regex")) {
                String pattern = (String) condition.get("regex");
                return actualValue.toString().matches(pattern);
            }
        }

        return actualValue.equals(requiredValue);
    }
}