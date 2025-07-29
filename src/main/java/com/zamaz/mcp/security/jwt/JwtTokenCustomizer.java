package com.zamaz.mcp.security.jwt;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * JWT token customizer for adding custom claims (organization, roles,
 * permissions).
 * Integrates with Spring Authorization Server to enhance JWT tokens with
 * MCP-specific claims.
 */
@Component
@Slf4j
public class JwtTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {
        Authentication principal = context.getPrincipal();

        if (principal != null) {
            // Add username claim
            context.getClaims().claim("username", principal.getName());

            // Add authorities/roles
            Set<String> authorities = principal.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());

            context.getClaims().claim("authorities", authorities);
            context.getClaims().claim("roles", authorities);

            // Add organization context if available
            String organizationId = extractOrganizationId(principal);
            if (organizationId != null) {
                context.getClaims().claim("organizationId", organizationId);
            }

            // Add custom MCP claims
            addMcpSpecificClaims(context, principal);

            log.debug("Customized JWT token for user: {} with authorities: {}",
                    principal.getName(), authorities);
        }
    }

    private String extractOrganizationId(Authentication principal) {
        // Extract organization ID from principal details or attributes
        if (principal.getDetails() instanceof java.util.Map) {
            @SuppressWarnings("unchecked")
            java.util.Map<String, Object> details = (java.util.Map<String, Object>) principal.getDetails();
            return (String) details.get("organizationId");
        }
        return null;
    }

    private void addMcpSpecificClaims(JwtEncodingContext context, Authentication principal) {
        // Add MCP-specific claims based on the token type and client
        String clientId = context.getRegisteredClient().getClientId();

        switch (clientId) {
            case "mcp-ui-client":
                // UI client gets full user context
                context.getClaims().claim("client_type", "ui");
                context.getClaims().claim("scope_type", "user");
                break;

            case "mcp-api-client":
                // API client gets limited context
                context.getClaims().claim("client_type", "api");
                context.getClaims().claim("scope_type", "service");
                break;

            case "mcp-service-client":
                // Service client gets internal service context
                context.getClaims().claim("client_type", "service");
                context.getClaims().claim("scope_type", "internal");
                break;

            default:
                context.getClaims().claim("client_type", "unknown");
        }

        // Add token metadata
        context.getClaims().claim("token_version", "1.0");
        context.getClaims().claim("issuer_service", "mcp-auth-server");
    }
}