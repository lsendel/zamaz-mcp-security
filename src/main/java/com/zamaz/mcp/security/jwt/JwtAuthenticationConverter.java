package com.zamaz.mcp.security.jwt;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Modern JWT authentication converter for extracting user context and
 * authorities.
 * Converts JWT tokens to Spring Security authentication objects with proper
 * authorities.
 */
@Component
@Slf4j
public class JwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private static final String AUTHORITIES_CLAIM = "authorities";
    private static final String ROLES_CLAIM = "roles";
    private static final String SCOPE_CLAIM = "scope";
    private static final String USERNAME_CLAIM = "username";
    private static final String ORGANIZATION_ID_CLAIM = "organizationId";

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);

        // Create authentication token with extracted authorities
        JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(jwt, authorities);

        // Add additional details
        authenticationToken.setDetails(createAuthenticationDetails(jwt));

        log.debug("Converted JWT to authentication token for user: {} with authorities: {}",
                jwt.getClaimAsString(USERNAME_CLAIM), authorities);

        return authenticationToken;
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        // Try to extract authorities from different claims
        Collection<GrantedAuthority> authorities = extractAuthoritiesFromClaim(jwt, AUTHORITIES_CLAIM);

        if (authorities.isEmpty()) {
            authorities = extractAuthoritiesFromClaim(jwt, ROLES_CLAIM);
        }

        if (authorities.isEmpty()) {
            authorities = extractScopeAuthorities(jwt);
        }

        return authorities;
    }

    private Collection<GrantedAuthority> extractAuthoritiesFromClaim(Jwt jwt, String claimName) {
        Object claim = jwt.getClaim(claimName);

        if (claim instanceof Collection) {
            @SuppressWarnings("unchecked")
            Collection<String> authorityClaims = (Collection<String>) claim;
            return authorityClaims.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        } else if (claim instanceof String) {
            String authorityClaim = (String) claim;
            return List.of(authorityClaim.split(" ")).stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }

        return Collections.emptyList();
    }

    private Collection<GrantedAuthority> extractScopeAuthorities(Jwt jwt) {
        String scopes = jwt.getClaimAsString(SCOPE_CLAIM);

        if (scopes != null && !scopes.trim().isEmpty()) {
            return List.of(scopes.split(" ")).stream()
                    .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                    .collect(Collectors.toList());
        }

        return Collections.emptyList();
    }

    private Object createAuthenticationDetails(Jwt jwt) {
        java.util.Map<String, Object> details = new java.util.HashMap<>();

        // Add username
        String username = jwt.getClaimAsString(USERNAME_CLAIM);
        if (username != null) {
            details.put("username", username);
        }

        // Add organization context
        String organizationId = jwt.getClaimAsString(ORGANIZATION_ID_CLAIM);
        if (organizationId != null) {
            details.put("organizationId", organizationId);
        }

        // Add client information
        String clientType = jwt.getClaimAsString("client_type");
        if (clientType != null) {
            details.put("clientType", clientType);
        }

        String scopeType = jwt.getClaimAsString("scope_type");
        if (scopeType != null) {
            details.put("scopeType", scopeType);
        }

        // Add token metadata
        details.put("tokenVersion", jwt.getClaimAsString("token_version"));
        details.put("issuerService", jwt.getClaimAsString("issuer_service"));

        return details;
    }
}