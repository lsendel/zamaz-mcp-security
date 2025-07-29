package com.zamaz.mcp.security.controller;

import com.zamaz.mcp.security.entity.OAuth2Client;
import com.zamaz.mcp.security.exception.ClientRegistrationException;
import com.zamaz.mcp.security.model.OAuth2ClientRegistrationRequest;
import com.zamaz.mcp.security.model.OAuth2ClientUpdateRequest;
import com.zamaz.mcp.security.service.OAuth2ClientService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * REST controller for OAuth2 client management.
 * Provides endpoints for client registration, updates, and queries.
 */
@RestController
@RequestMapping("/api/v1/oauth2/clients")
@Tag(name = "OAuth2 Client Management", description = "Dynamic OAuth2 client registration and management")
@SecurityRequirement(name = "bearer-jwt")
public class OAuth2ClientController {
    
    private static final Logger logger = LoggerFactory.getLogger(OAuth2ClientController.class);
    
    @Autowired
    private OAuth2ClientService clientService;
    
    /**
     * Register a new OAuth2 client
     */
    @PostMapping
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('oauth2:clients:create')")
    @Operation(summary = "Register new OAuth2 client", 
               description = "Creates a new OAuth2 client registration with the specified configuration")
    @ApiResponses({
        @ApiResponse(responseCode = "201", description = "Client successfully registered"),
        @ApiResponse(responseCode = "400", description = "Invalid registration request"),
        @ApiResponse(responseCode = "403", description = "Insufficient permissions")
    })
    public ResponseEntity<OAuth2ClientResponse> registerClient(
            @Valid @RequestBody OAuth2ClientRegistrationRequest request,
            Authentication authentication) {
        
        logger.info("Client registration request from user: {}", authentication.getName());
        
        try {
            OAuth2Client client = clientService.registerClient(request, authentication.getName());
            
            OAuth2ClientResponse response = mapToResponse(client);
            
            // Include client secret in response for initial registration only
            String tempSecret = client.getAdditionalSettings().get("_temp_secret");
            if (tempSecret != null) {
                response.setClientSecret(tempSecret);
                // Remove temporary secret from entity
                client.getAdditionalSettings().remove("_temp_secret");
            }
            
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
            
        } catch (ClientRegistrationException e) {
            logger.error("Client registration failed: {}", e.getMessage());
            throw e;
        }
    }
    
    /**
     * Get client by ID
     */
    @GetMapping("/{clientId}")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('oauth2:clients:read') or " +
                  "@securityExpressions.isClientOwner(#clientId, authentication.name)")
    @Operation(summary = "Get OAuth2 client", 
               description = "Retrieves OAuth2 client details by client ID")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Client found"),
        @ApiResponse(responseCode = "404", description = "Client not found"),
        @ApiResponse(responseCode = "403", description = "Insufficient permissions")
    })
    public ResponseEntity<OAuth2ClientResponse> getClient(
            @Parameter(description = "Client ID") @PathVariable String clientId) {
        
        return clientService.getClient(clientId)
            .map(client -> ResponseEntity.ok(mapToResponse(client)))
            .orElse(ResponseEntity.notFound().build());
    }
    
    /**
     * Update client
     */
    @PutMapping("/{clientId}")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('oauth2:clients:update') or " +
                  "@securityExpressions.isClientOwner(#clientId, authentication.name)")
    @Operation(summary = "Update OAuth2 client", 
               description = "Updates OAuth2 client configuration")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Client successfully updated"),
        @ApiResponse(responseCode = "400", description = "Invalid update request"),
        @ApiResponse(responseCode = "404", description = "Client not found"),
        @ApiResponse(responseCode = "403", description = "Insufficient permissions")
    })
    public ResponseEntity<OAuth2ClientResponse> updateClient(
            @Parameter(description = "Client ID") @PathVariable String clientId,
            @Valid @RequestBody OAuth2ClientUpdateRequest request,
            Authentication authentication) {
        
        logger.info("Client update request for {} from user: {}", clientId, authentication.getName());
        
        try {
            OAuth2Client client = clientService.updateClient(clientId, request, authentication.getName());
            return ResponseEntity.ok(mapToResponse(client));
            
        } catch (ClientRegistrationException e) {
            if (e.getMessage().contains("not found")) {
                return ResponseEntity.notFound().build();
            }
            throw e;
        }
    }
    
    /**
     * Regenerate client secret
     */
    @PostMapping("/{clientId}/secret")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('oauth2:clients:secret') or " +
                  "@securityExpressions.isClientOwner(#clientId, authentication.name)")
    @Operation(summary = "Regenerate client secret", 
               description = "Generates a new client secret for confidential clients")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Secret successfully regenerated"),
        @ApiResponse(responseCode = "400", description = "Cannot regenerate secret for public client"),
        @ApiResponse(responseCode = "404", description = "Client not found"),
        @ApiResponse(responseCode = "403", description = "Insufficient permissions")
    })
    public ResponseEntity<Map<String, String>> regenerateSecret(
            @Parameter(description = "Client ID") @PathVariable String clientId,
            Authentication authentication) {
        
        logger.info("Secret regeneration request for {} from user: {}", clientId, authentication.getName());
        
        try {
            String newSecret = clientService.regenerateClientSecret(clientId, authentication.getName());
            
            Map<String, String> response = new HashMap<>();
            response.put("clientId", clientId);
            response.put("clientSecret", newSecret);
            response.put("message", "New client secret generated. Please save it securely as it won't be shown again.");
            
            return ResponseEntity.ok(response);
            
        } catch (ClientRegistrationException e) {
            if (e.getMessage().contains("not found")) {
                return ResponseEntity.notFound().build();
            }
            throw e;
        }
    }
    
    /**
     * Deactivate client
     */
    @DeleteMapping("/{clientId}")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('oauth2:clients:delete')")
    @Operation(summary = "Deactivate OAuth2 client", 
               description = "Deactivates an OAuth2 client (soft delete)")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Client successfully deactivated"),
        @ApiResponse(responseCode = "404", description = "Client not found"),
        @ApiResponse(responseCode = "403", description = "Insufficient permissions")
    })
    public ResponseEntity<Void> deactivateClient(
            @Parameter(description = "Client ID") @PathVariable String clientId,
            Authentication authentication) {
        
        logger.info("Client deactivation request for {} from user: {}", clientId, authentication.getName());
        
        try {
            clientService.deactivateClient(clientId, authentication.getName());
            return ResponseEntity.noContent().build();
            
        } catch (ClientRegistrationException e) {
            if (e.getMessage().contains("not found")) {
                return ResponseEntity.notFound().build();
            }
            throw e;
        }
    }
    
    /**
     * Reactivate client
     */
    @PostMapping("/{clientId}/reactivate")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('oauth2:clients:update')")
    @Operation(summary = "Reactivate OAuth2 client", 
               description = "Reactivates a previously deactivated OAuth2 client")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Client successfully reactivated"),
        @ApiResponse(responseCode = "404", description = "Client not found"),
        @ApiResponse(responseCode = "403", description = "Insufficient permissions")
    })
    public ResponseEntity<OAuth2ClientResponse> reactivateClient(
            @Parameter(description = "Client ID") @PathVariable String clientId,
            Authentication authentication) {
        
        logger.info("Client reactivation request for {} from user: {}", clientId, authentication.getName());
        
        try {
            clientService.reactivateClient(clientId, authentication.getName());
            return clientService.getClient(clientId)
                .map(client -> ResponseEntity.ok(mapToResponse(client)))
                .orElse(ResponseEntity.notFound().build());
            
        } catch (ClientRegistrationException e) {
            if (e.getMessage().contains("not found")) {
                return ResponseEntity.notFound().build();
            }
            throw e;
        }
    }
    
    /**
     * List clients for organization
     */
    @GetMapping("/organization/{organizationId}")
    @PreAuthorize("hasRole('ADMIN') or " +
                  "@securityExpressions.isSameOrganization(#organizationId)")
    @Operation(summary = "List organization clients", 
               description = "Lists all OAuth2 clients for an organization")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Clients found"),
        @ApiResponse(responseCode = "403", description = "Insufficient permissions")
    })
    public ResponseEntity<List<OAuth2ClientResponse>> listOrganizationClients(
            @Parameter(description = "Organization ID") @PathVariable String organizationId) {
        
        List<OAuth2Client> clients = clientService.getOrganizationClients(organizationId);
        List<OAuth2ClientResponse> responses = clients.stream()
            .map(this::mapToResponse)
            .toList();
        
        return ResponseEntity.ok(responses);
    }
    
    /**
     * Search clients
     */
    @GetMapping("/search")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('oauth2:clients:read')")
    @Operation(summary = "Search OAuth2 clients", 
               description = "Searches OAuth2 clients by name or description")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Search results"),
        @ApiResponse(responseCode = "403", description = "Insufficient permissions")
    })
    public ResponseEntity<List<OAuth2ClientResponse>> searchClients(
            @Parameter(description = "Search term") @RequestParam String query) {
        
        List<OAuth2Client> clients = clientService.searchClients(query);
        List<OAuth2ClientResponse> responses = clients.stream()
            .map(this::mapToResponse)
            .toList();
        
        return ResponseEntity.ok(responses);
    }
    
    /**
     * Maps OAuth2Client entity to response DTO
     */
    private OAuth2ClientResponse mapToResponse(OAuth2Client client) {
        OAuth2ClientResponse response = new OAuth2ClientResponse();
        response.setClientId(client.getClientId());
        response.setClientName(client.getClientName());
        response.setDescription(client.getDescription());
        response.setClientType(client.getClientType());
        response.setRedirectUris(client.getRedirectUris());
        response.setGrantTypes(client.getAuthorizedGrantTypes());
        response.setScopes(client.getScopes());
        response.setAuthenticationMethods(client.getClientAuthenticationMethods());
        response.setAccessTokenValidity(client.getAccessTokenValidity());
        response.setRefreshTokenValidity(client.getRefreshTokenValidity());
        response.setRequireConsent(client.getRequireAuthorizationConsent());
        response.setRequirePkce(client.getRequirePkce());
        response.setLogoUri(client.getLogoUri());
        response.setClientUri(client.getClientUri());
        response.setPolicyUri(client.getPolicyUri());
        response.setTosUri(client.getTosUri());
        response.setContacts(client.getContacts());
        response.setActive(client.getActive());
        response.setCreatedAt(client.getCreatedAt());
        response.setUpdatedAt(client.getUpdatedAt());
        return response;
    }
    
    /**
     * Response DTO for OAuth2 client
     */
    public static class OAuth2ClientResponse {
        private String clientId;
        private String clientSecret; // Only included in registration response
        private String clientName;
        private String description;
        private OAuth2Client.ClientType clientType;
        private Set<String> redirectUris;
        private Set<OAuth2Client.GrantType> grantTypes;
        private Set<String> scopes;
        private Set<OAuth2Client.ClientAuthenticationMethod> authenticationMethods;
        private Integer accessTokenValidity;
        private Integer refreshTokenValidity;
        private Boolean requireConsent;
        private Boolean requirePkce;
        private String logoUri;
        private String clientUri;
        private String policyUri;
        private String tosUri;
        private Set<String> contacts;
        private Boolean active;
        private java.time.LocalDateTime createdAt;
        private java.time.LocalDateTime updatedAt;
        
        // Getters and setters
        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }
        
        public String getClientSecret() { return clientSecret; }
        public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
        
        public String getClientName() { return clientName; }
        public void setClientName(String clientName) { this.clientName = clientName; }
        
        public String getDescription() { return description; }
        public void setDescription(String description) { this.description = description; }
        
        public OAuth2Client.ClientType getClientType() { return clientType; }
        public void setClientType(OAuth2Client.ClientType clientType) { this.clientType = clientType; }
        
        public Set<String> getRedirectUris() { return redirectUris; }
        public void setRedirectUris(Set<String> redirectUris) { this.redirectUris = redirectUris; }
        
        public Set<OAuth2Client.GrantType> getGrantTypes() { return grantTypes; }
        public void setGrantTypes(Set<OAuth2Client.GrantType> grantTypes) { this.grantTypes = grantTypes; }
        
        public Set<String> getScopes() { return scopes; }
        public void setScopes(Set<String> scopes) { this.scopes = scopes; }
        
        public Set<OAuth2Client.ClientAuthenticationMethod> getAuthenticationMethods() { 
            return authenticationMethods; 
        }
        public void setAuthenticationMethods(Set<OAuth2Client.ClientAuthenticationMethod> authenticationMethods) { 
            this.authenticationMethods = authenticationMethods; 
        }
        
        public Integer getAccessTokenValidity() { return accessTokenValidity; }
        public void setAccessTokenValidity(Integer accessTokenValidity) { 
            this.accessTokenValidity = accessTokenValidity; 
        }
        
        public Integer getRefreshTokenValidity() { return refreshTokenValidity; }
        public void setRefreshTokenValidity(Integer refreshTokenValidity) { 
            this.refreshTokenValidity = refreshTokenValidity; 
        }
        
        public Boolean getRequireConsent() { return requireConsent; }
        public void setRequireConsent(Boolean requireConsent) { this.requireConsent = requireConsent; }
        
        public Boolean getRequirePkce() { return requirePkce; }
        public void setRequirePkce(Boolean requirePkce) { this.requirePkce = requirePkce; }
        
        public String getLogoUri() { return logoUri; }
        public void setLogoUri(String logoUri) { this.logoUri = logoUri; }
        
        public String getClientUri() { return clientUri; }
        public void setClientUri(String clientUri) { this.clientUri = clientUri; }
        
        public String getPolicyUri() { return policyUri; }
        public void setPolicyUri(String policyUri) { this.policyUri = policyUri; }
        
        public String getTosUri() { return tosUri; }
        public void setTosUri(String tosUri) { this.tosUri = tosUri; }
        
        public Set<String> getContacts() { return contacts; }
        public void setContacts(Set<String> contacts) { this.contacts = contacts; }
        
        public Boolean getActive() { return active; }
        public void setActive(Boolean active) { this.active = active; }
        
        public java.time.LocalDateTime getCreatedAt() { return createdAt; }
        public void setCreatedAt(java.time.LocalDateTime createdAt) { this.createdAt = createdAt; }
        
        public java.time.LocalDateTime getUpdatedAt() { return updatedAt; }
        public void setUpdatedAt(java.time.LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
    }
}