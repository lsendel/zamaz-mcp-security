package com.zamaz.mcp.security.model;

import com.zamaz.mcp.security.entity.OAuth2Client;
import jakarta.validation.constraints.*;

import java.util.List;
import java.util.Set;

/**
 * Request model for OAuth2 client registration.
 * Used for dynamic client registration endpoints.
 */
public class OAuth2ClientRegistrationRequest {
    
    @NotBlank(message = "Client name is required")
    @Size(min = 3, max = 100, message = "Client name must be between 3 and 100 characters")
    private String clientName;
    
    @Size(max = 500, message = "Description must not exceed 500 characters")
    private String description;
    
    @NotNull(message = "Client type is required")
    private OAuth2Client.ClientType clientType;
    
    private Set<OAuth2Client.GrantType> grantTypes;
    
    private List<String> redirectUris;
    
    private Set<String> scopes;
    
    @Min(value = 300, message = "Access token validity must be at least 300 seconds")
    @Max(value = 86400, message = "Access token validity must not exceed 86400 seconds")
    private Integer accessTokenValidity;
    
    @Min(value = 3600, message = "Refresh token validity must be at least 3600 seconds")
    @Max(value = 31536000, message = "Refresh token validity must not exceed 31536000 seconds")
    private Integer refreshTokenValidity;
    
    private Boolean requireConsent = true;
    
    @Pattern(regexp = "^https?://.*", message = "Logo URI must be a valid URL")
    private String logoUri;
    
    @Pattern(regexp = "^https?://.*", message = "Client URI must be a valid URL")
    private String clientUri;
    
    @Pattern(regexp = "^https?://.*", message = "Policy URI must be a valid URL")
    private String policyUri;
    
    @Pattern(regexp = "^https?://.*", message = "Terms of Service URI must be a valid URL")
    private String tosUri;
    
    private List<@Email String> contacts;
    
    @NotBlank(message = "Organization ID is required")
    private String organizationId;
    
    // Constructor
    public OAuth2ClientRegistrationRequest() {}
    
    // Builder pattern for convenience
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private final OAuth2ClientRegistrationRequest request = new OAuth2ClientRegistrationRequest();
        
        public Builder clientName(String clientName) {
            request.clientName = clientName;
            return this;
        }
        
        public Builder description(String description) {
            request.description = description;
            return this;
        }
        
        public Builder clientType(OAuth2Client.ClientType clientType) {
            request.clientType = clientType;
            return this;
        }
        
        public Builder grantTypes(Set<OAuth2Client.GrantType> grantTypes) {
            request.grantTypes = grantTypes;
            return this;
        }
        
        public Builder redirectUris(List<String> redirectUris) {
            request.redirectUris = redirectUris;
            return this;
        }
        
        public Builder scopes(Set<String> scopes) {
            request.scopes = scopes;
            return this;
        }
        
        public Builder accessTokenValidity(Integer accessTokenValidity) {
            request.accessTokenValidity = accessTokenValidity;
            return this;
        }
        
        public Builder refreshTokenValidity(Integer refreshTokenValidity) {
            request.refreshTokenValidity = refreshTokenValidity;
            return this;
        }
        
        public Builder requireConsent(Boolean requireConsent) {
            request.requireConsent = requireConsent;
            return this;
        }
        
        public Builder logoUri(String logoUri) {
            request.logoUri = logoUri;
            return this;
        }
        
        public Builder clientUri(String clientUri) {
            request.clientUri = clientUri;
            return this;
        }
        
        public Builder policyUri(String policyUri) {
            request.policyUri = policyUri;
            return this;
        }
        
        public Builder tosUri(String tosUri) {
            request.tosUri = tosUri;
            return this;
        }
        
        public Builder contacts(List<String> contacts) {
            request.contacts = contacts;
            return this;
        }
        
        public Builder organizationId(String organizationId) {
            request.organizationId = organizationId;
            return this;
        }
        
        public OAuth2ClientRegistrationRequest build() {
            return request;
        }
    }
    
    // Getters and setters
    public String getClientName() { return clientName; }
    public void setClientName(String clientName) { this.clientName = clientName; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public OAuth2Client.ClientType getClientType() { return clientType; }
    public void setClientType(OAuth2Client.ClientType clientType) { this.clientType = clientType; }
    
    public Set<OAuth2Client.GrantType> getGrantTypes() { return grantTypes; }
    public void setGrantTypes(Set<OAuth2Client.GrantType> grantTypes) { this.grantTypes = grantTypes; }
    
    public List<String> getRedirectUris() { return redirectUris; }
    public void setRedirectUris(List<String> redirectUris) { this.redirectUris = redirectUris; }
    
    public Set<String> getScopes() { return scopes; }
    public void setScopes(Set<String> scopes) { this.scopes = scopes; }
    
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
    
    public String getLogoUri() { return logoUri; }
    public void setLogoUri(String logoUri) { this.logoUri = logoUri; }
    
    public String getClientUri() { return clientUri; }
    public void setClientUri(String clientUri) { this.clientUri = clientUri; }
    
    public String getPolicyUri() { return policyUri; }
    public void setPolicyUri(String policyUri) { this.policyUri = policyUri; }
    
    public String getTosUri() { return tosUri; }
    public void setTosUri(String tosUri) { this.tosUri = tosUri; }
    
    public List<String> getContacts() { return contacts; }
    public void setContacts(List<String> contacts) { this.contacts = contacts; }
    
    public String getOrganizationId() { return organizationId; }
    public void setOrganizationId(String organizationId) { this.organizationId = organizationId; }
}