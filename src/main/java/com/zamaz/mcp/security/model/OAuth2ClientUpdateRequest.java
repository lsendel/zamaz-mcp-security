package com.zamaz.mcp.security.model;

import jakarta.validation.constraints.*;

import java.util.List;
import java.util.Set;

/**
 * Request model for OAuth2 client updates.
 * All fields are optional - only provided fields will be updated.
 */
public class OAuth2ClientUpdateRequest {
    
    @Size(min = 3, max = 100, message = "Client name must be between 3 and 100 characters")
    private String clientName;
    
    @Size(max = 500, message = "Description must not exceed 500 characters")
    private String description;
    
    private List<String> redirectUris;
    
    private Set<String> scopes;
    
    @Min(value = 300, message = "Access token validity must be at least 300 seconds")
    @Max(value = 86400, message = "Access token validity must not exceed 86400 seconds")
    private Integer accessTokenValidity;
    
    @Min(value = 3600, message = "Refresh token validity must be at least 3600 seconds")
    @Max(value = 31536000, message = "Refresh token validity must not exceed 31536000 seconds")
    private Integer refreshTokenValidity;
    
    private Boolean requireConsent;
    
    @Pattern(regexp = "^https?://.*", message = "Logo URI must be a valid URL")
    private String logoUri;
    
    @Pattern(regexp = "^https?://.*", message = "Client URI must be a valid URL")
    private String clientUri;
    
    @Pattern(regexp = "^https?://.*", message = "Policy URI must be a valid URL")
    private String policyUri;
    
    @Pattern(regexp = "^https?://.*", message = "Terms of Service URI must be a valid URL")
    private String tosUri;
    
    private List<@Email String> contacts;
    
    // Constructor
    public OAuth2ClientUpdateRequest() {}
    
    // Getters and setters
    public String getClientName() { return clientName; }
    public void setClientName(String clientName) { this.clientName = clientName; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
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
}