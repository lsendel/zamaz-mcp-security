package com.zamaz.mcp.security.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * OAuth2 client registration entity for dynamic client management.
 * Supports various OAuth2 flows including authorization code, client credentials, and PKCE.
 */
@Entity
@Table(name = "oauth2_clients")
public class OAuth2Client {
    
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    
    @Column(name = "client_id", unique = true, nullable = false)
    private String clientId;
    
    @Column(name = "client_secret")
    private String clientSecret;
    
    @Column(name = "client_name", nullable = false)
    private String clientName;
    
    @Column(name = "description", columnDefinition = "TEXT")
    private String description;
    
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
        name = "oauth2_client_redirect_uris",
        joinColumns = @JoinColumn(name = "client_id")
    )
    @Column(name = "redirect_uri")
    private Set<String> redirectUris = new HashSet<>();
    
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
        name = "oauth2_client_grant_types",
        joinColumns = @JoinColumn(name = "client_id")
    )
    @Column(name = "grant_type")
    @Enumerated(EnumType.STRING)
    private Set<GrantType> authorizedGrantTypes = new HashSet<>();
    
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
        name = "oauth2_client_scopes",
        joinColumns = @JoinColumn(name = "client_id")
    )
    @Column(name = "scope")
    private Set<String> scopes = new HashSet<>();
    
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
        name = "oauth2_client_auth_methods",
        joinColumns = @JoinColumn(name = "client_id")
    )
    @Column(name = "auth_method")
    @Enumerated(EnumType.STRING)
    private Set<ClientAuthenticationMethod> clientAuthenticationMethods = new HashSet<>();
    
    @Column(name = "access_token_validity")
    private Integer accessTokenValidity = 3600; // 1 hour default
    
    @Column(name = "refresh_token_validity")
    private Integer refreshTokenValidity = 2592000; // 30 days default
    
    @Column(name = "require_authorization_consent")
    private Boolean requireAuthorizationConsent = true;
    
    @Column(name = "require_pkce")
    private Boolean requirePkce = false;
    
    @Column(name = "organization_id")
    private String organizationId;
    
    @Column(name = "client_type")
    @Enumerated(EnumType.STRING)
    private ClientType clientType = ClientType.CONFIDENTIAL;
    
    @Column(name = "logo_uri")
    private String logoUri;
    
    @Column(name = "client_uri")
    private String clientUri;
    
    @Column(name = "policy_uri")
    private String policyUri;
    
    @Column(name = "tos_uri")
    private String tosUri;
    
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
        name = "oauth2_client_contacts",
        joinColumns = @JoinColumn(name = "client_id")
    )
    @Column(name = "contact")
    private Set<String> contacts = new HashSet<>();
    
    @Column(name = "active")
    private Boolean active = true;
    
    @Column(name = "created_by")
    private String createdBy;
    
    @Column(name = "created_at")
    @CreationTimestamp
    private LocalDateTime createdAt;
    
    @Column(name = "updated_at")
    @UpdateTimestamp
    private LocalDateTime updatedAt;
    
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
        name = "oauth2_client_settings",
        joinColumns = @JoinColumn(name = "client_id")
    )
    @MapKeyColumn(name = "setting_key")
    @Column(name = "setting_value")
    private Map<String, String> additionalSettings = new HashMap<>();
    
    // Enums
    public enum GrantType {
        AUTHORIZATION_CODE,
        CLIENT_CREDENTIALS,
        REFRESH_TOKEN,
        PASSWORD,  // Deprecated but included for compatibility
        IMPLICIT,  // Deprecated but included for compatibility
        JWT_BEARER
    }
    
    public enum ClientAuthenticationMethod {
        CLIENT_SECRET_BASIC,
        CLIENT_SECRET_POST,
        CLIENT_SECRET_JWT,
        PRIVATE_KEY_JWT,
        NONE  // For public clients
    }
    
    public enum ClientType {
        CONFIDENTIAL,  // Can maintain client secret securely
        PUBLIC        // Cannot maintain client secret (mobile apps, SPAs)
    }
    
    // Getters and Setters
    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }
    
    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }
    
    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
    
    public String getClientName() { return clientName; }
    public void setClientName(String clientName) { this.clientName = clientName; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public Set<String> getRedirectUris() { return redirectUris; }
    public void setRedirectUris(Set<String> redirectUris) { this.redirectUris = redirectUris; }
    
    public Set<GrantType> getAuthorizedGrantTypes() { return authorizedGrantTypes; }
    public void setAuthorizedGrantTypes(Set<GrantType> authorizedGrantTypes) { 
        this.authorizedGrantTypes = authorizedGrantTypes; 
    }
    
    public Set<String> getScopes() { return scopes; }
    public void setScopes(Set<String> scopes) { this.scopes = scopes; }
    
    public Set<ClientAuthenticationMethod> getClientAuthenticationMethods() { 
        return clientAuthenticationMethods; 
    }
    public void setClientAuthenticationMethods(Set<ClientAuthenticationMethod> clientAuthenticationMethods) { 
        this.clientAuthenticationMethods = clientAuthenticationMethods; 
    }
    
    public Integer getAccessTokenValidity() { return accessTokenValidity; }
    public void setAccessTokenValidity(Integer accessTokenValidity) { 
        this.accessTokenValidity = accessTokenValidity; 
    }
    
    public Integer getRefreshTokenValidity() { return refreshTokenValidity; }
    public void setRefreshTokenValidity(Integer refreshTokenValidity) { 
        this.refreshTokenValidity = refreshTokenValidity; 
    }
    
    public Boolean getRequireAuthorizationConsent() { return requireAuthorizationConsent; }
    public void setRequireAuthorizationConsent(Boolean requireAuthorizationConsent) { 
        this.requireAuthorizationConsent = requireAuthorizationConsent; 
    }
    
    public Boolean getRequirePkce() { return requirePkce; }
    public void setRequirePkce(Boolean requirePkce) { this.requirePkce = requirePkce; }
    
    public String getOrganizationId() { return organizationId; }
    public void setOrganizationId(String organizationId) { this.organizationId = organizationId; }
    
    public ClientType getClientType() { return clientType; }
    public void setClientType(ClientType clientType) { this.clientType = clientType; }
    
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
    
    public String getCreatedBy() { return createdBy; }
    public void setCreatedBy(String createdBy) { this.createdBy = createdBy; }
    
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
    
    public Map<String, String> getAdditionalSettings() { return additionalSettings; }
    public void setAdditionalSettings(Map<String, String> additionalSettings) { 
        this.additionalSettings = additionalSettings; 
    }
    
    // Helper methods
    public boolean isPublicClient() {
        return ClientType.PUBLIC.equals(clientType);
    }
    
    public boolean requiresPkce() {
        return Boolean.TRUE.equals(requirePkce) || isPublicClient();
    }
    
    public boolean supportsGrantType(GrantType grantType) {
        return authorizedGrantTypes.contains(grantType);
    }
    
    public boolean supportsScope(String scope) {
        return scopes.contains(scope) || scopes.contains("*");
    }
}