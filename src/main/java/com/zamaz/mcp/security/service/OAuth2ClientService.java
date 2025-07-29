package com.zamaz.mcp.security.service;

import com.zamaz.mcp.security.entity.OAuth2Client;
import com.zamaz.mcp.security.entity.OAuth2Client.*;
import com.zamaz.mcp.security.repository.OAuth2ClientRepository;
import com.zamaz.mcp.security.audit.SecurityAuditService;
import com.zamaz.mcp.security.exception.ClientRegistrationException;
import com.zamaz.mcp.security.model.OAuth2ClientRegistrationRequest;
import com.zamaz.mcp.security.model.OAuth2ClientUpdateRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service for OAuth2 client registration and management.
 * Handles dynamic client registration, updates, and validation.
 */
@Service
@Transactional
public class OAuth2ClientService {
    
    private static final Logger logger = LoggerFactory.getLogger(OAuth2ClientService.class);
    
    private static final int CLIENT_ID_LENGTH = 32;
    private static final int CLIENT_SECRET_LENGTH = 48;
    private static final String CLIENT_ID_PREFIX = "mcp_";
    
    @Autowired
    private OAuth2ClientRepository clientRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private SecurityAuditService auditService;
    
    private final SecureRandom secureRandom = new SecureRandom();
    
    /**
     * Register a new OAuth2 client
     */
    public OAuth2Client registerClient(OAuth2ClientRegistrationRequest request, String createdBy) {
        logger.info("Registering new OAuth2 client: {}", request.getClientName());
        
        // Validate request
        validateRegistrationRequest(request);
        
        // Create new client
        OAuth2Client client = new OAuth2Client();
        client.setClientId(generateClientId());
        client.setClientName(request.getClientName());
        client.setDescription(request.getDescription());
        client.setOrganizationId(request.getOrganizationId());
        client.setClientType(request.getClientType());
        client.setCreatedBy(createdBy);
        
        // Set grant types
        if (request.getGrantTypes() != null && !request.getGrantTypes().isEmpty()) {
            client.setAuthorizedGrantTypes(new HashSet<>(request.getGrantTypes()));
        } else {
            // Default grant types based on client type
            client.setAuthorizedGrantTypes(getDefaultGrantTypes(request.getClientType()));
        }
        
        // Set redirect URIs
        if (request.getRedirectUris() != null && !request.getRedirectUris().isEmpty()) {
            validateRedirectUris(request.getRedirectUris(), request.getClientType());
            client.setRedirectUris(new HashSet<>(request.getRedirectUris()));
        }
        
        // Set scopes
        if (request.getScopes() != null && !request.getScopes().isEmpty()) {
            client.setScopes(new HashSet<>(request.getScopes()));
        } else {
            client.setScopes(getDefaultScopes());
        }
        
        // Set authentication methods
        if (request.getClientType() == ClientType.CONFIDENTIAL) {
            // Generate client secret for confidential clients
            String clientSecret = generateClientSecret();
            client.setClientSecret(passwordEncoder.encode(clientSecret));
            client.setClientAuthenticationMethods(
                Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                       ClientAuthenticationMethod.CLIENT_SECRET_POST));
            
            // Store plain secret temporarily for response
            client.getAdditionalSettings().put("_temp_secret", clientSecret);
        } else {
            // Public clients don't have secrets
            client.setClientAuthenticationMethods(Set.of(ClientAuthenticationMethod.NONE));
            client.setRequirePkce(true); // PKCE is required for public clients
        }
        
        // Set token validity
        if (request.getAccessTokenValidity() != null) {
            client.setAccessTokenValidity(request.getAccessTokenValidity());
        }
        if (request.getRefreshTokenValidity() != null) {
            client.setRefreshTokenValidity(request.getRefreshTokenValidity());
        }
        
        // Set additional properties
        client.setRequireAuthorizationConsent(request.getRequireConsent() != null ? 
            request.getRequireConsent() : true);
        client.setLogoUri(request.getLogoUri());
        client.setClientUri(request.getClientUri());
        client.setPolicyUri(request.getPolicyUri());
        client.setTosUri(request.getTosUri());
        
        if (request.getContacts() != null) {
            client.setContacts(new HashSet<>(request.getContacts()));
        }
        
        // Save client
        OAuth2Client savedClient = clientRepository.save(client);
        
        // Audit log
        auditService.logClientRegistration(savedClient.getClientId(), createdBy);
        
        logger.info("Successfully registered OAuth2 client: {}", savedClient.getClientId());
        
        return savedClient;
    }
    
    /**
     * Update an existing OAuth2 client
     */
    public OAuth2Client updateClient(String clientId, OAuth2ClientUpdateRequest request, String updatedBy) {
        logger.info("Updating OAuth2 client: {}", clientId);
        
        OAuth2Client client = clientRepository.findByClientId(clientId)
            .orElseThrow(() -> new ClientRegistrationException("Client not found: " + clientId));
        
        // Update allowed fields
        if (request.getClientName() != null) {
            client.setClientName(request.getClientName());
        }
        if (request.getDescription() != null) {
            client.setDescription(request.getDescription());
        }
        if (request.getRedirectUris() != null) {
            validateRedirectUris(request.getRedirectUris(), client.getClientType());
            client.setRedirectUris(new HashSet<>(request.getRedirectUris()));
        }
        if (request.getScopes() != null) {
            client.setScopes(new HashSet<>(request.getScopes()));
        }
        if (request.getAccessTokenValidity() != null) {
            client.setAccessTokenValidity(request.getAccessTokenValidity());
        }
        if (request.getRefreshTokenValidity() != null) {
            client.setRefreshTokenValidity(request.getRefreshTokenValidity());
        }
        if (request.getRequireConsent() != null) {
            client.setRequireAuthorizationConsent(request.getRequireConsent());
        }
        if (request.getLogoUri() != null) {
            client.setLogoUri(request.getLogoUri());
        }
        if (request.getClientUri() != null) {
            client.setClientUri(request.getClientUri());
        }
        if (request.getPolicyUri() != null) {
            client.setPolicyUri(request.getPolicyUri());
        }
        if (request.getTosUri() != null) {
            client.setTosUri(request.getTosUri());
        }
        if (request.getContacts() != null) {
            client.setContacts(new HashSet<>(request.getContacts()));
        }
        
        // Save updated client
        OAuth2Client updatedClient = clientRepository.save(client);
        
        // Audit log
        auditService.logClientUpdate(clientId, updatedBy);
        
        logger.info("Successfully updated OAuth2 client: {}", clientId);
        
        return updatedClient;
    }
    
    /**
     * Regenerate client secret
     */
    public String regenerateClientSecret(String clientId, String requestedBy) {
        logger.info("Regenerating client secret for: {}", clientId);
        
        OAuth2Client client = clientRepository.findByClientId(clientId)
            .orElseThrow(() -> new ClientRegistrationException("Client not found: " + clientId));
        
        if (client.getClientType() != ClientType.CONFIDENTIAL) {
            throw new ClientRegistrationException("Cannot regenerate secret for public client");
        }
        
        // Generate new secret
        String newSecret = generateClientSecret();
        client.setClientSecret(passwordEncoder.encode(newSecret));
        
        // Save client
        clientRepository.save(client);
        
        // Audit log
        auditService.logClientSecretRegeneration(clientId, requestedBy);
        
        logger.info("Successfully regenerated client secret for: {}", clientId);
        
        return newSecret;
    }
    
    /**
     * Deactivate a client
     */
    public void deactivateClient(String clientId, String deactivatedBy) {
        logger.info("Deactivating OAuth2 client: {}", clientId);
        
        OAuth2Client client = clientRepository.findByClientId(clientId)
            .orElseThrow(() -> new ClientRegistrationException("Client not found: " + clientId));
        
        client.setActive(false);
        clientRepository.save(client);
        
        // Audit log
        auditService.logClientDeactivation(clientId, deactivatedBy);
        
        logger.info("Successfully deactivated OAuth2 client: {}", clientId);
    }
    
    /**
     * Reactivate a client
     */
    public void reactivateClient(String clientId, String reactivatedBy) {
        logger.info("Reactivating OAuth2 client: {}", clientId);
        
        OAuth2Client client = clientRepository.findByClientId(clientId)
            .orElseThrow(() -> new ClientRegistrationException("Client not found: " + clientId));
        
        client.setActive(true);
        clientRepository.save(client);
        
        // Audit log
        auditService.logClientReactivation(clientId, reactivatedBy);
        
        logger.info("Successfully reactivated OAuth2 client: {}", clientId);
    }
    
    /**
     * Get client by ID
     */
    @Transactional(readOnly = true)
    public Optional<OAuth2Client> getClient(String clientId) {
        return clientRepository.findByClientIdAndActiveTrue(clientId);
    }
    
    /**
     * Get all clients for an organization
     */
    @Transactional(readOnly = true)
    public List<OAuth2Client> getOrganizationClients(String organizationId) {
        return clientRepository.findByOrganizationIdAndActiveTrue(organizationId);
    }
    
    /**
     * Search clients
     */
    @Transactional(readOnly = true)
    public List<OAuth2Client> searchClients(String searchTerm) {
        return clientRepository.searchClients(searchTerm);
    }
    
    /**
     * Validate client credentials
     */
    public boolean validateClientCredentials(String clientId, String clientSecret) {
        Optional<OAuth2Client> clientOpt = clientRepository.findByClientIdAndActiveTrue(clientId);
        
        if (clientOpt.isEmpty()) {
            return false;
        }
        
        OAuth2Client client = clientOpt.get();
        
        // Public clients don't have secrets
        if (client.getClientType() == ClientType.PUBLIC) {
            return clientSecret == null || clientSecret.isEmpty();
        }
        
        // Validate secret for confidential clients
        return client.getClientSecret() != null && 
               passwordEncoder.matches(clientSecret, client.getClientSecret());
    }
    
    /**
     * Validate redirect URI
     */
    public boolean validateRedirectUri(String clientId, String redirectUri) {
        Optional<OAuth2Client> clientOpt = clientRepository.findByClientIdAndActiveTrue(clientId);
        
        if (clientOpt.isEmpty()) {
            return false;
        }
        
        OAuth2Client client = clientOpt.get();
        
        // Exact match
        if (client.getRedirectUris().contains(redirectUri)) {
            return true;
        }
        
        // Check for localhost variations in development
        if (redirectUri.startsWith("http://localhost:") || 
            redirectUri.startsWith("http://127.0.0.1:")) {
            for (String registeredUri : client.getRedirectUris()) {
                if (registeredUri.startsWith("http://localhost:") || 
                    registeredUri.startsWith("http://127.0.0.1:")) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    // Private helper methods
    
    private void validateRegistrationRequest(OAuth2ClientRegistrationRequest request) {
        if (request.getClientName() == null || request.getClientName().trim().isEmpty()) {
            throw new ClientRegistrationException("Client name is required");
        }
        
        if (request.getClientType() == null) {
            throw new ClientRegistrationException("Client type is required");
        }
        
        // Validate grant types
        if (request.getGrantTypes() != null) {
            for (GrantType grantType : request.getGrantTypes()) {
                if (grantType == GrantType.IMPLICIT || grantType == GrantType.PASSWORD) {
                    throw new ClientRegistrationException(
                        "Grant type " + grantType + " is deprecated and not allowed");
                }
            }
        }
        
        // Public clients must use PKCE
        if (request.getClientType() == ClientType.PUBLIC && 
            request.getGrantTypes() != null && 
            request.getGrantTypes().contains(GrantType.AUTHORIZATION_CODE)) {
            // PKCE will be enforced automatically
        }
    }
    
    private void validateRedirectUris(List<String> redirectUris, ClientType clientType) {
        for (String uri : redirectUris) {
            // Validate URI format
            if (!isValidUri(uri)) {
                throw new ClientRegistrationException("Invalid redirect URI: " + uri);
            }
            
            // Production URIs must use HTTPS
            if (!uri.startsWith("http://localhost") && 
                !uri.startsWith("http://127.0.0.1") && 
                !uri.startsWith("https://")) {
                throw new ClientRegistrationException(
                    "Redirect URIs must use HTTPS (except localhost): " + uri);
            }
            
            // Mobile app deep links are allowed
            if (clientType == ClientType.PUBLIC && 
                (uri.startsWith("myapp://") || uri.matches("^[a-z]+://.*"))) {
                // Allow custom schemes for mobile apps
                continue;
            }
        }
    }
    
    private boolean isValidUri(String uri) {
        try {
            new java.net.URI(uri);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    private Set<GrantType> getDefaultGrantTypes(ClientType clientType) {
        if (clientType == ClientType.CONFIDENTIAL) {
            return Set.of(GrantType.AUTHORIZATION_CODE, 
                         GrantType.CLIENT_CREDENTIALS, 
                         GrantType.REFRESH_TOKEN);
        } else {
            return Set.of(GrantType.AUTHORIZATION_CODE, 
                         GrantType.REFRESH_TOKEN);
        }
    }
    
    private Set<String> getDefaultScopes() {
        return Set.of("openid", "profile", "email");
    }
    
    private String generateClientId() {
        String clientId;
        do {
            clientId = CLIENT_ID_PREFIX + generateRandomString(CLIENT_ID_LENGTH);
        } while (clientRepository.existsByClientId(clientId));
        
        return clientId;
    }
    
    private String generateClientSecret() {
        return generateRandomString(CLIENT_SECRET_LENGTH);
    }
    
    private String generateRandomString(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
            .substring(0, length);
    }
}