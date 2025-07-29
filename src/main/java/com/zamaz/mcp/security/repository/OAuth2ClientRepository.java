package com.zamaz.mcp.security.repository;

import com.zamaz.mcp.security.entity.OAuth2Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for OAuth2 client management.
 * Provides methods for querying clients by various criteria.
 */
@Repository
public interface OAuth2ClientRepository extends JpaRepository<OAuth2Client, UUID> {
    
    /**
     * Find client by client ID
     */
    Optional<OAuth2Client> findByClientId(String clientId);
    
    /**
     * Find active client by client ID
     */
    Optional<OAuth2Client> findByClientIdAndActiveTrue(String clientId);
    
    /**
     * Find all clients for an organization
     */
    List<OAuth2Client> findByOrganizationId(String organizationId);
    
    /**
     * Find active clients for an organization
     */
    List<OAuth2Client> findByOrganizationIdAndActiveTrue(String organizationId);
    
    /**
     * Find clients by grant type
     */
    @Query("SELECT c FROM OAuth2Client c JOIN c.authorizedGrantTypes gt WHERE gt = :grantType")
    List<OAuth2Client> findByGrantType(@Param("grantType") OAuth2Client.GrantType grantType);
    
    /**
     * Find clients by scope
     */
    @Query("SELECT c FROM OAuth2Client c JOIN c.scopes s WHERE s = :scope")
    List<OAuth2Client> findByScope(@Param("scope") String scope);
    
    /**
     * Find public clients (mobile apps, SPAs)
     */
    List<OAuth2Client> findByClientType(OAuth2Client.ClientType clientType);
    
    /**
     * Find clients requiring PKCE
     */
    List<OAuth2Client> findByRequirePkceTrue();
    
    /**
     * Check if client ID already exists
     */
    boolean existsByClientId(String clientId);
    
    /**
     * Find clients created by a specific user
     */
    List<OAuth2Client> findByCreatedBy(String userId);
    
    /**
     * Search clients by name or description
     */
    @Query("SELECT c FROM OAuth2Client c WHERE " +
           "LOWER(c.clientName) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
           "LOWER(c.description) LIKE LOWER(CONCAT('%', :searchTerm, '%'))")
    List<OAuth2Client> searchClients(@Param("searchTerm") String searchTerm);
    
    /**
     * Find clients with specific redirect URI
     */
    @Query("SELECT c FROM OAuth2Client c JOIN c.redirectUris r WHERE r = :redirectUri")
    List<OAuth2Client> findByRedirectUri(@Param("redirectUri") String redirectUri);
    
    /**
     * Count active clients for an organization
     */
    long countByOrganizationIdAndActiveTrue(String organizationId);
    
    /**
     * Find clients that support a specific authentication method
     */
    @Query("SELECT c FROM OAuth2Client c JOIN c.clientAuthenticationMethods m WHERE m = :method")
    List<OAuth2Client> findByAuthenticationMethod(
        @Param("method") OAuth2Client.ClientAuthenticationMethod method);
}