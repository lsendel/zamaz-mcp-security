package com.zamaz.mcp.security.repository;

import com.zamaz.mcp.security.entity.WebAuthnCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for WebAuthn credential management.
 */
@Repository
public interface WebAuthnCredentialRepository extends JpaRepository<WebAuthnCredential, UUID> {
    
    /**
     * Find all credentials for a user
     */
    List<WebAuthnCredential> findByUserId(UUID userId);
    
    /**
     * Find credential by credential ID
     */
    Optional<WebAuthnCredential> findByCredentialId(String credentialId);
    
    /**
     * Find credential by user ID and credential ID
     */
    Optional<WebAuthnCredential> findByUserIdAndCredentialId(UUID userId, String credentialId);
    
    /**
     * Count credentials for a user
     */
    long countByUserId(UUID userId);
    
    /**
     * Delete all credentials for a user
     */
    @Modifying
    @Query("DELETE FROM WebAuthnCredential w WHERE w.userId = :userId")
    void deleteByUserId(@Param("userId") UUID userId);
    
    /**
     * Find inactive credentials
     */
    @Query("SELECT w FROM WebAuthnCredential w WHERE w.lastUsedAt < :inactiveDate")
    List<WebAuthnCredential> findInactiveCredentials(@Param("inactiveDate") LocalDateTime inactiveDate);
    
    /**
     * Update last used timestamp
     */
    @Modifying
    @Query("UPDATE WebAuthnCredential w SET w.lastUsedAt = :timestamp, w.signCount = :signCount " +
           "WHERE w.id = :id")
    void updateLastUsed(@Param("id") UUID id, 
                       @Param("timestamp") LocalDateTime timestamp,
                       @Param("signCount") long signCount);
}