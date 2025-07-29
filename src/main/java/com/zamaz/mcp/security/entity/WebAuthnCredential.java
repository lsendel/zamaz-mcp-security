package com.zamaz.mcp.security.entity;

import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Entity representing a WebAuthn/FIDO2 credential for passwordless authentication.
 */
@Entity
@Table(name = "webauthn_credentials",
    indexes = {
        @Index(name = "idx_webauthn_user_id", columnList = "user_id"),
        @Index(name = "idx_webauthn_credential_id", columnList = "credential_id", unique = true)
    }
)
public class WebAuthnCredential {
    
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    
    @Column(name = "user_id", nullable = false)
    private UUID userId;
    
    @Column(name = "credential_id", nullable = false, unique = true)
    private String credentialId;
    
    @Column(name = "public_key", nullable = false, columnDefinition = "TEXT")
    private String publicKey;
    
    @Column(name = "user_handle", nullable = false)
    private String userHandle;
    
    @Column(name = "sign_count", nullable = false)
    private long signCount;
    
    @Column(name = "aaguid")
    private String aaguid;
    
    @Column(name = "device_name")
    private String deviceName;
    
    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;
    
    @Column(name = "last_used_at")
    private LocalDateTime lastUsedAt;
    
    @Column(name = "is_backup_eligible")
    private Boolean isBackupEligible;
    
    @Column(name = "is_backed_up")
    private Boolean isBackedUp;
    
    @Column(name = "transport_hints")
    @JdbcTypeCode(SqlTypes.JSON)
    private String[] transportHints;
    
    // Transient fields for WebAuthn4J compatibility
    @Transient
    private AttestedCredentialData attestedCredentialData;
    
    @Transient
    private AttestationStatement attestationStatement;
    
    // Constructors
    public WebAuthnCredential() {
        this.createdAt = LocalDateTime.now();
    }
    
    // Getters and setters
    public UUID getId() {
        return id;
    }
    
    public void setId(UUID id) {
        this.id = id;
    }
    
    public UUID getUserId() {
        return userId;
    }
    
    public void setUserId(UUID userId) {
        this.userId = userId;
    }
    
    public String getCredentialId() {
        return credentialId;
    }
    
    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }
    
    public String getPublicKey() {
        return publicKey;
    }
    
    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
    
    public String getUserHandle() {
        return userHandle;
    }
    
    public void setUserHandle(String userHandle) {
        this.userHandle = userHandle;
    }
    
    public long getSignCount() {
        return signCount;
    }
    
    public void setSignCount(long signCount) {
        this.signCount = signCount;
    }
    
    public String getAaguid() {
        return aaguid;
    }
    
    public void setAaguid(String aaguid) {
        this.aaguid = aaguid;
    }
    
    public String getDeviceName() {
        return deviceName;
    }
    
    public void setDeviceName(String deviceName) {
        this.deviceName = deviceName;
    }
    
    public LocalDateTime getCreatedAt() {
        return createdAt;
    }
    
    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
    
    public LocalDateTime getLastUsedAt() {
        return lastUsedAt;
    }
    
    public void setLastUsedAt(LocalDateTime lastUsedAt) {
        this.lastUsedAt = lastUsedAt;
    }
    
    public Boolean getBackupEligible() {
        return isBackupEligible;
    }
    
    public void setBackupEligible(Boolean backupEligible) {
        isBackupEligible = backupEligible;
    }
    
    public Boolean getBackedUp() {
        return isBackedUp;
    }
    
    public void setBackedUp(Boolean backedUp) {
        isBackedUp = backedUp;
    }
    
    public String[] getTransportHints() {
        return transportHints;
    }
    
    public void setTransportHints(String[] transportHints) {
        this.transportHints = transportHints;
    }
    
    public AttestedCredentialData getAttestedCredentialData() {
        return attestedCredentialData;
    }
    
    public void setAttestedCredentialData(AttestedCredentialData attestedCredentialData) {
        this.attestedCredentialData = attestedCredentialData;
    }
    
    public AttestationStatement getAttestationStatement() {
        return attestationStatement;
    }
    
    public void setAttestationStatement(AttestationStatement attestationStatement) {
        this.attestationStatement = attestationStatement;
    }
}