package com.zamaz.mcp.security.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Enhanced User entity with MFA support, account locking, and audit fields.
 * Supports multi-tenant organization membership and hierarchical roles.
 */
@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_users_email", columnList = "email"),
        @Index(name = "idx_users_active", columnList = "isActive"),
        @Index(name = "idx_users_email_verified", columnList = "emailVerified"),
        @Index(name = "idx_users_account_locked", columnList = "accountLocked"),
        @Index(name = "idx_users_mfa_enabled", columnList = "mfaEnabled")
})
@Data
@EqualsAndHashCode(exclude = { "userRoles", "userPermissions", "auditLogs" })
@ToString(exclude = { "userRoles", "userPermissions", "auditLogs", "passwordHash", "mfaSecret" })
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 255)
    private String email;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Column(name = "first_name", length = 100)
    private String firstName;

    @Column(name = "last_name", length = 100)
    private String lastName;

    @Column(name = "display_name", length = 200)
    private String displayName;

    @Column(name = "phone_number", length = 20)
    private String phoneNumber;

    // Email verification
    @Column(name = "email_verified", nullable = false)
    private Boolean emailVerified = false;

    @Column(name = "email_verification_token", length = 255)
    private String emailVerificationToken;

    @Column(name = "email_verification_expires_at")
    private LocalDateTime emailVerificationExpiresAt;

    // Multi-Factor Authentication
    @Column(name = "mfa_enabled", nullable = false)
    private Boolean mfaEnabled = false;

    @Column(name = "mfa_secret", length = 255)
    private String mfaSecret;

    @Column(name = "mfa_backup_codes", columnDefinition = "TEXT")
    private String mfaBackupCodes; // JSON array of backup codes

    @Column(name = "mfa_recovery_codes_used", nullable = false)
    private Integer mfaRecoveryCodesUsed = 0;

    // Account Security
    @Column(name = "account_locked", nullable = false)
    private Boolean accountLocked = false;

    @Column(name = "account_lock_reason", length = 500)
    private String accountLockReason;

    @Column(name = "account_locked_at")
    private LocalDateTime accountLockedAt;

    @Column(name = "account_locked_until")
    private LocalDateTime accountLockedUntil;

    @Column(name = "failed_login_attempts", nullable = false)
    private Integer failedLoginAttempts = 0;

    @Column(name = "last_failed_login_at")
    private LocalDateTime lastFailedLoginAt;

    // Password Management
    @Column(name = "password_changed_at")
    private LocalDateTime passwordChangedAt;

    @Column(name = "password_expires_at")
    private LocalDateTime passwordExpiresAt;

    @Column(name = "password_reset_token", length = 255)
    private String passwordResetToken;

    @Column(name = "password_reset_expires_at")
    private LocalDateTime passwordResetExpiresAt;

    @Column(name = "force_password_change", nullable = false)
    private Boolean forcePasswordChange = false;

    // Session Management
    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    @Column(name = "last_login_ip", length = 45)
    private String lastLoginIp;

    @Column(name = "current_session_id", length = 255)
    private String currentSessionId;

    @Column(name = "concurrent_sessions_allowed", nullable = false)
    private Integer concurrentSessionsAllowed = 3;

    // Account Status
    @Column(name = "is_active", nullable = false)
    private Boolean isActive = true;

    @Column(name = "deactivated_at")
    private LocalDateTime deactivatedAt;

    @Column(name = "deactivated_reason", length = 500)
    private String deactivatedReason;

    // Privacy and Preferences
    @Column(name = "privacy_settings", columnDefinition = "jsonb")
    private String privacySettings; // JSON object

    @Column(name = "notification_preferences", columnDefinition = "jsonb")
    private String notificationPreferences; // JSON object

    // WebAuthn Settings
    @Column(name = "webauthn_enabled", nullable = false)
    private Boolean webauthnEnabled = false;

    @Column(name = "preferred_auth_method", length = 50)
    private String preferredAuthMethod = "password";

    @Column(name = "locale", length = 10)
    private String locale = "en_US";

    @Column(name = "timezone", length = 50)
    private String timezone = "UTC";

    // Audit Fields
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @Column(name = "created_by", length = 255)
    private String createdBy;

    @Column(name = "updated_by", length = 255)
    private String updatedBy;

    // Relationships
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private Set<UserRole> userRoles = new HashSet<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private Set<UserPermission> userPermissions = new HashSet<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private Set<SecurityAuditLog> auditLogs = new HashSet<>();

    // Helper Methods
    public String getFullName() {
        if (firstName != null && lastName != null) {
            return firstName + " " + lastName;
        } else if (displayName != null) {
            return displayName;
        } else {
            return email;
        }
    }

    public boolean isAccountNonLocked() {
        if (!accountLocked) {
            return true;
        }

        // Check if temporary lock has expired
        if (accountLockedUntil != null && LocalDateTime.now().isAfter(accountLockedUntil)) {
            return true;
        }

        return false;
    }

    public boolean isCredentialsNonExpired() {
        return passwordExpiresAt == null || LocalDateTime.now().isBefore(passwordExpiresAt);
    }

    public boolean isAccountNonExpired() {
        return isActive && (deactivatedAt == null);
    }

    public boolean isEnabled() {
        return isActive && emailVerified && isAccountNonLocked();
    }

    public void incrementFailedLoginAttempts() {
        this.failedLoginAttempts++;
        this.lastFailedLoginAt = LocalDateTime.now();
    }

    public void resetFailedLoginAttempts() {
        this.failedLoginAttempts = 0;
        this.lastFailedLoginAt = null;
    }

    public void lockAccount(String reason) {
        this.accountLocked = true;
        this.accountLockReason = reason;
        this.accountLockedAt = LocalDateTime.now();
    }

    public void lockAccountTemporarily(String reason, LocalDateTime until) {
        lockAccount(reason);
        this.accountLockedUntil = until;
    }

    public void unlockAccount() {
        this.accountLocked = false;
        this.accountLockReason = null;
        this.accountLockedAt = null;
        this.accountLockedUntil = null;
        resetFailedLoginAttempts();
    }
}