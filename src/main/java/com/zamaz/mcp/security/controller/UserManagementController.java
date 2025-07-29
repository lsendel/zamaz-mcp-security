package com.zamaz.mcp.security.controller;

import com.zamaz.mcp.security.entity.User;
import com.zamaz.mcp.security.service.UserManagementService;
import com.zamaz.mcp.security.service.PasswordPolicyService;
import com.zamaz.mcp.security.service.MfaService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;

/**
 * User management endpoints with proper RBAC enforcement.
 * Provides comprehensive user administration capabilities.
 */
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Slf4j
public class UserManagementController {

    private final UserManagementService userManagementService;
    private final PasswordPolicyService passwordPolicyService;
    private final MfaService mfaService;

    /**
     * Get all users in the current organization.
     */
    @GetMapping
    @PreAuthorize("@securityExpressions.hasPermission('user', 'read')")
    public ResponseEntity<Page<UserDto>> getUsers(Pageable pageable) {
        Page<User> users = userManagementService.getUsers(pageable);
        Page<UserDto> userDtos = users.map(this::convertToDto);
        return ResponseEntity.ok(userDtos);
    }

    /**
     * Get user by ID.
     */
    @GetMapping("/{userId}")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('user', 'read', #userId) or @securityExpressions.isOwnerOrHasPermission('user', 'read', #userId)")
    public ResponseEntity<UserDto> getUser(@PathVariable UUID userId) {
        User user = userManagementService.getUser(userId);
        return ResponseEntity.ok(convertToDto(user));
    }

    /**
     * Create new user.
     */
    @PostMapping
    @PreAuthorize("@securityExpressions.hasPermission('user', 'create')")
    public ResponseEntity<UserDto> createUser(@Valid @RequestBody CreateUserRequest request) {
        // Validate password policy
        PasswordPolicyService.PasswordValidationResult validation = passwordPolicyService
                .validatePassword(request.getPassword(), request.getEmail(), request.getEmail());

        if (!validation.isValid()) {
            return ResponseEntity.badRequest().build();
        }

        User user = userManagementService.createUser(request);
        return ResponseEntity.ok(convertToDto(user));
    }

    /**
     * Update user.
     */
    @PutMapping("/{userId}")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('user', 'update', #userId) or @securityExpressions.canManageUser(#userId)")
    public ResponseEntity<UserDto> updateUser(@PathVariable UUID userId,
            @Valid @RequestBody UpdateUserRequest request) {
        User user = userManagementService.updateUser(userId, request);
        return ResponseEntity.ok(convertToDto(user));
    }

    /**
     * Delete user.
     */
    @DeleteMapping("/{userId}")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('user', 'delete', #userId) or @securityExpressions.canManageUser(#userId)")
    public ResponseEntity<Void> deleteUser(@PathVariable UUID userId) {
        userManagementService.deleteUser(userId);
        return ResponseEntity.noContent().build();
    }

    /**
     * Change user password.
     */
    @PostMapping("/{userId}/change-password")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('user', 'update', #userId) or @securityExpressions.isOwnerOrHasPermission('user', 'update', #userId)")
    public ResponseEntity<Void> changePassword(@PathVariable UUID userId,
            @Valid @RequestBody ChangePasswordRequest request) {
        // Validate new password
        PasswordPolicyService.PasswordValidationResult validation = passwordPolicyService
                .validatePassword(request.getNewPassword(), null, null);

        if (!validation.isValid()) {
            return ResponseEntity.badRequest().build();
        }

        userManagementService.changePassword(userId, request.getCurrentPassword(), request.getNewPassword());
        return ResponseEntity.ok().build();
    }

    /**
     * Enable MFA for user.
     */
    @PostMapping("/{userId}/mfa/enable")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('user', 'update', #userId) or @securityExpressions.isOwnerOrHasPermission('user', 'update', #userId)")
    public ResponseEntity<MfaSetupResponse> enableMfa(@PathVariable UUID userId) {
        MfaService.MfaSetupResult result = mfaService.enableMfa(userId);

        MfaSetupResponse response = new MfaSetupResponse();
        response.setSecret(result.getSecret());
        response.setQrCodeUrl(result.getQrCodeUrl());
        response.setQrCodeImage(result.getQrCodeImageBase64());
        response.setBackupCodes(result.getBackupCodes());

        return ResponseEntity.ok(response);
    }

    /**
     * Verify MFA setup.
     */
    @PostMapping("/{userId}/mfa/verify")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('user', 'update', #userId) or @securityExpressions.isOwnerOrHasPermission('user', 'update', #userId)")
    public ResponseEntity<Void> verifyMfa(@PathVariable UUID userId, @RequestBody VerifyMfaRequest request) {
        boolean verified = mfaService.verifyMfaSetup(userId, request.getCode());

        if (verified) {
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * Disable MFA for user.
     */
    @PostMapping("/{userId}/mfa/disable")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('user', 'update', #userId) or @securityExpressions.isOwnerOrHasPermission('user', 'update', #userId)")
    public ResponseEntity<Void> disableMfa(@PathVariable UUID userId) {
        mfaService.disableMfa(userId);
        return ResponseEntity.ok().build();
    }

    /**
     * Get MFA status.
     */
    @GetMapping("/{userId}/mfa/status")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('user', 'read', #userId) or @securityExpressions.isOwnerOrHasPermission('user', 'read', #userId)")
    public ResponseEntity<MfaService.MfaStatus> getMfaStatus(@PathVariable UUID userId) {
        MfaService.MfaStatus status = mfaService.getMfaStatus(userId);
        return ResponseEntity.ok(status);
    }

    /**
     * Regenerate backup codes.
     */
    @PostMapping("/{userId}/mfa/backup-codes/regenerate")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('user', 'update', #userId) or @securityExpressions.isOwnerOrHasPermission('user', 'update', #userId)")
    public ResponseEntity<List<String>> regenerateBackupCodes(@PathVariable UUID userId) {
        List<String> backupCodes = mfaService.regenerateBackupCodes(userId);
        return ResponseEntity.ok(backupCodes);
    }

    /**
     * Lock user account.
     */
    @PostMapping("/{userId}/lock")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('user', 'manage', #userId) or @securityExpressions.canManageUser(#userId)")
    public ResponseEntity<Void> lockUser(@PathVariable UUID userId, @RequestBody LockUserRequest request) {
        userManagementService.lockUser(userId, request.getReason());
        return ResponseEntity.ok().build();
    }

    /**
     * Unlock user account.
     */
    @PostMapping("/{userId}/unlock")
    @PreAuthorize("@securityExpressions.hasPermissionOnResource('user', 'manage', #userId) or @securityExpressions.canManageUser(#userId)")
    public ResponseEntity<Void> unlockUser(@PathVariable UUID userId) {
        userManagementService.unlockUser(userId);
        return ResponseEntity.ok().build();
    }

    private UserDto convertToDto(User user) {
        UserDto dto = new UserDto();
        dto.setId(user.getId());
        dto.setEmail(user.getEmail());
        dto.setFirstName(user.getFirstName());
        dto.setLastName(user.getLastName());
        dto.setDisplayName(user.getDisplayName());
        dto.setEmailVerified(user.getEmailVerified());
        dto.setMfaEnabled(user.getMfaEnabled());
        dto.setAccountLocked(user.getAccountLocked());
        dto.setIsActive(user.getIsActive());
        dto.setCreatedAt(user.getCreatedAt());
        dto.setLastLoginAt(user.getLastLoginAt());
        return dto;
    }

    // DTOs
    public static class UserDto {
        private UUID id;
        private String email;
        private String firstName;
        private String lastName;
        private String displayName;
        private Boolean emailVerified;
        private Boolean mfaEnabled;
        private Boolean accountLocked;
        private Boolean isActive;
        private java.time.LocalDateTime createdAt;
        private java.time.LocalDateTime lastLoginAt;

        // Getters and setters
        public UUID getId() {
            return id;
        }

        public void setId(UUID id) {
            this.id = id;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getFirstName() {
            return firstName;
        }

        public void setFirstName(String firstName) {
            this.firstName = firstName;
        }

        public String getLastName() {
            return lastName;
        }

        public void setLastName(String lastName) {
            this.lastName = lastName;
        }

        public String getDisplayName() {
            return displayName;
        }

        public void setDisplayName(String displayName) {
            this.displayName = displayName;
        }

        public Boolean getEmailVerified() {
            return emailVerified;
        }

        public void setEmailVerified(Boolean emailVerified) {
            this.emailVerified = emailVerified;
        }

        public Boolean getMfaEnabled() {
            return mfaEnabled;
        }

        public void setMfaEnabled(Boolean mfaEnabled) {
            this.mfaEnabled = mfaEnabled;
        }

        public Boolean getAccountLocked() {
            return accountLocked;
        }

        public void setAccountLocked(Boolean accountLocked) {
            this.accountLocked = accountLocked;
        }

        public Boolean getIsActive() {
            return isActive;
        }

        public void setIsActive(Boolean isActive) {
            this.isActive = isActive;
        }

        public java.time.LocalDateTime getCreatedAt() {
            return createdAt;
        }

        public void setCreatedAt(java.time.LocalDateTime createdAt) {
            this.createdAt = createdAt;
        }

        public java.time.LocalDateTime getLastLoginAt() {
            return lastLoginAt;
        }

        public void setLastLoginAt(java.time.LocalDateTime lastLoginAt) {
            this.lastLoginAt = lastLoginAt;
        }
    }

    public static class CreateUserRequest {
        private String email;
        private String password;
        private String firstName;
        private String lastName;

        // Getters and setters
        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getFirstName() {
            return firstName;
        }

        public void setFirstName(String firstName) {
            this.firstName = firstName;
        }

        public String getLastName() {
            return lastName;
        }

        public void setLastName(String lastName) {
            this.lastName = lastName;
        }
    }

    public static class UpdateUserRequest {
        private String firstName;
        private String lastName;
        private String displayName;

        // Getters and setters
        public String getFirstName() {
            return firstName;
        }

        public void setFirstName(String firstName) {
            this.firstName = firstName;
        }

        public String getLastName() {
            return lastName;
        }

        public void setLastName(String lastName) {
            this.lastName = lastName;
        }

        public String getDisplayName() {
            return displayName;
        }

        public void setDisplayName(String displayName) {
            this.displayName = displayName;
        }
    }

    public static class ChangePasswordRequest {
        private String currentPassword;
        private String newPassword;

        // Getters and setters
        public String getCurrentPassword() {
            return currentPassword;
        }

        public void setCurrentPassword(String currentPassword) {
            this.currentPassword = currentPassword;
        }

        public String getNewPassword() {
            return newPassword;
        }

        public void setNewPassword(String newPassword) {
            this.newPassword = newPassword;
        }
    }

    public static class MfaSetupResponse {
        private String secret;
        private String qrCodeUrl;
        private String qrCodeImage;
        private List<String> backupCodes;

        // Getters and setters
        public String getSecret() {
            return secret;
        }

        public void setSecret(String secret) {
            this.secret = secret;
        }

        public String getQrCodeUrl() {
            return qrCodeUrl;
        }

        public void setQrCodeUrl(String qrCodeUrl) {
            this.qrCodeUrl = qrCodeUrl;
        }

        public String getQrCodeImage() {
            return qrCodeImage;
        }

        public void setQrCodeImage(String qrCodeImage) {
            this.qrCodeImage = qrCodeImage;
        }

        public List<String> getBackupCodes() {
            return backupCodes;
        }

        public void setBackupCodes(List<String> backupCodes) {
            this.backupCodes = backupCodes;
        }
    }

    public static class VerifyMfaRequest {
        private String code;

        // Getters and setters
        public String getCode() {
            return code;
        }

        public void setCode(String code) {
            this.code = code;
        }
    }

    public static class LockUserRequest {
        private String reason;

        // Getters and setters
        public String getReason() {
            return reason;
        }

        public void setReason(String reason) {
            this.reason = reason;
        }
    }
}