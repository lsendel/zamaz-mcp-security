package com.zamaz.mcp.security.service;

import com.zamaz.mcp.security.controller.UserManagementController;
import com.zamaz.mcp.security.entity.User;
import com.zamaz.mcp.security.repository.UserRepository;
import com.zamaz.mcp.security.tenant.TenantSecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * User management service with proper RBAC enforcement.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UserManagementService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SecurityAuditService auditService;

    /**
     * Get all users in the current organization.
     */
    @Transactional(readOnly = true)
    public Page<User> getUsers(Pageable pageable) {
        UUID organizationId = TenantSecurityContext.getCurrentTenant();
        return userRepository.findByOrganizationId(organizationId, pageable);
    }

    /**
     * Get user by ID.
     */
    @Transactional(readOnly = true)
    public User getUser(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
    }

    /**
     * Create new user.
     */
    public User createUser(UserManagementController.CreateUserRequest request) {
        User user = new User();
        user.setEmail(request.getEmail());
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEmailVerified(false);
        user.setIsActive(true);
        user.setPasswordChangedAt(LocalDateTime.now());

        User savedUser = userRepository.save(user);

        auditService.logAdministrativeAction(
                "USER_CREATED",
                "New user created: " + request.getEmail(),
                null,
                savedUser);

        return savedUser;
    }

    /**
     * Update user.
     */
    public User updateUser(UUID userId, UserManagementController.UpdateUserRequest request) {
        User user = getUser(userId);
        User beforeState = cloneUser(user);

        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setDisplayName(request.getDisplayName());

        User savedUser = userRepository.save(user);

        auditService.logAdministrativeAction(
                "USER_UPDATED",
                "User updated: " + user.getEmail(),
                beforeState,
                savedUser);

        return savedUser;
    }

    /**
     * Delete user.
     */
    public void deleteUser(UUID userId) {
        User user = getUser(userId);

        auditService.logAdministrativeAction(
                "USER_DELETED",
                "User deleted: " + user.getEmail(),
                user,
                null);

        userRepository.delete(user);
    }

    /**
     * Change user password.
     */
    public void changePassword(UUID userId, String currentPassword, String newPassword) {
        User user = getUser(userId);

        // Verify current password
        if (!passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
            throw new IllegalArgumentException("Current password is incorrect");
        }

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setPasswordChangedAt(LocalDateTime.now());
        user.setForcePasswordChange(false);

        userRepository.save(user);

        auditService.logAdministrativeAction(
                "PASSWORD_CHANGED",
                "Password changed for user: " + user.getEmail(),
                null,
                null);
    }

    /**
     * Lock user account.
     */
    public void lockUser(UUID userId, String reason) {
        User user = getUser(userId);
        user.lockAccount(reason);
        userRepository.save(user);

        auditService.logAdministrativeAction(
                "USER_LOCKED",
                "User account locked: " + user.getEmail() + " - " + reason,
                null,
                user);
    }

    /**
     * Unlock user account.
     */
    public void unlockUser(UUID userId) {
        User user = getUser(userId);
        user.unlockAccount();
        userRepository.save(user);

        auditService.logAdministrativeAction(
                "USER_UNLOCKED",
                "User account unlocked: " + user.getEmail(),
                null,
                user);
    }

    private User cloneUser(User user) {
        User clone = new User();
        clone.setId(user.getId());
        clone.setEmail(user.getEmail());
        clone.setFirstName(user.getFirstName());
        clone.setLastName(user.getLastName());
        clone.setDisplayName(user.getDisplayName());
        return clone;
    }
}