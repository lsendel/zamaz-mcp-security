package com.zamaz.mcp.security.service;

import com.zamaz.mcp.security.entity.User;
import com.zamaz.mcp.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Account lockout service implementing progressive delay patterns to prevent
 * brute force attacks.
 * Follows security best practices for account protection.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AccountLockoutService {

    private final UserRepository userRepository;
    private final SecurityAuditService auditService;

    @Value("${security.lockout.max-attempts:5}")
    private int maxFailedAttempts;

    @Value("${security.lockout.initial-duration-minutes:5}")
    private int initialLockoutDurationMinutes;

    @Value("${security.lockout.max-duration-minutes:1440}") // 24 hours
    private int maxLockoutDurationMinutes;

    @Value("${security.lockout.progressive-multiplier:2}")
    private int progressiveMultiplier;

    /**
     * Record a failed login attempt and potentially lock the account.
     */
    @Transactional
    public LockoutResult recordFailedAttempt(UUID userId, String reason) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // Increment failed attempts
        user.incrementFailedLoginAttempts();
        user.setLastFailedLoginAt(LocalDateTime.now());

        boolean shouldLock = user.getFailedLoginAttempts() >= maxFailedAttempts;

        if (shouldLock) {
            // Calculate lockout duration with progressive delay
            int lockoutDuration = calculateLockoutDuration(user.getFailedLoginAttempts());
            LocalDateTime lockoutUntil = LocalDateTime.now().plusMinutes(lockoutDuration);

            user.lockAccountTemporarily(reason, lockoutUntil);

            log.warn("Account locked for user {} due to {} failed attempts. Locked until: {}",
                    user.getEmail(), user.getFailedLoginAttempts(), lockoutUntil);

            // Audit log
            auditService.logSecurityViolation(
                    "ACCOUNT_LOCKOUT",
                    String.format("Account locked after %d failed attempts: %s",
                            user.getFailedLoginAttempts(), reason),
                    com.zamaz.mcp.security.entity.SecurityAuditLog.RiskLevel.HIGH);
        }

        userRepository.save(user);

        return new LockoutResult(
                shouldLock,
                user.getFailedLoginAttempts(),
                maxFailedAttempts,
                shouldLock ? user.getAccountLockedUntil() : null);
    }

    /**
     * Record a successful login and reset failed attempts.
     */
    @Transactional
    public void recordSuccessfulLogin(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (user.getFailedLoginAttempts() > 0) {
            log.info("Resetting failed login attempts for user {} after successful login", user.getEmail());
            user.resetFailedLoginAttempts();
            userRepository.save(user);
        }
    }

    /**
     * Check if an account is currently locked.
     */
    public boolean isAccountLocked(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        return !user.isAccountNonLocked();
    }

    /**
     * Manually unlock an account (admin function).
     */
    @Transactional
    public void unlockAccount(UUID userId, String reason) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (user.getAccountLocked()) {
            user.unlockAccount();
            userRepository.save(user);

            log.info("Account manually unlocked for user {}: {}", user.getEmail(), reason);

            // Audit log
            auditService.logAdministrativeAction(
                    "ACCOUNT_UNLOCK",
                    String.format("Account manually unlocked for user %s: %s", user.getEmail(), reason),
                    null,
                    null);
        }
    }

    /**
     * Get lockout status for a user.
     */
    public LockoutStatus getLockoutStatus(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        boolean isLocked = !user.isAccountNonLocked();
        int remainingAttempts = Math.max(0, maxFailedAttempts - user.getFailedLoginAttempts());

        return new LockoutStatus(
                isLocked,
                user.getFailedLoginAttempts(),
                remainingAttempts,
                user.getAccountLockedUntil(),
                user.getAccountLockReason());
    }

    /**
     * Calculate progressive lockout duration.
     */
    private int calculateLockoutDuration(int failedAttempts) {
        // Progressive delay: 5min, 10min, 20min, 40min, 80min, etc.
        int duration = initialLockoutDurationMinutes;

        for (int i = maxFailedAttempts; i < failedAttempts; i++) {
            duration *= progressiveMultiplier;
            if (duration > maxLockoutDurationMinutes) {
                duration = maxLockoutDurationMinutes;
                break;
            }
        }

        return duration;
    }

    /**
     * Result of a lockout check.
     */
    public static class LockoutResult {
        private final boolean accountLocked;
        private final int failedAttempts;
        private final int maxAttempts;
        private final LocalDateTime lockedUntil;

        public LockoutResult(boolean accountLocked, int failedAttempts, int maxAttempts, LocalDateTime lockedUntil) {
            this.accountLocked = accountLocked;
            this.failedAttempts = failedAttempts;
            this.maxAttempts = maxAttempts;
            this.lockedUntil = lockedUntil;
        }

        public boolean isAccountLocked() {
            return accountLocked;
        }

        public int getFailedAttempts() {
            return failedAttempts;
        }

        public int getMaxAttempts() {
            return maxAttempts;
        }

        public int getRemainingAttempts() {
            return Math.max(0, maxAttempts - failedAttempts);
        }

        public LocalDateTime getLockedUntil() {
            return lockedUntil;
        }
    }

    /**
     * Current lockout status.
     */
    public static class LockoutStatus {
        private final boolean locked;
        private final int failedAttempts;
        private final int remainingAttempts;
        private final LocalDateTime lockedUntil;
        private final String lockReason;

        public LockoutStatus(boolean locked, int failedAttempts, int remainingAttempts,
                LocalDateTime lockedUntil, String lockReason) {
            this.locked = locked;
            this.failedAttempts = failedAttempts;
            this.remainingAttempts = remainingAttempts;
            this.lockedUntil = lockedUntil;
            this.lockReason = lockReason;
        }

        public boolean isLocked() {
            return locked;
        }

        public int getFailedAttempts() {
            return failedAttempts;
        }

        public int getRemainingAttempts() {
            return remainingAttempts;
        }

        public LocalDateTime getLockedUntil() {
            return lockedUntil;
        }

        public String getLockReason() {
            return lockReason;
        }

        public boolean isTemporaryLock() {
            return locked && lockedUntil != null && LocalDateTime.now().isBefore(lockedUntil);
        }

        public long getMinutesUntilUnlock() {
            if (!isTemporaryLock())
                return 0;
            return java.time.Duration.between(LocalDateTime.now(), lockedUntil).toMinutes();
        }
    }
}