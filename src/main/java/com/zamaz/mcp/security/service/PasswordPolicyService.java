package com.zamaz.mcp.security.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * NIST 800-63B compliant password validation service.
 * Implements modern password policies with entropy checking and breach
 * detection.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordPolicyService {

    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${security.password.min-length:12}")
    private int minLength;

    @Value("${security.password.max-length:128}")
    private int maxLength;

    @Value("${security.password.breach-check.enabled:true}")
    private boolean breachCheckEnabled;

    @Value("${security.password.breach-check.api-url:https://api.pwnedpasswords.com/range/}")
    private String breachCheckApiUrl;

    // Common weak passwords and patterns
    private static final List<String> COMMON_PASSWORDS = List.of(
            "password", "123456", "password123", "admin", "qwerty", "letmein",
            "welcome", "monkey", "dragon", "master", "shadow", "superman");

    private static final Pattern REPEATED_CHARS = Pattern.compile("(.)\\1{2,}");
    private static final Pattern SEQUENTIAL_CHARS = Pattern.compile(
            "(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)");

    /**
     * Validate password against NIST 800-63B guidelines.
     */
    public PasswordValidationResult validatePassword(String password, String username, String email) {
        List<String> violations = new ArrayList<>();
        PasswordStrength strength = PasswordStrength.WEAK;

        // Length check
        if (password == null || password.length() < minLength) {
            violations.add(String.format("Password must be at least %d characters long", minLength));
        } else if (password.length() > maxLength) {
            violations.add(String.format("Password must not exceed %d characters", maxLength));
        }

        if (password != null) {
            // Check against common passwords
            if (COMMON_PASSWORDS.contains(password.toLowerCase())) {
                violations.add("Password is too common and easily guessable");
            }

            // Check for username/email in password
            if (username != null && password.toLowerCase().contains(username.toLowerCase())) {
                violations.add("Password must not contain username");
            }

            if (email != null) {
                String emailLocal = email.split("@")[0];
                if (password.toLowerCase().contains(emailLocal.toLowerCase())) {
                    violations.add("Password must not contain email address");
                }
            }

            // Check for repeated characters
            if (REPEATED_CHARS.matcher(password).find()) {
                violations.add("Password contains too many repeated characters");
            }

            // Check for sequential characters
            if (SEQUENTIAL_CHARS.matcher(password.toLowerCase()).find()) {
                violations.add("Password contains sequential characters");
            }

            // Calculate password strength
            strength = calculatePasswordStrength(password);

            // Minimum strength requirement
            if (strength == PasswordStrength.WEAK) {
                violations.add("Password is too weak - use a mix of uppercase, lowercase, numbers, and symbols");
            }

            // Check against known breaches
            if (breachCheckEnabled && violations.isEmpty()) {
                try {
                    if (isPasswordBreached(password)) {
                        violations.add("Password has been found in data breaches and must be changed");
                    }
                } catch (Exception e) {
                    log.warn("Failed to check password against breach database: {}", e.getMessage());
                }
            }
        }

        return new PasswordValidationResult(violations.isEmpty(), violations, strength);
    }

    /**
     * Calculate password strength based on entropy and composition.
     */
    private PasswordStrength calculatePasswordStrength(String password) {
        int score = 0;

        // Length scoring
        if (password.length() >= 12)
            score += 2;
        else if (password.length() >= 8)
            score += 1;

        // Character set diversity
        boolean hasLower = password.matches(".*[a-z].*");
        boolean hasUpper = password.matches(".*[A-Z].*");
        boolean hasDigit = password.matches(".*\\d.*");
        boolean hasSymbol = password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?].*");

        int charSetCount = 0;
        if (hasLower)
            charSetCount++;
        if (hasUpper)
            charSetCount++;
        if (hasDigit)
            charSetCount++;
        if (hasSymbol)
            charSetCount++;

        score += charSetCount;

        // Bonus for length
        if (password.length() >= 16)
            score += 1;
        if (password.length() >= 20)
            score += 1;

        // Penalty for common patterns
        if (password.matches(".*\\d{4,}.*"))
            score -= 1; // 4+ consecutive digits
        if (password.matches(".*[a-zA-Z]{6,}.*"))
            score -= 1; // 6+ consecutive letters

        // Determine strength
        if (score >= 7)
            return PasswordStrength.VERY_STRONG;
        if (score >= 5)
            return PasswordStrength.STRONG;
        if (score >= 3)
            return PasswordStrength.MEDIUM;
        return PasswordStrength.WEAK;
    }

    /**
     * Check if password has been found in data breaches using HaveIBeenPwned API.
     */
    private boolean isPasswordBreached(String password) {
        try {
            // Use SHA-1 hash and k-anonymity model
            String sha1Hash = org.apache.commons.codec.digest.DigestUtils.sha1Hex(password).toUpperCase();
            String prefix = sha1Hash.substring(0, 5);
            String suffix = sha1Hash.substring(5);

            String response = restTemplate.getForObject(breachCheckApiUrl + prefix, String.class);

            if (response != null) {
                return response.contains(suffix);
            }
        } catch (Exception e) {
            log.debug("Error checking password breach status: {}", e.getMessage());
        }

        return false;
    }

    /**
     * Generate password strength requirements message.
     */
    public String getPasswordRequirements() {
        return String.format(
                "Password must be %d-%d characters long and contain a mix of uppercase letters, " +
                        "lowercase letters, numbers, and symbols. Avoid common passwords, personal information, " +
                        "and repeated or sequential characters.",
                minLength, maxLength);
    }

    /**
     * Password validation result.
     */
    public static class PasswordValidationResult {
        private final boolean valid;
        private final List<String> violations;
        private final PasswordStrength strength;

        public PasswordValidationResult(boolean valid, List<String> violations, PasswordStrength strength) {
            this.valid = valid;
            this.violations = violations;
            this.strength = strength;
        }

        public boolean isValid() {
            return valid;
        }

        public List<String> getViolations() {
            return violations;
        }

        public PasswordStrength getStrength() {
            return strength;
        }
    }

    /**
     * Password strength levels.
     */
    public enum PasswordStrength {
        WEAK, MEDIUM, STRONG, VERY_STRONG
    }
}