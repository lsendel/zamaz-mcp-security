package com.zamaz.mcp.security.service;

import com.zamaz.mcp.security.entity.User;
import com.zamaz.mcp.security.entity.WebAuthnCredential;
import com.zamaz.mcp.security.repository.UserRepository;
import com.zamaz.mcp.security.repository.WebAuthnCredentialRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

/**
 * Service for managing user authentication preferences and methods.
 * Handles fallback authentication methods and preference management.
 */
@Service
public class AuthenticationPreferenceService {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationPreferenceService.class);
    
    private final UserRepository userRepository;
    private final WebAuthnCredentialRepository webAuthnCredentialRepository;
    
    public enum AuthMethod {
        PASSWORD("password"),
        WEBAUTHN("webauthn"),
        TOTP("totp"),
        SMS("sms"),
        EMAIL("email");
        
        private final String value;
        
        AuthMethod(String value) {
            this.value = value;
        }
        
        public String getValue() {
            return value;
        }
        
        public static AuthMethod fromValue(String value) {
            for (AuthMethod method : values()) {
                if (method.value.equalsIgnoreCase(value)) {
                    return method;
                }
            }
            return PASSWORD;
        }
    }
    
    public AuthenticationPreferenceService(
            UserRepository userRepository,
            WebAuthnCredentialRepository webAuthnCredentialRepository) {
        this.userRepository = userRepository;
        this.webAuthnCredentialRepository = webAuthnCredentialRepository;
    }
    
    /**
     * Get available authentication methods for a user
     */
    @Transactional(readOnly = true)
    public Map<String, Object> getAvailableAuthMethods(String username) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        boolean hasPassword = user.getPassword() != null && !user.getPassword().isEmpty();
        boolean hasWebAuthn = webAuthnCredentialRepository.countByUserId(user.getId()) > 0;
        boolean hasTOTP = user.getMfaSecret() != null && user.isMfaEnabled();
        
        String preferredMethod = user.getPreferredAuthMethod() != null 
            ? user.getPreferredAuthMethod() 
            : AuthMethod.PASSWORD.getValue();
        
        return Map.of(
            "password", hasPassword,
            "webauthn", hasWebAuthn,
            "totp", hasTOTP,
            "preferredMethod", preferredMethod,
            "webauthnCredentialCount", webAuthnCredentialRepository.countByUserId(user.getId())
        );
    }
    
    /**
     * Update user's preferred authentication method
     */
    @Transactional
    public void updatePreferredAuthMethod(String username, AuthMethod method) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        // Validate that the user has this method available
        validateAuthMethodAvailable(user, method);
        
        user.setPreferredAuthMethod(method.getValue());
        userRepository.save(user);
        
        logger.info("Updated preferred auth method for user {} to {}", username, method.getValue());
    }
    
    /**
     * Check if user can use passwordless authentication
     */
    @Transactional(readOnly = true)
    public boolean canUsePasswordless(String username) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        return webAuthnCredentialRepository.countByUserId(user.getId()) > 0;
    }
    
    /**
     * Enable WebAuthn for user
     */
    @Transactional
    public void enableWebAuthn(String username) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        user.setWebauthnEnabled(true);
        userRepository.save(user);
        
        logger.info("Enabled WebAuthn for user: {}", username);
    }
    
    /**
     * Disable WebAuthn for user
     */
    @Transactional
    public void disableWebAuthn(String username) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        // Delete all WebAuthn credentials
        webAuthnCredentialRepository.deleteByUserId(user.getId());
        
        user.setWebauthnEnabled(false);
        
        // Reset to password if WebAuthn was preferred
        if (AuthMethod.WEBAUTHN.getValue().equals(user.getPreferredAuthMethod())) {
            user.setPreferredAuthMethod(AuthMethod.PASSWORD.getValue());
        }
        
        userRepository.save(user);
        
        logger.info("Disabled WebAuthn for user: {}", username);
    }
    
    /**
     * Get fallback authentication methods
     */
    @Transactional(readOnly = true)
    public List<String> getFallbackMethods(String username) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        List<String> fallbackMethods = new java.util.ArrayList<>();
        
        // Always allow password as fallback if set
        if (user.getPassword() != null && !user.getPassword().isEmpty()) {
            fallbackMethods.add(AuthMethod.PASSWORD.getValue());
        }
        
        // TOTP as fallback
        if (user.isMfaEnabled() && user.getMfaSecret() != null) {
            fallbackMethods.add(AuthMethod.TOTP.getValue());
        }
        
        // Email OTP as ultimate fallback
        if (user.getEmail() != null && user.isEmailVerified()) {
            fallbackMethods.add(AuthMethod.EMAIL.getValue());
        }
        
        return fallbackMethods;
    }
    
    /**
     * Check if authentication method upgrade is recommended
     */
    @Transactional(readOnly = true)
    public Map<String, Object> getSecurityRecommendations(String username) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        boolean hasWebAuthn = webAuthnCredentialRepository.countByUserId(user.getId()) > 0;
        boolean hasMFA = user.isMfaEnabled();
        
        Map<String, Object> recommendations = new java.util.HashMap<>();
        
        if (!hasWebAuthn) {
            recommendations.put("webauthn", Map.of(
                "recommended", true,
                "reason", "WebAuthn provides the strongest authentication security"
            ));
        }
        
        if (!hasMFA && !hasWebAuthn) {
            recommendations.put("mfa", Map.of(
                "recommended", true,
                "reason", "Enable MFA for additional account security"
            ));
        }
        
        // Check for old WebAuthn credentials
        if (hasWebAuthn) {
            List<WebAuthnCredential> oldCredentials = webAuthnCredentialRepository
                .findInactiveCredentials(java.time.LocalDateTime.now().minusMonths(6));
            
            if (!oldCredentials.isEmpty()) {
                recommendations.put("removeOldCredentials", Map.of(
                    "recommended", true,
                    "count", oldCredentials.size(),
                    "reason", "Remove unused security keys to maintain account hygiene"
                ));
            }
        }
        
        return recommendations;
    }
    
    private void validateAuthMethodAvailable(User user, AuthMethod method) {
        switch (method) {
            case PASSWORD:
                if (user.getPassword() == null || user.getPassword().isEmpty()) {
                    throw new IllegalArgumentException("Password not set for user");
                }
                break;
            case WEBAUTHN:
                if (webAuthnCredentialRepository.countByUserId(user.getId()) == 0) {
                    throw new IllegalArgumentException("No WebAuthn credentials registered");
                }
                break;
            case TOTP:
                if (!user.isMfaEnabled() || user.getMfaSecret() == null) {
                    throw new IllegalArgumentException("MFA not enabled for user");
                }
                break;
            default:
                throw new IllegalArgumentException("Authentication method not supported: " + method);
        }
    }
}