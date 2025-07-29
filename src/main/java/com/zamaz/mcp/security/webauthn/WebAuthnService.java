package com.zamaz.mcp.security.webauthn;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.validator.exception.ValidationException;
import com.zamaz.mcp.security.entity.User;
import com.zamaz.mcp.security.entity.WebAuthnCredential;
import com.zamaz.mcp.security.repository.UserRepository;
import com.zamaz.mcp.security.repository.WebAuthnCredentialRepository;
import com.zamaz.mcp.security.service.UserManagementService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service for WebAuthn/FIDO2 passwordless authentication.
 * Handles passkey registration and authentication flows.
 */
@Service
public class WebAuthnService {
    
    private static final Logger logger = LoggerFactory.getLogger(WebAuthnService.class);
    
    private final WebAuthnCredentialRepository credentialRepository;
    private final UserRepository userRepository;
    private final UserManagementService userManagementService;
    private final RedisTemplate<String, String> redisTemplate;
    private final WebAuthnManager webAuthnManager;
    private final ObjectConverter objectConverter;
    
    @Value("${security.webauthn.rp-id:localhost}")
    private String rpId;
    
    @Value("${security.webauthn.rp-name:MCP Platform}")
    private String rpName;
    
    @Value("${security.webauthn.origin:http://localhost:3001}")
    private String origin;
    
    @Value("${security.webauthn.challenge-timeout:300}")
    private int challengeTimeoutSeconds;
    
    private final SecureRandom secureRandom = new SecureRandom();
    
    public WebAuthnService(
            WebAuthnCredentialRepository credentialRepository,
            UserRepository userRepository,
            UserManagementService userManagementService,
            RedisTemplate<String, String> redisTemplate) {
        this.credentialRepository = credentialRepository;
        this.userRepository = userRepository;
        this.userManagementService = userManagementService;
        this.redisTemplate = redisTemplate;
        this.webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();
        this.objectConverter = new ObjectConverter();
    }
    
    /**
     * Start WebAuthn registration process
     */
    @Transactional(readOnly = true)
    public WebAuthnRegistrationOptions startRegistration(String username) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        // Generate challenge
        byte[] challengeBytes = new byte[32];
        secureRandom.nextBytes(challengeBytes);
        String challenge = Base64UrlUtil.encodeToString(challengeBytes);
        
        // Store challenge in Redis with timeout
        String challengeKey = "webauthn:registration:" + username;
        redisTemplate.opsForValue().set(challengeKey, challenge, 
            Duration.ofSeconds(challengeTimeoutSeconds));
        
        // Get existing credentials to exclude
        List<WebAuthnCredential> existingCredentials = 
            credentialRepository.findByUserId(user.getId());
        
        List<PublicKeyCredentialDescriptor> excludeCredentials = 
            existingCredentials.stream()
                .map(cred -> new PublicKeyCredentialDescriptor(
                    PublicKeyCredentialType.PUBLIC_KEY,
                    Base64UrlUtil.decode(cred.getCredentialId()),
                    null
                ))
                .collect(Collectors.toList());
        
        // Build registration options
        WebAuthnRegistrationOptions options = new WebAuthnRegistrationOptions();
        options.setRp(new WebAuthnRegistrationOptions.RelyingParty(rpId, rpName));
        options.setUser(new WebAuthnRegistrationOptions.UserInfo(
            Base64UrlUtil.encodeToString(user.getId().toString().getBytes()),
            username,
            user.getEmail()
        ));
        options.setChallenge(challenge);
        options.setPubKeyCredParams(getPreferredAlgorithms());
        options.setExcludeCredentials(excludeCredentials);
        options.setAuthenticatorSelection(new WebAuthnRegistrationOptions.AuthenticatorSelection(
            null, // No specific authenticator attachment
            true, // Require resident key
            "preferred" // User verification
        ));
        options.setAttestation("none"); // Don't require attestation for privacy
        options.setTimeout(challengeTimeoutSeconds * 1000L);
        
        logger.info("Started WebAuthn registration for user: {}", username);
        
        return options;
    }
    
    /**
     * Complete WebAuthn registration process
     */
    @Transactional
    public WebAuthnCredential completeRegistration(
            String username, 
            String credentialId,
            String clientDataJSON,
            String attestationObject) {
        
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        // Retrieve and validate challenge
        String challengeKey = "webauthn:registration:" + username;
        String challengeString = redisTemplate.opsForValue().get(challengeKey);
        if (challengeString == null) {
            throw new IllegalStateException("Registration challenge expired or not found");
        }
        
        Challenge challenge = new DefaultChallenge(Base64UrlUtil.decode(challengeString));
        
        try {
            // Parse registration data
            byte[] credentialIdBytes = Base64UrlUtil.decode(credentialId);
            byte[] clientDataBytes = Base64UrlUtil.decode(clientDataJSON);
            byte[] attestationObjectBytes = Base64UrlUtil.decode(attestationObject);
            
            // Create server property
            ServerProperty serverProperty = new ServerProperty(
                new Origin(origin),
                rpId,
                challenge,
                null // No token binding
            );
            
            // Validate registration
            RegistrationData registrationData = webAuthnManager.parse(
                new RegistrationRequest(
                    attestationObjectBytes,
                    clientDataBytes
                )
            );
            
            RegistrationParameters registrationParameters = new RegistrationParameters(
                serverProperty,
                new ArrayList<>(), // No public key params restrictions
                false, // User verification not required
                true // User presence required
            );
            
            webAuthnManager.validate(registrationData, registrationParameters);
            
            // Create and save credential
            WebAuthnCredential credential = new WebAuthnCredential();
            credential.setId(UUID.randomUUID());
            credential.setUserId(user.getId());
            credential.setCredentialId(credentialId);
            credential.setPublicKey(Base64UrlUtil.encodeToString(
                registrationData.getAttestationObject().getAuthenticatorData()
                    .getAttestedCredentialData().getCredentialPublicKey().getBytes()
            ));
            credential.setSignCount(registrationData.getAttestationObject()
                .getAuthenticatorData().getSignCount());
            credential.setAaguid(Base64UrlUtil.encodeToString(
                registrationData.getAttestationObject().getAuthenticatorData()
                    .getAttestedCredentialData().getAaguid().getBytes()
            ));
            credential.setUserHandle(Base64UrlUtil.encodeToString(
                user.getId().toString().getBytes()
            ));
            credential.setCreatedAt(LocalDateTime.now());
            credential.setLastUsedAt(LocalDateTime.now());
            
            // Generate a friendly name for the credential
            String deviceName = generateDeviceName(registrationData);
            credential.setDeviceName(deviceName);
            
            credential = credentialRepository.save(credential);
            
            // Clean up challenge
            redisTemplate.delete(challengeKey);
            
            logger.info("WebAuthn registration completed for user: {} with credential: {}", 
                username, deviceName);
            
            return credential;
            
        } catch (DataConversionException | ValidationException e) {
            logger.error("WebAuthn registration validation failed", e);
            throw new IllegalArgumentException("Invalid registration data", e);
        }
    }
    
    /**
     * Start WebAuthn authentication process
     */
    @Transactional(readOnly = true)
    public WebAuthnAuthenticationOptions startAuthentication(String username) {
        // Username can be null for usernameless flow
        List<WebAuthnCredential> credentials;
        if (username != null) {
            User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
            credentials = credentialRepository.findByUserId(user.getId());
        } else {
            credentials = new ArrayList<>(); // Usernameless flow
        }
        
        // Generate challenge
        byte[] challengeBytes = new byte[32];
        secureRandom.nextBytes(challengeBytes);
        String challenge = Base64UrlUtil.encodeToString(challengeBytes);
        
        // Store challenge in Redis
        String challengeKey = "webauthn:authentication:" + 
            (username != null ? username : "usernameless:" + UUID.randomUUID());
        redisTemplate.opsForValue().set(challengeKey, challenge, 
            Duration.ofSeconds(challengeTimeoutSeconds));
        
        // Build allowed credentials
        List<PublicKeyCredentialDescriptor> allowCredentials = 
            credentials.stream()
                .map(cred -> new PublicKeyCredentialDescriptor(
                    PublicKeyCredentialType.PUBLIC_KEY,
                    Base64UrlUtil.decode(cred.getCredentialId()),
                    null
                ))
                .collect(Collectors.toList());
        
        // Build authentication options
        WebAuthnAuthenticationOptions options = new WebAuthnAuthenticationOptions();
        options.setChallenge(challenge);
        options.setRpId(rpId);
        options.setAllowCredentials(allowCredentials);
        options.setUserVerification("preferred");
        options.setTimeout(challengeTimeoutSeconds * 1000L);
        
        logger.info("Started WebAuthn authentication for user: {}", 
            username != null ? username : "usernameless");
        
        return options;
    }
    
    /**
     * Complete WebAuthn authentication process
     */
    @Transactional
    public User completeAuthentication(
            String credentialId,
            String clientDataJSON,
            String authenticatorData,
            String signature,
            String userHandle) {
        
        // Find credential
        WebAuthnCredential credential = credentialRepository.findByCredentialId(credentialId)
            .orElseThrow(() -> new IllegalArgumentException("Credential not found"));
        
        // Find user
        User user = userRepository.findById(credential.getUserId())
            .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        // Retrieve challenge
        String challengeKey = "webauthn:authentication:" + user.getUsername();
        String challengeString = redisTemplate.opsForValue().get(challengeKey);
        
        // Try usernameless challenge if not found
        if (challengeString == null && userHandle != null) {
            // Search for usernameless challenges
            challengeKey = findUsernamelessChallenge(credentialId);
            if (challengeKey != null) {
                challengeString = redisTemplate.opsForValue().get(challengeKey);
            }
        }
        
        if (challengeString == null) {
            throw new IllegalStateException("Authentication challenge expired or not found");
        }
        
        Challenge challenge = new DefaultChallenge(Base64UrlUtil.decode(challengeString));
        
        try {
            // Parse authentication data
            byte[] credentialIdBytes = Base64UrlUtil.decode(credentialId);
            byte[] clientDataBytes = Base64UrlUtil.decode(clientDataJSON);
            byte[] authenticatorDataBytes = Base64UrlUtil.decode(authenticatorData);
            byte[] signatureBytes = Base64UrlUtil.decode(signature);
            byte[] userHandleBytes = userHandle != null ? 
                Base64UrlUtil.decode(userHandle) : null;
            
            // Create authenticator
            Authenticator authenticator = new AuthenticatorImpl(
                credential.getAttestedCredentialData(),
                credential.getAttestationStatement(),
                credential.getSignCount()
            );
            
            // Create server property
            ServerProperty serverProperty = new ServerProperty(
                new Origin(origin),
                rpId,
                challenge,
                null // No token binding
            );
            
            // Validate authentication
            AuthenticationData authenticationData = webAuthnManager.parse(
                new AuthenticationRequest(
                    credentialIdBytes,
                    userHandleBytes,
                    authenticatorDataBytes,
                    clientDataBytes,
                    signatureBytes
                )
            );
            
            AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                serverProperty,
                authenticator,
                false, // User verification not required
                true // User presence required
            );
            
            webAuthnManager.validate(authenticationData, authenticationParameters);
            
            // Update credential
            credential.setSignCount(authenticationData.getAuthenticatorData().getSignCount());
            credential.setLastUsedAt(LocalDateTime.now());
            credentialRepository.save(credential);
            
            // Clean up challenge
            redisTemplate.delete(challengeKey);
            
            logger.info("WebAuthn authentication completed for user: {}", user.getUsername());
            
            return user;
            
        } catch (DataConversionException | ValidationException e) {
            logger.error("WebAuthn authentication validation failed", e);
            throw new IllegalArgumentException("Invalid authentication data", e);
        }
    }
    
    /**
     * Remove WebAuthn credential
     */
    @Transactional
    public void removeCredential(String username, String credentialId) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        WebAuthnCredential credential = credentialRepository
            .findByUserIdAndCredentialId(user.getId(), credentialId)
            .orElseThrow(() -> new IllegalArgumentException("Credential not found"));
        
        credentialRepository.delete(credential);
        
        logger.info("Removed WebAuthn credential {} for user: {}", 
            credential.getDeviceName(), username);
    }
    
    /**
     * List user's WebAuthn credentials
     */
    @Transactional(readOnly = true)
    public List<WebAuthnCredentialInfo> listUserCredentials(String username) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        return credentialRepository.findByUserId(user.getId()).stream()
            .map(cred -> new WebAuthnCredentialInfo(
                cred.getCredentialId(),
                cred.getDeviceName(),
                cred.getCreatedAt(),
                cred.getLastUsedAt()
            ))
            .collect(Collectors.toList());
    }
    
    private List<PublicKeyCredentialParameters> getPreferredAlgorithms() {
        List<PublicKeyCredentialParameters> params = new ArrayList<>();
        
        // ES256 (recommended)
        params.add(new PublicKeyCredentialParameters(
            PublicKeyCredentialType.PUBLIC_KEY,
            COSEAlgorithmIdentifier.ES256
        ));
        
        // RS256 (fallback)
        params.add(new PublicKeyCredentialParameters(
            PublicKeyCredentialType.PUBLIC_KEY,
            COSEAlgorithmIdentifier.RS256
        ));
        
        return params;
    }
    
    private String generateDeviceName(RegistrationData data) {
        // Try to determine device type from authenticator data
        String aaguid = Base64UrlUtil.encodeToString(
            data.getAttestationObject().getAuthenticatorData()
                .getAttestedCredentialData().getAaguid().getBytes()
        );
        
        // This would normally map AAGUIDs to device names
        // For now, generate a generic name
        return "Security Key " + LocalDateTime.now().toString();
    }
    
    private String findUsernamelessChallenge(String credentialId) {
        // Search for usernameless challenges in Redis
        // This is a simplified implementation
        return null;
    }
    
    /**
     * DTO classes for WebAuthn options
     */
    public static class WebAuthnRegistrationOptions {
        private RelyingParty rp;
        private UserInfo user;
        private String challenge;
        private List<PublicKeyCredentialParameters> pubKeyCredParams;
        private List<PublicKeyCredentialDescriptor> excludeCredentials;
        private AuthenticatorSelection authenticatorSelection;
        private String attestation;
        private Long timeout;
        
        // Getters and setters
        public RelyingParty getRp() { return rp; }
        public void setRp(RelyingParty rp) { this.rp = rp; }
        
        public UserInfo getUser() { return user; }
        public void setUser(UserInfo user) { this.user = user; }
        
        public String getChallenge() { return challenge; }
        public void setChallenge(String challenge) { this.challenge = challenge; }
        
        public List<PublicKeyCredentialParameters> getPubKeyCredParams() { return pubKeyCredParams; }
        public void setPubKeyCredParams(List<PublicKeyCredentialParameters> pubKeyCredParams) { 
            this.pubKeyCredParams = pubKeyCredParams; 
        }
        
        public List<PublicKeyCredentialDescriptor> getExcludeCredentials() { return excludeCredentials; }
        public void setExcludeCredentials(List<PublicKeyCredentialDescriptor> excludeCredentials) { 
            this.excludeCredentials = excludeCredentials; 
        }
        
        public AuthenticatorSelection getAuthenticatorSelection() { return authenticatorSelection; }
        public void setAuthenticatorSelection(AuthenticatorSelection authenticatorSelection) { 
            this.authenticatorSelection = authenticatorSelection; 
        }
        
        public String getAttestation() { return attestation; }
        public void setAttestation(String attestation) { this.attestation = attestation; }
        
        public Long getTimeout() { return timeout; }
        public void setTimeout(Long timeout) { this.timeout = timeout; }
        
        public static class RelyingParty {
            private String id;
            private String name;
            
            public RelyingParty(String id, String name) {
                this.id = id;
                this.name = name;
            }
            
            public String getId() { return id; }
            public String getName() { return name; }
        }
        
        public static class UserInfo {
            private String id;
            private String name;
            private String displayName;
            
            public UserInfo(String id, String name, String displayName) {
                this.id = id;
                this.name = name;
                this.displayName = displayName;
            }
            
            public String getId() { return id; }
            public String getName() { return name; }
            public String getDisplayName() { return displayName; }
        }
        
        public static class AuthenticatorSelection {
            private String authenticatorAttachment;
            private boolean requireResidentKey;
            private String userVerification;
            
            public AuthenticatorSelection(String authenticatorAttachment, 
                                        boolean requireResidentKey, 
                                        String userVerification) {
                this.authenticatorAttachment = authenticatorAttachment;
                this.requireResidentKey = requireResidentKey;
                this.userVerification = userVerification;
            }
            
            public String getAuthenticatorAttachment() { return authenticatorAttachment; }
            public boolean isRequireResidentKey() { return requireResidentKey; }
            public String getUserVerification() { return userVerification; }
        }
    }
    
    public static class WebAuthnAuthenticationOptions {
        private String challenge;
        private String rpId;
        private List<PublicKeyCredentialDescriptor> allowCredentials;
        private String userVerification;
        private Long timeout;
        
        // Getters and setters
        public String getChallenge() { return challenge; }
        public void setChallenge(String challenge) { this.challenge = challenge; }
        
        public String getRpId() { return rpId; }
        public void setRpId(String rpId) { this.rpId = rpId; }
        
        public List<PublicKeyCredentialDescriptor> getAllowCredentials() { return allowCredentials; }
        public void setAllowCredentials(List<PublicKeyCredentialDescriptor> allowCredentials) { 
            this.allowCredentials = allowCredentials; 
        }
        
        public String getUserVerification() { return userVerification; }
        public void setUserVerification(String userVerification) { this.userVerification = userVerification; }
        
        public Long getTimeout() { return timeout; }
        public void setTimeout(Long timeout) { this.timeout = timeout; }
    }
    
    public static class WebAuthnCredentialInfo {
        private String credentialId;
        private String deviceName;
        private LocalDateTime createdAt;
        private LocalDateTime lastUsedAt;
        
        public WebAuthnCredentialInfo(String credentialId, String deviceName, 
                                    LocalDateTime createdAt, LocalDateTime lastUsedAt) {
            this.credentialId = credentialId;
            this.deviceName = deviceName;
            this.createdAt = createdAt;
            this.lastUsedAt = lastUsedAt;
        }
        
        // Getters
        public String getCredentialId() { return credentialId; }
        public String getDeviceName() { return deviceName; }
        public LocalDateTime getCreatedAt() { return createdAt; }
        public LocalDateTime getLastUsedAt() { return lastUsedAt; }
    }
}