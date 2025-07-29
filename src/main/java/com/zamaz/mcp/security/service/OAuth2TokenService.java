package com.zamaz.mcp.security.service;

import com.zamaz.mcp.security.entity.OAuth2Client;
import com.zamaz.mcp.security.entity.User;
import com.zamaz.mcp.security.exception.OAuth2Exception;
import com.zamaz.mcp.security.model.*;
import com.zamaz.mcp.security.repository.OAuth2ClientRepository;
import com.zamaz.mcp.security.repository.UserRepository;
import com.zamaz.mcp.security.audit.SecurityAuditService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Service for OAuth2 token operations including client credentials flow and PKCE support.
 * Handles token generation, validation, and revocation for various OAuth2 flows.
 */
@Service
@Transactional
public class OAuth2TokenService {
    
    private static final Logger logger = LoggerFactory.getLogger(OAuth2TokenService.class);
    
    // PKCE constants
    private static final int PKCE_CODE_VERIFIER_MIN_LENGTH = 43;
    private static final int PKCE_CODE_VERIFIER_MAX_LENGTH = 128;
    private static final String PKCE_CHALLENGE_METHOD_S256 = "S256";
    private static final String PKCE_CHALLENGE_METHOD_PLAIN = "plain";
    
    // Token type constants
    private static final String TOKEN_TYPE_BEARER = "Bearer";
    private static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    private static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
    private static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
    
    @Autowired
    private OAuth2ClientRepository clientRepository;
    
    @Autowired
    private OAuth2ClientService clientService;
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private SecurityAuditService auditService;
    
    @Value("${security.jwt.secret:default-secret-key-change-in-production}")
    private String jwtSecret;
    
    @Value("${security.jwt.issuer:http://localhost:9000}")
    private String jwtIssuer;
    
    // In-memory storage for authorization codes (should be replaced with Redis in production)
    private final Map<String, AuthorizationCode> authorizationCodes = new ConcurrentHashMap<>();
    
    // In-memory storage for refresh tokens (should be replaced with Redis in production)
    private final Map<String, RefreshTokenData> refreshTokens = new ConcurrentHashMap<>();
    
    /**
     * Process token request based on grant type
     */
    public OAuth2TokenResponse processTokenRequest(OAuth2TokenRequest request) {
        logger.info("Processing token request for grant type: {}", request.getGrantType());
        
        return switch (request.getGrantType()) {
            case GRANT_TYPE_CLIENT_CREDENTIALS -> processClientCredentialsGrant(request);
            case GRANT_TYPE_AUTHORIZATION_CODE -> processAuthorizationCodeGrant(request);
            case GRANT_TYPE_REFRESH_TOKEN -> processRefreshTokenGrant(request);
            default -> throw new OAuth2Exception("unsupported_grant_type", 
                "Grant type not supported: " + request.getGrantType());
        };
    }
    
    /**
     * Process client credentials grant for service-to-service authentication
     */
    private OAuth2TokenResponse processClientCredentialsGrant(OAuth2TokenRequest request) {
        // Validate client credentials
        OAuth2Client client = validateClientCredentials(request.getClientId(), request.getClientSecret());
        
        // Verify client supports client credentials grant
        if (!client.supportsGrantType(OAuth2Client.GrantType.CLIENT_CREDENTIALS)) {
            throw new OAuth2Exception("unauthorized_client", 
                "Client is not authorized for client credentials grant");
        }
        
        // Parse requested scopes
        Set<String> requestedScopes = parseScopes(request.getScope());
        Set<String> grantedScopes = validateAndFilterScopes(client, requestedScopes);
        
        // Generate access token for client
        String accessToken = generateClientAccessToken(client, grantedScopes);
        
        // Client credentials flow doesn't issue refresh tokens
        OAuth2TokenResponse response = new OAuth2TokenResponse();
        response.setAccessToken(accessToken);
        response.setTokenType(TOKEN_TYPE_BEARER);
        response.setExpiresIn(client.getAccessTokenValidity());
        response.setScope(String.join(" ", grantedScopes));
        
        // Audit log
        auditService.logResourceAccess("oauth2_token", "client_credentials", client.getClientId(), true);
        
        logger.info("Issued client credentials token for client: {}", client.getClientId());
        
        return response;
    }
    
    /**
     * Process authorization code grant with PKCE support
     */
    private OAuth2TokenResponse processAuthorizationCodeGrant(OAuth2TokenRequest request) {
        if (request.getCode() == null) {
            throw new OAuth2Exception("invalid_request", "Authorization code is required");
        }
        
        if (request.getRedirectUri() == null) {
            throw new OAuth2Exception("invalid_request", "Redirect URI is required");
        }
        
        // Retrieve and validate authorization code
        AuthorizationCode authCode = authorizationCodes.remove(request.getCode());
        if (authCode == null) {
            throw new OAuth2Exception("invalid_grant", "Invalid or expired authorization code");
        }
        
        // Validate code hasn't expired
        if (authCode.getExpiresAt().isBefore(Instant.now())) {
            throw new OAuth2Exception("invalid_grant", "Authorization code has expired");
        }
        
        // Validate client
        OAuth2Client client = validateClient(request.getClientId());
        
        // Validate redirect URI matches
        if (!request.getRedirectUri().equals(authCode.getRedirectUri())) {
            throw new OAuth2Exception("invalid_grant", "Redirect URI mismatch");
        }
        
        // Validate PKCE if required
        if (client.requiresPkce() || authCode.getCodeChallenge() != null) {
            validatePkce(authCode, request.getCodeVerifier());
        }
        
        // Generate tokens
        User user = userRepository.findById(authCode.getUserId())
            .orElseThrow(() -> new OAuth2Exception("invalid_grant", "User not found"));
        
        String accessToken = generateUserAccessToken(user, client, authCode.getScopes());
        String refreshToken = null;
        
        if (client.supportsGrantType(OAuth2Client.GrantType.REFRESH_TOKEN)) {
            refreshToken = generateRefreshToken(user, client, authCode.getScopes());
        }
        
        // Build response
        OAuth2TokenResponse response = new OAuth2TokenResponse();
        response.setAccessToken(accessToken);
        response.setTokenType(TOKEN_TYPE_BEARER);
        response.setExpiresIn(client.getAccessTokenValidity());
        response.setRefreshToken(refreshToken);
        response.setScope(String.join(" ", authCode.getScopes()));
        
        // Include ID token for OpenID Connect
        if (authCode.getScopes().contains("openid")) {
            response.setIdToken(generateIdToken(user, client, authCode.getNonce()));
        }
        
        // Audit log
        auditService.logResourceAccess("oauth2_token", "authorization_code", client.getClientId(), true);
        
        logger.info("Issued authorization code token for user: {} and client: {}", 
            user.getEmail(), client.getClientId());
        
        return response;
    }
    
    /**
     * Process refresh token grant
     */
    private OAuth2TokenResponse processRefreshTokenGrant(OAuth2TokenRequest request) {
        if (request.getRefreshToken() == null) {
            throw new OAuth2Exception("invalid_request", "Refresh token is required");
        }
        
        // Validate refresh token
        RefreshTokenData tokenData = refreshTokens.get(request.getRefreshToken());
        if (tokenData == null) {
            throw new OAuth2Exception("invalid_grant", "Invalid refresh token");
        }
        
        // Validate token hasn't expired
        if (tokenData.getExpiresAt().isBefore(Instant.now())) {
            refreshTokens.remove(request.getRefreshToken());
            throw new OAuth2Exception("invalid_grant", "Refresh token has expired");
        }
        
        // Validate client
        OAuth2Client client = validateClient(request.getClientId());
        if (!tokenData.getClientId().equals(client.getClientId())) {
            throw new OAuth2Exception("invalid_grant", "Refresh token was issued to a different client");
        }
        
        // Load user
        User user = userRepository.findById(tokenData.getUserId())
            .orElseThrow(() -> new OAuth2Exception("invalid_grant", "User not found"));
        
        // Generate new access token
        String accessToken = generateUserAccessToken(user, client, tokenData.getScopes());
        
        // Optionally rotate refresh token
        String newRefreshToken = request.getRefreshToken();
        if (shouldRotateRefreshToken()) {
            refreshTokens.remove(request.getRefreshToken());
            newRefreshToken = generateRefreshToken(user, client, tokenData.getScopes());
        }
        
        // Build response
        OAuth2TokenResponse response = new OAuth2TokenResponse();
        response.setAccessToken(accessToken);
        response.setTokenType(TOKEN_TYPE_BEARER);
        response.setExpiresIn(client.getAccessTokenValidity());
        response.setRefreshToken(newRefreshToken);
        response.setScope(String.join(" ", tokenData.getScopes()));
        
        // Audit log
        auditService.logResourceAccess("oauth2_token", "refresh_token", client.getClientId(), true);
        
        logger.info("Refreshed token for user: {} and client: {}", user.getEmail(), client.getClientId());
        
        return response;
    }
    
    /**
     * Generate authorization code with PKCE support
     */
    public String generateAuthorizationCode(UUID userId, String clientId, String redirectUri, 
                                          Set<String> scopes, String codeChallenge, 
                                          String codeChallengeMethod, String nonce) {
        String code = generateSecureRandomString(32);
        
        AuthorizationCode authCode = new AuthorizationCode();
        authCode.setCode(code);
        authCode.setUserId(userId);
        authCode.setClientId(clientId);
        authCode.setRedirectUri(redirectUri);
        authCode.setScopes(scopes);
        authCode.setCodeChallenge(codeChallenge);
        authCode.setCodeChallengeMethod(codeChallengeMethod);
        authCode.setNonce(nonce);
        authCode.setExpiresAt(Instant.now().plus(10, ChronoUnit.MINUTES));
        
        authorizationCodes.put(code, authCode);
        
        // Audit log
        auditService.logResourceAccess("oauth2_authorization_code", "generate", clientId, true);
        
        logger.info("Generated authorization code for user: {} and client: {}", userId, clientId);
        
        return code;
    }
    
    /**
     * Validate client credentials
     */
    private OAuth2Client validateClientCredentials(String clientId, String clientSecret) {
        if (clientId == null || clientSecret == null) {
            throw new OAuth2Exception("invalid_client", "Client credentials are required");
        }
        
        OAuth2Client client = clientRepository.findByClientIdAndActiveTrue(clientId)
            .orElseThrow(() -> new OAuth2Exception("invalid_client", "Invalid client credentials"));
        
        if (client.getClientType() != OAuth2Client.ClientType.CONFIDENTIAL) {
            throw new OAuth2Exception("invalid_client", 
                "Client credentials grant requires a confidential client");
        }
        
        if (!passwordEncoder.matches(clientSecret, client.getClientSecret())) {
            throw new OAuth2Exception("invalid_client", "Invalid client credentials");
        }
        
        return client;
    }
    
    /**
     * Validate client
     */
    private OAuth2Client validateClient(String clientId) {
        if (clientId == null) {
            throw new OAuth2Exception("invalid_client", "Client ID is required");
        }
        
        return clientRepository.findByClientIdAndActiveTrue(clientId)
            .orElseThrow(() -> new OAuth2Exception("invalid_client", "Invalid client"));
    }
    
    /**
     * Validate PKCE code verifier
     */
    private void validatePkce(AuthorizationCode authCode, String codeVerifier) {
        if (authCode.getCodeChallenge() == null) {
            return; // PKCE not used for this authorization
        }
        
        if (codeVerifier == null) {
            throw new OAuth2Exception("invalid_grant", "Code verifier is required for PKCE");
        }
        
        // Validate code verifier length
        if (codeVerifier.length() < PKCE_CODE_VERIFIER_MIN_LENGTH || 
            codeVerifier.length() > PKCE_CODE_VERIFIER_MAX_LENGTH) {
            throw new OAuth2Exception("invalid_grant", "Invalid code verifier length");
        }
        
        // Calculate challenge from verifier
        String calculatedChallenge;
        if (PKCE_CHALLENGE_METHOD_S256.equals(authCode.getCodeChallengeMethod())) {
            calculatedChallenge = calculateS256CodeChallenge(codeVerifier);
        } else if (PKCE_CHALLENGE_METHOD_PLAIN.equals(authCode.getCodeChallengeMethod())) {
            calculatedChallenge = codeVerifier;
        } else {
            throw new OAuth2Exception("invalid_grant", "Unsupported code challenge method");
        }
        
        // Compare with stored challenge
        if (!calculatedChallenge.equals(authCode.getCodeChallenge())) {
            throw new OAuth2Exception("invalid_grant", "Invalid code verifier");
        }
    }
    
    /**
     * Calculate S256 code challenge for PKCE
     */
    private String calculateS256CodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
    
    /**
     * Generate access token for client (service-to-service)
     */
    private String generateClientAccessToken(OAuth2Client client, Set<String> scopes) {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(client.getAccessTokenValidity());
        
        return Jwts.builder()
            .setIssuer(jwtIssuer)
            .setSubject(client.getClientId())
            .setAudience("mcp-services")
            .setIssuedAt(Date.from(now))
            .setExpiration(Date.from(expiry))
            .claim("client_id", client.getClientId())
            .claim("scope", String.join(" ", scopes))
            .claim("token_type", "client_credentials")
            .claim("organization_id", client.getOrganizationId())
            .signWith(key, SignatureAlgorithm.HS256)
            .compact();
    }
    
    /**
     * Generate access token for user
     */
    private String generateUserAccessToken(User user, OAuth2Client client, Set<String> scopes) {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(client.getAccessTokenValidity());
        
        // Get user roles and permissions
        Set<String> authorities = user.getUserRoles().stream()
            .map(ur -> "ROLE_" + ur.getRole().getName())
            .collect(Collectors.toSet());
        
        return Jwts.builder()
            .setIssuer(jwtIssuer)
            .setSubject(user.getId().toString())
            .setAudience("mcp-services")
            .setIssuedAt(Date.from(now))
            .setExpiration(Date.from(expiry))
            .claim("email", user.getEmail())
            .claim("client_id", client.getClientId())
            .claim("scope", String.join(" ", scopes))
            .claim("authorities", authorities)
            .claim("organization_id", extractUserOrganization(user))
            .signWith(key, SignatureAlgorithm.HS256)
            .compact();
    }
    
    /**
     * Generate refresh token
     */
    private String generateRefreshToken(User user, OAuth2Client client, Set<String> scopes) {
        String refreshToken = generateSecureRandomString(48);
        
        RefreshTokenData tokenData = new RefreshTokenData();
        tokenData.setToken(refreshToken);
        tokenData.setUserId(user.getId());
        tokenData.setClientId(client.getClientId());
        tokenData.setScopes(scopes);
        tokenData.setExpiresAt(Instant.now().plusSeconds(client.getRefreshTokenValidity()));
        
        refreshTokens.put(refreshToken, tokenData);
        
        return refreshToken;
    }
    
    /**
     * Generate ID token for OpenID Connect
     */
    private String generateIdToken(User user, OAuth2Client client, String nonce) {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(client.getAccessTokenValidity());
        
        var builder = Jwts.builder()
            .setIssuer(jwtIssuer)
            .setSubject(user.getId().toString())
            .setAudience(client.getClientId())
            .setIssuedAt(Date.from(now))
            .setExpiration(Date.from(expiry))
            .claim("email", user.getEmail())
            .claim("email_verified", user.getEmailVerified())
            .claim("name", user.getFirstName() + " " + user.getLastName());
        
        if (nonce != null) {
            builder.claim("nonce", nonce);
        }
        
        return builder.signWith(key, SignatureAlgorithm.HS256).compact();
    }
    
    /**
     * Parse scope string into set
     */
    private Set<String> parseScopes(String scopeString) {
        if (scopeString == null || scopeString.trim().isEmpty()) {
            return new HashSet<>();
        }
        return new HashSet<>(Arrays.asList(scopeString.split("\\s+")));
    }
    
    /**
     * Validate and filter requested scopes
     */
    private Set<String> validateAndFilterScopes(OAuth2Client client, Set<String> requestedScopes) {
        if (requestedScopes.isEmpty()) {
            return client.getScopes(); // Return all client scopes if none requested
        }
        
        // Filter to only scopes the client is authorized for
        return requestedScopes.stream()
            .filter(client::supportsScope)
            .collect(Collectors.toSet());
    }
    
    /**
     * Generate secure random string
     */
    private String generateSecureRandomString(int length) {
        byte[] bytes = new byte[length];
        new java.security.SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    
    /**
     * Extract user's organization
     */
    private String extractUserOrganization(User user) {
        // This would typically come from user's organization membership
        // For now, return a default value
        return user.getUserRoles().stream()
            .map(ur -> ur.getOrganizationId())
            .filter(Objects::nonNull)
            .findFirst()
            .orElse("default");
    }
    
    /**
     * Check if refresh token should be rotated
     */
    private boolean shouldRotateRefreshToken() {
        // Can be configured based on security requirements
        return true;
    }
    
    /**
     * Revoke tokens for a client
     */
    public void revokeClientTokens(String clientId) {
        // Remove all authorization codes for client
        authorizationCodes.entrySet().removeIf(entry -> 
            entry.getValue().getClientId().equals(clientId));
        
        // Remove all refresh tokens for client
        refreshTokens.entrySet().removeIf(entry -> 
            entry.getValue().getClientId().equals(clientId));
        
        logger.info("Revoked all tokens for client: {}", clientId);
    }
    
    /**
     * Inner class for authorization code data
     */
    private static class AuthorizationCode {
        private String code;
        private UUID userId;
        private String clientId;
        private String redirectUri;
        private Set<String> scopes;
        private String codeChallenge;
        private String codeChallengeMethod;
        private String nonce;
        private Instant expiresAt;
        
        // Getters and setters
        public String getCode() { return code; }
        public void setCode(String code) { this.code = code; }
        public UUID getUserId() { return userId; }
        public void setUserId(UUID userId) { this.userId = userId; }
        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }
        public String getRedirectUri() { return redirectUri; }
        public void setRedirectUri(String redirectUri) { this.redirectUri = redirectUri; }
        public Set<String> getScopes() { return scopes; }
        public void setScopes(Set<String> scopes) { this.scopes = scopes; }
        public String getCodeChallenge() { return codeChallenge; }
        public void setCodeChallenge(String codeChallenge) { this.codeChallenge = codeChallenge; }
        public String getCodeChallengeMethod() { return codeChallengeMethod; }
        public void setCodeChallengeMethod(String codeChallengeMethod) { 
            this.codeChallengeMethod = codeChallengeMethod; 
        }
        public String getNonce() { return nonce; }
        public void setNonce(String nonce) { this.nonce = nonce; }
        public Instant getExpiresAt() { return expiresAt; }
        public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    }
    
    /**
     * Inner class for refresh token data
     */
    private static class RefreshTokenData {
        private String token;
        private UUID userId;
        private String clientId;
        private Set<String> scopes;
        private Instant expiresAt;
        
        // Getters and setters
        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
        public UUID getUserId() { return userId; }
        public void setUserId(UUID userId) { this.userId = userId; }
        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }
        public Set<String> getScopes() { return scopes; }
        public void setScopes(Set<String> scopes) { this.scopes = scopes; }
        public Instant getExpiresAt() { return expiresAt; }
        public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    }
}