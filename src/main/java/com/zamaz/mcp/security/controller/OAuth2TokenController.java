package com.zamaz.mcp.security.controller;

import com.zamaz.mcp.security.exception.OAuth2Exception;
import com.zamaz.mcp.security.model.OAuth2TokenRequest;
import com.zamaz.mcp.security.model.OAuth2TokenResponse;
import com.zamaz.mcp.security.service.OAuth2TokenService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * OAuth2 token endpoint controller.
 * Implements RFC 6749 compliant token endpoint for various grant types.
 */
@RestController
@RequestMapping("/oauth2")
@Tag(name = "OAuth2 Token Endpoint", description = "OAuth2 token issuance and management")
public class OAuth2TokenController {
    
    private static final Logger logger = LoggerFactory.getLogger(OAuth2TokenController.class);
    
    @Autowired
    private OAuth2TokenService tokenService;
    
    /**
     * Token endpoint - supports multiple grant types
     */
    @PostMapping(value = "/token", 
                consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "OAuth2 token endpoint", 
               description = "Issues access tokens for various grant types including " +
                           "authorization_code, client_credentials, and refresh_token")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Token issued successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid request or grant"),
        @ApiResponse(responseCode = "401", description = "Invalid client credentials")
    })
    public ResponseEntity<OAuth2TokenResponse> issueToken(
            @RequestParam MultiValueMap<String, String> parameters,
            HttpServletRequest request) {
        
        try {
            // Convert form parameters to token request
            OAuth2TokenRequest tokenRequest = mapToTokenRequest(parameters);
            
            // Extract client credentials from Authorization header if present
            extractClientCredentialsFromHeader(request, tokenRequest);
            
            logger.info("Processing token request for grant type: {}", tokenRequest.getGrantType());
            
            // Process token request
            OAuth2TokenResponse response = tokenService.processTokenRequest(tokenRequest);
            
            return ResponseEntity.ok(response);
            
        } catch (OAuth2Exception e) {
            logger.error("OAuth2 error: {} - {}", e.getError(), e.getErrorDescription());
            
            OAuth2TokenResponse errorResponse = OAuth2TokenResponse.error(
                e.getError(), e.getErrorDescription());
            errorResponse.setErrorUri(e.getErrorUri());
            
            return ResponseEntity.status(e.getHttpStatus()).body(errorResponse);
            
        } catch (Exception e) {
            logger.error("Unexpected error processing token request", e);
            
            OAuth2TokenResponse errorResponse = OAuth2TokenResponse.error(
                "server_error", "An unexpected error occurred");
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }
    
    /**
     * Token endpoint with JSON body (alternative for testing)
     */
    @PostMapping(value = "/token/json", 
                consumes = MediaType.APPLICATION_JSON_VALUE,
                produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "OAuth2 token endpoint (JSON)", 
               description = "Alternative token endpoint accepting JSON body for testing")
    public ResponseEntity<OAuth2TokenResponse> issueTokenJson(
            @Valid @RequestBody OAuth2TokenRequest tokenRequest,
            HttpServletRequest request) {
        
        try {
            // Extract client credentials from Authorization header if present
            extractClientCredentialsFromHeader(request, tokenRequest);
            
            logger.info("Processing token request (JSON) for grant type: {}", 
                tokenRequest.getGrantType());
            
            // Process token request
            OAuth2TokenResponse response = tokenService.processTokenRequest(tokenRequest);
            
            return ResponseEntity.ok(response);
            
        } catch (OAuth2Exception e) {
            logger.error("OAuth2 error: {} - {}", e.getError(), e.getErrorDescription());
            
            OAuth2TokenResponse errorResponse = OAuth2TokenResponse.error(
                e.getError(), e.getErrorDescription());
            errorResponse.setErrorUri(e.getErrorUri());
            
            return ResponseEntity.status(e.getHttpStatus()).body(errorResponse);
            
        } catch (Exception e) {
            logger.error("Unexpected error processing token request", e);
            
            OAuth2TokenResponse errorResponse = OAuth2TokenResponse.error(
                "server_error", "An unexpected error occurred");
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }
    
    /**
     * Token revocation endpoint
     */
    @PostMapping(value = "/revoke",
                consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @Operation(summary = "Revoke token", 
               description = "Revokes an access or refresh token")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Token revoked successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid request"),
        @ApiResponse(responseCode = "401", description = "Invalid client credentials")
    })
    public ResponseEntity<Void> revokeToken(
            @RequestParam("token") String token,
            @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint,
            HttpServletRequest request) {
        
        logger.info("Token revocation request received");
        
        // TODO: Implement token revocation
        // For now, return success
        
        return ResponseEntity.ok().build();
    }
    
    /**
     * Token introspection endpoint
     */
    @PostMapping(value = "/introspect",
                consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Introspect token", 
               description = "Returns metadata about a token")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Token metadata returned"),
        @ApiResponse(responseCode = "401", description = "Invalid client credentials")
    })
    public ResponseEntity<TokenIntrospectionResponse> introspectToken(
            @RequestParam("token") String token,
            @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint,
            HttpServletRequest request) {
        
        logger.info("Token introspection request received");
        
        // TODO: Implement token introspection
        // For now, return a basic response
        
        TokenIntrospectionResponse response = new TokenIntrospectionResponse();
        response.setActive(false);
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Map form parameters to token request
     */
    private OAuth2TokenRequest mapToTokenRequest(MultiValueMap<String, String> parameters) {
        OAuth2TokenRequest request = new OAuth2TokenRequest();
        
        request.setGrantType(parameters.getFirst("grant_type"));
        request.setClientId(parameters.getFirst("client_id"));
        request.setClientSecret(parameters.getFirst("client_secret"));
        request.setCode(parameters.getFirst("code"));
        request.setRedirectUri(parameters.getFirst("redirect_uri"));
        request.setCodeVerifier(parameters.getFirst("code_verifier"));
        request.setRefreshToken(parameters.getFirst("refresh_token"));
        request.setScope(parameters.getFirst("scope"));
        request.setUsername(parameters.getFirst("username"));
        request.setPassword(parameters.getFirst("password"));
        
        return request;
    }
    
    /**
     * Extract client credentials from Authorization header
     */
    private void extractClientCredentialsFromHeader(HttpServletRequest request, 
                                                   OAuth2TokenRequest tokenRequest) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        
        if (authHeader != null && authHeader.startsWith("Basic ")) {
            String credentials = authHeader.substring(6);
            byte[] decodedBytes = Base64.getDecoder().decode(credentials);
            String decodedCredentials = new String(decodedBytes, StandardCharsets.UTF_8);
            
            String[] parts = decodedCredentials.split(":", 2);
            if (parts.length == 2) {
                if (tokenRequest.getClientId() == null) {
                    tokenRequest.setClientId(parts[0]);
                }
                if (tokenRequest.getClientSecret() == null) {
                    tokenRequest.setClientSecret(parts[1]);
                }
            }
        }
    }
    
    /**
     * Token introspection response
     */
    public static class TokenIntrospectionResponse {
        private boolean active;
        private String scope;
        private String clientId;
        private String username;
        private String tokenType;
        private Long exp;
        private Long iat;
        private Long nbf;
        private String sub;
        private String aud;
        private String iss;
        private String jti;
        
        // Getters and setters
        public boolean isActive() { return active; }
        public void setActive(boolean active) { this.active = active; }
        
        public String getScope() { return scope; }
        public void setScope(String scope) { this.scope = scope; }
        
        @JsonProperty("client_id")
        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }
        
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        
        @JsonProperty("token_type")
        public String getTokenType() { return tokenType; }
        public void setTokenType(String tokenType) { this.tokenType = tokenType; }
        
        public Long getExp() { return exp; }
        public void setExp(Long exp) { this.exp = exp; }
        
        public Long getIat() { return iat; }
        public void setIat(Long iat) { this.iat = iat; }
        
        public Long getNbf() { return nbf; }
        public void setNbf(Long nbf) { this.nbf = nbf; }
        
        public String getSub() { return sub; }
        public void setSub(String sub) { this.sub = sub; }
        
        public String getAud() { return aud; }
        public void setAud(String aud) { this.aud = aud; }
        
        public String getIss() { return iss; }
        public void setIss(String iss) { this.iss = iss; }
        
        public String getJti() { return jti; }
        public void setJti(String jti) { this.jti = jti; }
    }
}