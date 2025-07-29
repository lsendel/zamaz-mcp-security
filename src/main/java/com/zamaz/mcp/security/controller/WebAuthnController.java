package com.zamaz.mcp.security.controller;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.zamaz.mcp.common.response.ApiResponse;
import com.zamaz.mcp.security.webauthn.WebAuthnService;
import com.zamaz.mcp.security.entity.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * REST controller for WebAuthn/FIDO2 passwordless authentication.
 */
@RestController
@RequestMapping("/api/v1/auth/webauthn")
@Tag(name = "WebAuthn", description = "WebAuthn passwordless authentication endpoints")
public class WebAuthnController {
    
    private static final Logger logger = LoggerFactory.getLogger(WebAuthnController.class);
    
    private final WebAuthnService webAuthnService;
    
    public WebAuthnController(WebAuthnService webAuthnService) {
        this.webAuthnService = webAuthnService;
    }
    
    /**
     * Start WebAuthn registration for authenticated user
     */
    @PostMapping("/register/start")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Start WebAuthn registration",
              description = "Initiate WebAuthn credential registration for the current user",
              security = @SecurityRequirement(name = "bearer-auth"))
    public ResponseEntity<ApiResponse<WebAuthnService.WebAuthnRegistrationOptions>> startRegistration(
            @AuthenticationPrincipal UserDetails userDetails) {
        
        logger.info("Starting WebAuthn registration for user: {}", userDetails.getUsername());
        
        WebAuthnService.WebAuthnRegistrationOptions options = 
            webAuthnService.startRegistration(userDetails.getUsername());
        
        return ResponseEntity.ok(ApiResponse.success(options));
    }
    
    /**
     * Complete WebAuthn registration
     */
    @PostMapping("/register/complete")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Complete WebAuthn registration",
              description = "Complete WebAuthn credential registration with attestation",
              security = @SecurityRequirement(name = "bearer-auth"))
    public ResponseEntity<ApiResponse<Map<String, Object>>> completeRegistration(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody RegistrationRequest request) {
        
        logger.info("Completing WebAuthn registration for user: {}", userDetails.getUsername());
        
        var credential = webAuthnService.completeRegistration(
            userDetails.getUsername(),
            request.getCredentialId(),
            request.getClientDataJSON(),
            request.getAttestationObject()
        );
        
        Map<String, Object> response = Map.of(
            "credentialId", credential.getCredentialId(),
            "deviceName", credential.getDeviceName(),
            "createdAt", credential.getCreatedAt()
        );
        
        return ResponseEntity.ok(ApiResponse.success(response));
    }
    
    /**
     * Start WebAuthn authentication
     */
    @PostMapping("/authenticate/start")
    @Operation(summary = "Start WebAuthn authentication",
              description = "Initiate WebAuthn authentication flow")
    public ResponseEntity<ApiResponse<WebAuthnService.WebAuthnAuthenticationOptions>> startAuthentication(
            @Valid @RequestBody AuthenticationStartRequest request) {
        
        logger.info("Starting WebAuthn authentication for user: {}", 
            request.getUsername() != null ? request.getUsername() : "usernameless");
        
        WebAuthnService.WebAuthnAuthenticationOptions options = 
            webAuthnService.startAuthentication(request.getUsername());
        
        return ResponseEntity.ok(ApiResponse.success(options));
    }
    
    /**
     * Complete WebAuthn authentication
     */
    @PostMapping("/authenticate/complete")
    @Operation(summary = "Complete WebAuthn authentication",
              description = "Complete WebAuthn authentication and receive JWT token")
    public ResponseEntity<ApiResponse<Map<String, Object>>> completeAuthentication(
            @Valid @RequestBody AuthenticationRequest request) {
        
        logger.info("Completing WebAuthn authentication");
        
        User user = webAuthnService.completeAuthentication(
            request.getCredentialId(),
            request.getClientDataJSON(),
            request.getAuthenticatorData(),
            request.getSignature(),
            request.getUserHandle()
        );
        
        // Generate JWT token (would be done by auth service)
        Map<String, Object> response = Map.of(
            "username", user.getUsername(),
            "userId", user.getId(),
            "message", "Authentication successful. JWT token would be generated here."
        );
        
        return ResponseEntity.ok(ApiResponse.success(response));
    }
    
    /**
     * List user's WebAuthn credentials
     */
    @GetMapping("/credentials")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "List WebAuthn credentials",
              description = "Get list of registered WebAuthn credentials for the current user",
              security = @SecurityRequirement(name = "bearer-auth"))
    public ResponseEntity<ApiResponse<List<WebAuthnService.WebAuthnCredentialInfo>>> listCredentials(
            @AuthenticationPrincipal UserDetails userDetails) {
        
        logger.info("Listing WebAuthn credentials for user: {}", userDetails.getUsername());
        
        List<WebAuthnService.WebAuthnCredentialInfo> credentials = 
            webAuthnService.listUserCredentials(userDetails.getUsername());
        
        return ResponseEntity.ok(ApiResponse.success(credentials));
    }
    
    /**
     * Remove WebAuthn credential
     */
    @DeleteMapping("/credentials/{credentialId}")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Remove WebAuthn credential",
              description = "Delete a specific WebAuthn credential",
              security = @SecurityRequirement(name = "bearer-auth"))
    public ResponseEntity<ApiResponse<Void>> removeCredential(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable String credentialId) {
        
        logger.info("Removing WebAuthn credential {} for user: {}", 
            credentialId, userDetails.getUsername());
        
        webAuthnService.removeCredential(userDetails.getUsername(), credentialId);
        
        return ResponseEntity.ok(ApiResponse.success());
    }
    
    /**
     * Request DTOs
     */
    public static class RegistrationRequest {
        @NotBlank
        @JsonProperty("id")
        private String credentialId;
        
        @NotBlank
        private String clientDataJSON;
        
        @NotBlank
        private String attestationObject;
        
        // Getters and setters
        public String getCredentialId() { return credentialId; }
        public void setCredentialId(String credentialId) { this.credentialId = credentialId; }
        
        public String getClientDataJSON() { return clientDataJSON; }
        public void setClientDataJSON(String clientDataJSON) { this.clientDataJSON = clientDataJSON; }
        
        public String getAttestationObject() { return attestationObject; }
        public void setAttestationObject(String attestationObject) { 
            this.attestationObject = attestationObject; 
        }
    }
    
    public static class AuthenticationStartRequest {
        private String username; // Optional for usernameless flow
        
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
    }
    
    public static class AuthenticationRequest {
        @NotBlank
        @JsonProperty("id")
        private String credentialId;
        
        @NotBlank
        private String clientDataJSON;
        
        @NotBlank
        private String authenticatorData;
        
        @NotBlank
        private String signature;
        
        private String userHandle; // Optional
        
        // Getters and setters
        public String getCredentialId() { return credentialId; }
        public void setCredentialId(String credentialId) { this.credentialId = credentialId; }
        
        public String getClientDataJSON() { return clientDataJSON; }
        public void setClientDataJSON(String clientDataJSON) { this.clientDataJSON = clientDataJSON; }
        
        public String getAuthenticatorData() { return authenticatorData; }
        public void setAuthenticatorData(String authenticatorData) { 
            this.authenticatorData = authenticatorData; 
        }
        
        public String getSignature() { return signature; }
        public void setSignature(String signature) { this.signature = signature; }
        
        public String getUserHandle() { return userHandle; }
        public void setUserHandle(String userHandle) { this.userHandle = userHandle; }
    }
}