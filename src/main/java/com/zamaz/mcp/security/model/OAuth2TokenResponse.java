package com.zamaz.mcp.security.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * OAuth2 token response model.
 * Contains access token, refresh token, and additional metadata.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OAuth2TokenResponse {
    
    @JsonProperty("access_token")
    private String accessToken;
    
    @JsonProperty("token_type")
    private String tokenType = "Bearer";
    
    @JsonProperty("expires_in")
    private Integer expiresIn;
    
    @JsonProperty("refresh_token")
    private String refreshToken;
    
    @JsonProperty("scope")
    private String scope;
    
    @JsonProperty("id_token")
    private String idToken;
    
    @JsonProperty("error")
    private String error;
    
    @JsonProperty("error_description")
    private String errorDescription;
    
    @JsonProperty("error_uri")
    private String errorUri;
    
    // Constructor
    public OAuth2TokenResponse() {}
    
    // Static factory methods for common responses
    public static OAuth2TokenResponse success(String accessToken, Integer expiresIn) {
        OAuth2TokenResponse response = new OAuth2TokenResponse();
        response.setAccessToken(accessToken);
        response.setExpiresIn(expiresIn);
        return response;
    }
    
    public static OAuth2TokenResponse error(String error, String description) {
        OAuth2TokenResponse response = new OAuth2TokenResponse();
        response.setError(error);
        response.setErrorDescription(description);
        return response;
    }
    
    // Getters and setters
    public String getAccessToken() { return accessToken; }
    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }
    
    public String getTokenType() { return tokenType; }
    public void setTokenType(String tokenType) { this.tokenType = tokenType; }
    
    public Integer getExpiresIn() { return expiresIn; }
    public void setExpiresIn(Integer expiresIn) { this.expiresIn = expiresIn; }
    
    public String getRefreshToken() { return refreshToken; }
    public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }
    
    public String getScope() { return scope; }
    public void setScope(String scope) { this.scope = scope; }
    
    public String getIdToken() { return idToken; }
    public void setIdToken(String idToken) { this.idToken = idToken; }
    
    public String getError() { return error; }
    public void setError(String error) { this.error = error; }
    
    public String getErrorDescription() { return errorDescription; }
    public void setErrorDescription(String errorDescription) { this.errorDescription = errorDescription; }
    
    public String getErrorUri() { return errorUri; }
    public void setErrorUri(String errorUri) { this.errorUri = errorUri; }
}