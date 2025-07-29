package com.zamaz.mcp.security.service;

import com.zamaz.mcp.security.audit.SecurityAuditService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Service for token revocation and blacklisting.
 * Manages revoked tokens to ensure they cannot be used even if not expired.
 */
@Service
public class TokenRevocationService {
    
    private static final Logger logger = LoggerFactory.getLogger(TokenRevocationService.class);
    
    private static final String REVOKED_TOKEN_PREFIX = "revoked-token:";
    private static final String REVOKED_USER_PREFIX = "revoked-user:";
    private static final String REVOKED_CLIENT_PREFIX = "revoked-client:";
    
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    
    @Autowired
    private RedisTemplate<String, String> stringRedisTemplate;
    
    @Autowired
    private SecurityAuditService auditService;
    
    @Value("${security.jwt.secret:default-secret-key-change-in-production}")
    private String jwtSecret;
    
    /**
     * Revoke a specific token
     */
    public void revokeToken(String token, String reason) {
        logger.info("Revoking token: {}", reason);
        
        try {
            // Parse token to get expiration
            Claims claims = parseToken(token);
            if (claims == null) {
                logger.warn("Failed to parse token for revocation");
                return;
            }
            
            String jti = claims.getId();
            Date expiration = claims.getExpiration();
            
            // Calculate TTL based on token expiration
            long ttl = calculateTtl(expiration);
            if (ttl <= 0) {
                logger.debug("Token already expired, skipping revocation");
                return;
            }
            
            // Store revoked token ID
            String key = REVOKED_TOKEN_PREFIX + jti;
            RevokedTokenInfo info = new RevokedTokenInfo();
            info.setTokenId(jti);
            info.setSubject(claims.getSubject());
            info.setRevokedAt(Instant.now());
            info.setReason(reason);
            info.setExpiresAt(expiration.toInstant());
            
            redisTemplate.opsForValue().set(key, info, ttl, TimeUnit.SECONDS);
            
            // Audit log
            auditService.logSecurityViolation("token_revoked", reason, 
                com.zamaz.mcp.security.entity.SecurityAuditLog.RiskLevel.MEDIUM);
            
            logger.info("Token revoked successfully: {}", jti);
            
        } catch (Exception e) {
            logger.error("Failed to revoke token", e);
        }
    }
    
    /**
     * Revoke all tokens for a user
     */
    public void revokeUserTokens(String userId, String reason) {
        logger.info("Revoking all tokens for user: {}", userId);
        
        // Mark user as revoked with timestamp
        String key = REVOKED_USER_PREFIX + userId;
        stringRedisTemplate.opsForValue().set(key, Instant.now().toString(), 24, TimeUnit.HOURS);
        
        // Audit log
        auditService.logSecurityViolation("user_tokens_revoked", 
            "All tokens revoked for user " + userId + ": " + reason, 
            com.zamaz.mcp.security.entity.SecurityAuditLog.RiskLevel.HIGH);
    }
    
    /**
     * Revoke all tokens for a client
     */
    public void revokeClientTokens(String clientId, String reason) {
        logger.info("Revoking all tokens for client: {}", clientId);
        
        // Mark client as revoked with timestamp
        String key = REVOKED_CLIENT_PREFIX + clientId;
        stringRedisTemplate.opsForValue().set(key, Instant.now().toString(), 24, TimeUnit.HOURS);
        
        // Audit log
        auditService.logSecurityViolation("client_tokens_revoked", 
            "All tokens revoked for client " + clientId + ": " + reason, 
            com.zamaz.mcp.security.entity.SecurityAuditLog.RiskLevel.HIGH);
    }
    
    /**
     * Check if a token is revoked
     */
    public boolean isTokenRevoked(String token) {
        try {
            Claims claims = parseToken(token);
            if (claims == null) {
                return true; // Invalid tokens are considered revoked
            }
            
            String jti = claims.getId();
            String subject = claims.getSubject();
            String clientId = claims.get("client_id", String.class);
            
            // Check if specific token is revoked
            if (jti != null && isSpecificTokenRevoked(jti)) {
                return true;
            }
            
            // Check if user's tokens are revoked
            if (subject != null && areUserTokensRevoked(subject, claims.getIssuedAt())) {
                return true;
            }
            
            // Check if client's tokens are revoked
            if (clientId != null && areClientTokensRevoked(clientId, claims.getIssuedAt())) {
                return true;
            }
            
            return false;
            
        } catch (Exception e) {
            logger.error("Failed to check token revocation status", e);
            return true; // Fail secure
        }
    }
    
    /**
     * Get revocation info for a token
     */
    public RevokedTokenInfo getRevocationInfo(String tokenId) {
        String key = REVOKED_TOKEN_PREFIX + tokenId;
        return (RevokedTokenInfo) redisTemplate.opsForValue().get(key);
    }
    
    /**
     * Clean up expired revocation entries (scheduled task)
     */
    @Scheduled(fixedDelay = 3600000) // Every hour
    public void cleanupExpiredRevocations() {
        logger.debug("Running token revocation cleanup task");
        
        // Clean up expired token revocations
        Set<String> tokenKeys = redisTemplate.keys(REVOKED_TOKEN_PREFIX + "*");
        if (tokenKeys != null) {
            int cleaned = 0;
            for (String key : tokenKeys) {
                RevokedTokenInfo info = (RevokedTokenInfo) redisTemplate.opsForValue().get(key);
                if (info != null && info.getExpiresAt().isBefore(Instant.now())) {
                    redisTemplate.delete(key);
                    cleaned++;
                }
            }
            if (cleaned > 0) {
                logger.info("Cleaned up {} expired token revocations", cleaned);
            }
        }
        
        // Note: User and client revocations expire automatically via TTL
    }
    
    // Private helper methods
    
    private Claims parseToken(String token) {
        try {
            SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
            return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        } catch (Exception e) {
            logger.debug("Failed to parse token: {}", e.getMessage());
            return null;
        }
    }
    
    private long calculateTtl(Date expiration) {
        long expirationTime = expiration.getTime();
        long currentTime = System.currentTimeMillis();
        long ttl = (expirationTime - currentTime) / 1000; // Convert to seconds
        
        // Add buffer to account for clock skew
        return ttl + 300; // 5 minutes buffer
    }
    
    private boolean isSpecificTokenRevoked(String tokenId) {
        String key = REVOKED_TOKEN_PREFIX + tokenId;
        return redisTemplate.hasKey(key);
    }
    
    private boolean areUserTokensRevoked(String userId, Date tokenIssuedAt) {
        String key = REVOKED_USER_PREFIX + userId;
        String revokedAtStr = stringRedisTemplate.opsForValue().get(key);
        
        if (revokedAtStr != null) {
            try {
                Instant revokedAt = Instant.parse(revokedAtStr);
                // Token is revoked if it was issued before the revocation time
                return tokenIssuedAt.toInstant().isBefore(revokedAt);
            } catch (Exception e) {
                logger.error("Failed to parse user revocation timestamp", e);
                return true; // Fail secure
            }
        }
        
        return false;
    }
    
    private boolean areClientTokensRevoked(String clientId, Date tokenIssuedAt) {
        String key = REVOKED_CLIENT_PREFIX + clientId;
        String revokedAtStr = stringRedisTemplate.opsForValue().get(key);
        
        if (revokedAtStr != null) {
            try {
                Instant revokedAt = Instant.parse(revokedAtStr);
                // Token is revoked if it was issued before the revocation time
                return tokenIssuedAt.toInstant().isBefore(revokedAt);
            } catch (Exception e) {
                logger.error("Failed to parse client revocation timestamp", e);
                return true; // Fail secure
            }
        }
        
        return false;
    }
    
    /**
     * Inner class for revoked token information
     */
    public static class RevokedTokenInfo {
        private String tokenId;
        private String subject;
        private Instant revokedAt;
        private String reason;
        private Instant expiresAt;
        
        // Getters and setters
        public String getTokenId() { return tokenId; }
        public void setTokenId(String tokenId) { this.tokenId = tokenId; }
        
        public String getSubject() { return subject; }
        public void setSubject(String subject) { this.subject = subject; }
        
        public Instant getRevokedAt() { return revokedAt; }
        public void setRevokedAt(Instant revokedAt) { this.revokedAt = revokedAt; }
        
        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
        
        public Instant getExpiresAt() { return expiresAt; }
        public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    }
}