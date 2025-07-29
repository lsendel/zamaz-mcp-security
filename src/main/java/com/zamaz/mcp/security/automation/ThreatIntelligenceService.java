package com.zamaz.mcp.security.automation;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.concurrent.TimeUnit;

/**
 * Threat Intelligence Service
 * Manages threat intelligence data for security automation
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ThreatIntelligenceService {

    private final RedisTemplate<String, Object> redisTemplate;
    
    private static final String MALICIOUS_IP_PREFIX = "threat:ip:malicious:";
    private static final String HIGH_RISK_IP_PREFIX = "threat:ip:high_risk:";
    private static final long DEFAULT_TTL_HOURS = 24;
    
    /**
     * Mark an IP as malicious
     */
    public void markIpAsMalicious(String ip, String reason, Instant timestamp) {
        ThreatData data = new ThreatData();
        data.setIp(ip);
        data.setReason(reason);
        data.setTimestamp(timestamp);
        data.setThreatLevel("MALICIOUS");
        
        redisTemplate.opsForValue().set(
            MALICIOUS_IP_PREFIX + ip, 
            data, 
            DEFAULT_TTL_HOURS, 
            TimeUnit.HOURS
        );
        
        log.warn("IP marked as malicious: {} - Reason: {}", ip, reason);
    }
    
    /**
     * Mark an IP as high risk
     */
    public void markIpAsHighRisk(String ip, String reason, Instant timestamp) {
        ThreatData data = new ThreatData();
        data.setIp(ip);
        data.setReason(reason);
        data.setTimestamp(timestamp);
        data.setThreatLevel("HIGH_RISK");
        
        redisTemplate.opsForValue().set(
            HIGH_RISK_IP_PREFIX + ip, 
            data, 
            DEFAULT_TTL_HOURS * 2, // Keep high-risk IPs longer
            TimeUnit.HOURS
        );
        
        log.warn("IP marked as high risk: {} - Reason: {}", ip, reason);
    }
    
    /**
     * Check if an IP is malicious
     */
    public boolean isMaliciousIp(String ip) {
        return redisTemplate.hasKey(MALICIOUS_IP_PREFIX + ip);
    }
    
    /**
     * Check if an IP is high risk
     */
    public boolean isHighRiskIp(String ip) {
        return redisTemplate.hasKey(HIGH_RISK_IP_PREFIX + ip);
    }
    
    /**
     * Get threat data for an IP
     */
    public ThreatData getThreatData(String ip) {
        ThreatData maliciousData = (ThreatData) redisTemplate.opsForValue()
            .get(MALICIOUS_IP_PREFIX + ip);
        if (maliciousData != null) {
            return maliciousData;
        }
        
        return (ThreatData) redisTemplate.opsForValue()
            .get(HIGH_RISK_IP_PREFIX + ip);
    }
    
    /**
     * Remove IP from threat lists
     */
    public void removeIpFromThreats(String ip) {
        redisTemplate.delete(MALICIOUS_IP_PREFIX + ip);
        redisTemplate.delete(HIGH_RISK_IP_PREFIX + ip);
        log.info("IP removed from threat lists: {}", ip);
    }
    
    @lombok.Data
    public static class ThreatData {
        private String ip;
        private String reason;
        private Instant timestamp;
        private String threatLevel;
    }
}
