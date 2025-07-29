# Security Module Troubleshooting Guide

## Table of Contents
1. [Common Authentication Issues](#common-authentication-issues)
2. [JWT Token Problems](#jwt-token-problems)
3. [Authorization Failures](#authorization-failures)
4. [WebAuthn Issues](#webauthn-issues)
5. [Session Management Problems](#session-management-problems)
6. [Database Connection Issues](#database-connection-issues)
7. [Redis/Cache Problems](#rediscache-problems)
8. [Performance Issues](#performance-issues)
9. [Debugging Tools](#debugging-tools)
10. [Error Reference](#error-reference)

## Common Authentication Issues

### Problem: Login fails with "Invalid credentials"

**Symptoms:**
- User cannot log in despite correct credentials
- Audit logs show authentication failures

**Diagnosis:**
```bash
# Check user account status
psql -d mcp_security -c "SELECT username, is_active, account_locked, failed_login_attempts FROM users WHERE username='user@example.com';"

# Check recent login attempts
psql -d mcp_security -c "SELECT * FROM security_audit_logs WHERE user_id='user-id' AND event_type='LOGIN_FAILURE' ORDER BY created_at DESC LIMIT 10;"
```

**Solutions:**

1. **Account is locked:**
```sql
-- Unlock account
UPDATE users 
SET account_locked = false, 
    failed_login_attempts = 0,
    account_locked_at = NULL,
    account_locked_until = NULL
WHERE username = 'user@example.com';
```

2. **Password expired:**
```sql
-- Check password expiration
SELECT password_expires_at FROM users WHERE username='user@example.com';

-- Extend password expiration
UPDATE users 
SET password_expires_at = NOW() + INTERVAL '90 days'
WHERE username = 'user@example.com';
```

3. **Email not verified:**
```sql
-- Verify email
UPDATE users 
SET email_verified = true,
    email_verified_at = NOW()
WHERE username = 'user@example.com';
```

### Problem: "Too many login attempts" error

**Symptoms:**
- User receives rate limit error
- Account may be temporarily locked

**Solutions:**

1. **Clear rate limit (Redis):**
```bash
# Connect to Redis
redis-cli -h localhost -p 6379

# Check current attempts
GET "login_attempts:user@example.com"

# Clear rate limit
DEL "login_attempts:user@example.com"
```

2. **Adjust rate limit configuration:**
```yaml
# application.yml
security:
  login:
    max-attempts: 10  # Increase from default 5
    lockout-duration: 300  # 5 minutes in seconds
```

## JWT Token Problems

### Problem: "Invalid token" or "Token expired"

**Symptoms:**
- API calls return 401 Unauthorized
- Token validation fails

**Diagnosis:**
```bash
# Decode JWT token (without verification)
echo "YOUR_JWT_TOKEN" | cut -d. -f2 | base64 -d | jq .

# Check token expiration
echo "YOUR_JWT_TOKEN" | cut -d. -f2 | base64 -d | jq '.exp | todate'
```

**Solutions:**

1. **Token expired:**
```java
// Implement token refresh endpoint
@PostMapping("/api/auth/refresh")
public ResponseEntity<TokenResponse> refreshToken(@RequestBody RefreshRequest request) {
    // Validate refresh token
    String newAccessToken = tokenService.refresh(request.getRefreshToken());
    return ResponseEntity.ok(new TokenResponse(newAccessToken));
}
```

2. **Clock skew between servers:**
```yaml
# Allow clock skew in JWT validation
security:
  jwt:
    clock-skew-seconds: 300  # 5 minutes tolerance
```

3. **Wrong signing key:**
```bash
# Verify public key matches private key
openssl rsa -in private_key.pem -pubout -outform PEM | diff public_key.pem -
```

### Problem: "Invalid signature" error

**Symptoms:**
- Token structure is valid but signature verification fails

**Solutions:**

1. **Key mismatch:**
```bash
# Generate new key pair
openssl genrsa -out private_key.pem 4096
openssl rsa -in private_key.pem -pubout -out public_key.pem

# Update application configuration
export JWT_PRIVATE_KEY_PATH=/path/to/private_key.pem
export JWT_PUBLIC_KEY_PATH=/path/to/public_key.pem
```

2. **Algorithm mismatch:**
```java
// Ensure consistent algorithm
Jwts.parserBuilder()
    .setSigningKey(publicKey)
    .requireAlgorithm("RS256")  // Must match token generation
    .build()
    .parseClaimsJws(token);
```

## Authorization Failures

### Problem: "Access Denied" despite having correct role

**Symptoms:**
- User has required role but still gets 403 Forbidden
- Permission checks fail unexpectedly

**Diagnosis:**
```java
// Enable security debug logging
@Component
public class SecurityDebugger {
    
    @EventListener
    public void handleAuthorizationFailure(AuthorizationFailureEvent event) {
        Authentication auth = event.getAuthentication();
        AccessDeniedException exception = event.getAccessDeniedException();
        
        logger.error("Authorization failed for user: {} with authorities: {}. Reason: {}",
            auth.getName(),
            auth.getAuthorities(),
            exception.getMessage()
        );
    }
}
```

**Solutions:**

1. **Role hierarchy not working:**
```java
// Verify role hierarchy configuration
@Bean
public RoleHierarchy roleHierarchy() {
    RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
    hierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
    return hierarchy;
}

// Use hierarchy in method security
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Configuration
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {
    @Override
    protected MethodSecurityExpressionHandler createExpressionHandler() {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy());
        return handler;
    }
}
```

2. **Organization context missing:**
```java
// Ensure organization context is set
@Component
public class OrganizationContextFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response,
                                  FilterChain chain) {
        String orgId = extractOrgId(request);
        if (orgId != null) {
            OrganizationContext.setCurrentOrganization(orgId);
        }
        
        try {
            chain.doFilter(request, response);
        } finally {
            OrganizationContext.clear();
        }
    }
}
```

### Problem: Custom permissions not evaluated

**Symptoms:**
- @PreAuthorize with hasPermission() always returns false

**Solutions:**

1. **Configure permission evaluator:**
```java
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    
    @Bean
    public PermissionEvaluator permissionEvaluator() {
        return new CustomPermissionEvaluator();
    }
    
    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(permissionEvaluator());
        return handler;
    }
}
```

## WebAuthn Issues

### Problem: WebAuthn registration fails

**Symptoms:**
- Browser shows "operation failed" error
- Registration ceremony doesn't complete

**Diagnosis:**
```javascript
// Browser console debugging
navigator.credentials.create({
    publicKey: registrationOptions
}).then(credential => {
    console.log('Credential created:', credential);
}).catch(error => {
    console.error('WebAuthn error:', error);
});
```

**Solutions:**

1. **HTTPS required:**
```nginx
# Ensure HTTPS is enabled
server {
    listen 443 ssl;
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
}
```

2. **Wrong relying party ID:**
```yaml
security:
  webauthn:
    rp-id: example.com  # Must match domain
    origin: https://example.com  # Must match exactly
```

3. **User verification not supported:**
```java
// Make user verification optional
WebAuthnRegistrationOptions options = new WebAuthnRegistrationOptions();
options.setAuthenticatorSelection(new AuthenticatorSelection(
    null, // No specific attachment
    true, // Require resident key
    "preferred" // Not "required"
));
```

### Problem: WebAuthn authentication fails

**Solutions:**

1. **Challenge expired:**
```yaml
security:
  webauthn:
    challenge-timeout: 300  # Increase to 5 minutes
```

2. **Credential not found:**
```sql
-- Check if credential exists
SELECT * FROM webauthn_credentials WHERE user_id = 'user-uuid';

-- Check credential ID encoding
SELECT credential_id, encode(credential_id::bytea, 'base64') FROM webauthn_credentials;
```

## Session Management Problems

### Problem: Sessions expire too quickly

**Symptoms:**
- Users complain about frequent logouts
- Session timeout seems shorter than configured

**Solutions:**

1. **Check Redis configuration:**
```bash
# Redis CLI
redis-cli
CONFIG GET maxmemory
CONFIG GET maxmemory-policy  # Should be allkeys-lru or volatile-lru
```

2. **Adjust session timeout:**
```yaml
spring:
  session:
    timeout: 1800  # 30 minutes in seconds
    redis:
      flush-mode: on_save  # Only save when necessary
      
server:
  servlet:
    session:
      timeout: 30m  # Alternative configuration
```

### Problem: Concurrent session limit not working

**Solutions:**

1. **Enable session registry:**
```java
@Configuration
public class SessionConfig {
    
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }
    
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
    
    @Bean
    public ConcurrentSessionControlAuthenticationStrategy sessionControlStrategy() {
        ConcurrentSessionControlAuthenticationStrategy strategy = 
            new ConcurrentSessionControlAuthenticationStrategy(sessionRegistry());
        strategy.setMaximumSessions(3);
        strategy.setExceptionIfMaximumExceeded(false);
        return strategy;
    }
}
```

## Database Connection Issues

### Problem: "Connection pool exhausted"

**Symptoms:**
- Intermittent connection failures
- Slow response times

**Diagnosis:**
```sql
-- Check active connections
SELECT count(*) FROM pg_stat_activity WHERE datname = 'mcp_security';

-- Check connection details
SELECT pid, usename, application_name, client_addr, state, state_change
FROM pg_stat_activity 
WHERE datname = 'mcp_security'
ORDER BY state_change;
```

**Solutions:**

1. **Increase pool size:**
```yaml
spring:
  datasource:
    hikari:
      maximum-pool-size: 30  # Increase from default 10
      minimum-idle: 5
      connection-timeout: 30000
      idle-timeout: 600000
      max-lifetime: 1800000
      leak-detection-threshold: 60000  # Detect leaks
```

2. **Fix connection leaks:**
```java
// Always use try-with-resources
try (Connection conn = dataSource.getConnection();
     PreparedStatement ps = conn.prepareStatement(sql)) {
    // Use connection
} // Automatically closed
```

## Redis/Cache Problems

### Problem: "Could not connect to Redis"

**Solutions:**

1. **Check Redis connectivity:**
```bash
# Test connection
redis-cli -h localhost -p 6379 ping

# Check Redis info
redis-cli info clients
redis-cli info memory
```

2. **Configure connection pool:**
```yaml
spring:
  redis:
    lettuce:
      pool:
        max-active: 20
        max-idle: 10
        min-idle: 5
        max-wait: -1
      shutdown-timeout: 100ms
```

### Problem: Cache inconsistency

**Solutions:**

1. **Clear specific cache entries:**
```java
@Service
public class CacheManager {
    
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    
    public void evictUserCache(String userId) {
        Set<String> keys = redisTemplate.keys("user:" + userId + ":*");
        redisTemplate.delete(keys);
    }
    
    public void clearAllCaches() {
        redisTemplate.execute((RedisCallback<Object>) connection -> {
            connection.flushDb();
            return null;
        });
    }
}
```

## Performance Issues

### Problem: Slow authentication requests

**Diagnosis:**
```java
// Add performance monitoring
@Aspect
@Component
public class PerformanceMonitor {
    
    @Around("@annotation(Timed)")
    public Object measureExecutionTime(ProceedingJoinPoint joinPoint) throws Throwable {
        long start = System.currentTimeMillis();
        
        try {
            return joinPoint.proceed();
        } finally {
            long duration = System.currentTimeMillis() - start;
            if (duration > 1000) {
                logger.warn("Slow operation: {} took {}ms", 
                    joinPoint.getSignature().toShortString(), duration);
            }
        }
    }
}
```

**Solutions:**

1. **Enable query optimization:**
```sql
-- Add missing indexes
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_security_audit_logs_user_event ON security_audit_logs(user_id, event_type, created_at);

-- Analyze query performance
EXPLAIN ANALYZE SELECT * FROM users WHERE username = 'user@example.com';
```

2. **Cache frequently accessed data:**
```java
@Service
public class UserService {
    
    @Cacheable(value = "users", key = "#username")
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }
    
    @CacheEvict(value = "users", key = "#user.username")
    public void updateUser(User user) {
        userRepository.save(user);
    }
}
```

## Debugging Tools

### Enable Debug Logging

```yaml
logging:
  level:
    org.springframework.security: DEBUG
    com.zamaz.mcp.security: TRACE
    org.hibernate.SQL: DEBUG
    org.hibernate.type.descriptor.sql.BasicBinder: TRACE
    org.springframework.web: DEBUG
```

### Security Event Listener

```java
@Component
public class SecurityEventListener {
    
    @EventListener
    public void handleAuthenticationSuccess(AuthenticationSuccessEvent event) {
        logger.info("Authentication success: {}", event.getAuthentication().getName());
    }
    
    @EventListener
    public void handleAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        logger.error("Authentication failure: {}", event.getException().getMessage());
    }
    
    @EventListener
    public void handleAuthorizationFailure(AuthorizationFailureEvent event) {
        logger.error("Authorization failure for {}: {}", 
            event.getAuthentication().getName(),
            event.getAccessDeniedException().getMessage());
    }
}
```

### HTTP Request/Response Logging

```java
@Component
public class RequestResponseLoggingFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response,
                                  FilterChain filterChain) throws ServletException, IOException {
        
        ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper(request);
        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(response);
        
        long startTime = System.currentTimeMillis();
        
        filterChain.doFilter(requestWrapper, responseWrapper);
        
        long duration = System.currentTimeMillis() - startTime;
        
        logger.info("Request: {} {} - Status: {} - Duration: {}ms",
            request.getMethod(),
            request.getRequestURI(),
            response.getStatus(),
            duration);
        
        if (logger.isDebugEnabled()) {
            logger.debug("Request body: {}", 
                new String(requestWrapper.getContentAsByteArray()));
            logger.debug("Response body: {}", 
                new String(responseWrapper.getContentAsByteArray()));
        }
        
        responseWrapper.copyBodyToResponse();
    }
}
```

## Error Reference

### Authentication Errors

| Error Code | Message | Cause | Solution |
|------------|---------|-------|----------|
| AUTH001 | Invalid credentials | Wrong username/password | Verify credentials |
| AUTH002 | Account locked | Too many failed attempts | Wait or admin unlock |
| AUTH003 | Account disabled | Account deactivated | Contact admin |
| AUTH004 | Email not verified | Registration incomplete | Verify email |
| AUTH005 | Password expired | Password too old | Reset password |

### Token Errors

| Error Code | Message | Cause | Solution |
|------------|---------|-------|----------|
| TOKEN001 | Token expired | Access token expired | Refresh token |
| TOKEN002 | Invalid signature | Key mismatch | Check JWT keys |
| TOKEN003 | Invalid token | Malformed token | Re-authenticate |
| TOKEN004 | Token revoked | Token blacklisted | Re-authenticate |
| TOKEN005 | Invalid issuer | Wrong issuer claim | Check configuration |

### Authorization Errors

| Error Code | Message | Cause | Solution |
|------------|---------|-------|----------|
| AUTHZ001 | Insufficient privileges | Missing role/permission | Check user roles |
| AUTHZ002 | Organization mismatch | Wrong organization context | Switch organization |
| AUTHZ003 | Resource not found | Resource doesn't exist | Verify resource ID |
| AUTHZ004 | Operation not permitted | Action not allowed | Check permissions |

### WebAuthn Errors

| Error Code | Message | Cause | Solution |
|------------|---------|-------|----------|
| WA001 | Registration failed | Browser/device issue | Try different browser |
| WA002 | Authentication failed | Credential not found | Re-register device |
| WA003 | Challenge expired | Timeout | Retry operation |
| WA004 | Invalid origin | Origin mismatch | Check configuration |

## Quick Fixes Script

```bash
#!/bin/bash
# security-fix.sh - Common security fixes

case "$1" in
  unlock-user)
    psql -d mcp_security -c "UPDATE users SET account_locked=false, failed_login_attempts=0 WHERE username='$2'"
    ;;
  clear-sessions)
    redis-cli KEYS "spring:session:*" | xargs redis-cli DEL
    ;;
  reset-rate-limit)
    redis-cli KEYS "rate_limit:*" | xargs redis-cli DEL
    ;;
  verify-email)
    psql -d mcp_security -c "UPDATE users SET email_verified=true WHERE username='$2'"
    ;;
  extend-token-expiry)
    echo "Update JWT expiration in application.yml and restart"
    ;;
  *)
    echo "Usage: $0 {unlock-user|clear-sessions|reset-rate-limit|verify-email|extend-token-expiry} [username]"
    exit 1
    ;;
esac
```