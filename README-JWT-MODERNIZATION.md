# JWT Modernization Implementation

This document describes the modern JWT implementation using JJWT 0.12.x and Spring Security OAuth2 patterns.

## Overview

The JWT implementation has been upgraded to use modern patterns and eliminate deprecated methods:

- **JJWT 0.12.x**: Latest version with modern builder patterns
- **Spring Security OAuth2**: Resource server and authorization server support
- **RS256 Support**: Production-ready RSA signing with proper key management
- **Custom Claims**: Organization, roles, and permissions support
- **Modern Exception Handling**: Proper JWT validation exceptions

## Key Components

### 1. JwtService (Modernized)

The core JWT service now uses modern JJWT 0.12.x builder patterns:

```java
// Modern token generation
JwtBuilder builder = Jwts.builder()
    .id(UUID.randomUUID().toString())           // Modern: id() instead of setId()
    .subject(subject)                           // Modern: subject() instead of setSubject()
    .issuer(issuer)                            // Modern: issuer() instead of setIssuer()
    .issuedAt(Date.from(now))                  // Modern: issuedAt() instead of setIssuedAt()
    .expiration(Date.from(expiration))         // Modern: expiration() instead of setExpiration()
    .claims(claims);                           // Modern: claims() instead of addClaims()
```

### 2. JwtKeyManager (Enhanced)

Supports both HMAC and RSA key management:

```java
// Modern HMAC key generation
this.hmacKey = Jwts.SIG.HS256.key().build();  // Modern: Jwts.SIG instead of Keys.secretKeyFor()

// RSA key support for production
if ("RS256".equals(signingAlgorithm)) {
    // Generate or load RSA keys
    generateRSAKeyPair();
}
```

### 3. Modern JWT Configuration

Spring Security OAuth2 integration:

```java
@Bean
public JwtDecoder jwtDecoder() {
    if (keyManager.isUsingRSA()) {
        return NimbusJwtDecoder.withPublicKey(keyManager.getRSAPublicKey()).build();
    } else {
        return NimbusJwtDecoder.withSecretKey((SecretKey) keyManager.getVerificationKey()).build();
    }
}

@Bean
public JwtEncoder jwtEncoder() {
    // Modern JWT encoding with proper key management
    return new NimbusJwtEncoder(jwkSource());
}
```

### 4. Custom Claims Support

Enhanced token generation with organization, roles, and permissions:

```java
public String generateTokenWithClaims(String subject, String organizationId, 
                                    Set<String> roles, Set<String> permissions) {
    Map<String, Object> claims = new HashMap<>();
    
    if (organizationId != null) {
        claims.put("organizationId", organizationId);
    }
    
    if (roles != null && !roles.isEmpty()) {
        claims.put("roles", roles);
    }
    
    if (permissions != null && !permissions.isEmpty()) {
        claims.put("permissions", permissions);
    }
    
    // Add token metadata
    claims.put("token_version", "1.0");
    claims.put("issuer_service", "mcp-security");
    
    return generateAccessToken(subject, claims);
}
```

## Configuration

### HMAC Configuration (Development)

```yaml
jwt:
  secret: your-secret-key-here
  signing:
    algorithm: HS256
  access-token-validity: 3600
  refresh-token-validity: 86400
  issuer: mcp-services
```

### RSA Configuration (Production)

```yaml
jwt:
  signing:
    algorithm: RS256
  rsa:
    private-key: |
      -----BEGIN PRIVATE KEY-----
      MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB...
      -----END PRIVATE KEY-----
    public-key: |
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1L7VLPHCgcI4B5uk...
      -----END PUBLIC KEY-----
  key:
    rotation:
      enabled: true
  access-token-validity: 3600
  refresh-token-validity: 86400
  issuer: mcp-services
```

## Usage Examples

### Basic Token Generation

```java
@Autowired
private JwtService jwtService;

// Generate access token
String token = jwtService.generateAccessToken("user@example.com", Map.of("role", "USER"));

// Generate token with custom claims
String tokenWithClaims = jwtService.generateTokenWithClaims(
    "user@example.com",
    "org-123",
    Set.of("ADMIN", "USER"),
    Set.of("read:debates", "write:debates")
);
```

### Modern Authentication Service

```java
@Autowired
private ModernAuthenticationService authService;

// Generate access token with authentication context
String accessToken = authService.generateAccessToken(authentication, "org-123");

// Generate service-to-service token
String serviceToken = authService.generateServiceToken("mcp-llm", Set.of("api:read", "api:write"));
```

### Token Validation

```java
// Validate token
Claims claims = jwtService.validateToken(token);

// Extract specific claims with type safety
String organizationId = jwtService.getClaim(token, "organizationId", String.class);
Set<String> roles = jwtService.getClaim(token, "roles", Set.class);

// Check token expiration
boolean isExpired = jwtService.isTokenExpired(token);
```

## Security Features

### 1. Algorithm Support

- **HS256**: HMAC with SHA-256 (development/testing)
- **RS256**: RSA with SHA-256 (production recommended)

### 2. Key Management

- **Key Rotation**: Automatic key rotation support
- **Secure Storage**: Integration with external secret management
- **Algorithm Migration**: Easy migration from HMAC to RSA

### 3. Custom Claims

- **Organization Context**: Multi-tenant support
- **Role-Based Access**: Hierarchical role support
- **Permission-Based Access**: Fine-grained permissions
- **Token Metadata**: Version and issuer tracking

### 4. Exception Handling

Modern exception handling with proper error messages:

```java
try {
    Claims claims = jwtService.validateToken(token);
} catch (JwtService.JwtValidationException e) {
    // Handle validation errors
    log.warn("JWT validation failed: {}", e.getMessage());
}
```

## Migration Guide

### From Deprecated JJWT Methods

| Deprecated Method | Modern Method |
|------------------|---------------|
| `setId(String)` | `id(String)` |
| `setSubject(String)` | `subject(String)` |
| `setIssuer(String)` | `issuer(String)` |
| `setIssuedAt(Date)` | `issuedAt(Date)` |
| `setExpiration(Date)` | `expiration(Date)` |
| `addClaims(Map)` | `claims(Map)` |
| `Keys.secretKeyFor(SignatureAlgorithm)` | `Jwts.SIG.HS256.key().build()` |

### Configuration Migration

1. **Update Dependencies**: Ensure JJWT 0.12.x is used
2. **Add OAuth2 Dependencies**: Include Spring Security OAuth2 Resource Server
3. **Update Configuration**: Use modern configuration patterns
4. **Test Migration**: Verify token compatibility

## Testing

Comprehensive test coverage includes:

- Modern JWT generation patterns
- Token validation with custom claims
- Key management (HMAC and RSA)
- Exception handling
- Configuration scenarios

Run tests:

```bash
mvn test -Dtest=JwtServiceModernTest
mvn test -Dtest=JwtKeyManagerTest
```

## Best Practices

1. **Use RS256 in Production**: RSA signing provides better security
2. **Implement Key Rotation**: Regular key rotation for enhanced security
3. **Validate All Claims**: Always validate issuer, audience, and expiration
4. **Use Type-Safe Claim Extraction**: Leverage generic methods for type safety
5. **Handle Exceptions Properly**: Implement proper error handling for JWT validation
6. **Monitor Token Usage**: Log and monitor JWT token generation and validation

## Dependencies

Required dependencies for modern JWT implementation:

```xml
<!-- JJWT 0.12.x -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.12.6</version>
</dependency>

<!-- Spring Security OAuth2 Resource Server -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>

<!-- Spring Security OAuth2 Authorization Server -->
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-authorization-server</artifactId>
</dependency>

<!-- Nimbus JOSE JWT -->
<dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
</dependency>
```

This modern JWT implementation provides a solid foundation for secure, scalable authentication and authorization in the MCP services ecosystem.
