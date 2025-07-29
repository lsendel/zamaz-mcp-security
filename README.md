# MCP Security Module

## Overview

The MCP Security module provides comprehensive authentication and authorization capabilities for the MCP platform. It implements modern security standards including OAuth2/OIDC, WebAuthn, fine-grained RBAC, and multi-tenant isolation.

## Features

### Authentication
- **OAuth2/OIDC Support**: Full OAuth2 authorization server with OIDC extensions
- **JWT Token Management**: Modern JWT implementation with RS256 signing
- **WebAuthn/FIDO2**: Passwordless authentication with hardware security keys
- **Multi-Factor Authentication**: TOTP-based MFA with backup codes
- **Password Policies**: NIST 800-63B compliant password validation
- **Account Lockout**: Progressive lockout with exponential backoff

### Authorization
- **Fine-Grained RBAC**: Resource and instance-level permissions
- **Hierarchical Roles**: Role inheritance with organization scoping
- **Dynamic Permissions**: Attribute-based access control (ABAC)
- **Custom Security Expressions**: SpEL-based authorization rules

### Multi-Tenancy
- **Organization Isolation**: Automatic tenant filtering
- **Cross-Tenant Protection**: Prevents unauthorized access
- **Tenant Context Management**: Thread-local tenant propagation

### Security Features
- **Audit Logging**: Comprehensive security event tracking
- **Session Management**: Redis-backed distributed sessions
- **Token Revocation**: Blacklisting with distributed cache
- **Security Monitoring**: Real-time threat detection
- **Rate Limiting**: Protection against brute force attacks

## Quick Start

### Maven Dependency

```xml
<dependency>
    <groupId>com.zamaz.mcp</groupId>
    <artifactId>mcp-security</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Basic Configuration

```yaml
# application.yml
security:
  jwt:
    issuer: https://your-domain.com
    audience: mcp-platform
    expiration: 3600 # 1 hour
    refresh-expiration: 604800 # 7 days
    
  oauth2:
    authorization-server-url: http://localhost:9000
    
  webauthn:
    rp-id: your-domain.com
    rp-name: MCP Platform
    origin: https://your-domain.com
    
  password:
    min-length: 12
    require-uppercase: true
    require-lowercase: true
    require-digits: true
    require-special: true
    check-breach: true
```

### Enable Security in Your Service

```java
@Configuration
@EnableWebSecurity
@Import(SharedSecurityConfig.class)
public class SecurityConfig {
    // Additional service-specific configuration
}
```

## Configuration Guide

### JWT Configuration

The module supports both symmetric (HS256) and asymmetric (RS256) key algorithms:

```yaml
security:
  jwt:
    algorithm: RS256 # or HS256
    # For HS256
    secret-key: ${JWT_SECRET_KEY}
    # For RS256
    private-key-path: ${JWT_PRIVATE_KEY_PATH}
    public-key-path: ${JWT_PUBLIC_KEY_PATH}
    key-store:
      path: ${JWT_KEYSTORE_PATH}
      password: ${JWT_KEYSTORE_PASSWORD}
      alias: ${JWT_KEY_ALIAS}
```

### OAuth2 Resource Server

Configure your microservice as an OAuth2 resource server:

```java
@Configuration
public class ResourceServerConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.decoder(jwtDecoder()))
            )
            .build();
    }
}
```

### WebAuthn Integration

Enable passwordless authentication:

```java
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    @Autowired
    private WebAuthnService webAuthnService;
    
    @PostMapping("/webauthn/register/start")
    public WebAuthnRegistrationOptions startRegistration(@AuthenticationPrincipal User user) {
        return webAuthnService.startRegistration(user.getUsername());
    }
    
    @PostMapping("/webauthn/register/complete")
    public void completeRegistration(@RequestBody RegistrationRequest request) {
        webAuthnService.completeRegistration(request);
    }
}
```

### Fine-Grained Authorization

Use custom security expressions:

```java
@RestController
@RequestMapping("/api/documents")
public class DocumentController {
    
    @GetMapping("/{id}")
    @PreAuthorize("hasPermission(#id, 'DOCUMENT', 'READ')")
    public Document getDocument(@PathVariable Long id) {
        // Method implementation
    }
    
    @PutMapping("/{id}")
    @PreAuthorize("hasPermission(#id, 'DOCUMENT', 'WRITE') and @securityService.isOwner(#id)")
    public Document updateDocument(@PathVariable Long id, @RequestBody Document doc) {
        // Method implementation
    }
    
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or (hasPermission(#id, 'DOCUMENT', 'DELETE') and @securityService.isOwner(#id))")
    public void deleteDocument(@PathVariable Long id) {
        // Method implementation
    }
}
```

### Multi-Tenant Configuration

Enable automatic tenant filtering:

```java
@Entity
@Table(name = "documents")
@TenantAware // Custom annotation for tenant filtering
public class Document {
    @Id
    private Long id;
    
    @TenantId // Marks the tenant field
    private UUID organizationId;
    
    // Other fields
}
```

## Security Best Practices

### 1. Token Management
- Use short-lived access tokens (1 hour)
- Implement refresh token rotation
- Store tokens securely (httpOnly cookies or secure storage)
- Implement token revocation for logout

### 2. Password Security
- Enforce strong password policies
- Use Argon2 for password hashing
- Check passwords against breach databases
- Implement password expiration policies

### 3. Session Security
- Use Redis for distributed session storage
- Implement session timeout and idle timeout
- Limit concurrent sessions per user
- Clear sessions on logout

### 4. API Security
- Always use HTTPS in production
- Implement rate limiting
- Validate and sanitize all inputs
- Use CORS policies appropriately

### 5. Audit and Monitoring
- Log all authentication events
- Monitor failed login attempts
- Alert on suspicious activities
- Regular security audits

## Deployment Guide

### Development Environment

1. Start required services:
```bash
docker-compose up -d postgres redis
```

2. Run database migrations:
```bash
./mvnw flyway:migrate
```

3. Start the application:
```bash
./mvnw spring-boot:run -Dspring.profiles.active=dev
```

### Production Environment

1. Environment Variables:
```bash
export JWT_PRIVATE_KEY_PATH=/secure/path/private_key.pem
export JWT_PUBLIC_KEY_PATH=/secure/path/public_key.pem
export DB_PASSWORD=$(vault kv get -field=password secret/db)
export REDIS_PASSWORD=$(vault kv get -field=password secret/redis)
```

2. JVM Options:
```bash
java -jar mcp-security.jar \
  -Xmx2g \
  -Dspring.profiles.active=prod \
  -Dserver.port=8443 \
  -Dserver.ssl.enabled=true
```

3. Health Checks:
```bash
curl https://localhost:8443/actuator/health
```

### Docker Deployment

```dockerfile
FROM openjdk:17-slim
COPY target/mcp-security.jar app.jar
EXPOSE 8443
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

```yaml
# docker-compose.yml
services:
  mcp-security:
    build: .
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - JWT_PRIVATE_KEY_PATH=/keys/private_key.pem
      - JWT_PUBLIC_KEY_PATH=/keys/public_key.pem
    volumes:
      - ./keys:/keys:ro
    ports:
      - "8443:8443"
```

## Troubleshooting

### Common Issues

1. **JWT Validation Errors**
   - Check token expiration
   - Verify issuer and audience claims
   - Ensure public key is correctly configured

2. **CORS Issues**
   - Verify allowed origins configuration
   - Check preflight request handling
   - Ensure credentials are included if needed

3. **Authentication Failures**
   - Check user account status (locked, expired)
   - Verify password or credential validity
   - Review audit logs for details

4. **Authorization Denied**
   - Verify user has required roles/permissions
   - Check organization context
   - Review security expressions

### Debug Logging

Enable debug logging for security:

```yaml
logging:
  level:
    org.springframework.security: DEBUG
    com.zamaz.mcp.security: DEBUG
```

### Performance Tuning

1. **JWT Decoding**: Cache decoded tokens
2. **Permission Checks**: Use Redis cache for permissions
3. **Database Queries**: Add appropriate indexes
4. **Session Management**: Configure Redis connection pool

## API Reference

### Authentication Endpoints

- `POST /api/v1/auth/login` - Username/password login
- `POST /api/v1/auth/logout` - Logout and revoke tokens
- `POST /api/v1/auth/refresh` - Refresh access token
- `POST /api/v1/auth/register` - User registration

### WebAuthn Endpoints

- `POST /api/v1/auth/webauthn/register/start` - Start credential registration
- `POST /api/v1/auth/webauthn/register/complete` - Complete registration
- `POST /api/v1/auth/webauthn/authenticate/start` - Start authentication
- `POST /api/v1/auth/webauthn/authenticate/complete` - Complete authentication

### User Management

- `GET /api/v1/users/profile` - Get current user profile
- `PUT /api/v1/users/profile` - Update profile
- `PUT /api/v1/users/password` - Change password
- `POST /api/v1/users/mfa/enable` - Enable MFA
- `DELETE /api/v1/users/sessions` - Revoke all sessions

### Administration

- `GET /api/v1/admin/users` - List users (ADMIN only)
- `POST /api/v1/admin/roles` - Create role
- `PUT /api/v1/admin/permissions` - Assign permissions
- `GET /api/v1/admin/audit-logs` - View audit logs

## Migration Guide

### From Legacy Authentication

1. Generate JWT keys:
```bash
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

2. Update security configuration
3. Migrate user data with password rehashing
4. Update API clients to use JWT tokens
5. Implement token refresh logic

## Support

For issues and questions:
- GitHub Issues: [mcp-security/issues](https://github.com/zamaz/mcp-security/issues)
- Documentation: [docs.mcp-platform.com/security](https://docs.mcp-platform.com/security)
- Security Issues: security@mcp-platform.com# Force GitHub to refresh
