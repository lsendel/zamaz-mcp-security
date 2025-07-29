# Security Best Practices Guide

## Table of Contents
1. [Authentication Best Practices](#authentication-best-practices)
2. [Authorization Guidelines](#authorization-guidelines)
3. [Token Security](#token-security)
4. [API Security](#api-security)
5. [Data Protection](#data-protection)
6. [Infrastructure Security](#infrastructure-security)
7. [Development Security](#development-security)
8. [Common Vulnerabilities](#common-vulnerabilities)
9. [Security Checklist](#security-checklist)

## Authentication Best Practices

### Password Management

#### DO:
```java
// Use strong password validation
@Service
public class PasswordValidator {
    public void validatePassword(String password) {
        if (password.length() < 12) {
            throw new WeakPasswordException("Password must be at least 12 characters");
        }
        
        // Check password entropy
        double entropy = calculateEntropy(password);
        if (entropy < 50) {
            throw new WeakPasswordException("Password is too predictable");
        }
        
        // Check against breach databases
        if (breachChecker.isBreached(password)) {
            throw new BreachedPasswordException("Password found in data breach");
        }
    }
}
```

#### DON'T:
```java
// Don't use weak validation
if (password.length() >= 6) { // Too short
    // Don't store plain text passwords
    user.setPassword(password); // NEVER do this
}
```

### Multi-Factor Authentication

#### Implementation:
```java
@Service
public class MfaService {
    
    @Transactional
    public void enableMfa(User user) {
        // Generate secure secret
        String secret = generateSecureSecret();
        
        // Encrypt secret before storage
        String encryptedSecret = encryptionService.encrypt(secret);
        user.setMfaSecret(encryptedSecret);
        
        // Generate backup codes
        List<String> backupCodes = generateBackupCodes(8);
        user.setBackupCodes(hashBackupCodes(backupCodes));
        
        // Audit the action
        auditService.logSecurityEvent(
            SecurityEventType.MFA_ENABLED,
            user.getUsername()
        );
    }
    
    public boolean verifyTotp(User user, String code) {
        // Rate limit verification attempts
        rateLimiter.checkLimit(user.getId(), "mfa_verify");
        
        // Decrypt secret
        String secret = encryptionService.decrypt(user.getMfaSecret());
        
        // Verify with time window
        return totpVerifier.verify(secret, code, 1); // Allow 1 window drift
    }
}
```

### Session Management

#### Secure Session Configuration:
```yaml
spring:
  session:
    store-type: redis
    timeout: 30m
    redis:
      flush-mode: on-save
      namespace: mcp:session
      
security:
  sessions:
    maximum-sessions: 3
    maximum-sessions-prevents-login: false
    session-fixation-protection: migrateSession
    invalid-session-url: /session-expired
```

#### Session Security Implementation:
```java
@Component
public class SessionSecurityConfig {
    
    @EventListener
    public void handleSessionCreated(HttpSessionEvent event) {
        HttpSession session = event.getSession();
        
        // Set secure session attributes
        session.setAttribute("created", Instant.now());
        session.setAttribute("ip", getClientIp());
        session.setMaxInactiveInterval(1800); // 30 minutes
        
        // Generate CSRF token
        String csrfToken = generateCsrfToken();
        session.setAttribute("csrf", csrfToken);
    }
    
    @Scheduled(fixedDelay = 300000) // Every 5 minutes
    public void cleanupExpiredSessions() {
        sessionRepository.cleanupExpiredSessions();
    }
}
```

## Authorization Guidelines

### Role-Based Access Control (RBAC)

#### Proper Role Hierarchy:
```java
@Configuration
public class RoleHierarchyConfig {
    
    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("""
            ROLE_SUPER_ADMIN > ROLE_ADMIN
            ROLE_ADMIN > ROLE_MANAGER
            ROLE_MANAGER > ROLE_USER
            ROLE_USER > ROLE_GUEST
            """);
        return hierarchy;
    }
}
```

#### Fine-Grained Permissions:
```java
@Service
public class PermissionEvaluator {
    
    public boolean hasPermission(Authentication auth, Object targetDomainObject, Object permission) {
        // Check ownership
        if (targetDomainObject instanceof OwnedResource) {
            OwnedResource resource = (OwnedResource) targetDomainObject;
            if (!resource.getOwnerId().equals(auth.getName())) {
                return false;
            }
        }
        
        // Check organization context
        OrganizationContext context = OrganizationContext.current();
        if (!hasOrganizationAccess(auth, context)) {
            return false;
        }
        
        // Check specific permission
        return hasGrantedPermission(auth, targetDomainObject, permission);
    }
}
```

### Method Security

#### DO:
```java
@RestController
@PreAuthorize("isAuthenticated()")
public class SecureController {
    
    @GetMapping("/api/users/{id}")
    @PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.id")
    public User getUser(@PathVariable Long id) {
        return userService.findById(id);
    }
    
    @PostMapping("/api/documents")
    @PreAuthorize("hasPermission(#document, 'CREATE')")
    @PostFilter("hasPermission(filterObject, 'READ')")
    public List<Document> createDocument(@RequestBody Document document) {
        return documentService.create(document);
    }
}
```

#### DON'T:
```java
// Don't check permissions in controller
@GetMapping("/api/users/{id}")
public User getUser(@PathVariable Long id, Authentication auth) {
    // Don't do manual checks in controller
    if (!auth.getAuthorities().contains("ROLE_ADMIN")) {
        throw new AccessDeniedException("Not authorized");
    }
    return userService.findById(id);
}
```

## Token Security

### JWT Best Practices

#### Secure Token Generation:
```java
@Service
public class JwtTokenService {
    
    public String generateToken(User user) {
        Instant now = Instant.now();
        Instant expiry = now.plus(1, ChronoUnit.HOURS);
        
        return Jwts.builder()
            .setIssuer(jwtProperties.getIssuer())
            .setSubject(user.getId().toString())
            .setAudience(jwtProperties.getAudience())
            .setIssuedAt(Date.from(now))
            .setExpiration(Date.from(expiry))
            .setNotBefore(Date.from(now))
            .claim("username", user.getUsername())
            .claim("org", user.getOrganizationId())
            .claim("roles", user.getRoles())
            .claim("jti", UUID.randomUUID().toString()) // Unique token ID
            .signWith(privateKey, SignatureAlgorithm.RS256)
            .compact();
    }
    
    public void validateToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .requireIssuer(jwtProperties.getIssuer())
                .requireAudience(jwtProperties.getAudience())
                .build()
                .parseClaimsJws(token)
                .getBody();
            
            // Check if token is blacklisted
            if (tokenBlacklist.isBlacklisted(claims.getId())) {
                throw new JwtException("Token has been revoked");
            }
            
            // Additional validation
            validateTokenClaims(claims);
            
        } catch (JwtException e) {
            auditService.logSecurityEvent(
                SecurityEventType.INVALID_TOKEN,
                token,
                e.getMessage()
            );
            throw new InvalidTokenException("Invalid token", e);
        }
    }
}
```

### Token Storage

#### Client-Side (Browser):
```javascript
// DO: Store in httpOnly cookie
document.cookie = "auth-token=; HttpOnly; Secure; SameSite=Strict";

// DON'T: Store in localStorage or sessionStorage
localStorage.setItem('token', token); // Vulnerable to XSS
```

#### Server-Side:
```java
@Configuration
public class CookieConfig {
    
    @Bean
    public CookieSameSiteSupplier cookieSameSiteSupplier() {
        return CookieSameSiteSupplier.ofStrict();
    }
    
    public ResponseCookie createAuthCookie(String token) {
        return ResponseCookie.from("auth-token", token)
            .httpOnly(true)
            .secure(true)
            .sameSite("Strict")
            .maxAge(Duration.ofHours(1))
            .path("/")
            .build();
    }
}
```

## API Security

### Input Validation

#### Comprehensive Validation:
```java
@RestController
@Validated
public class UserController {
    
    @PostMapping("/api/users")
    public User createUser(@Valid @RequestBody CreateUserRequest request) {
        // Validate business rules
        validateBusinessRules(request);
        
        // Sanitize input
        request.setUsername(sanitizer.sanitize(request.getUsername()));
        request.setEmail(sanitizer.sanitizeEmail(request.getEmail()));
        
        return userService.create(request);
    }
    
    @Data
    public static class CreateUserRequest {
        @NotBlank
        @Size(min = 3, max = 50)
        @Pattern(regexp = "^[a-zA-Z0-9_-]+$")
        private String username;
        
        @NotBlank
        @Email
        private String email;
        
        @NotBlank
        @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
        private String password;
        
        @Valid
        @NotNull
        private OrganizationReference organization;
    }
}
```

### Rate Limiting

#### Implementation:
```java
@Component
public class RateLimitingFilter extends OncePerRequestFilter {
    
    private final RateLimiter rateLimiter;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response,
                                  FilterChain chain) throws ServletException, IOException {
        
        String key = getKey(request);
        
        if (!rateLimiter.tryAcquire(key)) {
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setHeader("Retry-After", "60");
            response.getWriter().write("""
                {
                    "error": "Rate limit exceeded",
                    "retryAfter": 60
                }
                """);
            return;
        }
        
        chain.doFilter(request, response);
    }
    
    private String getKey(HttpServletRequest request) {
        // Use authenticated user if available
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated()) {
            return "user:" + auth.getName();
        }
        
        // Fall back to IP address
        return "ip:" + getClientIp(request);
    }
}
```

### CORS Configuration

#### Secure CORS Setup:
```java
@Configuration
public class CorsConfig {
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // Specify allowed origins explicitly
        configuration.setAllowedOrigins(Arrays.asList(
            "https://app.mcp-platform.com",
            "https://admin.mcp-platform.com"
        ));
        
        // Specify allowed methods
        configuration.setAllowedMethods(Arrays.asList(
            "GET", "POST", "PUT", "DELETE", "OPTIONS"
        ));
        
        // Specify allowed headers
        configuration.setAllowedHeaders(Arrays.asList(
            "Authorization",
            "Content-Type",
            "X-Requested-With",
            "X-Organization-ID"
        ));
        
        // Expose necessary headers
        configuration.setExposedHeaders(Arrays.asList(
            "X-Total-Count",
            "X-Page-Number"
        ));
        
        // Allow credentials
        configuration.setAllowCredentials(true);
        
        // Cache preflight response
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", configuration);
        
        return source;
    }
}
```

## Data Protection

### Encryption at Rest

#### Field-Level Encryption:
```java
@Entity
public class SensitiveData {
    
    @Id
    private Long id;
    
    @Convert(converter = EncryptedStringConverter.class)
    @Column(columnDefinition = "TEXT")
    private String ssn;
    
    @Convert(converter = EncryptedStringConverter.class)
    @Column(columnDefinition = "TEXT")
    private String creditCardNumber;
}

@Converter
public class EncryptedStringConverter implements AttributeConverter<String, String> {
    
    @Autowired
    private EncryptionService encryptionService;
    
    @Override
    public String convertToDatabaseColumn(String attribute) {
        return attribute != null ? encryptionService.encrypt(attribute) : null;
    }
    
    @Override
    public String convertToEntityAttribute(String dbData) {
        return dbData != null ? encryptionService.decrypt(dbData) : null;
    }
}
```

### Audit Logging

#### Comprehensive Audit Trail:
```java
@Aspect
@Component
public class AuditAspect {
    
    @Around("@annotation(Audited)")
    public Object audit(ProceedingJoinPoint joinPoint) throws Throwable {
        AuditLog log = new AuditLog();
        log.setTimestamp(Instant.now());
        log.setUser(getCurrentUser());
        log.setAction(joinPoint.getSignature().getName());
        log.setResource(getResourceType(joinPoint));
        log.setIpAddress(getClientIp());
        
        try {
            Object result = joinPoint.proceed();
            log.setStatus("SUCCESS");
            log.setResult(sanitizeResult(result));
            return result;
        } catch (Exception e) {
            log.setStatus("FAILURE");
            log.setError(e.getMessage());
            throw e;
        } finally {
            auditService.save(log);
        }
    }
}
```

## Infrastructure Security

### Network Security

#### Security Groups:
```hcl
# Terraform example
resource "aws_security_group" "app_security_group" {
  name        = "mcp-security-app"
  description = "Security group for MCP Security application"
  
  # Allow inbound HTTPS only
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"] # Internal VPC only
  }
  
  # Allow health checks from load balancer
  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  
  # Deny all other inbound
  # Allow all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

### Secret Management

#### Using HashiCorp Vault:
```java
@Configuration
public class VaultConfig {
    
    @Bean
    public VaultTemplate vaultTemplate() {
        VaultEndpoint endpoint = VaultEndpoint.from(new URI("https://vault.internal:8200"));
        
        ClientAuthentication auth = new TokenAuthentication(getVaultToken());
        
        return new VaultTemplate(endpoint, auth);
    }
    
    @Component
    public class SecretService {
        
        @Autowired
        private VaultTemplate vault;
        
        public String getDatabasePassword() {
            VaultResponseSupport<Map> response = vault.read("secret/database");
            return (String) response.getData().get("password");
        }
        
        public void rotateApiKey(String service) {
            String newKey = generateSecureApiKey();
            
            vault.write("secret/api-keys/" + service, 
                Collections.singletonMap("key", newKey));
            
            auditService.logSecurityEvent(
                SecurityEventType.SECRET_ROTATED,
                service
            );
        }
    }
}
```

## Development Security

### Secure Coding Practices

#### Dependency Scanning:
```xml
<!-- pom.xml -->
<plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>8.0.0</version>
    <configuration>
        <failBuildOnCVSS>7</failBuildOnCVSS>
        <suppressionFile>dependency-check-suppressions.xml</suppressionFile>
    </configuration>
    <executions>
        <execution>
            <goals>
                <goal>check</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

#### Code Analysis:
```java
// SonarQube rules
@SuppressWarnings("squid:S2068") // Not a hardcoded password
private static final String PASSWORD_PATTERN = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{12,}$";

// SpotBugs annotations
@SuppressFBWarnings(value = "PREDICTABLE_RANDOM", justification = "Not used for security")
private final Random random = new Random();

// Secure random for security
private final SecureRandom secureRandom = new SecureRandom();
```

### Security Testing

#### Integration Tests:
```java
@SpringBootTest
@AutoConfigureMockMvc
public class SecurityIntegrationTest {
    
    @Test
    public void testUnauthorizedAccess() throws Exception {
        mockMvc.perform(get("/api/admin/users"))
            .andExpect(status().isUnauthorized());
    }
    
    @Test
    @WithMockUser(roles = "USER")
    public void testInsufficientPrivileges() throws Exception {
        mockMvc.perform(delete("/api/admin/users/123"))
            .andExpect(status().isForbidden());
    }
    
    @Test
    public void testSqlInjection() throws Exception {
        String maliciousInput = "'; DROP TABLE users; --";
        
        mockMvc.perform(get("/api/users")
                .param("name", maliciousInput))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("Invalid input"));
    }
    
    @Test
    public void testXssProtection() throws Exception {
        String xssPayload = "<script>alert('XSS')</script>";
        
        mockMvc.perform(post("/api/comments")
                .content(xssPayload)
                .contentType(MediaType.TEXT_PLAIN))
            .andExpect(status().isBadRequest());
    }
}
```

## Common Vulnerabilities

### SQL Injection Prevention

#### DO:
```java
// Use parameterized queries
@Repository
public class UserRepository {
    
    @Query("SELECT u FROM User u WHERE u.email = :email")
    Optional<User> findByEmail(@Param("email") String email);
    
    // Use JPA Criteria API for dynamic queries
    public List<User> searchUsers(String name, String email) {
        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<User> query = cb.createQuery(User.class);
        Root<User> user = query.from(User.class);
        
        List<Predicate> predicates = new ArrayList<>();
        if (name != null) {
            predicates.add(cb.like(user.get("name"), "%" + name + "%"));
        }
        if (email != null) {
            predicates.add(cb.equal(user.get("email"), email));
        }
        
        query.where(predicates.toArray(new Predicate[0]));
        return entityManager.createQuery(query).getResultList();
    }
}
```

#### DON'T:
```java
// Never concatenate user input
String query = "SELECT * FROM users WHERE email = '" + email + "'";
```

### XSS Prevention

#### Output Encoding:
```java
@Component
public class XssFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain chain) throws ServletException, IOException {
        
        XssRequestWrapper wrappedRequest = new XssRequestWrapper(request);
        
        // Set security headers
        response.setHeader("X-XSS-Protection", "1; mode=block");
        response.setHeader("X-Content-Type-Options", "nosniff");
        
        chain.doFilter(wrappedRequest, response);
    }
}

public class XssRequestWrapper extends HttpServletRequestWrapper {
    
    @Override
    public String getParameter(String name) {
        String value = super.getParameter(name);
        return value != null ? HtmlUtils.htmlEscape(value) : null;
    }
    
    @Override
    public String[] getParameterValues(String name) {
        String[] values = super.getParameterValues(name);
        if (values != null) {
            return Arrays.stream(values)
                .map(HtmlUtils::htmlEscape)
                .toArray(String[]::new);
        }
        return null;
    }
}
```

### CSRF Protection

#### Configuration:
```java
@Configuration
public class CsrfConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .ignoringRequestMatchers("/api/webhooks/**") // External webhooks
            )
            .build();
    }
    
    @Component
    public class CsrfTokenLogger implements Filter {
        
        @Override
        public void doFilter(ServletRequest request, ServletResponse response,
                           FilterChain chain) throws IOException, ServletException {
            
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            CsrfToken csrf = (CsrfToken) httpRequest.getAttribute(CsrfToken.class.getName());
            
            if (csrf != null) {
                // Log CSRF token generation
                logger.debug("CSRF token generated: {}", csrf.getToken());
            }
            
            chain.doFilter(request, response);
        }
    }
}
```

## Security Checklist

### Pre-Deployment Checklist

- [ ] All dependencies updated to latest secure versions
- [ ] Security scanning performed (OWASP dependency check)
- [ ] Code analysis completed (SonarQube, SpotBugs)
- [ ] Penetration testing performed
- [ ] SSL/TLS certificates valid and properly configured
- [ ] Secrets removed from code and configuration files
- [ ] Audit logging enabled and tested
- [ ] Rate limiting configured
- [ ] CORS properly configured
- [ ] Security headers implemented
- [ ] Input validation on all endpoints
- [ ] Output encoding for all user-generated content
- [ ] Authentication required for all non-public endpoints
- [ ] Authorization checks on all protected resources
- [ ] Session timeout configured
- [ ] Account lockout mechanism tested
- [ ] Password policy enforced
- [ ] MFA available and tested
- [ ] Token expiration and refresh tested
- [ ] Error messages don't leak sensitive information

### Production Monitoring

- [ ] Security event monitoring configured
- [ ] Intrusion detection system active
- [ ] Log aggregation and analysis enabled
- [ ] Alerting configured for security events
- [ ] Regular security audits scheduled
- [ ] Incident response plan documented
- [ ] Backup and recovery procedures tested
- [ ] Compliance requirements verified

### Regular Maintenance

- [ ] Weekly dependency updates check
- [ ] Monthly security patch review
- [ ] Quarterly penetration testing
- [ ] Annual security audit
- [ ] Regular secret rotation
- [ ] Access review and cleanup
- [ ] Security training for development team