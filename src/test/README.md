# Security Module Tests

This directory contains comprehensive tests for the MCP Security module, covering authentication, authorization, and security features.

## Test Coverage

### Unit Tests

1. **AuthorizationAspectTest**
   - Tests method-level security annotations (@RequiresPermission, @RequiresRole)
   - Validates permission checking logic
   - Tests organization-level access control
   - Verifies audit logging on authorization events

2. **JwtAuthenticationFilterTest**
   - Tests JWT token extraction from requests
   - Validates authentication flow
   - Tests error handling for invalid tokens
   - Verifies security context population

3. **JwtServiceTest**
   - Tests JWT token generation and validation
   - Validates token claims extraction
   - Tests token expiration handling
   - Verifies token refresh functionality

4. **SecurityAuditLoggerTest**
   - Tests security event logging
   - Validates audit log format and content
   - Tests all security event types
   - Verifies sensitive data is not logged

### Integration Tests

1. **SecurityAnnotationIntegrationTest**
   - Tests security annotations in Spring context
   - Validates AOP integration
   - Tests method interception
   - Verifies end-to-end security flow

## Running Tests

### Run all tests in the security module:
```bash
cd mcp-security
mvn test
```

### Run specific test class:
```bash
mvn test -Dtest=AuthorizationAspectTest
```

### Run with coverage:
```bash
mvn test jacoco:report
# Coverage report will be in target/site/jacoco/index.html
```

### Run integration tests only:
```bash
mvn test -Dtest=*IntegrationTest
```

## Test Configuration

### Mock Services
- **MockUserDetailsService**: In-memory user store for testing
- Pre-configured test users:
  - `user1`: Regular user with basic permissions
  - `user2`: Admin user with elevated permissions
  - `user3`: Multi-organization user

### Test Security Configuration
- **TestSecurityConfiguration**: Minimal Spring Security setup
- Disables CSRF for testing
- Permits all requests by default
- Enables method security annotations

## Writing New Tests

### Unit Test Template
```java
@ExtendWith(MockitoExtension.class)
class YourServiceTest {
    @Mock
    private DependencyService dependency;
    
    @InjectMocks
    private YourService service;
    
    @Test
    void testMethod_WithValidInput_ShouldSucceed() {
        // Given
        // When
        // Then
    }
}
```

### Integration Test Template
```java
@SpringBootTest
@ActiveProfiles("test")
class YourIntegrationTest {
    @Autowired
    private YourService service;
    
    @MockBean
    private ExternalService externalService;
    
    @Test
    void testEndToEnd() {
        // Test full flow
    }
}
```

## Common Test Scenarios

### Testing with Authentication
```java
private void authenticateUser(McpUser user) {
    UsernamePasswordAuthenticationToken auth = 
        new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
    SecurityContextHolder.getContext().setAuthentication(auth);
}
```

### Testing Authorization
```java
@Test
void testRequiresPermission() {
    // Given
    authenticateUser(testUser);
    when(authorizationService.hasPermission(testUser, permission, orgId))
        .thenReturn(true);
    
    // When
    service.securedMethod(orgId);
    
    // Then - no exception thrown
}
```

### Testing JWT Tokens
```java
@Test
void testJwtGeneration() {
    // Given
    McpUser user = createTestUser();
    
    // When
    String token = jwtService.generateToken(user);
    
    // Then
    assertNotNull(token);
    assertEquals(user.getId(), jwtService.extractUserId(token));
}
```

## Troubleshooting

### Common Issues

1. **NoSuchBeanDefinitionException**
   - Ensure @MockBean or @Bean annotations are present
   - Check component scanning configuration

2. **Authentication is null**
   - Set up SecurityContext before test
   - Use authenticateUser() helper method

3. **AOP not working**
   - Ensure @EnableAspectJAutoProxy in test config
   - Check that aspects are in component scan path

### Debug Tips

1. Enable debug logging:
```properties
logging.level.com.zamaz.mcp.security=DEBUG
logging.level.org.springframework.security=DEBUG
```

2. Use MockMvc for web layer tests:
```java
@AutoConfigureMockMvc
@Test
void testSecuredEndpoint() throws Exception {
    mockMvc.perform(get("/api/secured")
        .header("Authorization", "Bearer " + token))
        .andExpect(status().isOk());
}
```

## Continuous Integration

Tests are automatically run on:
- Every push to feature branches
- Pull request creation/update
- Pre-merge validation

Failed tests will block deployment to ensure security features are working correctly.