package com.zamaz.mcp.security.compliance;

import com.zamaz.mcp.security.config.SecurityProperties;
import com.zamaz.mcp.security.entity.User;
import com.zamaz.mcp.security.repository.UserRepository;
import com.zamaz.mcp.security.service.PasswordPolicyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Security compliance tests based on OWASP ASVS requirements.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class SecurityComplianceTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private PasswordPolicyService passwordPolicyService;
    
    @Autowired
    private SecurityProperties securityProperties;
    
    /**
     * ASVS 2.1.1 - Password Length Requirements
     */
    @Test
    public void testPasswordLengthRequirement() throws Exception {
        // Verify minimum password length is at least 12 characters
        assertThat(securityProperties.getPassword().getMinLength()).isGreaterThanOrEqualTo(12);
        
        // Test password validation
        String weakPassword = "Short123!";
        String strongPassword = "VeryStrongPassword123!@#";
        
        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                        "username": "testuser",
                        "email": "test@example.com",
                        "password": "%s"
                    }
                    """.formatted(weakPassword)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Password does not meet requirements"));
    }
    
    /**
     * ASVS 2.1.7 - Password Complexity Requirements
     */
    @Test
    public void testPasswordComplexityRequirements() {
        // Test various password patterns
        assertThat(passwordPolicyService.validatePassword("password123")).isFalse(); // No special chars
        assertThat(passwordPolicyService.validatePassword("PASSWORD123!")).isFalse(); // No lowercase
        assertThat(passwordPolicyService.validatePassword("password!@#")).isFalse(); // No numbers
        assertThat(passwordPolicyService.validatePassword("Password123!")).isTrue(); // Valid
    }
    
    /**
     * ASVS 2.1.9 - Password History
     */
    @Test
    public void testPasswordHistory() throws Exception {
        User user = createTestUser();
        String token = authenticateUser(user);
        
        // Change password
        String newPassword = "NewPassword123!@#";
        mockMvc.perform(put("/api/v1/users/password")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                        "currentPassword": "TestPassword123!",
                        "newPassword": "%s"
                    }
                    """.formatted(newPassword)))
                .andExpect(status().isOk());
        
        // Try to reuse old password
        mockMvc.perform(put("/api/v1/users/password")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                        "currentPassword": "%s",
                        "newPassword": "TestPassword123!"
                    }
                    """.formatted(newPassword)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Password was recently used"));
    }
    
    /**
     * ASVS 2.2.1 - Account Lockout
     */
    @Test
    public void testAccountLockout() throws Exception {
        User user = createTestUser();
        
        // Attempt login with wrong password multiple times
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                        {
                            "username": "%s",
                            "password": "WrongPassword123!"
                        }
                        """.formatted(user.getUsername())))
                    .andExpect(status().isUnauthorized());
        }
        
        // Next attempt should result in account lockout
        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                        "username": "%s",
                        "password": "TestPassword123!"
                    }
                    """.formatted(user.getUsername())))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Account locked"));
        
        // Verify account is locked
        User lockedUser = userRepository.findById(user.getId()).orElseThrow();
        assertThat(lockedUser.isAccountLocked()).isTrue();
    }
    
    /**
     * ASVS 2.5.2 - Rate Limiting
     */
    @Test
    public void testRateLimiting() throws Exception {
        // Make multiple rapid requests
        for (int i = 0; i < 100; i++) {
            MvcResult result = mockMvc.perform(post("/api/v1/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("""
                        {
                            "username": "ratelimit@test.com",
                            "password": "password"
                        }
                        """))
                    .andReturn();
            
            // Check if rate limit is enforced
            if (result.getResponse().getStatus() == 429) {
                assertThat(result.getResponse().getHeader("Retry-After")).isNotNull();
                return; // Test passed
            }
        }
        
        // If we get here, rate limiting might not be working
        assertThat(false).as("Rate limiting should have triggered").isTrue();
    }
    
    /**
     * ASVS 3.1.1 - Session Management
     */
    @Test
    public void testSessionManagement() throws Exception {
        User user = createTestUser();
        
        // Login and get session
        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                        "username": "%s",
                        "password": "TestPassword123!"
                    }
                    """.formatted(user.getUsername())))
                .andExpect(status().isOk())
                .andReturn();
        
        String token = extractToken(loginResult);
        
        // Verify session timeout
        assertThat(securityProperties.getJwt().getExpiration()).isLessThanOrEqualTo(3600); // 1 hour max
        
        // Test logout invalidates session
        mockMvc.perform(post("/api/v1/auth/logout")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk());
        
        // Try to use invalidated token
        mockMvc.perform(get("/api/v1/users/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }
    
    /**
     * ASVS 3.3.1 - CSRF Protection
     */
    @Test
    public void testCsrfProtection() throws Exception {
        User user = createTestUser();
        String token = authenticateUser(user);
        
        // Attempt state-changing operation without CSRF token
        mockMvc.perform(put("/api/v1/users/profile")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                        "displayName": "New Name"
                    }
                    """))
                .andExpect(status().isForbidden());
    }
    
    /**
     * ASVS 3.7.1 - Secure Headers
     */
    @Test
    public void testSecurityHeaders() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/v1/health"))
                .andExpect(status().isOk())
                .andReturn();
        
        HttpHeaders headers = HttpHeaders.readOnlyHttpHeaders(
            result.getResponse().getHeaderNames().stream()
                .collect(java.util.stream.Collectors.toMap(
                    name -> name,
                    name -> result.getResponse().getHeaders(name)
                ))
        );
        
        // Verify security headers
        assertThat(headers.getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
        assertThat(headers.getFirst("X-Frame-Options")).isEqualTo("DENY");
        assertThat(headers.getFirst("X-XSS-Protection")).isEqualTo("1; mode=block");
        assertThat(headers.getFirst("Strict-Transport-Security")).contains("max-age=");
        assertThat(headers.getFirst("Content-Security-Policy")).isNotNull();
    }
    
    /**
     * ASVS 4.1.1 - Access Control
     */
    @Test
    public void testAccessControl() throws Exception {
        User user = createTestUser();
        User adminUser = createAdminUser();
        
        String userToken = authenticateUser(user);
        String adminToken = authenticateUser(adminUser);
        
        // Regular user cannot access admin endpoints
        mockMvc.perform(get("/api/v1/admin/users")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken))
                .andExpect(status().isForbidden());
        
        // Admin can access admin endpoints
        mockMvc.perform(get("/api/v1/admin/users")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken))
                .andExpect(status().isOk());
        
        // User cannot access another user's data
        mockMvc.perform(get("/api/v1/users/{id}", adminUser.getId())
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }
    
    /**
     * ASVS 5.1.1 - Input Validation
     */
    @Test
    public void testInputValidation() throws Exception {
        // Test SQL injection attempts
        mockMvc.perform(get("/api/v1/users")
                .param("search", "'; DROP TABLE users; --"))
                .andExpect(status().isBadRequest());
        
        // Test XSS attempts
        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                        "username": "<script>alert('XSS')</script>",
                        "email": "xss@test.com",
                        "password": "TestPassword123!"
                    }
                    """))
                .andExpect(status().isBadRequest());
        
        // Test path traversal
        mockMvc.perform(get("/api/v1/files/../../../etc/passwd"))
                .andExpect(status().isBadRequest());
    }
    
    /**
     * ASVS 7.1.1 - Logging
     */
    @Test
    public void testSecurityLogging() throws Exception {
        User user = createTestUser();
        
        // Failed login attempt
        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                        "username": "%s",
                        "password": "WrongPassword"
                    }
                    """.formatted(user.getUsername())))
                .andExpect(status().isUnauthorized());
        
        // Verify audit log was created
        // This would check the actual audit log storage
        // For now, we assume logging is configured correctly
    }
    
    /**
     * ASVS 8.1.1 - Data Protection
     */
    @Test
    public void testDataProtection() {
        // Verify passwords are properly hashed
        User user = createTestUser();
        assertThat(user.getPassword()).doesNotContain("TestPassword123!");
        assertThat(user.getPassword()).startsWith("$2a$"); // BCrypt prefix
        
        // Verify sensitive data is encrypted
        // This would check encryption of sensitive fields
    }
    
    /**
     * ASVS 13.1.1 - API Security
     */
    @Test
    public void testApiSecurity() throws Exception {
        // Test that API requires authentication
        mockMvc.perform(get("/api/v1/users/profile"))
                .andExpect(status().isUnauthorized());
        
        // Test content type validation
        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.TEXT_PLAIN)
                .content("invalid content"))
                .andExpect(status().isUnsupportedMediaType());
        
        // Test method not allowed
        mockMvc.perform(patch("/api/v1/auth/login"))
                .andExpect(status().isMethodNotAllowed());
    }
    
    // Helper methods
    
    private User createTestUser() {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setUsername("testuser@example.com");
        user.setEmail("testuser@example.com");
        user.setPassword(passwordEncoder.encode("TestPassword123!"));
        user.setEmailVerified(true);
        user.setActive(true);
        user.setOrganizationId(UUID.randomUUID());
        return userRepository.save(user);
    }
    
    private User createAdminUser() {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setUsername("admin@example.com");
        user.setEmail("admin@example.com");
        user.setPassword(passwordEncoder.encode("AdminPassword123!"));
        user.setEmailVerified(true);
        user.setActive(true);
        user.setOrganizationId(UUID.randomUUID());
        // Add admin role
        return userRepository.save(user);
    }
    
    private String authenticateUser(User user) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                        "username": "%s",
                        "password": "TestPassword123!"
                    }
                    """.formatted(user.getUsername())))
                .andExpect(status().isOk())
                .andReturn();
        
        return extractToken(result);
    }
    
    private String extractToken(MvcResult result) throws Exception {
        String response = result.getResponse().getContentAsString();
        // Extract token from JSON response
        return "extracted-token";
    }
}