package com.zamaz.mcp.security.jwt;

import com.zamaz.mcp.security.model.McpUser;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    @Mock
    private JwtKeyManager keyManager;

    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService(keyManager);
        ReflectionTestUtils.setField(jwtService, "expiration", 86400000L);
        ReflectionTestUtils.setField(jwtService, "issuer", "test-issuer");

        // Mock key manager to return HMAC key for testing
        when(keyManager.getSigningAlgorithm()).thenReturn("HS256");
        when(keyManager.isUsingRSA()).thenReturn(false);

        // Initialize the service
        jwtService.init();
    }

    @Test
    void shouldGenerateValidToken() {
        // Given
        McpUser user = createTestUser();

        // When
        String token = jwtService.generateToken(user);

        // Then
        assertThat(token).isNotNull();
        assertThat(jwtService.isTokenValid(token)).isTrue();
    }

    @Test
    void shouldExtractUserIdFromToken() {
        // Given
        McpUser user = createTestUser();
        String token = jwtService.generateToken(user);

        // When
        String extractedUserId = jwtService.extractUserId(token);

        // Then
        assertThat(extractedUserId).isEqualTo(user.getId());
    }

    @Test
    void shouldExtractUsernameFromToken() {
        // Given
        McpUser user = createTestUser();
        String token = jwtService.generateToken(user);

        // When
        String extractedUsername = jwtService.extractUsername(token);

        // Then
        assertThat(extractedUsername).isEqualTo(user.getUsername());
    }

    @Test
    void shouldExtractOrganizationIdFromToken() {
        // Given
        McpUser user = createTestUser();
        String token = jwtService.generateToken(user);

        // When
        String extractedOrgId = jwtService.extractOrganizationId(token);

        // Then
        assertThat(extractedOrgId).isEqualTo(user.getCurrentOrganizationId());
    }

    @Test
    void shouldExtractRolesFromToken() {
        // Given
        McpUser user = createTestUser();
        String token = jwtService.generateToken(user);

        // When
        List<String> extractedRoles = jwtService.extractRoles(token);

        // Then
        assertThat(extractedRoles).containsExactlyInAnyOrderElementsOf(user.getRoles());
    }

    @Test
    void shouldRefreshTokenWithSameClaims() {
        // Given
        McpUser user = createTestUser();
        String originalToken = jwtService.generateToken(user);

        // When
        String refreshedToken = jwtService.refreshToken(originalToken);

        // Then
        assertThat(refreshedToken).isNotNull();
        assertThat(refreshedToken).isNotEqualTo(originalToken);
        assertThat(jwtService.isTokenValid(refreshedToken)).isTrue();

        // Verify claims are preserved
        assertThat(jwtService.extractUserId(refreshedToken)).isEqualTo(user.getId());
        assertThat(jwtService.extractUsername(refreshedToken)).isEqualTo(user.getUsername());
        assertThat(jwtService.extractOrganizationId(refreshedToken)).isEqualTo(user.getCurrentOrganizationId());
    }

    @Test
    void shouldExtractAllClaims() {
        // Given
        McpUser user = createTestUser();
        String token = jwtService.generateToken(user);

        // When
        Claims claims = jwtService.extractAllClaims(token);

        // Then
        assertThat(claims).isNotNull();
        assertThat(claims.getSubject()).isEqualTo(user.getId());
        assertThat(claims.get("username")).isEqualTo(user.getUsername());
        assertThat(claims.get("organizationId")).isEqualTo(user.getCurrentOrganizationId());
        assertThat(claims.getIssuer()).isEqualTo("test-issuer");
    }

    private McpUser createTestUser() {
        McpUser user = new McpUser();
        user.setId("test-user-id");
        user.setUsername("testuser");
        user.setEmail("test@example.com");
        user.setCurrentOrganizationId("test-org-id");
        user.setOrganizationIds(List.of("test-org-id", "another-org-id"));
        user.setRoles(List.of("ROLE_USER", "ROLE_MEMBER"));
        return user;
    }
}