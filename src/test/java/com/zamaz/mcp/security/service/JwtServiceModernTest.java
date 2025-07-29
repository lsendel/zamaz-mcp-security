package com.zamaz.mcp.security.service;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Test class for modern JWT service implementation using JJWT 0.12.x patterns.
 */
@ExtendWith(MockitoExtension.class)
class JwtServiceModernTest {

    private JwtService jwtService;
    private static final String TEST_SECRET = "test-secret-key-that-is-long-enough-for-hmac-sha256-algorithm";
    private static final String TEST_ISSUER = "mcp-test-services";
    private static final long ACCESS_TOKEN_VALIDITY = 3600; // 1 hour
    private static final long REFRESH_TOKEN_VALIDITY = 86400; // 24 hours

    @BeforeEach
    void setUp() {
        jwtService = new JwtService(
                TEST_SECRET,
                ACCESS_TOKEN_VALIDITY,
                REFRESH_TOKEN_VALIDITY,
                TEST_ISSUER);
    }

    @Test
    void shouldGenerateAccessTokenWithModernPatterns() {
        // Given
        String subject = "test@example.com";
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", "USER");
        claims.put("organizationId", "org-123");

        // When
        String token = jwtService.generateAccessToken(subject, claims);

        // Then
        assertThat(token).isNotNull();
        assertThat(token.split("\\.")).hasSize(3); // JWT has 3 parts

        Claims parsedClaims = jwtService.validateToken(token);
        assertThat(parsedClaims.getSubject()).isEqualTo(subject);
        assertThat(parsedClaims.getIssuer()).isEqualTo(TEST_ISSUER);
        assertThat(parsedClaims.get("role")).isEqualTo("USER");
        assertThat(parsedClaims.get("organizationId")).isEqualTo("org-123");
    }

    @Test
    void shouldGenerateRefreshToken() {
        // Given
        String subject = "test@example.com";

        // When
        String refreshToken = jwtService.generateRefreshToken(subject);

        // Then
        assertThat(refreshToken).isNotNull();

        Claims claims = jwtService.validateToken(refreshToken);
        assertThat(claims.getSubject()).isEqualTo(subject);
        assertThat(claims.get("type")).isEqualTo("refresh");
    }

    @Test
    void shouldGenerateTokenWithCustomClaims() {
        // Given
        String subject = "user@example.com";
        String organizationId = "org-456";
        Set<String> roles = Set.of("ADMIN", "USER");
        Set<String> permissions = Set.of("read:debates", "write:debates", "admin:users");

        // When
        String token = jwtService.generateTokenWithClaims(subject, organizationId, roles, permissions);

        // Then
        assertThat(token).isNotNull();

        Claims claims = jwtService.validateToken(token);
        assertThat(claims.getSubject()).isEqualTo(subject);
        assertThat(claims.get("organizationId")).isEqualTo(organizationId);
        assertThat(claims.get("roles")).isEqualTo(roles);
        assertThat(claims.get("permissions")).isEqualTo(permissions);
        assertThat(claims.get("token_version")).isEqualTo("1.0");
        assertThat(claims.get("issuer_service")).isEqualTo("mcp-security");
    }

    @Test
    void shouldExtractSubjectFromToken() {
        // Given
        String expectedSubject = "test@example.com";
        String token = jwtService.generateAccessToken(expectedSubject, Map.of());

        // When
        String actualSubject = jwtService.getSubject(token);

        // Then
        assertThat(actualSubject).isEqualTo(expectedSubject);
    }

    @Test
    void shouldExtractClaimFromToken() {
        // Given
        String subject = "test@example.com";
        Map<String, Object> claims = Map.of("customClaim", "customValue");
        String token = jwtService.generateAccessToken(subject, claims);

        // When
        Object claimValue = jwtService.getClaim(token, "customClaim");

        // Then
        assertThat(claimValue).isEqualTo("customValue");
    }

    @Test
    void shouldExtractTypedClaimFromToken() {
        // Given
        String subject = "test@example.com";
        Map<String, Object> claims = Map.of("numericClaim", 42);
        String token = jwtService.generateAccessToken(subject, claims);

        // When
        Integer claimValue = jwtService.getClaim(token, "numericClaim", Integer.class);

        // Then
        assertThat(claimValue).isEqualTo(42);
    }

    @Test
    void shouldDetectExpiredToken() throws InterruptedException {
        // Given - Create service with very short validity
        JwtService shortLivedService = new JwtService(
                TEST_SECRET,
                1, // 1 second
                1,
                TEST_ISSUER);
        String token = shortLivedService.generateAccessToken("test@example.com", Map.of());

        // Wait for token to expire
        Thread.sleep(1100);

        // When/Then
        assertThat(shortLivedService.isTokenExpired(token)).isTrue();
    }

    @Test
    void shouldValidateTokenWithExpectedSubject() {
        // Given
        String subject = "test@example.com";
        String token = jwtService.generateAccessToken(subject, Map.of());

        // When/Then
        assertThat(jwtService.validateToken(token, subject)).isTrue();
        assertThat(jwtService.validateToken(token, "different@example.com")).isFalse();
    }

    @Test
    void shouldThrowExceptionForInvalidToken() {
        // Given
        String invalidToken = "invalid.jwt.token";

        // When/Then
        assertThatThrownBy(() -> jwtService.validateToken(invalidToken))
                .isInstanceOf(JwtService.JwtValidationException.class)
                .hasMessageContaining("Token is malformed");
    }

    @Test
    void shouldThrowExceptionForTamperedToken() {
        // Given
        String validToken = jwtService.generateAccessToken("test@example.com", Map.of());
        String tamperedToken = validToken.substring(0, validToken.length() - 5) + "XXXXX";

        // When/Then
        assertThatThrownBy(() -> jwtService.validateToken(tamperedToken))
                .isInstanceOf(JwtService.JwtValidationException.class)
                .hasMessageContaining("Token validation failed");
    }

    @Test
    void shouldHandleNullClaims() {
        // Given
        String subject = "test@example.com";

        // When
        String token = jwtService.generateAccessToken(subject, null);

        // Then
        assertThat(token).isNotNull();
        Claims claims = jwtService.validateToken(token);
        assertThat(claims.getSubject()).isEqualTo(subject);
    }

    @Test
    void shouldHandleEmptyClaims() {
        // Given
        String subject = "test@example.com";
        Map<String, Object> emptyClaims = new HashMap<>();

        // When
        String token = jwtService.generateAccessToken(subject, emptyClaims);

        // Then
        assertThat(token).isNotNull();
        Claims claims = jwtService.validateToken(token);
        assertThat(claims.getSubject()).isEqualTo(subject);
    }

    @Test
    void shouldGenerateTokenWithNullOrganizationId() {
        // Given
        String subject = "test@example.com";
        Set<String> roles = Set.of("USER");

        // When
        String token = jwtService.generateTokenWithClaims(subject, null, roles, null);

        // Then
        assertThat(token).isNotNull();
        Claims claims = jwtService.validateToken(token);
        assertThat(claims.getSubject()).isEqualTo(subject);
        assertThat(claims.get("roles")).isEqualTo(roles);
        assertThat(claims.get("organizationId")).isNull();
        assertThat(claims.get("permissions")).isNull();
    }
}