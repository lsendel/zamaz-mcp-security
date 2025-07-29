package com.zamaz.mcp.security.filter;

import com.zamaz.mcp.security.jwt.JwtService;
import com.zamaz.mcp.security.model.McpUser;
import com.zamaz.mcp.security.service.UserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private UserDetailsService userDetailsService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @Mock
    private SecurityContext securityContext;

    @InjectMocks
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    private static final String VALID_TOKEN = "valid.jwt.token";
    private static final String INVALID_TOKEN = "invalid.jwt.token";
    private static final String USER_ID = "user123";
    private static final String USERNAME = "testuser";

    @BeforeEach
    void setUp() {
        SecurityContextHolder.setContext(securityContext);
    }

    @Test
    void doFilterInternal_WithValidToken_ShouldAuthenticateUser() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn("Bearer " + VALID_TOKEN);
        when(jwtService.isTokenValid(VALID_TOKEN)).thenReturn(true);
        when(jwtService.extractUserId(VALID_TOKEN)).thenReturn(USER_ID);
        
        McpUser user = createTestUser();
        when(userDetailsService.loadUserById(USER_ID)).thenReturn(user);
        when(securityContext.getAuthentication()).thenReturn(null);

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService).isTokenValid(VALID_TOKEN);
        verify(jwtService).extractUserId(VALID_TOKEN);
        verify(userDetailsService).loadUserById(USER_ID);
        verify(securityContext).setAuthentication(any(UsernamePasswordAuthenticationToken.class));
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_WithInvalidToken_ShouldNotAuthenticate() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn("Bearer " + INVALID_TOKEN);
        when(jwtService.isTokenValid(INVALID_TOKEN)).thenReturn(false);

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService).isTokenValid(INVALID_TOKEN);
        verify(userDetailsService, never()).loadUserById(anyString());
        verify(securityContext, never()).setAuthentication(any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_WithNoAuthorizationHeader_ShouldSkipAuthentication() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn(null);

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService, never()).isTokenValid(anyString());
        verify(userDetailsService, never()).loadUserById(anyString());
        verify(securityContext, never()).setAuthentication(any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_WithInvalidAuthorizationFormat_ShouldSkipAuthentication() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn("Basic sometoken");

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService, never()).isTokenValid(anyString());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_WithExistingAuthentication_ShouldSkipAuthentication() throws ServletException, IOException {
        // Given
        Authentication existingAuth = mock(Authentication.class);
        when(securityContext.getAuthentication()).thenReturn(existingAuth);
        when(existingAuth.isAuthenticated()).thenReturn(true);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + VALID_TOKEN);

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService, never()).isTokenValid(anyString());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_WhenUserNotFound_ShouldNotAuthenticate() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn("Bearer " + VALID_TOKEN);
        when(jwtService.isTokenValid(VALID_TOKEN)).thenReturn(true);
        when(jwtService.extractUserId(VALID_TOKEN)).thenReturn(USER_ID);
        when(userDetailsService.loadUserById(USER_ID)).thenReturn(null);
        when(securityContext.getAuthentication()).thenReturn(null);

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(userDetailsService).loadUserById(USER_ID);
        verify(securityContext, never()).setAuthentication(any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void doFilterInternal_WhenJwtServiceThrowsException_ShouldContinueFilter() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn("Bearer " + VALID_TOKEN);
        when(jwtService.isTokenValid(VALID_TOKEN)).thenThrow(new RuntimeException("JWT parsing error"));

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(filterChain).doFilter(request, response);
        verify(securityContext, never()).setAuthentication(any());
    }

    @Test
    void extractToken_WithValidBearerToken_ShouldReturnToken() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn("Bearer " + VALID_TOKEN);
        when(jwtService.isTokenValid(VALID_TOKEN)).thenReturn(false); // To prevent further processing

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService).isTokenValid(VALID_TOKEN);
    }

    @Test
    void extractToken_WithExtraSpaces_ShouldTrimToken() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn("Bearer   " + VALID_TOKEN + "  ");
        when(jwtService.isTokenValid(VALID_TOKEN)).thenReturn(false); // Expected trimmed token

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        verify(jwtService).isTokenValid(VALID_TOKEN);
    }

    @Test
    void doFilterInternal_ShouldSetAuthenticationDetails() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn("Bearer " + VALID_TOKEN);
        when(jwtService.isTokenValid(VALID_TOKEN)).thenReturn(true);
        when(jwtService.extractUserId(VALID_TOKEN)).thenReturn(USER_ID);
        
        McpUser user = createTestUser();
        when(userDetailsService.loadUserById(USER_ID)).thenReturn(user);
        when(securityContext.getAuthentication()).thenReturn(null);

        // Capture the authentication object
        UsernamePasswordAuthenticationToken[] capturedAuth = new UsernamePasswordAuthenticationToken[1];
        doAnswer(invocation -> {
            capturedAuth[0] = invocation.getArgument(0);
            return null;
        }).when(securityContext).setAuthentication(any(UsernamePasswordAuthenticationToken.class));

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        assertNotNull(capturedAuth[0]);
        assertEquals(user, capturedAuth[0].getPrincipal());
        assertNull(capturedAuth[0].getCredentials());
        assertTrue(capturedAuth[0].isAuthenticated());
        assertEquals(user.getAuthorities(), capturedAuth[0].getAuthorities());
    }

    private McpUser createTestUser() {
        McpUser user = new McpUser();
        user.setId(USER_ID);
        user.setUsername(USERNAME);
        user.setEmail("test@example.com");
        user.setOrganizationIds(Collections.singletonList("org123"));
        user.setCurrentOrganizationId("org123");
        return user;
    }
}