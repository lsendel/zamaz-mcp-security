package com.zamaz.mcp.security.controller;

import com.zamaz.mcp.security.model.SessionInfo;
import com.zamaz.mcp.security.service.SessionManagementService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * REST controller for session management.
 * Provides endpoints for viewing and managing user sessions.
 */
@RestController
@RequestMapping("/api/v1/sessions")
@Tag(name = "Session Management", description = "User session management and monitoring")
@SecurityRequirement(name = "bearer-jwt")
public class SessionController {
    
    private static final Logger logger = LoggerFactory.getLogger(SessionController.class);
    
    @Autowired
    private SessionManagementService sessionService;
    
    /**
     * Get current session information
     */
    @GetMapping("/current")
    @Operation(summary = "Get current session", 
               description = "Returns information about the current user session")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Session information returned"),
        @ApiResponse(responseCode = "401", description = "Not authenticated")
    })
    public ResponseEntity<SessionInfo> getCurrentSession(
            HttpServletRequest request,
            Authentication authentication) {
        
        String sessionId = request.getSession(false) != null ? 
            request.getSession().getId() : null;
        
        if (sessionId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        
        return sessionService.getSession(sessionId)
            .map(ResponseEntity::ok)
            .orElse(ResponseEntity.notFound().build());
    }
    
    /**
     * Get all sessions for current user
     */
    @GetMapping("/my-sessions")
    @Operation(summary = "Get my sessions", 
               description = "Returns all active sessions for the current user")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Sessions returned"),
        @ApiResponse(responseCode = "401", description = "Not authenticated")
    })
    public ResponseEntity<List<SessionInfo>> getMySessions(Authentication authentication) {
        String userId = authentication.getName();
        List<SessionInfo> sessions = sessionService.getUserSessions(userId);
        
        return ResponseEntity.ok(sessions);
    }
    
    /**
     * Get sessions for a specific user (admin only)
     */
    @GetMapping("/user/{userId}")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('sessions:read')")
    @Operation(summary = "Get user sessions", 
               description = "Returns all active sessions for a specific user")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Sessions returned"),
        @ApiResponse(responseCode = "403", description = "Insufficient permissions")
    })
    public ResponseEntity<List<SessionInfo>> getUserSessions(
            @Parameter(description = "User ID") @PathVariable String userId) {
        
        List<SessionInfo> sessions = sessionService.getUserSessions(userId);
        return ResponseEntity.ok(sessions);
    }
    
    /**
     * Invalidate a specific session
     */
    @DeleteMapping("/{sessionId}")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('sessions:delete') or " +
                  "@sessionService.isSessionOwnedBy(#sessionId, authentication.name)")
    @Operation(summary = "Invalidate session", 
               description = "Invalidates a specific session")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Session invalidated"),
        @ApiResponse(responseCode = "404", description = "Session not found"),
        @ApiResponse(responseCode = "403", description = "Insufficient permissions")
    })
    public ResponseEntity<Void> invalidateSession(
            @Parameter(description = "Session ID") @PathVariable String sessionId,
            Authentication authentication) {
        
        logger.info("Session invalidation requested for {} by {}", sessionId, authentication.getName());
        
        if (!sessionService.isSessionValid(sessionId)) {
            return ResponseEntity.notFound().build();
        }
        
        sessionService.invalidateSession(sessionId);
        return ResponseEntity.noContent().build();
    }
    
    /**
     * Invalidate all sessions for current user
     */
    @PostMapping("/logout-all")
    @Operation(summary = "Logout from all sessions", 
               description = "Invalidates all sessions for the current user")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "All sessions invalidated"),
        @ApiResponse(responseCode = "401", description = "Not authenticated")
    })
    public ResponseEntity<Void> logoutAll(Authentication authentication) {
        String userId = authentication.getName();
        
        logger.info("Logout from all sessions requested by user: {}", userId);
        
        sessionService.invalidateUserSessions(userId);
        return ResponseEntity.noContent().build();
    }
    
    /**
     * Invalidate all sessions for a user (admin only)
     */
    @PostMapping("/user/{userId}/logout-all")
    @PreAuthorize("hasRole('ADMIN') or hasAuthority('sessions:delete')")
    @Operation(summary = "Force logout user", 
               description = "Invalidates all sessions for a specific user")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "All sessions invalidated"),
        @ApiResponse(responseCode = "403", description = "Insufficient permissions")
    })
    public ResponseEntity<Void> forceLogoutUser(
            @Parameter(description = "User ID") @PathVariable String userId,
            Authentication authentication) {
        
        logger.info("Force logout requested for user {} by {}", userId, authentication.getName());
        
        sessionService.invalidateUserSessions(userId);
        return ResponseEntity.noContent().build();
    }
    
    /**
     * Get session statistics for current user
     */
    @GetMapping("/stats")
    @Operation(summary = "Get session statistics", 
               description = "Returns session statistics for the current user")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Statistics returned"),
        @ApiResponse(responseCode = "401", description = "Not authenticated")
    })
    public ResponseEntity<Map<String, Object>> getSessionStats(Authentication authentication) {
        String userId = authentication.getName();
        
        Map<String, Object> stats = new HashMap<>();
        stats.put("userId", userId);
        stats.put("activeSessions", sessionService.getUserSessionCount(userId));
        stats.put("maxConcurrentSessions", 5); // From configuration
        
        List<SessionInfo> sessions = sessionService.getUserSessions(userId);
        if (!sessions.isEmpty()) {
            stats.put("oldestSession", sessions.get(sessions.size() - 1).getCreatedAt());
            stats.put("newestSession", sessions.get(0).getCreatedAt());
        }
        
        return ResponseEntity.ok(stats);
    }
    
    /**
     * Extend current session
     */
    @PostMapping("/extend")
    @Operation(summary = "Extend session", 
               description = "Extends the current session timeout")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Session extended"),
        @ApiResponse(responseCode = "401", description = "Not authenticated")
    })
    public ResponseEntity<Map<String, Object>> extendSession(
            HttpServletRequest request,
            @RequestParam(defaultValue = "1800") int additionalSeconds) {
        
        String sessionId = request.getSession(false) != null ? 
            request.getSession().getId() : null;
        
        if (sessionId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        
        sessionService.extendSession(sessionId, additionalSeconds);
        
        Map<String, Object> response = new HashMap<>();
        response.put("sessionId", sessionId);
        response.put("extendedBy", additionalSeconds);
        response.put("message", "Session extended successfully");
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Touch session (update last accessed time)
     */
    @PostMapping("/touch")
    @Operation(summary = "Touch session", 
               description = "Updates the last accessed time of the current session")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Session touched"),
        @ApiResponse(responseCode = "401", description = "Not authenticated")
    })
    public ResponseEntity<Void> touchSession(HttpServletRequest request) {
        String sessionId = request.getSession(false) != null ? 
            request.getSession().getId() : null;
        
        if (sessionId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        
        sessionService.touchSession(sessionId);
        return ResponseEntity.noContent().build();
    }
}