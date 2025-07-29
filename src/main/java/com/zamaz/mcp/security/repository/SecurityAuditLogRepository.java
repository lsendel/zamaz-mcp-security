package com.zamaz.mcp.security.repository;

import com.zamaz.mcp.security.entity.SecurityAuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Repository
public interface SecurityAuditLogRepository extends JpaRepository<SecurityAuditLog, UUID> {

    /**
     * Find audit logs by user ID.
     */
    Page<SecurityAuditLog> findByUserIdOrderByTimestampDesc(UUID userId, Pageable pageable);

    /**
     * Find audit logs by organization ID.
     */
    Page<SecurityAuditLog> findByOrganizationIdOrderByTimestampDesc(UUID organizationId, Pageable pageable);

    /**
     * Find audit logs by event type.
     */
    Page<SecurityAuditLog> findByEventTypeOrderByTimestampDesc(SecurityAuditLog.SecurityEventType eventType,
            Pageable pageable);

    /**
     * Find audit logs by event category.
     */
    Page<SecurityAuditLog> findByEventCategoryOrderByTimestampDesc(SecurityAuditLog.EventCategory eventCategory,
            Pageable pageable);

    /**
     * Find audit logs by outcome.
     */
    Page<SecurityAuditLog> findByOutcomeOrderByTimestampDesc(SecurityAuditLog.AuditOutcome outcome, Pageable pageable);

    /**
     * Find audit logs by risk level.
     */
    Page<SecurityAuditLog> findByRiskLevelOrderByTimestampDesc(SecurityAuditLog.RiskLevel riskLevel, Pageable pageable);

    /**
     * Find high-risk audit logs.
     */
    @Query("SELECT a FROM SecurityAuditLog a WHERE a.riskLevel IN ('HIGH', 'CRITICAL') ORDER BY a.timestamp DESC")
    Page<SecurityAuditLog> findHighRiskEvents(Pageable pageable);

    /**
     * Find audit logs with anomalies detected.
     */
    Page<SecurityAuditLog> findByAnomalyDetectedTrueOrderByTimestampDesc(Pageable pageable);

    /**
     * Find audit logs by IP address.
     */
    Page<SecurityAuditLog> findByIpAddressOrderByTimestampDesc(String ipAddress, Pageable pageable);

    /**
     * Find audit logs by session ID.
     */
    List<SecurityAuditLog> findBySessionIdOrderByTimestampDesc(String sessionId);

    /**
     * Find audit logs by correlation ID.
     */
    List<SecurityAuditLog> findByCorrelationIdOrderByTimestampDesc(String correlationId);

    /**
     * Find audit logs within time range.
     */
    @Query("SELECT a FROM SecurityAuditLog a WHERE a.timestamp BETWEEN :startTime AND :endTime ORDER BY a.timestamp DESC")
    Page<SecurityAuditLog> findByTimestampBetween(@Param("startTime") LocalDateTime startTime,
            @Param("endTime") LocalDateTime endTime,
            Pageable pageable);

    /**
     * Find failed authentication attempts.
     */
    @Query("SELECT a FROM SecurityAuditLog a WHERE a.eventType IN ('LOGIN_FAILURE', 'MFA_FAILURE') " +
            "AND a.timestamp >= :since ORDER BY a.timestamp DESC")
    List<SecurityAuditLog> findFailedAuthenticationsSince(@Param("since") LocalDateTime since);

    /**
     * Find failed authentication attempts by username.
     */
    @Query("SELECT a FROM SecurityAuditLog a WHERE a.eventType IN ('LOGIN_FAILURE', 'MFA_FAILURE') " +
            "AND a.username = :username AND a.timestamp >= :since ORDER BY a.timestamp DESC")
    List<SecurityAuditLog> findFailedAuthenticationsByUserSince(@Param("username") String username,
            @Param("since") LocalDateTime since);

    /**
     * Find security violations.
     */
    @Query("SELECT a FROM SecurityAuditLog a WHERE a.eventType IN ('SECURITY_VIOLATION', 'SUSPICIOUS_ACTIVITY') " +
            "ORDER BY a.timestamp DESC")
    Page<SecurityAuditLog> findSecurityViolations(Pageable pageable);

    /**
     * Find audit logs by resource type and action.
     */
    Page<SecurityAuditLog> findByResourceTypeAndActionOrderByTimestampDesc(String resourceType, String action,
            Pageable pageable);

    /**
     * Find audit logs for specific resource.
     */
    Page<SecurityAuditLog> findByResourceTypeAndResourceIdOrderByTimestampDesc(String resourceType, String resourceId,
            Pageable pageable);

    /**
     * Count events by type within time range.
     */
    @Query("SELECT a.eventType, COUNT(a) FROM SecurityAuditLog a " +
            "WHERE a.timestamp BETWEEN :startTime AND :endTime " +
            "GROUP BY a.eventType")
    List<Object[]> countEventsByTypeInRange(@Param("startTime") LocalDateTime startTime,
            @Param("endTime") LocalDateTime endTime);

    /**
     * Count events by outcome within time range.
     */
    @Query("SELECT a.outcome, COUNT(a) FROM SecurityAuditLog a " +
            "WHERE a.timestamp BETWEEN :startTime AND :endTime " +
            "GROUP BY a.outcome")
    List<Object[]> countEventsByOutcomeInRange(@Param("startTime") LocalDateTime startTime,
            @Param("endTime") LocalDateTime endTime);

    /**
     * Count events by risk level within time range.
     */
    @Query("SELECT a.riskLevel, COUNT(a) FROM SecurityAuditLog a " +
            "WHERE a.timestamp BETWEEN :startTime AND :endTime " +
            "GROUP BY a.riskLevel")
    List<Object[]> countEventsByRiskLevelInRange(@Param("startTime") LocalDateTime startTime,
            @Param("endTime") LocalDateTime endTime);

    /**
     * Find top IP addresses by event count.
     */
    @Query("SELECT a.ipAddress, COUNT(a) as eventCount FROM SecurityAuditLog a " +
            "WHERE a.timestamp >= :since AND a.ipAddress IS NOT NULL " +
            "GROUP BY a.ipAddress ORDER BY eventCount DESC")
    List<Object[]> findTopIpAddressesSince(@Param("since") LocalDateTime since, Pageable pageable);

    /**
     * Find top users by event count.
     */
    @Query("SELECT a.username, COUNT(a) as eventCount FROM SecurityAuditLog a " +
            "WHERE a.timestamp >= :since AND a.username IS NOT NULL " +
            "GROUP BY a.username ORDER BY eventCount DESC")
    List<Object[]> findTopUsersSince(@Param("since") LocalDateTime since, Pageable pageable);

    /**
     * Find audit logs that require alerts.
     */
    @Query("SELECT a FROM SecurityAuditLog a WHERE " +
            "(a.riskLevel IN ('HIGH', 'CRITICAL') OR a.anomalyDetected = true OR " +
            "a.eventType IN ('SECURITY_VIOLATION', 'SUSPICIOUS_ACTIVITY')) " +
            "ORDER BY a.timestamp DESC")
    Page<SecurityAuditLog> findEventsRequiringAlerts(Pageable pageable);

    /**
     * Find expired audit logs for cleanup.
     */
    @Query("SELECT a FROM SecurityAuditLog a WHERE a.retentionPeriodDays IS NOT NULL " +
            "AND a.timestamp < :cutoffDate AND a.archived = false")
    List<SecurityAuditLog> findExpiredAuditLogs(@Param("cutoffDate") LocalDateTime cutoffDate);

    /**
     * Find archived audit logs.
     */
    Page<SecurityAuditLog> findByArchivedTrueOrderByArchivedAtDesc(Pageable pageable);

    /**
     * Count total events.
     */
    long count();

    /**
     * Count events by organization.
     */
    long countByOrganizationId(UUID organizationId);

    /**
     * Count events by user.
     */
    long countByUserId(UUID userId);

    /**
     * Count events since timestamp.
     */
    @Query("SELECT COUNT(a) FROM SecurityAuditLog a WHERE a.timestamp >= :since")
    long countEventsSince(@Param("since") LocalDateTime since);

    /**
     * Delete old archived logs.
     */
    @Query("DELETE FROM SecurityAuditLog a WHERE a.archived = true AND a.archivedAt < :cutoffDate")
    void deleteArchivedLogsBefore(@Param("cutoffDate") LocalDateTime cutoffDate);
}