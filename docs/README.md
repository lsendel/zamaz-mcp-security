# MCP-Security Service Documentation

The MCP-Security service provides centralized security features for the Zamaz Debate MCP system, including authentication, authorization, and security monitoring.

## Overview

The MCP-Security service implements cross-cutting security concerns for the entire MCP system. It handles authentication, authorization, rate limiting, audit logging, and security monitoring across all services, ensuring consistent security enforcement throughout the platform.

## Features

- **Authentication**: Centralized authentication for all services
- **Authorization**: Role-based access control and permission management
- **API Key Management**: Validation and management of API keys
- **Rate Limiting**: Protection against abuse and DoS attacks
- **Audit Logging**: Comprehensive logging of security-relevant events
- **Security Monitoring**: Detection of suspicious activities
- **JWT Token Management**: Generation and validation of JWT tokens
- **Multi-tenant Security**: Enforcement of tenant isolation

## Architecture

The Security service follows a clean architecture pattern:

- **Controllers**: Handle HTTP requests and responses
- **Services**: Implement security business logic
- **Repositories**: Manage security data persistence
- **Filters**: Implement security filters for requests
- **Providers**: Connect with authentication providers

## API Endpoints

### Authentication

- `POST /api/v1/auth/login`: User login
- `POST /api/v1/auth/logout`: User logout
- `POST /api/v1/auth/refresh`: Refresh JWT token
- `POST /api/v1/auth/validate`: Validate authentication token

### API Keys

- `POST /api/v1/api-keys/validate`: Validate API key
- `GET /api/v1/api-keys/info`: Get API key information
- `POST /api/v1/api-keys/revoke`: Revoke API key

### Authorization

- `POST /api/v1/auth/check-permission`: Check user permission
- `GET /api/v1/auth/user-permissions`: Get user permissions
- `POST /api/v1/auth/impersonate`: Impersonate user (admin only)

### Security Monitoring

- `GET /api/v1/security/events`: List security events
- `GET /api/v1/security/alerts`: List security alerts
- `POST /api/v1/security/alerts/{id}/resolve`: Resolve security alert

### MCP Tools

The service exposes the following MCP tools:

- `validate_token`: Validate authentication token
- `validate_api_key`: Validate API key
- `check_permission`: Check user permission
- `generate_token`: Generate JWT token
- `log_security_event`: Log security event

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_HOST` | PostgreSQL host | postgres |
| `DB_PORT` | PostgreSQL port | 5432 |
| `DB_NAME` | PostgreSQL database name | security_db |
| `DB_USER` | PostgreSQL username | postgres |
| `DB_PASSWORD` | PostgreSQL password | postgres |
| `REDIS_HOST` | Redis host | redis |
| `REDIS_PORT` | Redis port | 6379 |
| `JWT_SECRET` | Secret for JWT token generation | your-256-bit-secret-key |
| `JWT_EXPIRATION_MINUTES` | JWT token expiration time | 60 |
| `SERVER_PORT` | Server port | 5007 |
| `LOG_LEVEL` | Logging level | INFO |

### Security Configuration

Security-specific settings can be configured in `config/security.yml`:

```yaml
security:
  authentication:
    token_expiration_minutes: 60
    refresh_token_expiration_days: 30
    max_login_attempts: 5
    lockout_duration_minutes: 30
    remember_me_duration_days: 30
    
  authorization:
    default_role: "user"
    system_roles:
      - "admin"
      - "user"
      - "guest"
    
  api_keys:
    expiration_days: 90
    max_keys_per_organization: 10
    
  rate_limiting:
    enabled: true
    default_limit_per_minute: 60
    default_limit_per_hour: 1000
    default_limit_per_day: 10000
    
  audit:
    enabled: true
    log_level: "INFO"
    events_to_log:
      - "authentication"
      - "authorization"
      - "api_key"
      - "data_access"
    retention_days: 90
```

## Usage Examples

### Validate JWT Token

```bash
curl -X POST http://localhost:5007/api/v1/auth/validate \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "requiredPermissions": ["debate:read"]
  }'
```

### Validate API Key

```bash
curl -X POST http://localhost:5007/api/v1/api-keys/validate \
  -H "Content-Type: application/json" \
  -d '{
    "apiKey": "key-abcdef123456",
    "organizationId": "org-123",
    "requiredScopes": ["debate:read", "llm:complete"]
  }'
```

### Check User Permission

```bash
curl -X POST http://localhost:5007/api/v1/auth/check-permission \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-jwt-token" \
  -d '{
    "permission": "debate:create",
    "resourceId": "debate-123",
    "organizationId": "org-456"
  }'
```

### Log Security Event

```bash
curl -X POST http://localhost:5007/api/v1/security/events \
  -H "Content-Type: application/json" \
  -H "X-Organization-ID: org-123" \
  -d '{
    "eventType": "suspicious_activity",
    "severity": "medium",
    "source": "mcp-llm",
    "description": "Unusual number of API requests from IP 192.168.1.100",
    "metadata": {
      "ip": "192.168.1.100",
      "requestCount": 150,
      "timeWindow": "5 minutes"
    }
  }'
```

## Data Models

### JWT Token

```json
{
  "sub": "user-123",
  "name": "John Doe",
  "org_id": "org-456",
  "roles": ["admin"],
  "permissions": ["debate:read", "debate:write", "debate:admin"],
  "iat": 1626192000,
  "exp": 1626195600,
  "jti": "unique-token-id"
}
```

### API Key Info

```json
{
  "id": "key-789",
  "organizationId": "org-456",
  "name": "Production API Key",
  "scopes": ["debate:read", "debate:write", "llm:complete"],
  "createdAt": "2025-06-15T10:30:00Z",
  "expiresAt": "2026-07-16T00:00:00Z",
  "lastUsedAt": "2025-07-16T14:22:15Z",
  "status": "active"
}
```

### Security Event

```json
{
  "id": "event-123",
  "eventType": "authentication_failure",
  "severity": "medium",
  "source": "mcp-organization",
  "description": "Failed login attempt for user john.doe@example.com",
  "organizationId": "org-456",
  "userId": "user-789",
  "ipAddress": "192.168.1.100",
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "metadata": {
    "attemptCount": 3,
    "reason": "invalid_password"
  },
  "timestamp": "2025-07-16T14:22:15Z"
}
```

### Security Alert

```json
{
  "id": "alert-456",
  "alertType": "brute_force_attempt",
  "severity": "high",
  "source": "mcp-security",
  "description": "Multiple failed login attempts detected",
  "organizationId": "org-456",
  "affectedUsers": ["user-789"],
  "ipAddresses": ["192.168.1.100"],
  "relatedEvents": ["event-123", "event-124", "event-125"],
  "metadata": {
    "attemptCount": 10,
    "timeWindow": "5 minutes"
  },
  "status": "open",
  "createdAt": "2025-07-16T14:25:00Z",
  "updatedAt": "2025-07-16T14:25:00Z"
}
```

## Authentication Flow

### User Authentication Flow

1. User submits credentials to `/api/v1/auth/login`
2. Security service validates credentials
3. If valid, generates JWT token and refresh token
4. Returns tokens to client
5. Client includes JWT token in subsequent requests
6. When token expires, client uses refresh token to get new JWT

### API Key Authentication Flow

1. Client includes API key in request header
2. Service calls Security service to validate API key
3. Security service checks API key validity, expiration, and scopes
4. If valid, request is authorized
5. Usage is logged for audit and rate limiting

## Authorization Model

The Security service implements a role-based access control (RBAC) model with:

### Roles

- **Admin**: Full system access
- **Manager**: Organization management access
- **User**: Standard user access
- **Guest**: Limited read-only access

### Permissions

Permissions follow a resource:action format:

- `debate:read`: Read debates
- `debate:write`: Create/update debates
- `debate:delete`: Delete debates
- `debate:admin`: Administrative debate actions
- `llm:complete`: Generate LLM completions
- `organization:admin`: Manage organization

### Permission Checks

Permission checks consider:
- User's assigned roles and permissions
- Organization membership
- Resource ownership
- Special conditions (e.g., resource sharing)

## Security Monitoring

The service includes security monitoring features:

### Event Monitoring

- Authentication events (login, logout, failures)
- Authorization events (permission checks, access denials)
- API key usage events
- Sensitive data access events

### Threat Detection

- Brute force attack detection
- Unusual access pattern detection
- Rate limit violation detection
- Suspicious IP address detection

### Alerting

- Real-time security alerts
- Alert severity classification
- Alert notification via email/Slack
- Alert management and resolution

## Audit Logging

The service maintains comprehensive audit logs:

- **Who**: User ID, API key ID, IP address
- **What**: Action performed, resources accessed
- **When**: Timestamp of the action
- **Where**: Source service, endpoint
- **How**: Access method, user agent
- **Result**: Success/failure, error details

## Rate Limiting

The service implements multi-level rate limiting:

- **Per-IP rate limiting**: Prevent abuse from specific IPs
- **Per-user rate limiting**: Limit individual user activity
- **Per-organization rate limiting**: Enforce organization quotas
- **Per-endpoint rate limiting**: Protect sensitive endpoints

## Monitoring and Metrics

The service exposes the following metrics:

- Authentication success/failure rate
- API key usage patterns
- Permission check statistics
- Rate limit violations
- Security event counts by type
- Alert counts by severity

Access metrics at: `http://localhost:5007/actuator/metrics`

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Check credentials are correct
   - Verify JWT token is not expired
   - Check for account lockout due to failed attempts

2. **Authorization Issues**
   - Verify user has required permissions
   - Check organization membership
   - Verify resource access permissions

3. **Rate Limiting Issues**
   - Check rate limit configuration
   - Monitor for unusual traffic patterns
   - Consider adjusting limits for legitimate high usage

### Logs

Service logs can be accessed via:

```bash
docker-compose logs mcp-security
```

## Development

### Building the Service

```bash
cd mcp-security
mvn clean install
```

### Running Tests

```bash
cd mcp-security
mvn test
```

### Local Development

```bash
cd mcp-security
mvn spring-boot:run
```

## Advanced Features

### Multi-factor Authentication

Enable MFA for enhanced security:

```bash
curl -X POST http://localhost:5007/api/v1/auth/mfa/enable \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-jwt-token" \
  -d '{
    "type": "totp",
    "phoneNumber": "+1234567890"
  }'
```

### IP Allowlisting

Configure IP allowlists for organizations:

```bash
curl -X POST http://localhost:5007/api/v1/organizations/org-123/ip-allowlist \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin-token" \
  -d '{
    "allowedIps": [
      "192.168.1.0/24",
      "10.0.0.1",
      "2001:db8::/64"
    ],
    "enforceAllowlist": true
  }'
```

### Security Policies

Configure organization security policies:

```bash
curl -X POST http://localhost:5007/api/v1/organizations/org-123/security-policies \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin-token" \
  -d '{
    "passwordPolicy": {
      "minLength": 12,
      "requireUppercase": true,
      "requireLowercase": true,
      "requireNumbers": true,
      "requireSpecialChars": true,
      "passwordExpirationDays": 90,
      "preventPasswordReuse": 5
    },
    "sessionPolicy": {
      "sessionTimeoutMinutes": 30,
      "maxConcurrentSessions": 5,
      "requireMfa": true
    },
    "apiKeyPolicy": {
      "maxApiKeys": 10,
      "apiKeyExpirationDays": 90,
      "requireKeyRotation": true
    }
  }'
```

### Security Compliance Reports

Generate security compliance reports:

```bash
curl -X POST http://localhost:5007/api/v1/security/compliance-report \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin-token" \
  -d '{
    "organizationId": "org-123",
    "reportType": "security_posture",
    "startDate": "2025-06-01T00:00:00Z",
    "endDate": "2025-07-01T00:00:00Z",
    "includeDetails": true
  }'
```
