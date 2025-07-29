# MCP Security Deployment Guide

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Development Deployment](#development-deployment)
4. [Staging Deployment](#staging-deployment)
5. [Production Deployment](#production-deployment)
6. [High Availability Setup](#high-availability-setup)
7. [Monitoring and Alerts](#monitoring-and-alerts)
8. [Backup and Recovery](#backup-and-recovery)

## Prerequisites

### Software Requirements
- Java 17 or higher
- Maven 3.8+
- Docker 20.10+
- PostgreSQL 14+
- Redis 6.2+
- Nginx (for production)

### Infrastructure Requirements
- Minimum 2 CPU cores, 4GB RAM per instance
- 20GB SSD storage
- Network connectivity to dependent services
- SSL certificates for production

## Environment Setup

### 1. Generate JWT Keys

#### Development (HS256)
```bash
# Generate a strong secret key
openssl rand -base64 64 > jwt-secret.key
```

#### Production (RS256)
```bash
# Generate RSA key pair
openssl genrsa -out jwt-private.pem 4096
openssl rsa -in jwt-private.pem -pubout -out jwt-public.pem

# Create PKCS12 keystore (optional)
openssl pkcs12 -export -name jwt-key \
  -in jwt-public.pem -inkey jwt-private.pem \
  -out jwt-keystore.p12
```

### 2. Database Setup

```sql
-- Create database and user
CREATE DATABASE mcp_security;
CREATE USER mcp_security_user WITH ENCRYPTED PASSWORD 'strong_password';
GRANT ALL PRIVILEGES ON DATABASE mcp_security TO mcp_security_user;

-- Enable required extensions
\c mcp_security
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
```

### 3. Redis Configuration

```bash
# redis.conf
bind 127.0.0.1 ::1
port 6379
requirepass your_redis_password
maxmemory 2gb
maxmemory-policy allkeys-lru
```

## Development Deployment

### 1. Environment Configuration

Create `.env.development`:
```bash
# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=mcp_security_dev
DB_USER=mcp_security_user
DB_PASSWORD=dev_password

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=dev_password

# JWT
JWT_ALGORITHM=HS256
JWT_SECRET_KEY=dev_secret_key_change_in_production
JWT_EXPIRATION=3600
JWT_REFRESH_EXPIRATION=604800

# OAuth2
AUTH_SERVER_URL=http://localhost:9000

# Application
SERVER_PORT=8080
SPRING_PROFILES_ACTIVE=dev
```

### 2. Docker Compose Setup

```yaml
# docker-compose.dev.yml
version: '3.8'
services:
  postgres:
    image: postgres:14-alpine
    environment:
      POSTGRES_DB: mcp_security_dev
      POSTGRES_USER: mcp_security_user
      POSTGRES_PASSWORD: dev_password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:6.2-alpine
    command: redis-server --requirepass dev_password
    ports:
      - "6379:6379"

  mcp-security:
    build:
      context: .
      dockerfile: Dockerfile.dev
    env_file: .env.development
    ports:
      - "8080:8080"
    depends_on:
      - postgres
      - redis
    volumes:
      - ./src:/app/src
      - ./target:/app/target

volumes:
  postgres_data:
```

### 3. Run Development Environment

```bash
# Start infrastructure
docker-compose -f docker-compose.dev.yml up -d postgres redis

# Run database migrations
./mvnw flyway:migrate

# Start application with hot reload
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

## Staging Deployment

### 1. Environment Configuration

Create `.env.staging`:
```bash
# Database
DB_HOST=staging-db.internal
DB_PORT=5432
DB_NAME=mcp_security_staging
DB_USER=mcp_security_user
DB_PASSWORD=${STAGING_DB_PASSWORD}

# Redis
REDIS_HOST=staging-redis.internal
REDIS_PORT=6379
REDIS_PASSWORD=${STAGING_REDIS_PASSWORD}

# JWT
JWT_ALGORITHM=RS256
JWT_PRIVATE_KEY_PATH=/secrets/jwt/private.pem
JWT_PUBLIC_KEY_PATH=/secrets/jwt/public.pem
JWT_EXPIRATION=3600
JWT_REFRESH_EXPIRATION=604800

# OAuth2
AUTH_SERVER_URL=https://auth-staging.mcp-platform.com

# Application
SERVER_PORT=8080
SPRING_PROFILES_ACTIVE=staging
```

### 2. Kubernetes Deployment

```yaml
# k8s/staging/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-security
  namespace: staging
spec:
  replicas: 2
  selector:
    matchLabels:
      app: mcp-security
  template:
    metadata:
      labels:
        app: mcp-security
    spec:
      containers:
      - name: mcp-security
        image: mcp-platform/security:staging
        ports:
        - containerPort: 8080
        env:
        - name: SPRING_PROFILES_ACTIVE
          value: staging
        envFrom:
        - secretRef:
            name: mcp-security-secrets
        - configMapRef:
            name: mcp-security-config
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /actuator/health/liveness
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /actuator/health/readiness
            port: 8080
          initialDelaySeconds: 20
          periodSeconds: 5
        volumeMounts:
        - name: jwt-keys
          mountPath: /secrets/jwt
          readOnly: true
      volumes:
      - name: jwt-keys
        secret:
          secretName: jwt-keys
```

## Production Deployment

### 1. Environment Configuration

Create production configuration using environment variables:

```bash
# Production environment variables (store in secure vault)
export DB_HOST=prod-db-cluster.region.rds.amazonaws.com
export DB_PORT=5432
export DB_NAME=mcp_security_prod
export DB_USER=mcp_security_prod_user
export DB_PASSWORD=$(aws secretsmanager get-secret-value --secret-id prod/db/password --query SecretString --output text)

export REDIS_CLUSTER_NODES=prod-redis-001.cache.amazonaws.com:6379,prod-redis-002.cache.amazonaws.com:6379
export REDIS_PASSWORD=$(aws secretsmanager get-secret-value --secret-id prod/redis/password --query SecretString --output text)

export JWT_ALGORITHM=RS256
export JWT_PRIVATE_KEY_PATH=/vault/secrets/jwt/private.pem
export JWT_PUBLIC_KEY_PATH=/vault/secrets/jwt/public.pem
```

### 2. High Availability Configuration

```yaml
# k8s/production/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-security
  namespace: production
spec:
  replicas: 4
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: mcp-security
  template:
    metadata:
      labels:
        app: mcp-security
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/path: "/actuator/prometheus"
        prometheus.io/port: "8080"
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - mcp-security
            topologyKey: kubernetes.io/hostname
      containers:
      - name: mcp-security
        image: mcp-platform/security:v1.0.0
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 8081
          name: management
        env:
        - name: SPRING_PROFILES_ACTIVE
          value: production
        - name: JAVA_OPTS
          value: "-Xmx2g -Xms2g -XX:+UseG1GC -XX:MaxGCPauseMillis=100"
        envFrom:
        - secretRef:
            name: mcp-security-secrets
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "3Gi"
            cpu: "2000m"
```

### 3. Load Balancer Configuration

```nginx
# nginx.conf
upstream mcp_security {
    least_conn;
    server mcp-security-1:8080 max_fails=3 fail_timeout=30s;
    server mcp-security-2:8080 max_fails=3 fail_timeout=30s;
    server mcp-security-3:8080 max_fails=3 fail_timeout=30s;
    server mcp-security-4:8080 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl http2;
    server_name auth.mcp-platform.com;
    
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    location / {
        proxy_pass http://mcp_security;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Security headers
        add_header X-Content-Type-Options nosniff;
        add_header X-Frame-Options DENY;
        add_header X-XSS-Protection "1; mode=block";
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    }
    
    location /actuator/health {
        proxy_pass http://mcp_security;
        access_log off;
    }
}
```

## High Availability Setup

### 1. Database Clustering

```bash
# PostgreSQL streaming replication setup
# On primary
postgresql.conf:
wal_level = replica
max_wal_senders = 3
wal_keep_segments = 64
archive_mode = on
archive_command = 'cp %p /archive/%f'

# On replica
recovery.conf:
standby_mode = 'on'
primary_conninfo = 'host=primary port=5432 user=replicator'
restore_command = 'cp /archive/%f %p'
```

### 2. Redis Sentinel Configuration

```bash
# sentinel.conf
port 26379
sentinel monitor mymaster redis-master 6379 2
sentinel down-after-milliseconds mymaster 5000
sentinel parallel-syncs mymaster 1
sentinel failover-timeout mymaster 10000
```

### 3. Application Clustering

```yaml
# application-production.yml
spring:
  session:
    store-type: redis
    redis:
      flush-mode: on-save
      namespace: mcp:session
  
  cache:
    type: redis
    redis:
      time-to-live: 300000
      cache-null-values: false
      
hazelcast:
  cluster:
    enabled: true
    members:
      - mcp-security-1
      - mcp-security-2
      - mcp-security-3
      - mcp-security-4
```

## Monitoring and Alerts

### 1. Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'mcp-security'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
```

### 2. Grafana Dashboard

Import dashboard JSON from `monitoring/grafana-dashboard.json`

Key metrics to monitor:
- Request rate and latency
- JWT validation errors
- Authentication failures
- Database connection pool
- Redis connection pool
- JVM memory and GC

### 3. Alert Rules

```yaml
# alerts.yml
groups:
  - name: security_alerts
    rules:
      - alert: HighAuthenticationFailureRate
        expr: rate(authentication_failures_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: High authentication failure rate
          
      - alert: JWTValidationErrors
        expr: rate(jwt_validation_errors_total[5m]) > 5
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: JWT validation errors detected
```

## Backup and Recovery

### 1. Database Backup

```bash
#!/bin/bash
# backup.sh
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="mcp_security_backup_${DATE}.sql"

pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME > $BACKUP_FILE
gzip $BACKUP_FILE
aws s3 cp ${BACKUP_FILE}.gz s3://mcp-backups/security/

# Cleanup old backups (keep 30 days)
find /backup -name "*.gz" -mtime +30 -delete
```

### 2. Redis Backup

```bash
# Redis RDB backup
redis-cli -h $REDIS_HOST -a $REDIS_PASSWORD BGSAVE
# Copy dump.rdb to backup location
```

### 3. Disaster Recovery Plan

1. **Database Recovery**
   ```bash
   gunzip backup.sql.gz
   psql -h $DB_HOST -U $DB_USER -d $DB_NAME < backup.sql
   ```

2. **Redis Recovery**
   ```bash
   redis-cli -h $REDIS_HOST -a $REDIS_PASSWORD --rdb dump.rdb
   ```

3. **Application Recovery**
   - Deploy from last known good container image
   - Restore configuration from vault
   - Verify JWT keys are intact
   - Run health checks

## Security Hardening

### 1. Network Security
- Use private subnets for database and Redis
- Configure security groups with minimal access
- Enable VPC flow logs
- Use AWS WAF or similar for DDoS protection

### 2. Secret Management
- Store all secrets in HashiCorp Vault or AWS Secrets Manager
- Rotate credentials regularly
- Use IAM roles for service authentication
- Enable audit logging for secret access

### 3. Compliance
- Enable encryption at rest for databases
- Enable encryption in transit (TLS 1.2+)
- Configure audit logging
- Implement log retention policies
- Regular security scanning

## Troubleshooting

### Common Deployment Issues

1. **Database Connection Failures**
   - Check network connectivity
   - Verify credentials
   - Check connection pool settings
   - Review firewall rules

2. **Redis Connection Issues**
   - Verify Redis is running
   - Check authentication
   - Test network connectivity
   - Review max connections

3. **JWT Key Issues**
   - Verify key file permissions (400)
   - Check key format (PEM)
   - Ensure paths are correct
   - Validate key pair match

4. **Memory Issues**
   - Increase JVM heap size
   - Check for memory leaks
   - Review cache settings
   - Monitor GC logs

### Health Check Endpoints

```bash
# Liveness probe
curl http://localhost:8080/actuator/health/liveness

# Readiness probe  
curl http://localhost:8080/actuator/health/readiness

# Full health check
curl http://localhost:8080/actuator/health
```

## Performance Tuning

### JVM Options
```bash
-Xmx2g
-Xms2g
-XX:+UseG1GC
-XX:MaxGCPauseMillis=100
-XX:+ParallelRefProcEnabled
-XX:+DisableExplicitGC
-XX:+AlwaysPreTouch
-XX:+UnlockExperimentalVMOptions
-XX:+UseStringDeduplication
```

### Database Connection Pool
```yaml
spring:
  datasource:
    hikari:
      maximum-pool-size: 20
      minimum-idle: 5
      connection-timeout: 30000
      idle-timeout: 600000
      max-lifetime: 1800000
```

### Redis Connection Pool
```yaml
spring:
  redis:
    lettuce:
      pool:
        max-active: 20
        max-idle: 10
        min-idle: 5
        max-wait: -1ms