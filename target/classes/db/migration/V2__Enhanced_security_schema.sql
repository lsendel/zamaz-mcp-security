-- Constants and Common Patterns
-- VARCHAR_DEFAULT: VARCHAR(255)
-- TIMESTAMP_DEFAULT: TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP
-- UUID_DEFAULT: UUID PRIMARY KEY DEFAULT gen_random_uuid()
-- AUDIT_COLUMNS: created_at, updated_at, created_by, updated_by

-- Constants
DECLARE
  C_DEFAULT_SCHEMA CONSTANT VARCHAR2(30) := 'PUBLIC';
  C_ERROR_MSG CONSTANT VARCHAR2(100) := 'An error occurred';
END;
/

-- Enhanced Security Schema Migration
-- Adds comprehensive RBAC, audit logging, and security features

-- Create extensions if not exists
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enhanced Users table (extends existing or creates new)
DO $$
BEGIN
    -- Add new columns to existing users table if they don't exist
    IF EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'users') THEN
        -- Display name and contact info
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'display_name') THEN
            ALTER TABLE users ADD COLUMN display_name VARCHAR(200);
        END IF;
        
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'phone_number') THEN
            ALTER TABLE users ADD COLUMN phone_number VARCHAR(20);
        END IF;
        
        -- Email verification enhancements
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'email_verification_token') THEN
            ALTER TABLE users ADD COLUMN email_verification_token VARCHAR(255);
        END IF;
        
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'email_verification_expires_at') THEN
            ALTER TABLE users ADD COLUMN email_verification_expires_at TIMESTAMP;
        END IF;
        
        -- MFA enhancements
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'mfa_backup_codes') THEN
            ALTER TABLE users ADD COLUMN mfa_backup_codes TEXT;
        END IF;
        
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'mfa_recovery_codes_used') THEN
            ALTER TABLE users ADD COLUMN mfa_recovery_codes_used INTEGER DEFAULT 0;
        END IF;
        
        -- Account security enhancements
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'account_lock_reason') THEN
            ALTER TABLE users ADD COLUMN account_lock_reason VARCHAR(500);
        END IF;
        
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'account_locked_at') THEN
            ALTER TABLE users ADD COLUMN account_locked_at TIMESTAMP;
        END IF;
        
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'account_locked_until') THEN
            ALTER TABLE users ADD COLUMN account_locked_until TIMESTAMP;
        END IF;
        
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'last_failed_login_at') THEN
            ALTER TABLE users ADD COLUMN last_failed_login_at TIMESTAMP;
        END IF;
        
        -- Password management enhancements
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'password_expires_at') THEN
            ALTER TABLE users ADD COLUMN password_expires_at TIMESTAMP;
        END IF;
        
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'password_reset_token') THEN
            ALTER TABLE users ADD COLUMN password_reset_token VARCHAR(255);
        END IF;
        
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'password_reset_expires_at') THEN
            ALTER TABLE users ADD COLUMN password_reset_expires_at TIMESTAMP;
        END IF;
        
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'force_password_change') THEN
            ALTER TABLE users ADD COLUMN force_password_change BOOLEAN DEFAULT false;
        END IF;
        
        -- Session management
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'last_login_ip') THEN
            ALTER TABLE users ADD COLUMN last_login_ip VARCHAR(45);
        END IF;
        
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'current_session_id') THEN
            ALTER TABLE users ADD COLUMN current_session_id VARCHAR(255);
        END IF;
        
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'concurrent_sessions_allowed') THEN
            ALTER TABLE users ADD COLUMN concurrent_sessions_allowed INTEGER DEFAULT 3;
        END IF;
        
        -- Account status enhancements
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'deactivated_at') THEN
            ALTER TABLE users ADD COLUMN deactivated_at TIMESTAMP;
        END IF;
        
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'deactivated_reason') THEN
            ALTER TABLE users ADD COLUMN deactivated_reason VARCHAR(500);
        END IF;
        
        -- Privacy and preferences
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'privacy_settings') THEN
            ALTER TABLE users ADD COLUMN privacy_settings JSONB;
        END IF;
        
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'notification_preferences') THEN
            ALTER TABLE users ADD COLUMN notification_preferences JSONB;
        END IF;
        
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'locale') THEN
            ALTER TABLE users ADD COLUMN locale VARCHAR(10) DEFAULT 'en_US';
        END IF;
        
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'timezone') THEN
            ALTER TABLE users ADD COLUMN timezone VARCHAR(50) DEFAULT 'UTC';
        END IF;
        
        -- Audit fields
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'created_by') THEN
            ALTER TABLE users ADD COLUMN created_by VARCHAR(255);
        END IF;
        
        IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'updated_by') THEN
            ALTER TABLE users ADD COLUMN updated_by VARCHAR(255);
        END IF;
    END IF;
END
$$;

-- Enhanced Roles table
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    description VARCHAR(500),
    display_name VARCHAR(200),
    organization_id UUID,
    is_system_role BOOLEAN NOT NULL DEFAULT false,
    is_default_role BOOLEAN NOT NULL DEFAULT false,
    hierarchy_level INTEGER NOT NULL DEFAULT 0,
    max_hierarchy_level INTEGER,
    role_type VARCHAR(50) NOT NULL DEFAULT 'FUNCTIONAL',
    role_category VARCHAR(100),
    max_users INTEGER,
    requires_approval BOOLEAN NOT NULL DEFAULT false,
    auto_expire_days INTEGER,
    delegation_allowed BOOLEAN NOT NULL DEFAULT false,
    max_delegation_depth INTEGER DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT true,
    effective_from TIMESTAMP,
    effective_until TIMESTAMP,
    role_metadata JSONB,
    access_patterns JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255),
    updated_by VARCHAR(255),
    CONSTRAINT uk_roles_name_org UNIQUE (name, organization_id)
);

-- Role Hierarchy table
CREATE TABLE IF NOT EXISTS role_hierarchy (
    child_role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    parent_role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (child_role_id, parent_role_id)
);

-- Enhanced Permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    description VARCHAR(500),
    display_name VARCHAR(200),
    resource_id VARCHAR(255),
    resource_pattern VARCHAR(500),
    organization_id UUID,
    permission_type VARCHAR(50) NOT NULL DEFAULT 'RESOURCE_BASED',
    permission_scope VARCHAR(50) NOT NULL DEFAULT 'INSTANCE',
    is_system_permission BOOLEAN NOT NULL DEFAULT false,
    condition_expression TEXT,
    subject_attributes JSONB,
    resource_attributes JSONB,
    environment_attributes JSONB,
    time_based BOOLEAN NOT NULL DEFAULT false,
    valid_from TIMESTAMP,
    valid_until TIMESTAMP,
    days_of_week VARCHAR(20),
    hours_of_day VARCHAR(50),
    ip_restrictions TEXT,
    location_restrictions TEXT,
    priority INTEGER NOT NULL DEFAULT 0,
    effect VARCHAR(10) NOT NULL DEFAULT 'ALLOW',
    delegation_allowed BOOLEAN NOT NULL DEFAULT false,
    max_delegation_depth INTEGER DEFAULT 1,
    category VARCHAR(100),
    tags TEXT,
    risk_level VARCHAR(20) DEFAULT 'LOW',
    is_active BOOLEAN NOT NULL DEFAULT true,
    requires_approval BOOLEAN NOT NULL DEFAULT false,
    auto_expire_days INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255),
    updated_by VARCHAR(255),
    CONSTRAINT uk_permissions_resource_action_org UNIQUE (resource, action, organization_id)
);

-- User-Role associations with enhanced features
CREATE TABLE IF NOT EXISTS user_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    organization_id UUID,
    assignment_type VARCHAR(50) NOT NULL DEFAULT 'DIRECT',
    assignment_status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
    is_active BOOLEAN NOT NULL DEFAULT true,
    effective_from TIMESTAMP,
    expires_at TIMESTAMP,
    auto_renew BOOLEAN NOT NULL DEFAULT false,
    renewal_period_days INTEGER,
    assignment_reason VARCHAR(500),
    assignment_context JSONB,
    conditions TEXT,
    requires_approval BOOLEAN NOT NULL DEFAULT false,
    approval_status VARCHAR(50),
    approved_by VARCHAR(255),
    approved_at TIMESTAMP,
    approval_comments VARCHAR(1000),
    is_delegated BOOLEAN NOT NULL DEFAULT false,
    delegated_from VARCHAR(255),
    delegation_depth INTEGER NOT NULL DEFAULT 0,
    delegation_expires_at TIMESTAMP,
    granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    granted_by VARCHAR(255),
    revoked_at TIMESTAMP,
    revoked_by VARCHAR(255),
    revocation_reason VARCHAR(500),
    last_used_at TIMESTAMP,
    usage_count BIGINT NOT NULL DEFAULT 0
);

-- Role-Permission associations
CREATE TABLE IF NOT EXISTS role_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    is_active BOOLEAN NOT NULL DEFAULT true,
    conditions TEXT,
    context_attributes JSONB,
    effective_from TIMESTAMP,
    expires_at TIMESTAMP,
    granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    granted_by VARCHAR(255),
    revoked_at TIMESTAMP,
    revoked_by VARCHAR(255),
    revocation_reason VARCHAR(500)
);

-- User-Permission direct associations
CREATE TABLE IF NOT EXISTS user_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    organization_id UUID,
    assignment_type VARCHAR(50) NOT NULL DEFAULT 'DIRECT',
    is_active BOOLEAN NOT NULL DEFAULT true,
    conditions TEXT,
    context_attributes JSONB,
    resource_constraints JSONB,
    effective_from TIMESTAMP,
    expires_at TIMESTAMP,
    auto_renew BOOLEAN NOT NULL DEFAULT false,
    renewal_period_days INTEGER,
    assignment_reason VARCHAR(500),
    emergency_grant BOOLEAN NOT NULL DEFAULT false,
    requires_justification BOOLEAN NOT NULL DEFAULT false,
    justification VARCHAR(1000),
    is_delegated BOOLEAN NOT NULL DEFAULT false,
    delegated_from VARCHAR(255),
    delegation_depth INTEGER NOT NULL DEFAULT 0,
    delegation_expires_at TIMESTAMP,
    granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    granted_by VARCHAR(255),
    revoked_at TIMESTAMP,
    revoked_by VARCHAR(255),
    revocation_reason VARCHAR(500),
    last_used_at TIMESTAMP,
    usage_count BIGINT NOT NULL DEFAULT 0
);

-- Security Audit Log table
CREATE TABLE IF NOT EXISTS security_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(50) NOT NULL,
    event_category VARCHAR(50) NOT NULL,
    event_description VARCHAR(1000),
    user_id UUID REFERENCES users(id),
    username VARCHAR(255),
    organization_id UUID,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    resource_name VARCHAR(500),
    action VARCHAR(100),
    ip_address VARCHAR(45),
    user_agent VARCHAR(1000),
    session_id VARCHAR(255),
    request_id VARCHAR(255),
    correlation_id VARCHAR(255),
    country_code VARCHAR(2),
    region VARCHAR(100),
    city VARCHAR(100),
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    outcome VARCHAR(20) NOT NULL,
    outcome_reason VARCHAR(500),
    error_code VARCHAR(50),
    error_message VARCHAR(1000),
    risk_level VARCHAR(20) NOT NULL DEFAULT 'LOW',
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_factors JSONB,
    anomaly_detected BOOLEAN NOT NULL DEFAULT false,
    anomaly_score DOUBLE PRECISION,
    details JSONB,
    before_state JSONB,
    after_state JSONB,
    compliance_tags TEXT,
    retention_period_days INTEGER,
    archived BOOLEAN NOT NULL DEFAULT false,
    archived_at TIMESTAMP,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    server_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create comprehensive indexes for performance

-- Users table indexes
CREATE INDEX IF NOT EXISTS idx_users_display_name ON users(display_name);
CREATE INDEX IF NOT EXISTS idx_users_phone_number ON users(phone_number);
CREATE INDEX IF NOT EXISTS idx_users_mfa_enabled ON users(mfa_enabled);
CREATE INDEX IF NOT EXISTS idx_users_account_locked ON users(account_locked);
CREATE INDEX IF NOT EXISTS idx_users_password_expires ON users(password_expires_at);
CREATE INDEX IF NOT EXISTS idx_users_last_login ON users(last_login_at);
CREATE INDEX IF NOT EXISTS idx_users_session_id ON users(current_session_id);
CREATE INDEX IF NOT EXISTS idx_users_locale ON users(locale);

-- Roles table indexes
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);
CREATE INDEX IF NOT EXISTS idx_roles_organization ON roles(organization_id);
CREATE INDEX IF NOT EXISTS idx_roles_active ON roles(is_active);
CREATE INDEX IF NOT EXISTS idx_roles_system ON roles(is_system_role);
CREATE INDEX IF NOT EXISTS idx_roles_hierarchy_level ON roles(hierarchy_level);
CREATE INDEX IF NOT EXISTS idx_roles_type ON roles(role_type);
CREATE INDEX IF NOT EXISTS idx_roles_category ON roles(role_category);

-- Role hierarchy indexes
CREATE INDEX IF NOT EXISTS idx_role_hierarchy_child ON role_hierarchy(child_role_id);
CREATE INDEX IF NOT EXISTS idx_role_hierarchy_parent ON role_hierarchy(parent_role_id);

-- Permissions table indexes
CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource);
CREATE INDEX IF NOT EXISTS idx_permissions_action ON permissions(action);
CREATE INDEX IF NOT EXISTS idx_permissions_organization ON permissions(organization_id);
CREATE INDEX IF NOT EXISTS idx_permissions_resource_id ON permissions(resource_id);
CREATE INDEX IF NOT EXISTS idx_permissions_active ON permissions(is_active);
CREATE INDEX IF NOT EXISTS idx_permissions_system ON permissions(is_system_permission);
CREATE INDEX IF NOT EXISTS idx_permissions_type ON permissions(permission_type);
CREATE INDEX IF NOT EXISTS idx_permissions_scope ON permissions(permission_scope);
CREATE INDEX IF NOT EXISTS idx_permissions_risk_level ON permissions(risk_level);

-- User-Role association indexes
CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_organization ON user_roles(organization_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_active ON user_roles(is_active);
CREATE INDEX IF NOT EXISTS idx_user_roles_expires ON user_roles(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_roles_granted_by ON user_roles(granted_by);
CREATE INDEX IF NOT EXISTS idx_user_roles_assignment_type ON user_roles(assignment_type);
CREATE INDEX IF NOT EXISTS idx_user_roles_status ON user_roles(assignment_status);

-- Role-Permission association indexes
CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission ON role_permissions(permission_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_active ON role_permissions(is_active);
CREATE INDEX IF NOT EXISTS idx_role_permissions_granted_by ON role_permissions(granted_by);

-- User-Permission association indexes
CREATE INDEX IF NOT EXISTS idx_user_permissions_user ON user_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_permissions_permission ON user_permissions(permission_id);
CREATE INDEX IF NOT EXISTS idx_user_permissions_organization ON user_permissions(organization_id);
CREATE INDEX IF NOT EXISTS idx_user_permissions_active ON user_permissions(is_active);
CREATE INDEX IF NOT EXISTS idx_user_permissions_granted_by ON user_permissions(granted_by);
CREATE INDEX IF NOT EXISTS idx_user_permissions_assignment_type ON user_permissions(assignment_type);

-- Security Audit Log indexes
CREATE INDEX IF NOT EXISTS idx_audit_log_user ON security_audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_organization ON security_audit_log(organization_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON security_audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_category ON security_audit_log(event_category);
CREATE INDEX IF NOT EXISTS idx_audit_log_outcome ON security_audit_log(outcome);
CREATE INDEX IF NOT EXISTS idx_audit_log_risk_level ON security_audit_log(risk_level);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON security_audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_ip_address ON security_audit_log(ip_address);
CREATE INDEX IF NOT EXISTS idx_audit_log_session ON security_audit_log(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_resource_type ON security_audit_log(resource_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_anomaly ON security_audit_log(anomaly_detected);
CREATE INDEX IF NOT EXISTS idx_audit_log_archived ON security_audit_log(archived);

-- Create or update triggers for updated_at columns
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply triggers to tables with updated_at columns
DO $$
BEGIN
    -- Users table trigger
    IF NOT EXISTS (SELECT FROM information_schema.triggers WHERE trigger_name = 'update_users_updated_at') THEN
        CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
    
    -- Roles table trigger
    IF NOT EXISTS (SELECT FROM information_schema.triggers WHERE trigger_name = 'update_roles_updated_at') THEN
        CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON roles
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
    
    -- Permissions table trigger
    IF NOT EXISTS (SELECT FROM information_schema.triggers WHERE trigger_name = 'update_permissions_updated_at') THEN
        CREATE TRIGGER update_permissions_updated_at BEFORE UPDATE ON permissions
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END
$$;