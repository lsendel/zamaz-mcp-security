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

-- OAuth2 Client Registration Tables
-- Supports dynamic client management with PKCE and various grant types

-- Main OAuth2 clients table
CREATE TABLE oauth2_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret VARCHAR(255), -- Null for public clients
    client_name VARCHAR(255) NOT NULL,
    description TEXT,
    organization_id VARCHAR(255),
    client_type VARCHAR(50) NOT NULL CHECK (client_type IN ('CONFIDENTIAL', 'PUBLIC')),
    access_token_validity INTEGER DEFAULT 3600,
    refresh_token_validity INTEGER DEFAULT 2592000,
    require_authorization_consent BOOLEAN DEFAULT TRUE,
    require_pkce BOOLEAN DEFAULT FALSE,
    logo_uri VARCHAR(500),
    client_uri VARCHAR(500),
    policy_uri VARCHAR(500),
    tos_uri VARCHAR(500),
    active BOOLEAN DEFAULT TRUE,
    created_by VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Index for client lookups
CREATE INDEX idx_oauth2_clients_client_id ON oauth2_clients(client_id);
CREATE INDEX idx_oauth2_clients_organization ON oauth2_clients(organization_id);
CREATE INDEX idx_oauth2_clients_active ON oauth2_clients(active);

-- Redirect URIs table
CREATE TABLE oauth2_client_redirect_uris (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) NOT NULL,
    redirect_uri VARCHAR(1000) NOT NULL,
    FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id) ON DELETE CASCADE,
    UNIQUE(client_id, redirect_uri)
);

-- Grant types table
CREATE TABLE oauth2_client_grant_types (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) NOT NULL,
    grant_type VARCHAR(50) NOT NULL CHECK (grant_type IN (
        'AUTHORIZATION_CODE', 'CLIENT_CREDENTIALS', 'REFRESH_TOKEN', 
        'PASSWORD', 'IMPLICIT', 'JWT_BEARER'
    )),
    FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id) ON DELETE CASCADE,
    UNIQUE(client_id, grant_type)
);

-- Scopes table
CREATE TABLE oauth2_client_scopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) NOT NULL,
    scope VARCHAR(255) NOT NULL,
    FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id) ON DELETE CASCADE,
    UNIQUE(client_id, scope)
);

-- Authentication methods table
CREATE TABLE oauth2_client_auth_methods (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) NOT NULL,
    auth_method VARCHAR(50) NOT NULL CHECK (auth_method IN (
        'CLIENT_SECRET_BASIC', 'CLIENT_SECRET_POST', 'CLIENT_SECRET_JWT',
        'PRIVATE_KEY_JWT', 'NONE'
    )),
    FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id) ON DELETE CASCADE,
    UNIQUE(client_id, auth_method)
);

-- Contacts table
CREATE TABLE oauth2_client_contacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) NOT NULL,
    contact VARCHAR(255) NOT NULL,
    FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id) ON DELETE CASCADE
);

-- Additional settings table (key-value pairs)
CREATE TABLE oauth2_client_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) NOT NULL,
    setting_key VARCHAR(255) NOT NULL,
    setting_value TEXT,
    FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id) ON DELETE CASCADE,
    UNIQUE(client_id, setting_key)
);

-- Trigger to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_oauth2_client_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_oauth2_clients_timestamp
    BEFORE UPDATE ON oauth2_clients
    FOR EACH ROW
    EXECUTE FUNCTION update_oauth2_client_timestamp();

-- Insert default OAuth2 clients for development
INSERT INTO oauth2_clients (
    client_id, client_secret, client_name, description, 
    organization_id, client_type, require_pkce
) VALUES 
(
    'mcp_ui_client',
    '$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG', -- bcrypt hash of 'ui-secret'
    'MCP UI Client',
    'Official MCP web UI client application',
    'default',
    'CONFIDENTIAL',
    FALSE
),
(
    'mcp_mobile_client',
    NULL, -- Public client, no secret
    'MCP Mobile Client', 
    'Official MCP mobile application',
    'default',
    'PUBLIC',
    TRUE -- PKCE required for public clients
);

-- Grant types for UI client
INSERT INTO oauth2_client_grant_types (client_id, grant_type) VALUES
('mcp_ui_client', 'AUTHORIZATION_CODE'),
('mcp_ui_client', 'REFRESH_TOKEN');

-- Grant types for mobile client
INSERT INTO oauth2_client_grant_types (client_id, grant_type) VALUES
('mcp_mobile_client', 'AUTHORIZATION_CODE'),
('mcp_mobile_client', 'REFRESH_TOKEN');

-- Redirect URIs for UI client
INSERT INTO oauth2_client_redirect_uris (client_id, redirect_uri) VALUES
('mcp_ui_client', 'http://localhost:3000/callback'),
('mcp_ui_client', 'http://localhost:3001/callback'),
('mcp_ui_client', 'https://app.mcp-services.com/callback');

-- Redirect URIs for mobile client
INSERT INTO oauth2_client_redirect_uris (client_id, redirect_uri) VALUES
('mcp_mobile_client', 'mcp://oauth/callback'),
('mcp_mobile_client', 'com.zamaz.mcp://oauth/callback');

-- Default scopes for both clients
INSERT INTO oauth2_client_scopes (client_id, scope) VALUES
('mcp_ui_client', 'openid'),
('mcp_ui_client', 'profile'),
('mcp_ui_client', 'email'),
('mcp_ui_client', 'debates:read'),
('mcp_ui_client', 'debates:write'),
('mcp_ui_client', 'organizations:read'),
('mcp_ui_client', 'organizations:write'),
('mcp_mobile_client', 'openid'),
('mcp_mobile_client', 'profile'),
('mcp_mobile_client', 'email'),
('mcp_mobile_client', 'debates:read'),
('mcp_mobile_client', 'debates:write');

-- Authentication methods
INSERT INTO oauth2_client_auth_methods (client_id, auth_method) VALUES
('mcp_ui_client', 'CLIENT_SECRET_BASIC'),
('mcp_ui_client', 'CLIENT_SECRET_POST'),
('mcp_mobile_client', 'NONE');

-- Add OAuth2 permissions
INSERT INTO permissions (id, resource, action, description) VALUES
('oauth2:clients:create', 'oauth2_client', 'create', 'Create OAuth2 clients'),
('oauth2:clients:read', 'oauth2_client', 'read', 'View OAuth2 clients'),
('oauth2:clients:update', 'oauth2_client', 'update', 'Update OAuth2 clients'),
('oauth2:clients:delete', 'oauth2_client', 'delete', 'Delete OAuth2 clients'),
('oauth2:clients:secret', 'oauth2_client', 'regenerate_secret', 'Regenerate client secrets')
ON CONFLICT (id) DO NOTHING;