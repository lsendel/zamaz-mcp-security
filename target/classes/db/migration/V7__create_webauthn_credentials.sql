-- Constants and Common Patterns
-- VARCHAR_DEFAULT: VARCHAR(255)
-- TIMESTAMP_DEFAULT: TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP
-- UUID_DEFAULT: UUID PRIMARY KEY DEFAULT gen_random_uuid()
-- AUDIT_COLUMNS: created_at, updated_at, created_by, updated_by

-- Create WebAuthn credentials table for passwordless authentication
CREATE TABLE webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id VARCHAR(512) NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    user_handle VARCHAR(512) NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    aaguid VARCHAR(255),
    device_name VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,
    is_backup_eligible BOOLEAN,
    is_backed_up BOOLEAN,
    transport_hints JSONB
);

-- Indexes for performance
CREATE INDEX idx_webauthn_user_id ON webauthn_credentials(user_id);
CREATE INDEX idx_webauthn_credential_id ON webauthn_credentials(credential_id);
CREATE INDEX idx_webauthn_last_used ON webauthn_credentials(last_used_at);

-- Comments
COMMENT ON TABLE webauthn_credentials IS 'WebAuthn/FIDO2 credentials for passwordless authentication';
COMMENT ON COLUMN webauthn_credentials.credential_id IS 'Base64URL encoded credential ID from authenticator';
COMMENT ON COLUMN webauthn_credentials.public_key IS 'Base64URL encoded public key in COSE format';
COMMENT ON COLUMN webauthn_credentials.user_handle IS 'Base64URL encoded user handle';
COMMENT ON COLUMN webauthn_credentials.sign_count IS 'Signature counter for replay attack prevention';
COMMENT ON COLUMN webauthn_credentials.aaguid IS 'Authenticator Attestation GUID';
COMMENT ON COLUMN webauthn_credentials.device_name IS 'User-friendly name for the authenticator';
COMMENT ON COLUMN webauthn_credentials.transport_hints IS 'Available transports (usb, nfc, ble, internal)';

-- Add WebAuthn preference to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS webauthn_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS preferred_auth_method VARCHAR(50) DEFAULT 'password';

-- Create audit trigger for WebAuthn credentials
CREATE OR REPLACE FUNCTION audit_webauthn_credential_changes() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO security_audit_logs (
            event_type, user_id, event_details, created_at
        ) VALUES (
            'WEBAUTHN_CREDENTIAL_ADDED',
            NEW.user_id,
            jsonb_build_object(
                'credential_id', NEW.credential_id,
                'device_name', NEW.device_name
            ),
            CURRENT_TIMESTAMP
        );
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO security_audit_logs (
            event_type, user_id, event_details, created_at
        ) VALUES (
            'WEBAUTHN_CREDENTIAL_REMOVED',
            OLD.user_id,
            jsonb_build_object(
                'credential_id', OLD.credential_id,
                'device_name', OLD.device_name
            ),
            CURRENT_TIMESTAMP
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER webauthn_credential_audit
    AFTER INSERT OR DELETE ON webauthn_credentials
    FOR EACH ROW EXECUTE FUNCTION audit_webauthn_credential_changes();