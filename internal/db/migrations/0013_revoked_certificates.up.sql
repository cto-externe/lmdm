-- Revoked agent certificates. The serial number is the lookup key because
-- that's what VerifyPeerCertificate receives from the TLS handshake.
-- The optional device_id is stored for operator reporting only.

CREATE TABLE revoked_certificates (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    serial_number      TEXT NOT NULL,
    device_id          UUID REFERENCES devices(id) ON DELETE SET NULL,
    revoked_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    reason             TEXT NOT NULL DEFAULT '',
    UNIQUE (tenant_id, serial_number)
);
CREATE INDEX revoked_certificates_serial_idx ON revoked_certificates (serial_number);

ALTER TABLE revoked_certificates ENABLE ROW LEVEL SECURITY;
CREATE POLICY revoked_certificates_tenant_scope ON revoked_certificates
    USING (tenant_id = lmdm_current_tenant())
    WITH CHECK (tenant_id = lmdm_current_tenant());

-- Track each device's currently issued cert serial. Populated at enrollment
-- (and at renewal) by the gRPC enrollment service.
ALTER TABLE devices ADD COLUMN current_cert_serial TEXT;
