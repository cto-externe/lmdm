-- Devices is the unified table for every managed device (workstations,
-- printers, network gear, mobile). Per architecture spec §4. At enrollment
-- time, only workstation rows are inserted; other types arrive in later plans.

CREATE TYPE device_type   AS ENUM ('workstation', 'printer', 'network', 'mobile');
CREATE TYPE device_status AS ENUM ('online', 'offline', 'degraded', 'decommissioned');

CREATE TABLE devices (
    id                    UUID PRIMARY KEY,
    tenant_id             UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    device_type           device_type NOT NULL,
    hostname              TEXT NOT NULL,
    serial_number         TEXT,
    manufacturer          TEXT,
    model                 TEXT,
    site_id               UUID,
    status                device_status NOT NULL DEFAULT 'offline',
    last_seen             TIMESTAMPTZ,
    enrolled_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    enrolled_via_token    UUID REFERENCES enrollment_tokens(id) ON DELETE SET NULL,

    -- Agent identity (workstation only at MVP; nullable otherwise)
    agent_pubkey_ed25519  BYTEA,
    agent_pubkey_mldsa    BYTEA,
    cert_serial           TEXT
);

CREATE INDEX devices_tenant_idx          ON devices (tenant_id);
CREATE INDEX devices_status_idx          ON devices (tenant_id, status);
CREATE UNIQUE INDEX devices_pubkey_unique ON devices (agent_pubkey_ed25519)
    WHERE agent_pubkey_ed25519 IS NOT NULL;

ALTER TABLE devices ENABLE ROW LEVEL SECURITY;

CREATE POLICY devices_tenant_scope ON devices
    USING (tenant_id = lmdm_current_tenant())
    WITH CHECK (tenant_id = lmdm_current_tenant());
