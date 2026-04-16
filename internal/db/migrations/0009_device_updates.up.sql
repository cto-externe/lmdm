CREATE TABLE device_updates (
    id                  BIGSERIAL PRIMARY KEY,
    device_id           UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    package_name        TEXT NOT NULL,
    current_version     TEXT NOT NULL,
    available_version   TEXT NOT NULL,
    is_security         BOOLEAN NOT NULL DEFAULT FALSE,
    source              TEXT NOT NULL DEFAULT 'apt',
    detected_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, package_name)
);

CREATE INDEX device_updates_tenant_idx ON device_updates (tenant_id);
CREATE INDEX device_updates_device_idx ON device_updates (device_id);
CREATE INDEX device_updates_security_idx ON device_updates (tenant_id, is_security) WHERE is_security = TRUE;

ALTER TABLE device_updates ENABLE ROW LEVEL SECURITY;
CREATE POLICY device_updates_tenant_scope ON device_updates
    USING (tenant_id = lmdm_current_tenant())
    WITH CHECK (tenant_id = lmdm_current_tenant());

ALTER TABLE devices ADD COLUMN reboot_required BOOLEAN NOT NULL DEFAULT FALSE;
