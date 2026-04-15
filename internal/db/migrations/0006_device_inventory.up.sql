-- device_inventory holds the latest full inventory report per device, stored
-- as both the raw protobuf bytes (for signature/roundtrip guarantees later)
-- and a protojson-rendered JSONB (for ad-hoc queries). One row per device;
-- UPSERT on device_id on each new full report.

CREATE TABLE device_inventory (
    device_id       UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    schema_version  INTEGER NOT NULL,
    is_full         BOOLEAN NOT NULL DEFAULT TRUE,
    report_bytes    BYTEA NOT NULL,        -- serialized lmdmv1.InventoryReport
    report_json     JSONB NOT NULL,        -- protojson of the same report
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX device_inventory_tenant_idx    ON device_inventory (tenant_id);
CREATE INDEX device_inventory_received_idx  ON device_inventory (received_at DESC);

-- Fast lookups by OS family / CPU model via JSONB path expressions. These
-- indexes are GIN on relevant JSONB subtrees.
CREATE INDEX device_inventory_os_gin    ON device_inventory USING GIN ((report_json -> 'software' -> 'os'));
CREATE INDEX device_inventory_cpu_gin   ON device_inventory USING GIN ((report_json -> 'hardware' -> 'cpu'));

ALTER TABLE device_inventory ENABLE ROW LEVEL SECURITY;

CREATE POLICY device_inventory_tenant_scope ON device_inventory
    USING (tenant_id = lmdm_current_tenant())
    WITH CHECK (tenant_id = lmdm_current_tenant());
