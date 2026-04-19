-- Health snapshots: time-series JSONB + indexed summary columns.
-- One row per (device, timestamp). The latest row is also denormalized on
-- devices via app-level upsert (see internal/devices/repo.go).
-- See plan §Task 1 for context.

CREATE TABLE health_snapshots (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    device_id               UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ts                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    overall_score           SMALLINT NOT NULL,
    battery_health_pct      INTEGER,
    critical_disk_count     INTEGER NOT NULL DEFAULT 0,
    warning_disk_count      INTEGER NOT NULL DEFAULT 0,
    fwupd_updates_count     INTEGER NOT NULL DEFAULT 0,
    fwupd_critical_count    INTEGER NOT NULL DEFAULT 0,
    snapshot                JSONB NOT NULL,
    CONSTRAINT health_snapshots_score_range CHECK (overall_score BETWEEN 0 AND 2)
);

CREATE INDEX health_snapshots_device_ts_idx
    ON health_snapshots (tenant_id, device_id, ts DESC);
CREATE INDEX health_snapshots_ts_idx ON health_snapshots (ts);
CREATE INDEX health_snapshots_snapshot_gin_idx ON health_snapshots USING GIN (snapshot);

ALTER TABLE health_snapshots ENABLE ROW LEVEL SECURITY;
CREATE POLICY health_snapshots_tenant_scope ON health_snapshots
    USING (tenant_id = lmdm_current_tenant())
    WITH CHECK (tenant_id = lmdm_current_tenant());

-- Denormalized summary on devices for list-view queries.
ALTER TABLE devices
    ADD COLUMN last_health_at         TIMESTAMPTZ,
    ADD COLUMN last_health_score      SMALLINT,
    ADD COLUMN battery_health_pct     INTEGER,
    ADD COLUMN fwupd_updates_count    INTEGER,
    ADD CONSTRAINT devices_health_score_range CHECK (last_health_score IS NULL OR last_health_score BETWEEN 0 AND 2);

CREATE INDEX devices_last_health_score_idx
    ON devices (tenant_id, last_health_score) WHERE last_health_score IS NOT NULL;
