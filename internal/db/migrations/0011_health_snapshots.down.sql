ALTER TABLE devices
    DROP CONSTRAINT IF EXISTS devices_health_score_range,
    DROP COLUMN IF EXISTS fwupd_updates_count,
    DROP COLUMN IF EXISTS battery_health_pct,
    DROP COLUMN IF EXISTS last_health_score,
    DROP COLUMN IF EXISTS last_health_at;

DROP TABLE IF EXISTS health_snapshots;
