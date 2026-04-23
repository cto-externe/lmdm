-- 0014_patch_schedules.down.sql
DROP POLICY IF EXISTS patch_schedules_tenant_scope ON patch_schedules;
DROP TABLE IF EXISTS patch_schedules;

ALTER TABLE devices
    DROP COLUMN IF EXISTS pending_reboot_last_deferred_at,
    DROP COLUMN IF EXISTS pending_reboot_defer_count,
    DROP COLUMN IF EXISTS maintenance_window_override,
    DROP COLUMN IF EXISTS reboot_policy_override;

ALTER TABLE tenants
    DROP COLUMN IF EXISTS maintenance_window,
    DROP COLUMN IF EXISTS reboot_policy;
