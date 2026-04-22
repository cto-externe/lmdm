-- 0014_patch_schedules.up.sql
-- Patch management: server-side scheduler + hybrid reboot policy.
-- Per brainstorm decisions 2026-04-21.

-- Reboot policy defaults (tenant-level).
-- Values: admin_only (default), immediate_after_apply, next_maintenance_window.
-- maintenance_window is a cron expression ("0 22 * * 2" = Tuesday 22h) or NULL.
ALTER TABLE tenants
    ADD COLUMN reboot_policy TEXT NOT NULL DEFAULT 'admin_only'
        CHECK (reboot_policy IN ('admin_only','immediate_after_apply','next_maintenance_window')),
    ADD COLUMN maintenance_window TEXT;

-- Per-device overrides. NULL = inherit from tenant.
-- pending_reboot_defer_count / _last_deferred_at track agent-reported defers.
ALTER TABLE devices
    ADD COLUMN reboot_policy_override TEXT
        CHECK (reboot_policy_override IS NULL OR reboot_policy_override IN
               ('admin_only','immediate_after_apply','next_maintenance_window')),
    ADD COLUMN maintenance_window_override TEXT,
    ADD COLUMN pending_reboot_defer_count INT NOT NULL DEFAULT 0,
    ADD COLUMN pending_reboot_last_deferred_at TIMESTAMPTZ;

-- patch_schedules: one row per tenant (device_id NULL) or per device.
CREATE TABLE patch_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    cron_expr TEXT NOT NULL,
    filter_security_only BOOLEAN NOT NULL DEFAULT FALSE,
    filter_include_packages TEXT[],
    filter_exclude_packages TEXT[],
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    next_fire_at TIMESTAMPTZ NOT NULL,
    last_ran_at TIMESTAMPTZ,
    last_run_status TEXT CHECK (last_run_status IS NULL OR last_run_status IN (
        'ok','skipped_missed_window','publish_error'
    )),
    skipped_runs_count INT NOT NULL DEFAULT 0,
    created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX patch_schedules_next_fire_idx
    ON patch_schedules (next_fire_at) WHERE enabled;
CREATE INDEX patch_schedules_tenant_idx
    ON patch_schedules (tenant_id);

ALTER TABLE patch_schedules ENABLE ROW LEVEL SECURITY;
CREATE POLICY patch_schedules_tenant_scope ON patch_schedules
    USING (tenant_id = lmdm_current_tenant())
    WITH CHECK (tenant_id = lmdm_current_tenant());
