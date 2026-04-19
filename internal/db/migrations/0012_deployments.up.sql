-- Deployments: orchestrated canary + rollout workflow per the spec §5B.
-- Each deployment targets a group or a device list, starts a canary on one
-- device, waits for health checks + optional admin validation, then rolls
-- out to the rest. State machine lives in internal/deployments/engine.go.

CREATE TABLE deployments (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    profile_id               UUID NOT NULL REFERENCES profiles(id) ON DELETE RESTRICT,
    target_group_id          UUID,
    target_device_ids        UUID[],
    canary_device_id         UUID NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    status                   TEXT NOT NULL CHECK (status IN (
        'planned','canary_running','canary_ok','canary_failed',
        'awaiting_validation','rolling_out','completed',
        'partially_failed','rolled_back'
    )),
    validation_mode          TEXT NOT NULL DEFAULT 'manual'
        CHECK (validation_mode IN ('manual','semi_auto','auto')),
    validation_timeout_s     INTEGER NOT NULL DEFAULT 1800,
    failure_threshold_pct    INTEGER NOT NULL DEFAULT 10
        CHECK (failure_threshold_pct BETWEEN 0 AND 100),
    created_by_user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    canary_started_at        TIMESTAMPTZ,
    canary_finished_at       TIMESTAMPTZ,
    validated_at             TIMESTAMPTZ,
    completed_at             TIMESTAMPTZ,
    reason                   TEXT,
    CONSTRAINT deployments_target_xor CHECK (
        (target_group_id IS NOT NULL AND target_device_ids IS NULL) OR
        (target_group_id IS NULL AND target_device_ids IS NOT NULL)
    )
);
CREATE INDEX deployments_tenant_status_idx
    ON deployments (tenant_id, status, created_at DESC);

ALTER TABLE deployments ENABLE ROW LEVEL SECURITY;
CREATE POLICY deployments_tenant_scope ON deployments
    USING (tenant_id = lmdm_current_tenant())
    WITH CHECK (tenant_id = lmdm_current_tenant());

CREATE TABLE deployment_results (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    deployment_id        UUID NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    device_id            UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    is_canary            BOOLEAN NOT NULL DEFAULT FALSE,
    status               TEXT NOT NULL CHECK (status IN (
        'pending','applying','success','failed','rolled_back'
    )),
    snapshot_id          TEXT,
    health_check_results JSONB,
    error_message        TEXT,
    applied_at           TIMESTAMPTZ,
    rolled_back_at       TIMESTAMPTZ,
    UNIQUE (deployment_id, device_id)
);
CREATE INDEX deployment_results_deployment_idx
    ON deployment_results (deployment_id);
CREATE INDEX deployment_results_device_idx
    ON deployment_results (device_id);

ALTER TABLE deployment_results ENABLE ROW LEVEL SECURITY;
CREATE POLICY deployment_results_tenant_scope ON deployment_results
    USING (tenant_id = lmdm_current_tenant())
    WITH CHECK (tenant_id = lmdm_current_tenant());
