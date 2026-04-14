-- Audit log: append-only record of every meaningful action in the system.
-- Every row is tagged with a tenant_id and guarded by RLS so the Enterprise
-- edition's cross-tenant routing needs no schema changes.

CREATE TABLE audit_log (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    ts            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,
    resource_type TEXT,
    resource_id   TEXT,
    source_ip     INET,
    details       JSONB
);

CREATE INDEX audit_log_tenant_ts_idx ON audit_log (tenant_id, ts DESC);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY audit_log_tenant_scope ON audit_log
    USING (tenant_id = lmdm_current_tenant())
    WITH CHECK (tenant_id = lmdm_current_tenant());
