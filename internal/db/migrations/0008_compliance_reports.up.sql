CREATE TABLE compliance_reports (
    device_id       UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    overall_status  TEXT NOT NULL CHECK (overall_status IN ('compliant', 'non_compliant', 'unknown')),
    report_json     JSONB NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX compliance_reports_tenant_idx ON compliance_reports (tenant_id);
CREATE INDEX compliance_reports_status_idx ON compliance_reports (tenant_id, overall_status);

ALTER TABLE compliance_reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY compliance_reports_tenant_scope ON compliance_reports
    USING (tenant_id = lmdm_current_tenant())
    WITH CHECK (tenant_id = lmdm_current_tenant());
