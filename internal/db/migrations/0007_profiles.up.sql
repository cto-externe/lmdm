-- Profiles store policy bundles as dual YAML+JSONB. The YAML is the signable
-- source of truth; the JSONB is a derived representation for efficient queries.
-- profile_assignments links profiles to devices (groups later).

CREATE TABLE profiles (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    name                TEXT NOT NULL,
    version             TEXT NOT NULL DEFAULT '1.0',
    description         TEXT NOT NULL DEFAULT '',
    yaml_content        TEXT NOT NULL,
    json_content        JSONB NOT NULL,
    signature_ed25519   BYTEA,
    signature_mldsa     BYTEA,
    source              TEXT NOT NULL DEFAULT 'custom',
    locked              BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name, version)
);

CREATE INDEX profiles_tenant_idx ON profiles (tenant_id);

ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY profiles_tenant_scope ON profiles
    USING (tenant_id = lmdm_current_tenant())
    WITH CHECK (tenant_id = lmdm_current_tenant());

CREATE TABLE profile_assignments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    profile_id      UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    target_type     TEXT NOT NULL CHECK (target_type IN ('device', 'group', 'tenant')),
    target_id       UUID NOT NULL,
    priority        INTEGER NOT NULL DEFAULT 0,
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (profile_id, target_type, target_id)
);

CREATE INDEX profile_assignments_target_idx ON profile_assignments (target_type, target_id);

ALTER TABLE profile_assignments ENABLE ROW LEVEL SECURITY;
CREATE POLICY profile_assignments_tenant_scope ON profile_assignments
    USING (tenant_id = lmdm_current_tenant())
    WITH CHECK (tenant_id = lmdm_current_tenant());
