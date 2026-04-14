-- Tenants are the unit of isolation. In the Community edition a single
-- default tenant is pre-inserted and used for all data. The Enterprise
-- edition adds routing and cross-tenant features on top.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE tenants (
    id           UUID PRIMARY KEY,
    name         TEXT NOT NULL,
    parent_id    UUID REFERENCES tenants(id) ON DELETE RESTRICT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Fixed well-known UUID for the Community-edition default tenant.
INSERT INTO tenants (id, name) VALUES
    ('00000000-0000-0000-0000-000000000000', 'default');

-- Helper that returns the tenant_id currently scoping the session. Used by
-- RLS policies on every tenant-scoped table. The server sets this via
-- SET LOCAL lmdm.tenant_id = '...' at the start of each request.
CREATE OR REPLACE FUNCTION lmdm_current_tenant() RETURNS UUID AS $$
BEGIN
    RETURN COALESCE(
        NULLIF(current_setting('lmdm.tenant_id', true), ''),
        '00000000-0000-0000-0000-000000000000'
    )::UUID;
END;
$$ LANGUAGE plpgsql STABLE;
