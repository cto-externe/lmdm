-- Enrollment tokens are issued by an admin out-of-band and presented by the
-- agent at first contact. The plaintext is shown ONCE at creation; only the
-- SHA-256 hash is stored. Tokens have a TTL, a max-uses count, optional site
-- pre-binding, and a list of group_ids the agent will join.

CREATE TABLE enrollment_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    secret_hash     BYTEA NOT NULL UNIQUE,    -- SHA-256 of plaintext
    description     TEXT NOT NULL,
    group_ids       TEXT[] NOT NULL DEFAULT '{}',
    site_id         UUID,                     -- nullable: agent uses inferred site if absent
    max_uses        INTEGER NOT NULL CHECK (max_uses > 0),
    used_count      INTEGER NOT NULL DEFAULT 0 CHECK (used_count >= 0),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      TEXT NOT NULL
);

CREATE INDEX enrollment_tokens_tenant_idx ON enrollment_tokens (tenant_id, expires_at);

ALTER TABLE enrollment_tokens ENABLE ROW LEVEL SECURITY;

CREATE POLICY enrollment_tokens_tenant_scope ON enrollment_tokens
    USING (tenant_id = lmdm_current_tenant())
    WITH CHECK (tenant_id = lmdm_current_tenant());
