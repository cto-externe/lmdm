-- Auth/RBAC: console admin user accounts and refresh-token rotation state.
-- Passwords are stored as argon2id hashes; TOTP secrets are stored encrypted
-- (envelope KMS) and only ever decrypted in-memory at verification time.
-- Refresh tokens are opaque random strings; only their SHA-256 hash is
-- persisted, and rotation is tracked via family_id/parent_id so that reuse
-- of a previously-rotated token can be detected and the whole family revoked.
-- Both tables are tenant-scoped and guarded by RLS just like every other
-- table in the schema (see internal/db/migrations/0001_tenants.up.sql for
-- the lmdm.tenant_id GUC and lmdm_current_tenant() helper).

CREATE TABLE users (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    email                   TEXT NOT NULL,
    password_hash           TEXT NOT NULL,
    role                    TEXT NOT NULL CHECK (role IN ('admin','operator','viewer')),
    totp_secret_encrypted   BYTEA,
    totp_enrolled_at        TIMESTAMPTZ,
    must_change_password    BOOLEAN NOT NULL DEFAULT FALSE,
    active                  BOOLEAN NOT NULL DEFAULT TRUE,
    failed_login_count      INTEGER NOT NULL DEFAULT 0,
    locked_until            TIMESTAMPTZ,
    last_login_at           TIMESTAMPTZ,
    last_login_ip           INET,
    deactivated_at          TIMESTAMPTZ,
    deactivated_by_user_id  UUID REFERENCES users(id),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX users_tenant_email_lower_idx
    ON users (tenant_id, lower(email));
CREATE INDEX users_tenant_idx ON users (tenant_id);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY users_tenant_scope ON users
    USING (tenant_id = lmdm_current_tenant())
    WITH CHECK (tenant_id = lmdm_current_tenant());

CREATE TABLE refresh_tokens (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash         BYTEA NOT NULL,
    family_id          UUID NOT NULL,
    parent_id          UUID REFERENCES refresh_tokens(id),
    issued_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ,
    revoked_reason     TEXT,
    user_agent         TEXT,
    client_ip          INET
);

CREATE UNIQUE INDEX refresh_tokens_token_hash_idx ON refresh_tokens (token_hash);
CREATE INDEX refresh_tokens_user_active_idx
    ON refresh_tokens (user_id) WHERE revoked_at IS NULL;
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_expires_idx ON refresh_tokens (expires_at);

ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY refresh_tokens_tenant_scope ON refresh_tokens
    USING (tenant_id = lmdm_current_tenant())
    WITH CHECK (tenant_id = lmdm_current_tenant());
