// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package users

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/cto-externe/lmdm/internal/db"
)

const defaultTenant = "00000000-0000-0000-0000-000000000000"

func setupRepo(t *testing.T) (*Repository, func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)

	pg, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("lmdm"),
		postgres.WithUsername("lmdm"),
		postgres.WithPassword("lmdm"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("5432/tcp").WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	dsn, _ := pg.ConnectionString(ctx, "sslmode=disable")
	if err := db.MigrateUp(dsn); err != nil {
		_ = pg.Terminate(ctx)
		cancel()
		t.Fatal(err)
	}
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		_ = pg.Terminate(ctx)
		cancel()
		t.Fatal(err)
	}
	cleanup := func() {
		pool.Close()
		_ = pg.Terminate(ctx)
		cancel()
	}
	return New(pool), cleanup
}

func TestIntegration_CreateFindByEmail_Duplicate(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()

	created, err := r.Create(ctx, tenantID, "alice@x.test", "hash1", "admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Email != "alice@x.test" || created.Role != "admin" {
		t.Fatalf("unexpected created user: %+v", created)
	}
	if !created.Active {
		t.Error("new user must default to active=true")
	}
	if created.FailedLoginCount != 0 {
		t.Errorf("failed_login_count = %d, want 0", created.FailedLoginCount)
	}

	// Case-insensitive lookup must return the same row.
	got, err := r.FindByEmail(ctx, tenantID, "ALICE@X.TEST")
	if err != nil {
		t.Fatalf("FindByEmail (upper): %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("FindByEmail returned id %s, want %s", got.ID, created.ID)
	}

	// Duplicate create must map to ErrDuplicateEmail.
	_, err = r.Create(ctx, tenantID, "alice@x.test", "hash2", "operator")
	if !errors.Is(err, ErrDuplicateEmail) {
		t.Errorf("second Create err = %v, want ErrDuplicateEmail", err)
	}

	// And also when the email differs only in case, since the unique index is
	// on lower(email).
	_, err = r.Create(ctx, tenantID, "Alice@X.Test", "hash3", "viewer")
	if !errors.Is(err, ErrDuplicateEmail) {
		t.Errorf("case-variant Create err = %v, want ErrDuplicateEmail", err)
	}
}

func TestIntegration_RecordLoginFailure_LocksAfter5(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()

	u, err := r.Create(ctx, tenantID, "bob@x.test", "hash", "operator")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Failures below the threshold must not set locked_until.
	for i := 1; i < MaxLoginFailures; i++ {
		count, lockedUntil, err := r.RecordLoginFailure(ctx, tenantID, u.ID)
		if err != nil {
			t.Fatalf("RecordLoginFailure #%d: %v", i, err)
		}
		if count != i {
			t.Errorf("failure #%d: count = %d, want %d", i, count, i)
		}
		if lockedUntil != nil {
			t.Errorf("failure #%d: lockedUntil = %v, want nil", i, lockedUntil)
		}
	}

	// The threshold-crossing failure must set locked_until to a future time.
	count, lockedUntil, err := r.RecordLoginFailure(ctx, tenantID, u.ID)
	if err != nil {
		t.Fatalf("RecordLoginFailure #%d: %v", MaxLoginFailures, err)
	}
	if count != MaxLoginFailures {
		t.Errorf("failure #%d: count = %d, want %d", MaxLoginFailures, count, MaxLoginFailures)
	}
	if lockedUntil == nil {
		t.Fatalf("failure #%d: lockedUntil is nil, want non-nil", MaxLoginFailures)
	}
	if !lockedUntil.After(time.Now()) {
		t.Errorf("failure #%d: lockedUntil = %v, want after now", MaxLoginFailures, lockedUntil)
	}

	// Persisted state must match.
	got, err := r.FindByID(ctx, tenantID, u.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.FailedLoginCount != MaxLoginFailures {
		t.Errorf("persisted count = %d, want %d", got.FailedLoginCount, MaxLoginFailures)
	}
	if got.LockedUntil == nil {
		t.Fatal("persisted LockedUntil is nil")
	}
	if !got.IsLocked(time.Now()) {
		t.Error("IsLocked(now) = false, want true")
	}
}

func TestIntegration_RecordLoginSuccess_ClearsCounter(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()

	u, err := r.Create(ctx, tenantID, "carol@x.test", "hash", "viewer")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, _, err := r.RecordLoginFailure(ctx, tenantID, u.ID); err != nil {
		t.Fatalf("RecordLoginFailure: %v", err)
	}

	clientIP := net.ParseIP("203.0.113.42")
	if err := r.RecordLoginSuccess(ctx, tenantID, u.ID, clientIP); err != nil {
		t.Fatalf("RecordLoginSuccess: %v", err)
	}

	got, err := r.FindByID(ctx, tenantID, u.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.FailedLoginCount != 0 {
		t.Errorf("FailedLoginCount = %d, want 0", got.FailedLoginCount)
	}
	if got.LockedUntil != nil {
		t.Errorf("LockedUntil = %v, want nil", got.LockedUntil)
	}
	if got.LastLoginAt == nil {
		t.Error("LastLoginAt is nil, want non-nil")
	}
	if got.LastLoginIP == nil {
		t.Fatal("LastLoginIP is nil, want the supplied IP")
	}
	if !got.LastLoginIP.Equal(clientIP) {
		t.Errorf("LastLoginIP = %v, want %v", got.LastLoginIP, clientIP)
	}
}

func TestIntegration_Deactivate_Reactivate_Unlock(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()

	admin, err := r.Create(ctx, tenantID, "admin@x.test", "ahash", "admin")
	if err != nil {
		t.Fatalf("Create admin: %v", err)
	}
	target, err := r.Create(ctx, tenantID, "dave@x.test", "hash", "operator")
	if err != nil {
		t.Fatalf("Create target: %v", err)
	}

	// Deactivate: active=false, deactivated_at set, deactivated_by_user_id set.
	if err := r.Deactivate(ctx, tenantID, target.ID, admin.ID); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	got, err := r.FindByID(ctx, tenantID, target.ID)
	if err != nil {
		t.Fatalf("FindByID after deactivate: %v", err)
	}
	if got.Active {
		t.Error("Active = true after Deactivate, want false")
	}
	if got.DeactivatedAt == nil {
		t.Error("DeactivatedAt is nil after Deactivate")
	}
	if got.DeactivatedByUserID == nil || *got.DeactivatedByUserID != admin.ID {
		t.Errorf("DeactivatedByUserID = %v, want %v", got.DeactivatedByUserID, admin.ID)
	}

	// Reactivate: active=true, deactivated columns cleared.
	if err := r.Reactivate(ctx, tenantID, target.ID); err != nil {
		t.Fatalf("Reactivate: %v", err)
	}
	got, err = r.FindByID(ctx, tenantID, target.ID)
	if err != nil {
		t.Fatalf("FindByID after reactivate: %v", err)
	}
	if !got.Active {
		t.Error("Active = false after Reactivate, want true")
	}
	if got.DeactivatedAt != nil {
		t.Errorf("DeactivatedAt = %v after Reactivate, want nil", got.DeactivatedAt)
	}
	if got.DeactivatedByUserID != nil {
		t.Errorf("DeactivatedByUserID = %v after Reactivate, want nil", got.DeactivatedByUserID)
	}

	// Lock the account via MaxLoginFailures failures, then Unlock.
	for i := 0; i < MaxLoginFailures; i++ {
		if _, _, err := r.RecordLoginFailure(ctx, tenantID, target.ID); err != nil {
			t.Fatalf("RecordLoginFailure: %v", err)
		}
	}
	got, err = r.FindByID(ctx, tenantID, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LockedUntil == nil {
		t.Fatal("LockedUntil is nil before Unlock, test precondition broken")
	}

	if err := r.Unlock(ctx, tenantID, target.ID); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	got, err = r.FindByID(ctx, tenantID, target.ID)
	if err != nil {
		t.Fatalf("FindByID after Unlock: %v", err)
	}
	if got.FailedLoginCount != 0 {
		t.Errorf("FailedLoginCount = %d after Unlock, want 0", got.FailedLoginCount)
	}
	if got.LockedUntil != nil {
		t.Errorf("LockedUntil = %v after Unlock, want nil", got.LockedUntil)
	}
}

// setupRLSRepo spins up Postgres, runs migrations, seeds two tenants, creates
// the non-owner lmdm_app role with FORCE ROW LEVEL SECURITY on the users
// table, then returns a Repository backed by a pool connected as lmdm_app.
// This is how the real server runs, so RLS actually applies — superuser
// connections bypass RLS and would make the cross-tenant assertions vacuous.
func setupRLSRepo(t *testing.T) (*Repository, uuid.UUID, uuid.UUID, func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)

	pg, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("lmdm"),
		postgres.WithUsername("lmdm"),
		postgres.WithPassword("lmdm"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("5432/tcp").WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	dsn, _ := pg.ConnectionString(ctx, "sslmode=disable")
	if err := db.MigrateUp(dsn); err != nil {
		_ = pg.Terminate(ctx)
		cancel()
		t.Fatal(err)
	}

	// Open as superuser to seed tenants + create the non-owner role.
	ownerPool, err := db.Open(ctx, dsn)
	if err != nil {
		_ = pg.Terminate(ctx)
		cancel()
		t.Fatal(err)
	}

	tenantA := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	tenantB := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	if _, err := ownerPool.Exec(ctx, `
		INSERT INTO tenants (id, name) VALUES
			('11111111-1111-1111-1111-111111111111', 'tenant-a'),
			('22222222-2222-2222-2222-222222222222', 'tenant-b');
		CREATE ROLE lmdm_app LOGIN PASSWORD 'appsecret';
		GRANT SELECT, INSERT, UPDATE, DELETE ON users TO lmdm_app;
		ALTER TABLE users FORCE ROW LEVEL SECURITY;
	`); err != nil {
		ownerPool.Close()
		_ = pg.Terminate(ctx)
		cancel()
		t.Fatalf("seed: %v", err)
	}
	ownerPool.Close()

	appPool, err := db.Open(ctx, replaceUserForRLS(dsn, "lmdm_app", "appsecret"))
	if err != nil {
		_ = pg.Terminate(ctx)
		cancel()
		t.Fatalf("open app pool: %v", err)
	}

	cleanup := func() {
		appPool.Close()
		_ = pg.Terminate(ctx)
		cancel()
	}
	return New(appPool), tenantA, tenantB, cleanup
}

// replaceUserForRLS swaps the userinfo component of a postgres:// DSN so the
// test can reconnect as the non-owner lmdm_app role.
func replaceUserForRLS(dsn, user, password string) string {
	const scheme = "postgres://"
	if len(dsn) < len(scheme) || dsn[:len(scheme)] != scheme {
		return dsn
	}
	rest := dsn[len(scheme):]
	at := -1
	for i := 0; i < len(rest); i++ {
		if rest[i] == '@' {
			at = i
			break
		}
	}
	if at < 0 {
		return dsn
	}
	return scheme + user + ":" + password + "@" + rest[at+1:]
}

func TestIntegration_RLS_IsolatesUsersAcrossTenants(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx := context.Background()

	r, tenantA, tenantB, cleanup := setupRLSRepo(t)
	defer cleanup()

	// Create a user under tenant A.
	ua, err := r.Create(ctx, tenantA, "a@x.test", "$argon2id$dummy", "admin")
	if err != nil {
		t.Fatal(err)
	}

	// FindByID under tenant B must not see it (RLS filters the row).
	if _, err := r.FindByID(ctx, tenantB, ua.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound across tenants, got %v", err)
	}
	// FindByEmail under tenant B must not see it either.
	if _, err := r.FindByEmail(ctx, tenantB, "a@x.test"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for cross-tenant email, got %v", err)
	}
	// Mutations scoped to tenant B also cannot reach the tenant A row — all
	// should return ErrNotFound (the update() helper conflates "no such row"
	// with "filtered by RLS" on purpose; see its godoc).
	if err := r.SetRole(ctx, tenantB, ua.ID, "viewer"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetRole cross-tenant should return ErrNotFound, got %v", err)
	}
	if err := r.Deactivate(ctx, tenantB, ua.ID, ua.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Deactivate cross-tenant should return ErrNotFound, got %v", err)
	}

	// Sanity: tenant A can still see its own user.
	if _, err := r.FindByID(ctx, tenantA, ua.ID); err != nil {
		t.Fatalf("tenant A must still see its own user: %v", err)
	}

	// List under tenant B must exclude the tenant A user.
	listB, err := r.List(ctx, tenantB, ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range listB {
		if u.ID == ua.ID {
			t.Errorf("tenant B List leaked tenant A user %s", u.ID)
		}
	}
}

func TestIntegration_SetPasswordHash_UpdatesHashAndMustChangeFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()

	u, err := r.Create(ctx, tenantID, "pw@x.test", "oldhash", "operator")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := r.SetPasswordHash(ctx, tenantID, u.ID, "newhash", true); err != nil {
		t.Fatalf("SetPasswordHash: %v", err)
	}
	got, err := r.FindByID(ctx, tenantID, u.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.PasswordHash != "newhash" {
		t.Errorf("PasswordHash = %q, want %q", got.PasswordHash, "newhash")
	}
	if !got.MustChangePassword {
		t.Error("MustChangePassword = false, want true")
	}
}

func TestIntegration_SetTOTP_PersistsEncryptedBlobAndEnrolledAt(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()

	u, err := r.Create(ctx, tenantID, "totp@x.test", "hash", "operator")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	blob := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	if err := r.SetTOTP(ctx, tenantID, u.ID, blob); err != nil {
		t.Fatalf("SetTOTP: %v", err)
	}
	got, err := r.FindByID(ctx, tenantID, u.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if !bytes.Equal(got.TOTPSecretEncrypted, blob) {
		t.Errorf("TOTPSecretEncrypted = %x, want %x", got.TOTPSecretEncrypted, blob)
	}
	if got.TOTPEnrolledAt == nil {
		t.Error("TOTPEnrolledAt is nil, want non-nil")
	}
}

func TestIntegration_SetRole_ChangesRole(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()

	u, err := r.Create(ctx, tenantID, "role@x.test", "hash", "viewer")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := r.SetRole(ctx, tenantID, u.ID, "admin"); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	got, err := r.FindByID(ctx, tenantID, u.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Role != "admin" {
		t.Errorf("Role = %q, want %q", got.Role, "admin")
	}
}

func TestIntegration_List_AppliesRoleAndActiveFilters(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	r, cleanup := setupRepo(t)
	defer cleanup()

	tenantID := uuid.MustParse(defaultTenant)
	ctx := context.Background()

	admin, err := r.Create(ctx, tenantID, "admin-list@x.test", "hash", "admin")
	if err != nil {
		t.Fatalf("Create admin: %v", err)
	}
	op, err := r.Create(ctx, tenantID, "op-list@x.test", "hash", "operator")
	if err != nil {
		t.Fatalf("Create operator: %v", err)
	}
	if err := r.Deactivate(ctx, tenantID, op.ID, admin.ID); err != nil {
		t.Fatalf("Deactivate operator: %v", err)
	}

	// Role filter: only admins come back.
	adminsOnly, err := r.List(ctx, tenantID, ListFilter{Role: "admin"})
	if err != nil {
		t.Fatalf("List(role=admin): %v", err)
	}
	for _, u := range adminsOnly {
		if u.Role != "admin" {
			t.Errorf("List returned role %q under Role=admin filter", u.Role)
		}
	}
	if len(adminsOnly) == 0 {
		t.Error("List(role=admin) returned 0 rows, want at least 1")
	}

	// ActiveOnly filter: deactivated operator must be excluded.
	activeOnly, err := r.List(ctx, tenantID, ListFilter{ActiveOnly: true})
	if err != nil {
		t.Fatalf("List(active-only): %v", err)
	}
	for _, u := range activeOnly {
		if u.ID == op.ID {
			t.Errorf("List(active-only) leaked deactivated user %s", op.ID)
		}
		if !u.Active {
			t.Errorf("List(active-only) returned inactive user %s", u.ID)
		}
	}
}
