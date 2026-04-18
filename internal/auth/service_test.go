// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/cto-externe/lmdm/internal/audit"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/users"
)

const svcDefaultTenant = "00000000-0000-0000-0000-000000000000"

// setupService spins up Postgres, runs migrations, and returns a *Service wired
// to a real users.Repository + real audit.Writer backed by the same pool, plus
// a cleanup func.
func setupService(t *testing.T) (*Service, func()) {
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

	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		pool.Close()
		_ = pg.Terminate(ctx)
		cancel()
		t.Fatal(err)
	}
	signer := NewJWTSigner(newTestKey(t), 15*time.Minute)
	svc := &Service{
		Users:    users.New(pool),
		Audit:    audit.NewWriter(pool),
		Signer:   signer,
		EncKey:   encKey,
		TenantID: uuid.MustParse(svcDefaultTenant),
		Issuer:   "LMDM-Test",
	}

	cleanup := func() {
		pool.Close()
		_ = pg.Terminate(ctx)
		cancel()
	}
	return svc, cleanup
}

// createUser inserts a user with the given password (hashed with argon2id) and
// optionally pre-enrolls a TOTP secret encrypted with svc.EncKey. Returns the
// persisted user and the plaintext TOTP secret (empty when totp=false).
func createUser(t *testing.T, svc *Service, email, password, role string, totp bool) (*users.User, string) {
	t.Helper()
	ctx := context.Background()
	h, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	u, err := svc.Users.Create(ctx, svc.TenantID, email, h, role)
	if err != nil {
		t.Fatal(err)
	}
	var secret string
	if totp {
		enr, err := EnrollTOTP(email, svc.Issuer)
		if err != nil {
			t.Fatal(err)
		}
		secret = enr.Secret
		ct, err := Encrypt(svc.EncKey, []byte(secret))
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.Users.SetTOTP(ctx, svc.TenantID, u.ID, ct); err != nil {
			t.Fatal(err)
		}
		// Re-read to get the TOTPSecretEncrypted populated.
		u, err = svc.Users.FindByID(ctx, svc.TenantID, u.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	return u, secret
}

// extractOTPSecret pulls the ?secret=... value out of an otpauth:// URI.
func extractOTPSecret(uri string) string {
	const k = "secret="
	i := strings.Index(uri, k)
	if i < 0 {
		return ""
	}
	j := i + len(k)
	for j < len(uri) && uri[j] != '&' {
		j++
	}
	return uri[i+len(k) : j]
}

// currentTOTP computes the code for secret at time.Now().
func currentTOTP(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestService_Login_InvalidCredentials(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	svc, cleanup := setupService(t)
	defer cleanup()

	_, err := svc.Login(context.Background(), "nobody@x.test", "pw-does-not-matter", net.ParseIP("203.0.113.1"))
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login(unknown email) err = %v, want ErrInvalidCredentials", err)
	}
}

func TestService_Login_LocksAfterFiveFailures(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	svc, cleanup := setupService(t)
	defer cleanup()

	const pw = "correct-horse-battery-staple"
	u, _ := createUser(t, svc, "lock@x.test", pw, "operator", false)
	ip := net.ParseIP("203.0.113.2")
	ctx := context.Background()

	for i := 0; i < users.MaxLoginFailures; i++ {
		_, err := svc.Login(ctx, u.Email, "wrong-password", ip)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("failure #%d: err = %v, want ErrInvalidCredentials", i+1, err)
		}
	}

	if _, err := svc.Login(ctx, u.Email, pw, ip); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("after 5 failures Login with correct pw err = %v, want ErrAccountLocked", err)
	}
}

func TestService_Login_Then_MFASetup_IssuesTokens(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	svc, cleanup := setupService(t)
	defer cleanup()

	const pw = "correct-horse-battery-staple"
	u, _ := createUser(t, svc, "mfa@x.test", pw, "admin", false)
	ctx := context.Background()
	ip := net.ParseIP("203.0.113.3")

	res, err := svc.Login(ctx, u.Email, pw, ip)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !res.NeedsMFASetup {
		t.Fatalf("expected NeedsMFASetup=true, got %+v", res)
	}

	enr, err := svc.EnrollMFA(ctx, res.StepUpToken, u.Email)
	if err != nil {
		t.Fatalf("EnrollMFA: %v", err)
	}
	secret := extractOTPSecret(enr.URI)
	if secret == "" {
		t.Fatalf("no secret in URI %q", enr.URI)
	}

	tok, err := svc.VerifyMFA(ctx, res.StepUpToken, currentTOTP(t, secret), enr.SetupHandle, "ua/1.0", ip)
	if err != nil {
		t.Fatalf("VerifyMFA: %v", err)
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatalf("empty token(s): %+v", tok)
	}

	// TOTPSecretEncrypted must now be populated in DB.
	got, err := svc.Users.FindByID(ctx, svc.TenantID, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TOTPSecretEncrypted == nil {
		t.Error("TOTPSecretEncrypted is nil after MFA setup, want populated")
	}
}

func TestService_Refresh_RotatesAndDetectsReuse(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	svc, cleanup := setupService(t)
	defer cleanup()

	const pw = "correct-horse-battery-staple"
	u, secret := createUser(t, svc, "rot@x.test", pw, "operator", true)
	ctx := context.Background()
	ip := net.ParseIP("203.0.113.4")

	res, err := svc.Login(ctx, u.Email, pw, ip)
	if err != nil {
		t.Fatal(err)
	}
	if !res.NeedsMFAVerify {
		t.Fatalf("expected NeedsMFAVerify=true, got %+v", res)
	}
	tok, err := svc.VerifyMFA(ctx, res.StepUpToken, currentTOTP(t, secret), "", "ua/1.0", ip)
	if err != nil {
		t.Fatalf("VerifyMFA: %v", err)
	}

	// Rotate once — should succeed and give a new refresh token.
	rotated, err := svc.Refresh(ctx, tok.RefreshToken, "ua/1.0", ip)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if rotated.RefreshToken == tok.RefreshToken {
		t.Error("rotated refresh token is identical to original")
	}

	// Reuse original (already rotated) → family must be revoked, including rotated.
	if _, err := svc.Refresh(ctx, tok.RefreshToken, "ua/1.0", ip); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("reuse: err = %v, want ErrUnauthorized", err)
	}

	// The newly-rotated one must now also fail.
	if _, err := svc.Refresh(ctx, rotated.RefreshToken, "ua/1.0", ip); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("rotated refresh after reuse-detection: err = %v, want ErrUnauthorized", err)
	}
}

func TestService_Logout_RevokesSession(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	svc, cleanup := setupService(t)
	defer cleanup()

	const pw = "correct-horse-battery-staple"
	u, secret := createUser(t, svc, "logout@x.test", pw, "operator", true)
	ctx := context.Background()
	ip := net.ParseIP("203.0.113.5")

	res, err := svc.Login(ctx, u.Email, pw, ip)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := svc.VerifyMFA(ctx, res.StepUpToken, currentTOTP(t, secret), "", "", ip)
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.Logout(ctx, tok.RefreshToken, u.ID, ip); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := svc.Refresh(ctx, tok.RefreshToken, "", ip); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Refresh after Logout: err = %v, want ErrUnauthorized", err)
	}
}

func TestService_LogoutAll_RevokesEverything(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	svc, cleanup := setupService(t)
	defer cleanup()

	const pw = "correct-horse-battery-staple"
	u, secret := createUser(t, svc, "logoutall@x.test", pw, "operator", true)
	ctx := context.Background()
	ip := net.ParseIP("203.0.113.6")

	// First session.
	r1, _ := svc.Login(ctx, u.Email, pw, ip)
	tok1, err := svc.VerifyMFA(ctx, r1.StepUpToken, currentTOTP(t, secret), "", "", ip)
	if err != nil {
		t.Fatalf("VerifyMFA 1: %v", err)
	}
	// Second session. TOTP replay protection is not implemented at the
	// service layer yet (see totp.go doc), so same-window code is fine here.
	r2, _ := svc.Login(ctx, u.Email, pw, ip)
	tok2, err := svc.VerifyMFA(ctx, r2.StepUpToken, currentTOTP(t, secret), "", "", ip)
	if err != nil {
		t.Fatalf("VerifyMFA 2: %v", err)
	}

	if err := svc.LogoutAll(ctx, u.ID, ip); err != nil {
		t.Fatalf("LogoutAll: %v", err)
	}
	if _, err := svc.Refresh(ctx, tok1.RefreshToken, "", ip); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Refresh tok1 after LogoutAll: err = %v, want ErrUnauthorized", err)
	}
	if _, err := svc.Refresh(ctx, tok2.RefreshToken, "", ip); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Refresh tok2 after LogoutAll: err = %v, want ErrUnauthorized", err)
	}
}

func TestService_ChangePassword_RequiresTOTP_AndRevokesSessions(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	svc, cleanup := setupService(t)
	defer cleanup()

	const current = "correct-horse-battery-staple"
	const next = "another-very-long-passphrase"
	u, secret := createUser(t, svc, "cp@x.test", current, "operator", true)
	ctx := context.Background()
	ip := net.ParseIP("203.0.113.7")

	r, _ := svc.Login(ctx, u.Email, current, ip)
	tok, err := svc.VerifyMFA(ctx, r.StepUpToken, currentTOTP(t, secret), "", "", ip)
	if err != nil {
		t.Fatal(err)
	}

	// Wrong current password → ErrInvalidCredentials.
	if err := svc.ChangePassword(ctx, u.ID, "wrong", next, currentTOTP(t, secret), ip); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong current: err = %v, want ErrInvalidCredentials", err)
	}

	// Wrong TOTP → ErrMFAInvalid.
	if err := svc.ChangePassword(ctx, u.ID, current, next, "000000", ip); !errors.Is(err, ErrMFAInvalid) {
		t.Fatalf("wrong totp: err = %v, want ErrMFAInvalid", err)
	}

	// Too-short new password → policy error.
	if err := svc.ChangePassword(ctx, u.ID, current, "short", currentTOTP(t, secret), ip); err == nil {
		t.Fatal("expected password policy error, got nil")
	}

	// Happy path.
	if err := svc.ChangePassword(ctx, u.ID, current, next, currentTOTP(t, secret), ip); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	// Previous refresh token should now be revoked.
	if _, err := svc.Refresh(ctx, tok.RefreshToken, "", ip); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Refresh after ChangePassword: err = %v, want ErrUnauthorized", err)
	}

	// Must-change flag should be FALSE (self-service sets it to false).
	got, err := svc.Users.FindByID(ctx, svc.TenantID, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.MustChangePassword {
		t.Error("MustChangePassword = true after self-service ChangePassword, want false")
	}
}

func TestService_ResetPasswordByAdmin_SetsMustChangeAndRevokes(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	svc, cleanup := setupService(t)
	defer cleanup()

	const pw = "correct-horse-battery-staple"
	admin, _ := createUser(t, svc, "admin@x.test", "admin-password-long", "admin", false)
	target, secret := createUser(t, svc, "target@x.test", pw, "operator", true)
	ctx := context.Background()
	ip := net.ParseIP("203.0.113.8")

	// Give the target an active session that must be revoked.
	r, _ := svc.Login(ctx, target.Email, pw, ip)
	tok, err := svc.VerifyMFA(ctx, r.StepUpToken, currentTOTP(t, secret), "", "", ip)
	if err != nil {
		t.Fatal(err)
	}

	temp, err := svc.ResetPasswordByAdmin(ctx, admin.ID, target.ID, ip)
	if err != nil {
		t.Fatalf("ResetPasswordByAdmin: %v", err)
	}
	if len(temp) < 12 {
		t.Errorf("temp password len = %d, want >= 12", len(temp))
	}

	got, err := svc.Users.FindByID(ctx, svc.TenantID, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.MustChangePassword {
		t.Error("MustChangePassword = false after admin reset, want true")
	}

	// Old refresh token must be revoked.
	if _, err := svc.Refresh(ctx, tok.RefreshToken, "", ip); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Refresh after admin reset: err = %v, want ErrUnauthorized", err)
	}

	// The returned temp password must work for Login; since target still has a
	// TOTP secret, it should route to MustChangePassword (flag wins over
	// NeedsMFAVerify in the switch).
	r2, err := svc.Login(ctx, target.Email, temp, ip)
	if err != nil {
		t.Fatalf("Login with temp password: %v", err)
	}
	if !r2.MustChangePassword {
		t.Fatalf("expected MustChangePassword=true, got %+v", r2)
	}
}
