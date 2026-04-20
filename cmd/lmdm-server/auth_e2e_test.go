// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/cto-externe/lmdm/internal/api"
	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/natsbus"
	profilesRepo "github.com/cto-externe/lmdm/internal/profiles"
	"github.com/cto-externe/lmdm/internal/server"
	"github.com/cto-externe/lmdm/internal/serverkey"
	"github.com/cto-externe/lmdm/internal/tokens"
)

// extractOTPSecret pulls the `secret=` query parameter value out of an otpauth:// URI.
func extractOTPSecret(uri string) string {
	i := strings.Index(uri, "secret=")
	if i < 0 {
		return ""
	}
	s := uri[i+len("secret="):]
	if j := strings.IndexByte(s, '&'); j >= 0 {
		s = s[:j]
	}
	return s
}

// postJSON issues a POST with a JSON body and (optionally) a Bearer token.
func postJSON(t *testing.T, url, bearer, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// readBody drains resp.Body and returns it as a string, closing the body.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestIntegrationAuthRBAC_EndToEnd drives the real HTTP auth flow from a cold
// DB: bootstrap admin with pre-enrolled TOTP → POST /auth/login → POST
// /auth/mfa/verify → authenticated GET /auth/me → 401/401 on missing/bad
// bearer → admin creates viewer → viewer first-login enrolls TOTP via the
// /auth/mfa/enroll + /auth/mfa/verify flow → viewer hits an endpoint they lack
// permission for (expect 403) → admin rotates refresh token (old token reuse
// 401s) → admin POST /auth/logout-all → rotated refresh now 401s.
func TestIntegrationAuthRBAC_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// --- Bring up Postgres + NATS ---
	pg, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("lmdm"), postgres.WithUsername("lmdm"), postgres.WithPassword("lmdm"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("5432/tcp").WithStartupTimeout(30*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.Terminate(ctx) })
	dsn, _ := pg.ConnectionString(ctx, "sslmode=disable")
	if err := db.MigrateUp(dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	natsReq := testcontainers.ContainerRequest{
		Image: "nats:2.10-alpine", ExposedPorts: []string{"4222/tcp"},
		Cmd: []string{"-js"}, WaitingFor: wait.ForLog("Server is ready").WithStartupTimeout(30 * time.Second),
	}
	natsC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: natsReq, Started: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = natsC.Terminate(ctx) })
	natsHost, _ := natsC.Host(ctx)
	natsPort, _ := natsC.MappedPort(ctx, "4222/tcp")
	natsURL := "nats://" + natsHost + ":" + natsPort.Port()
	bus, err := natsbus.Connect(ctx, natsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	if err := bus.EnsureStreams(ctx); err != nil {
		t.Fatal(err)
	}

	// --- Wire up API deps ---
	tokenRepo := tokens.NewRepository(pool)
	deviceRepo := devices.NewRepository(pool)
	keyPath := t.TempDir() + "/server.key"
	serverPriv, _, err := serverkey.LoadOrGenerate(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	apiDeps, _ := newTestAPIDeps(t, pool, deviceRepo, tokenRepo,
		profilesRepo.NewRepository(pool, serverPriv), bus.NC(), tenantID)

	httpAddr := freeAddr(t)
	grpcAddr := freeAddr(t)
	mux := http.NewServeMux()
	mux.Handle("/api/", api.Router(apiDeps))
	srv, err := server.New(httpAddr, grpcAddr, mux, nil)
	if err != nil {
		t.Fatal(err)
	}
	errs := srv.Start()
	defer func() { _ = srv.Shutdown(5 * time.Second) }()
	select {
	case e := <-errs:
		t.Fatalf("server: %v", e)
	case <-time.After(200 * time.Millisecond):
	}
	baseURL := "http://" + httpAddr

	// --- Step 2: bootstrap admin with a pre-enrolled TOTP secret ---
	const adminEmail = "admin@x.test"
	const adminPassword = "correct-horse-battery-12"
	adminHash, err := auth.HashPassword(adminPassword)
	if err != nil {
		t.Fatal(err)
	}
	adminUser, err := apiDeps.Users.Create(ctx, tenantID, adminEmail, adminHash, string(auth.RoleAdmin))
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	adminEnr, err := auth.EnrollTOTP(adminEmail, "LMDM")
	if err != nil {
		t.Fatal(err)
	}
	adminSecret := adminEnr.Secret
	adminEncBlob, err := auth.Encrypt(apiDeps.Auth.EncKey, []byte(adminSecret))
	if err != nil {
		t.Fatal(err)
	}
	if err := apiDeps.Users.SetTOTP(ctx, tenantID, adminUser.ID, adminEncBlob); err != nil {
		t.Fatalf("set admin totp: %v", err)
	}

	// --- Step 3: POST /api/v1/auth/login (admin) ---
	resp := postJSON(t, baseURL+"/api/v1/auth/login", "",
		`{"email":"`+adminEmail+`","password":"`+adminPassword+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: %d %s", resp.StatusCode, readBody(t, resp))
	}
	var loginBody struct {
		StepUpToken    string `json:"step_up_token"`
		NeedsMFAVerify bool   `json:"needs_mfa_verify"`
		NeedsMFASetup  bool   `json:"needs_mfa_setup"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&loginBody); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if loginBody.StepUpToken == "" || !loginBody.NeedsMFAVerify || loginBody.NeedsMFASetup {
		t.Fatalf("login body = %+v, want step_up_token + needs_mfa_verify", loginBody)
	}

	// --- Step 4 + 5: compute TOTP and POST /auth/mfa/verify ---
	adminCode, err := totp.GenerateCode(adminSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = postJSON(t, baseURL+"/api/v1/auth/mfa/verify", "",
		`{"step_up_token":"`+loginBody.StepUpToken+`","code":"`+adminCode+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mfa/verify: %d %s", resp.StatusCode, readBody(t, resp))
	}
	var mfaBody struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresAt    int64  `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&mfaBody); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if mfaBody.AccessToken == "" || mfaBody.RefreshToken == "" || mfaBody.ExpiresAt == 0 {
		t.Fatalf("mfa body = %+v", mfaBody)
	}
	adminAccess := mfaBody.AccessToken
	adminRefresh := mfaBody.RefreshToken

	// --- Step 6: GET /auth/me with admin bearer ---
	resp = authedGet(t, baseURL+"/api/v1/auth/me", adminAccess)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me: %d %s", resp.StatusCode, readBody(t, resp))
	}
	var meBody struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"`
		Email  string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meBody); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if meBody.Role != string(auth.RoleAdmin) || meBody.Email != adminEmail || meBody.UserID != adminUser.ID.String() {
		t.Fatalf("me body = %+v, want admin/%s/%s", meBody, adminEmail, adminUser.ID)
	}

	// --- Step 7: GET /auth/me with no Authorization header ---
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/auth/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("me (no auth): status %d, want 401", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// --- Step 8: GET /auth/me with garbage bearer ---
	resp = authedGet(t, baseURL+"/api/v1/auth/me", "not-a-real-jwt")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("me (bad bearer): status %d, want 401", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// --- Step 9: admin creates a viewer via POST /users ---
	const viewerEmail = "viewer@x.test"
	const viewerPassword = "viewer-pass-12long" //nolint:gosec // test fixture, not a real credential
	resp = postJSON(t, baseURL+"/api/v1/users", adminAccess,
		`{"email":"`+viewerEmail+`","role":"viewer","password":"`+viewerPassword+`"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create viewer: %d %s", resp.StatusCode, readBody(t, resp))
	}
	var viewerJSON struct {
		ID   uuid.UUID `json:"id"`
		Role string    `json:"role"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&viewerJSON); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if viewerJSON.Role != string(auth.RoleViewer) || viewerJSON.ID == uuid.Nil {
		t.Fatalf("viewer json = %+v", viewerJSON)
	}

	// --- Step 10: viewer first login + MFA enrollment ---
	resp = postJSON(t, baseURL+"/api/v1/auth/login", "",
		`{"email":"`+viewerEmail+`","password":"`+viewerPassword+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("viewer login: %d %s", resp.StatusCode, readBody(t, resp))
	}
	var viewerLogin struct {
		StepUpToken   string `json:"step_up_token"`
		NeedsMFASetup bool   `json:"needs_mfa_setup"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&viewerLogin); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if !viewerLogin.NeedsMFASetup || viewerLogin.StepUpToken == "" {
		t.Fatalf("viewer login body = %+v, want needs_mfa_setup", viewerLogin)
	}
	resp = postJSON(t, baseURL+"/api/v1/auth/mfa/enroll", "",
		`{"step_up_token":"`+viewerLogin.StepUpToken+`","email":"`+viewerEmail+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("viewer enroll: %d %s", resp.StatusCode, readBody(t, resp))
	}
	var viewerEnrol struct {
		URI         string `json:"uri"`
		SetupHandle string `json:"setup_handle"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&viewerEnrol); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	viewerSecret := extractOTPSecret(viewerEnrol.URI)
	if viewerSecret == "" || viewerEnrol.SetupHandle == "" {
		t.Fatalf("viewer enroll parse: secret=%q handle=%q uri=%q",
			viewerSecret, viewerEnrol.SetupHandle, viewerEnrol.URI)
	}
	viewerCode, err := totp.GenerateCode(viewerSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = postJSON(t, baseURL+"/api/v1/auth/mfa/verify", "",
		`{"step_up_token":"`+viewerLogin.StepUpToken+`","code":"`+viewerCode+
			`","setup_handle":"`+viewerEnrol.SetupHandle+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("viewer verify: %d %s", resp.StatusCode, readBody(t, resp))
	}
	var viewerTokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&viewerTokens); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if viewerTokens.AccessToken == "" {
		t.Fatal("viewer access token empty")
	}

	// --- Step 11: viewer hits an admin/operator-only endpoint → 403 ---
	resp = authedPost(t, baseURL+"/api/v1/devices/"+uuid.New().String()+"/updates/apply",
		viewerTokens.AccessToken, "application/json", `{"update_ids":["foo"]}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer updates/apply: status %d, want 403; body=%s",
			resp.StatusCode, readBody(t, resp))
	}
	_ = resp.Body.Close()

	// --- Step 12: admin refresh rotation ---
	resp = postJSON(t, baseURL+"/api/v1/auth/refresh", "",
		`{"refresh_token":"`+adminRefresh+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %d %s", resp.StatusCode, readBody(t, resp))
	}
	var refreshed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&refreshed); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if refreshed.RefreshToken == "" || refreshed.RefreshToken == adminRefresh {
		t.Fatalf("refreshed token = %q, want a new non-empty token (old=%q)",
			refreshed.RefreshToken, adminRefresh)
	}
	if refreshed.AccessToken == "" {
		t.Fatal("refreshed access token empty")
	}
	// Reusing the original refresh token must fail.
	resp = postJSON(t, baseURL+"/api/v1/auth/refresh", "",
		`{"refresh_token":"`+adminRefresh+`"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("refresh (reuse old): status %d, want 401; body=%s",
			resp.StatusCode, readBody(t, resp))
	}
	_ = resp.Body.Close()

	// --- Step 13: admin logout-all (using freshly-rotated access token) ---
	resp = authedPost(t, baseURL+"/api/v1/auth/logout-all",
		refreshed.AccessToken, "application/json", "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout-all: status %d, want 204; body=%s",
			resp.StatusCode, readBody(t, resp))
	}
	_ = resp.Body.Close()
	// The rotated refresh token must now be revoked.
	resp = postJSON(t, baseURL+"/api/v1/auth/refresh", "",
		`{"refresh_token":"`+refreshed.RefreshToken+`"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("refresh after logout-all: status %d, want 401; body=%s",
			resp.StatusCode, readBody(t, resp))
	}
	_ = resp.Body.Close()

	// Sanity: admin and viewer rows exist.
	if _, err := apiDeps.Users.FindByID(ctx, tenantID, viewerJSON.ID); err != nil {
		t.Fatalf("viewer not persisted: %v", err)
	}
}
