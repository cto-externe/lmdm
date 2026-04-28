// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/cto-externe/lmdm/internal/audit"
	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/users"
	"github.com/cto-externe/lmdm/internal/webui"
)

// TestIntegrationWebUIAuth_EndToEnd exercises the full WebUI cookie auth flow:
//
//  1. Bootstrap admin with pre-enrolled TOTP via the same pattern auth_e2e_test uses.
//  2. Mount webui on a real httptest.Server.
//  3. GET /web/login → 200, lmdm_csrf cookie set.
//  4. POST /web/login (form data + CSRF) → 200, HX-Redirect=/web/login/mfa, lmdm_mfa_pending set.
//  5. POST /web/login/mfa (TOTP code) → 200, HX-Redirect=/web/dashboard,
//     lmdm_session and lmdm_refresh cookies set, lmdm_mfa_pending cleared.
//  6. GET /web/dashboard with cookies → 200, body contains "Tableau de bord".
//  7. POST /web/logout (with CSRF) → 303 to /web/login, all session cookies cleared.
func TestIntegrationWebUIAuth_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// --- Bring up Postgres ---
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

	// --- Wire up deps ---
	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000000")
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := auth.NewJWTSigner(pk, 15*time.Minute)
	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		t.Fatal(err)
	}
	usersRepo := users.New(pool)
	auditWriter := audit.NewWriter(pool)
	authSvc := &auth.Service{
		Users:    usersRepo,
		Audit:    auditWriter,
		Signer:   signer,
		EncKey:   encKey,
		TenantID: tenantID,
		Issuer:   "LMDM",
	}
	deviceRepo := devices.NewRepository(pool)

	// --- Bootstrap admin with pre-enrolled TOTP (mirrors auth_e2e_test.go) ---
	const adminEmail = "admin@webui.test"
	const adminPassword = "correct-horse-battery-12"
	adminHash, err := auth.HashPassword(adminPassword)
	if err != nil {
		t.Fatal(err)
	}
	adminUser, err := usersRepo.Create(ctx, tenantID, adminEmail, adminHash, string(auth.RoleAdmin))
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	adminEnr, err := auth.EnrollTOTP(adminEmail, "LMDM")
	if err != nil {
		t.Fatal(err)
	}
	adminSecret := adminEnr.Secret
	adminEncBlob, err := auth.Encrypt(encKey, []byte(adminSecret))
	if err != nil {
		t.Fatal(err)
	}
	if err := usersRepo.SetTOTP(ctx, tenantID, adminUser.ID, adminEncBlob); err != nil {
		t.Fatalf("set admin totp: %v", err)
	}

	// --- Mount webui on a real httptest server ---
	csrfKey := []byte("test-secret-32-bytes-............")
	mux := http.NewServeMux()
	if err := webui.Mount(mux, webui.Deps{
		Signer:        signer,
		AuthService:   authSvc,
		DevicesRepo:   deviceRepo,
		CSRFKey:       csrfKey,
		SecureCookies: false,
		EnableHSTS:    false,
	}); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // don't auto-follow HX-Redirect or 303
		},
	}

	// 1. GET /web/login → 200 + lmdm_csrf cookie
	resp, err := client.Get(srv.URL + "/web/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /web/login = %d", resp.StatusCode)
	}
	csrfTok := webuiGetCookie(jar, srv.URL, "lmdm_csrf")
	if csrfTok == "" {
		t.Fatal("lmdm_csrf cookie not set after GET /web/login")
	}

	// 2. POST /web/login → HX-Redirect /web/login/mfa, lmdm_mfa_pending set
	resp = webuiPostForm(t, client, srv.URL+"/web/login", csrfTok, url.Values{
		"email":    {adminEmail},
		"password": {adminPassword},
	})
	if resp.StatusCode != http.StatusOK {
		body := webuiReadBody(t, resp)
		t.Fatalf("POST /web/login = %d : %s", resp.StatusCode, body[:min(200, len(body))])
	}
	if got := resp.Header.Get("HX-Redirect"); got != "/web/login/mfa" {
		t.Errorf("POST /web/login HX-Redirect = %q, want /web/login/mfa", got)
	}
	resp.Body.Close()
	if webuiGetCookie(jar, srv.URL, "lmdm_mfa_pending") == "" {
		t.Fatal("lmdm_mfa_pending cookie not set after POST /web/login")
	}

	// 3. GET /web/login/mfa to get a fresh CSRF token
	resp, err = client.Get(srv.URL + "/web/login/mfa")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /web/login/mfa = %d", resp.StatusCode)
	}
	csrfTok = webuiGetCookie(jar, srv.URL, "lmdm_csrf")
	if csrfTok == "" {
		t.Fatal("lmdm_csrf cookie not set after GET /web/login/mfa")
	}

	// 4. POST /web/login/mfa with the TOTP code
	code, err := totp.GenerateCode(adminSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = webuiPostForm(t, client, srv.URL+"/web/login/mfa", csrfTok, url.Values{
		"code": {code},
	})
	if resp.StatusCode != http.StatusOK {
		body := webuiReadBody(t, resp)
		t.Fatalf("POST /web/login/mfa = %d : %s", resp.StatusCode, body[:min(200, len(body))])
	}
	if got := resp.Header.Get("HX-Redirect"); got != "/web/dashboard" {
		t.Errorf("POST /web/login/mfa HX-Redirect = %q, want /web/dashboard", got)
	}
	resp.Body.Close()

	if webuiGetCookie(jar, srv.URL, "lmdm_session") == "" {
		t.Error("lmdm_session cookie not set after MFA verification")
	}
	if webuiGetCookie(jar, srv.URL, "lmdm_refresh") == "" {
		t.Error("lmdm_refresh cookie not set after MFA verification")
	}

	// 5. GET /web/dashboard with cookies → 200, body contains "Tableau de bord"
	resp, err = client.Get(srv.URL + "/web/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	body := webuiReadBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /web/dashboard = %d : %s", resp.StatusCode, body[:min(200, len(body))])
	}
	if !strings.Contains(body, "Tableau de bord") {
		t.Errorf("dashboard body missing 'Tableau de bord'; got %d bytes", len(body))
	}

	// 6. POST /web/logout → 303 to /web/login
	csrfTok = webuiGetCookie(jar, srv.URL, "lmdm_csrf")
	resp = webuiPostForm(t, client, srv.URL+"/web/logout", csrfTok, url.Values{})
	if resp.StatusCode != http.StatusSeeOther {
		body := webuiReadBody(t, resp)
		t.Fatalf("POST /web/logout = %d : %s", resp.StatusCode, body[:min(200, len(body))])
	}
	if loc := resp.Header.Get("Location"); loc != "/web/login" {
		t.Errorf("POST /web/logout Location = %q, want /web/login", loc)
	}
	resp.Body.Close()
}

// --- Helpers (webui-specific, prefixed to avoid collisions with auth_e2e_test helpers) ---

func webuiPostForm(t *testing.T, client *http.Client, rawURL, csrf string, body url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(body.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func webuiGetCookie(jar *cookiejar.Jar, srvURL, name string) string {
	u, _ := url.Parse(srvURL)
	for _, c := range jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func webuiReadBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

