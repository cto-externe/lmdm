// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package webui

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/webui/i18n"
)

// TestMount_LoginPageRendersWithoutAuth confirms the login page is publicly
// reachable and renders i18n strings.
func TestMount_LoginPageRendersWithoutAuth(t *testing.T) {
	mux := http.NewServeMux()
	deps := Deps{
		CSRFKey:       []byte("test-secret-32-bytes-............"),
		SecureCookies: false,
		EnableHSTS:    false,
	}
	if err := Mount(mux, deps); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/web/login", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("GET /web/login = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `name="email"`) {
		t.Errorf("login body missing email input: %s", rr.Body.String()[:200])
	}
}

// TestMount_DashboardRequiresAuth confirms the dashboard is gated.
func TestMount_DashboardRequiresAuth(t *testing.T) {
	// We need a Signer for RequireAuth to be constructable.
	// Mount is what we're testing; the response must be 401 from RequireAuth.
	mux := http.NewServeMux()
	deps := Deps{
		Signer:        newTestSigner(t),
		CSRFKey:       []byte("test-secret-32-bytes-............"),
		SecureCookies: false,
	}
	if err := Mount(mux, deps); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/web/dashboard", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != 401 {
		t.Errorf("GET /web/dashboard unauth = %d, want 401", rr.Code)
	}
}

// TestMount_StaticAssetsServed confirms embedded assets work.
func TestMount_StaticAssetsServed(t *testing.T) {
	mux := http.NewServeMux()
	if err := Mount(mux, Deps{
		CSRFKey:       []byte("test-secret-32-bytes-............"),
		SecureCookies: false,
	}); err != nil {
		t.Fatal(err)
	}
	// htmx.min.js MUST be served (vendored in assets/).
	req := httptest.NewRequest("GET", "/web/static/htmx.min.js", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Errorf("htmx asset = %d", rr.Code)
	}
	// Ensure the body is not empty.
	if rr.Body.Len() < 100 {
		t.Errorf("htmx asset body too small: %d bytes", rr.Body.Len())
	}
}

// TestMount_RootRedirectsToLogin confirms /web/ → /web/login.
func TestMount_RootRedirectsToLogin(t *testing.T) {
	mux := http.NewServeMux()
	if err := Mount(mux, Deps{
		CSRFKey:       []byte("test-secret-32-bytes-............"),
		SecureCookies: false,
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/web/", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("GET /web/ = %d, want 303", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/web/login" {
		t.Errorf("Location = %q, want /web/login", loc)
	}
}

// Ensure i18n loads in tests (needed since Mount calls Load each time, but
// individual handler tests below skip Mount).
func init() {
	_ = i18n.Load()
}

func newTestSigner(t *testing.T) *auth.JWTSigner {
	t.Helper()
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return auth.NewJWTSigner(pk, time.Minute)
}
