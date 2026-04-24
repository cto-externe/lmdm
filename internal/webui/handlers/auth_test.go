// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package handlers

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/webui/csrf"
	"github.com/cto-externe/lmdm/internal/webui/i18n"
)

// fakeAuthService is a test double for authService.
type fakeAuthService struct {
	loginResult *auth.LoginResult
	loginErr    error
	mfaTokens   *auth.Tokens
	mfaErr      error
	logoutErr   error
}

func (f *fakeAuthService) Login(_ context.Context, _, _ string, _ net.IP) (*auth.LoginResult, error) {
	return f.loginResult, f.loginErr
}
func (f *fakeAuthService) VerifyMFA(_ context.Context, _, _, _, _ string, _ net.IP) (*auth.Tokens, error) {
	return f.mfaTokens, f.mfaErr
}
func (f *fakeAuthService) Logout(_ context.Context, _ string, _ uuid.UUID, _ net.IP) error {
	return f.logoutErr
}

// newTestDeps returns an AuthDeps wired with a CSRF middleware using a fixed test key.
func newTestDeps(svc authService) *AuthDeps {
	_ = i18n.Load() // load embedded locales so T() returns real strings
	return &AuthDeps{
		Auth:          svc,
		CSRF:          csrf.New([]byte("test-key-32-bytes-padding-xxxxxX")),
		SecureCookies: false,
	}
}

// findCookie returns the named Set-Cookie from the response, or nil.
func findCookie(rr *httptest.ResponseRecorder, name string) *http.Cookie {
	resp := rr.Result()
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestHandleLoginGET_IssuesCSRFCookie(t *testing.T) {
	d := newTestDeps(&fakeAuthService{})
	r := httptest.NewRequest(http.MethodGet, "/web/login", nil)
	rr := httptest.NewRecorder()

	d.HandleLoginGET(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	c := findCookie(rr, csrf.CookieName)
	if c == nil {
		t.Fatal("expected lmdm_csrf cookie to be set")
	}
	if c.HttpOnly {
		t.Error("lmdm_csrf must not be HttpOnly (HTMX reads it via JS)")
	}
	body := rr.Body.String()
	if !strings.Contains(body, `name="email"`) {
		t.Error("expected login form to contain input[name=email]")
	}
}

func TestHandleLoginPOST_InvalidCredentials_RendersFlash(t *testing.T) {
	d := newTestDeps(&fakeAuthService{loginErr: auth.ErrInvalidCredentials})

	form := url.Values{"email": {"test@example.com"}, "password": {"wrong"}}
	r := httptest.NewRequest(http.MethodPost, "/web/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	d.HandleLoginPOST(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	// The FR locale key "login.error.invalid" maps to "Email ou mot de passe incorrect"
	if !strings.Contains(body, "Email ou mot de passe incorrect") {
		t.Errorf("expected FR error message in body, got:\n%s", body)
	}
}

func TestHandleLoginPOST_Success_SetsPendingMFACookie_HXRedirect(t *testing.T) {
	d := newTestDeps(&fakeAuthService{
		loginResult: &auth.LoginResult{
			StepUpToken:    "step-token",
			UserID:         uuid.New(),
			NeedsMFAVerify: true,
		},
	})

	form := url.Values{"email": {"test@example.com"}, "password": {"correct-pass"}}
	r := httptest.NewRequest(http.MethodPost, "/web/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	d.HandleLoginPOST(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	c := findCookie(rr, mfaPendingCookieName)
	if c == nil {
		t.Fatal("expected lmdm_mfa_pending cookie")
	}
	if c.Value != "step-token" {
		t.Errorf("expected step-token, got %q", c.Value)
	}
	if rr.Header().Get("HX-Redirect") != "/web/login/mfa" {
		t.Errorf("expected HX-Redirect /web/login/mfa, got %q", rr.Header().Get("HX-Redirect"))
	}
}

func TestHandleMFAPOST_Success_SetsSessionCookies(t *testing.T) {
	d := newTestDeps(&fakeAuthService{
		mfaTokens: &auth.Tokens{
			AccessToken:  "access-jwt",
			RefreshToken: "refresh-plain",
			ExpiresAt:    time.Now().Add(15 * time.Minute),
		},
	})

	form := url.Values{"code": {"123456"}}
	r := httptest.NewRequest(http.MethodPost, "/web/login/mfa", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: mfaPendingCookieName, Value: "step-token"})
	rr := httptest.NewRecorder()

	d.HandleMFAPOST(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if rr.Header().Get("HX-Redirect") != "/web/dashboard" {
		t.Errorf("expected HX-Redirect /web/dashboard, got %q", rr.Header().Get("HX-Redirect"))
	}

	session := findCookie(rr, auth.SessionCookieName)
	if session == nil || session.Value != "access-jwt" {
		t.Error("expected lmdm_session cookie with access-jwt")
	}
	refresh := findCookie(rr, "lmdm_refresh")
	if refresh == nil || refresh.Value != "refresh-plain" {
		t.Error("expected lmdm_refresh cookie with refresh-plain")
	}
	csrfC := findCookie(rr, csrf.CookieName)
	if csrfC == nil || csrfC.Value == "" {
		t.Error("expected lmdm_csrf cookie to be re-issued")
	}
	pending := findCookie(rr, mfaPendingCookieName)
	if pending == nil || pending.MaxAge != -1 {
		t.Error("expected lmdm_mfa_pending to be cleared (MaxAge=-1)")
	}
}

func TestHandleMFAPOST_NoPendingCookie_RedirectsLogin(t *testing.T) {
	d := newTestDeps(&fakeAuthService{})

	form := url.Values{"code": {"123456"}}
	r := httptest.NewRequest(http.MethodPost, "/web/login/mfa", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// No lmdm_mfa_pending cookie.
	rr := httptest.NewRecorder()

	d.HandleMFAPOST(rr, r)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/web/login" {
		t.Errorf("expected redirect to /web/login, got %q", loc)
	}
}

func TestHandleMFAPOST_BadCode_RendersMFAFlash(t *testing.T) {
	d := newTestDeps(&fakeAuthService{mfaErr: errors.New("bad code")})

	form := url.Values{"code": {"000000"}}
	r := httptest.NewRequest(http.MethodPost, "/web/login/mfa", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: mfaPendingCookieName, Value: "step-token"})
	rr := httptest.NewRecorder()

	d.HandleMFAPOST(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	// The FR locale key "mfa.error.invalid" maps to "Code incorrect"
	body := rr.Body.String()
	if !strings.Contains(body, "Code incorrect") {
		t.Errorf("expected MFA error message in body, got:\n%s", body)
	}
}

func TestHandleLogout_ClearsCookiesAndRedirects(t *testing.T) {
	d := newTestDeps(&fakeAuthService{})

	r := httptest.NewRequest(http.MethodPost, "/web/logout", nil)
	r.AddCookie(&http.Cookie{Name: "lmdm_refresh", Value: "some-token"})
	// Inject a Principal into context so HandleLogout calls Auth.Logout.
	principal := &auth.Principal{UserID: uuid.New()}
	r = r.WithContext(auth.WithPrincipal(r.Context(), principal))
	rr := httptest.NewRecorder()

	d.HandleLogout(rr, r)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/web/login" {
		t.Errorf("expected redirect to /web/login, got %q", loc)
	}

	// All three cookies must be cleared.
	for _, name := range []string{auth.SessionCookieName, "lmdm_refresh", csrf.CookieName} {
		c := findCookie(rr, name)
		if c == nil {
			t.Errorf("expected %s cookie in response", name)
			continue
		}
		if c.MaxAge != -1 {
			t.Errorf("expected %s cookie MaxAge=-1 (cleared), got %d", name, c.MaxAge)
		}
	}
}
