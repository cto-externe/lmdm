// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newMwKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRequireAuth_RejectsMissingBearer(t *testing.T) {
	pk := newMwKey(t)
	signer := NewJWTSigner(pk, time.Minute)
	h := RequireAuth(signer)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	req := httptest.NewRequest("GET", "/x", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestRequireAuth_RejectsEmptyBearer(t *testing.T) {
	pk := newMwKey(t)
	signer := NewJWTSigner(pk, time.Minute)
	h := RequireAuth(signer)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer ")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestRequireAuth_RejectsBadScheme(t *testing.T) {
	pk := newMwKey(t)
	signer := NewJWTSigner(pk, time.Minute)
	h := RequireAuth(signer)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestRequireAuth_AcceptsValidToken(t *testing.T) {
	pk := newMwKey(t)
	signer := NewJWTSigner(pk, time.Minute)
	tok, _ := signer.IssueAccess(uuid.New(), uuid.New(), RoleAdmin, "x@y.test")
	called := false
	h := RequireAuth(signer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := PrincipalFrom(r.Context())
		if p == nil {
			t.Fatal("no principal in context")
		}
		if p.Role != RoleAdmin {
			t.Errorf("wrong role: %v", p.Role)
		}
		called = true
		w.WriteHeader(200)
	}))
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 || !called {
		t.Fatalf("got %d called=%v", rr.Code, called)
	}
}

func TestRequirePermission_DeniesMissingPermission(t *testing.T) {
	pk := newMwKey(t)
	signer := NewJWTSigner(pk, time.Minute)
	tok, _ := signer.IssueAccess(uuid.New(), uuid.New(), RoleViewer, "v@y.test")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	h := RequireAuth(signer)(RequirePermission(PermUpdatesApply, next))
	req := httptest.NewRequest("POST", "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestRequirePermission_AllowsWithPermission(t *testing.T) {
	pk := newMwKey(t)
	signer := NewJWTSigner(pk, time.Minute)
	tok, _ := signer.IssueAccess(uuid.New(), uuid.New(), RoleOperator, "o@y.test")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	h := RequireAuth(signer)(RequirePermission(PermUpdatesApply, next))
	req := httptest.NewRequest("POST", "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 204 {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
}

func TestRequirePermission_NoPrincipal_401(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	h := RequirePermission(PermDevicesRead, next)
	req := httptest.NewRequest("GET", "/x", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 (no principal), got %d", rr.Code)
	}
}

func TestRequireAuth_AcceptsCookieFallback(t *testing.T) {
	pk := newMwKey(t)
	signer := NewJWTSigner(pk, time.Minute)
	tok, err := signer.IssueAccess(uuid.New(), uuid.New(), RoleAdmin, "x@y.test")
	if err != nil {
		t.Fatal(err)
	}
	h := RequireAuth(signer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if PrincipalFrom(r.Context()) == nil {
			t.Fatal("no principal")
		}
		w.WriteHeader(200)
	}))
	req := httptest.NewRequest("GET", "/api/v1/devices", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tok})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("cookie auth failed: status = %d", rr.Code)
	}
}

func TestRequireAuth_HeaderTakesPrecedenceOverCookie(t *testing.T) {
	pk := newMwKey(t)
	signer := NewJWTSigner(pk, time.Minute)
	adminTok, _ := signer.IssueAccess(uuid.New(), uuid.New(), RoleAdmin, "admin@y.test")
	viewerTok, _ := signer.IssueAccess(uuid.New(), uuid.New(), RoleViewer, "viewer@y.test")

	var seenRole string
	h := RequireAuth(signer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := PrincipalFrom(r.Context())
		seenRole = string(p.Role)
		w.WriteHeader(200)
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: viewerTok})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if seenRole != string(RoleAdmin) {
		t.Errorf("header should win, got role %q", seenRole)
	}
}

func TestRequireAuth_NeitherHeaderNorCookie_401(t *testing.T) {
	pk := newMwKey(t)
	signer := NewJWTSigner(pk, time.Minute)
	h := RequireAuth(signer)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Code != 401 {
		t.Errorf("no auth = %d, want 401", rr.Code)
	}
}

func TestRequireAuth_EmptyBearerFallsBackToCookie(t *testing.T) {
	pk := newMwKey(t)
	signer := NewJWTSigner(pk, time.Minute)
	tok, _ := signer.IssueAccess(uuid.New(), uuid.New(), RoleAdmin, "x@y.test")
	h := RequireAuth(signer)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer ")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tok})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("empty bearer + cookie should auth, got %d", rr.Code)
	}
}
