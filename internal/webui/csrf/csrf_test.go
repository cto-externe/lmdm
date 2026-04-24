// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package csrf

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

var testKey = []byte("test-secret-32-bytes-............")

func TestIssueAndVerify_Roundtrip(t *testing.T) {
	m := New(testKey)
	tok := m.Issue()
	if !m.verify(tok) {
		t.Fatal("issued token must verify")
	}
}

func TestVerify_RejectsTamperedToken(t *testing.T) {
	m := New(testKey)
	tok := m.Issue()
	tampered := tok[:len(tok)-1] + "X"
	if m.verify(tampered) {
		t.Fatal("tampered token must not verify")
	}
}

func TestMiddleware_GET_PassesWithoutToken(t *testing.T) {
	m := New(testKey)
	h := m.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest("GET", "/web/anything", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("GET status = %d", rr.Code)
	}
}

func TestMiddleware_POST_RequiresMatchingToken(t *testing.T) {
	m := New(testKey)
	h := m.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	// No token at all → 403.
	req := httptest.NewRequest("POST", "/web/anything", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 403 {
		t.Fatalf("no token POST = %d, want 403", rr.Code)
	}

	// Valid token in both cookie and header → 200.
	tok := m.Issue()
	req = httptest.NewRequest("POST", "/web/anything", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: tok})
	req.Header.Set("X-CSRF-Token", tok)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("valid token POST = %d, want 200", rr.Code)
	}

	// Mismatched tokens → 403.
	tok2 := m.Issue()
	req = httptest.NewRequest("POST", "/web/anything", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: tok})
	req.Header.Set("X-CSRF-Token", tok2)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 403 {
		t.Fatalf("mismatched tokens = %d, want 403", rr.Code)
	}
}
