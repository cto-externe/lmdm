// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLimiter_AllowsUnderLimit(t *testing.T) {
	l := New(5, 5*time.Minute)
	h := l.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("POST", "/web/login", nil)
		req.RemoteAddr = "1.2.3.4:12345"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("req %d = %d, want 200", i, rr.Code)
		}
	}
}

func TestLimiter_BlocksOverLimit(t *testing.T) {
	l := New(3, 5*time.Minute)
	h := l.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	addr := "1.2.3.4:12345"
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/web/login", nil)
		req.RemoteAddr = addr
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	req := httptest.NewRequest("POST", "/web/login", nil)
	req.RemoteAddr = addr
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 429 {
		t.Fatalf("4th req = %d, want 429", rr.Code)
	}
}

func TestLimiter_PerIP(t *testing.T) {
	l := New(1, 5*time.Minute)
	h := l.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	// IP A consumes its quota.
	reqA := httptest.NewRequest("POST", "/web/login", nil)
	reqA.RemoteAddr = "10.0.0.1:1"
	h.ServeHTTP(httptest.NewRecorder(), reqA)
	// IP B still has quota.
	reqB := httptest.NewRequest("POST", "/web/login", nil)
	reqB.RemoteAddr = "10.0.0.2:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, reqB)
	if rr.Code != 200 {
		t.Fatalf("IP B blocked = %d", rr.Code)
	}
}
