// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package security

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMiddleware_SetsBaselineHeaders(t *testing.T) {
	h := Middleware(Options{EnableHSTS: true})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	for _, want := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Strict-Transport-Security"} {
		if rr.Header().Get(want) == "" {
			t.Errorf("header %s missing", want)
		}
	}
	if !strings.Contains(rr.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Errorf("CSP missing frame-ancestors: %q", rr.Header().Get("Content-Security-Policy"))
	}
}

func TestMiddleware_HSTSOffInDev(t *testing.T) {
	h := Middleware(Options{EnableHSTS: false})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Header().Get("Strict-Transport-Security") != "" {
		t.Errorf("HSTS must be absent in dev")
	}
}
