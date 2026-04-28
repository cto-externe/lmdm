// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package csrf implements a double-submit-cookie CSRF protection scheme
// suitable for HTMX. Token format: <random-16-bytes-base64>.<hmac-sha256-base64>.
// On GET requests the middleware is a no-op (render pages freely). On
// state-changing methods (POST/PUT/PATCH/DELETE), the middleware requires:
//  1. A cookie "lmdm_csrf" with a valid signed token.
//  2. A header X-CSRF-Token with the same value.
//
// HTMX is configured at the layout level to include the header automatically.
package csrf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
)

// CookieName is the name of the CSRF cookie set on the client.
const CookieName = "lmdm_csrf"

// Middleware holds the signing key shared across requests.
type Middleware struct {
	key []byte
}

// New returns a Middleware. key must be at least 32 bytes.
func New(key []byte) *Middleware { return &Middleware{key: key} }

// Issue returns a fresh signed token suitable for setting in the lmdm_csrf cookie.
func (m *Middleware) Issue() string {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	nb := base64.RawURLEncoding.EncodeToString(nonce)
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(nb))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return nb + "." + sig
}

// verify returns true when token is well-formed and its HMAC matches.
func (m *Middleware) verify(token string) bool {
	dot := strings.IndexByte(token, '.')
	if dot < 0 || dot == len(token)-1 {
		return false
	}
	nb, sig := token[:dot], token[dot+1:]
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(nb))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(sig), []byte(want))
}

// Protect wraps next with the double-submit check. Safe methods (GET, HEAD, OPTIONS) pass through.
func (m *Middleware) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		c, err := r.Cookie(CookieName)
		if err != nil || c.Value == "" {
			http.Error(w, "CSRF token missing", http.StatusForbidden)
			return
		}
		hdr := r.Header.Get("X-CSRF-Token")
		if hdr == "" || hdr != c.Value {
			http.Error(w, "CSRF token mismatch", http.StatusForbidden)
			return
		}
		if !m.verify(c.Value) {
			http.Error(w, "CSRF token invalid", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
