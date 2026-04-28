// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package auth

import (
	"net/http"
	"strings"
)

// SessionCookieName is the cookie the WebUI uses to carry the JWT access token.
// The API/CLI continue to use the Authorization header; the middleware accepts
// either source (header wins when both are present).
const SessionCookieName = "lmdm_session"

// RequireAuth parses the JWT from either:
//  1. Authorization: Bearer <jwt>  (API / CLI)
//  2. Cookie lmdm_session           (WebUI)
//
// Header wins when both are present. Validates via signer, injects the
// Principal into the request context. Returns 401 on any failure.
func RequireAuth(signer *JWTSigner) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := extractToken(r)
			if raw == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			p, err := signer.VerifyAccess(raw)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := WithPrincipal(r.Context(), p)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractToken returns the raw JWT from header (preferred) or cookie, or "".
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if tok := strings.TrimPrefix(h, "Bearer "); tok != "" {
			return tok
		}
	}
	if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	return ""
}

// RequirePermission wraps a handler so only principals with perm may proceed.
// MUST run after RequireAuth (it reads Principal from context).
func RequirePermission(perm Permission, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := PrincipalFrom(r.Context())
		if p == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !HasPermission(p.Role, perm) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}
