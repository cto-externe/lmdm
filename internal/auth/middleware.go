// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package auth

import (
	"net/http"
	"strings"
)

// RequireAuth parses the `Authorization: Bearer <jwt>` header, validates the JWT
// with signer, injects the Principal into the request context, and delegates
// to the next handler. Returns 401 Unauthorized on any failure.
func RequireAuth(signer *JWTSigner) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			const prefix = "Bearer "
			if !strings.HasPrefix(h, prefix) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			raw := strings.TrimPrefix(h, prefix)
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
