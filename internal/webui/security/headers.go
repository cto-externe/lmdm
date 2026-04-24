// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package security applies baseline HTTP security headers to WebUI responses.
package security

import "net/http"

// Options tunes the middleware. Production sets HSTS; dev leaves it off to
// allow http://localhost iteration.
type Options struct {
	EnableHSTS bool
}

// Middleware wraps next with CSP, X-Frame-Options, X-Content-Type-Options,
// Referrer-Policy and (optionally) HSTS.
func Middleware(opts Options) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			// 'unsafe-inline' on style-src is required for Tailwind's JIT-applied
			// @layer base style attributes and for the tiny inline script in
			// layout.templ that copies the csrf cookie to the X-CSRF-Token header.
			h.Set("Content-Security-Policy",
				"default-src 'self'; "+
					"script-src 'self' 'unsafe-inline'; "+
					"style-src 'self' 'unsafe-inline'; "+
					"img-src 'self' data:; "+
					"font-src 'self'; "+
					"connect-src 'self'; "+
					"frame-ancestors 'none'")
			h.Set("X-Frame-Options", "DENY")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "same-origin")
			if opts.EnableHSTS {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}
