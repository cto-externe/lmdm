// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package server

import (
	"context"
	"encoding/json"
	"net/http"
)

// HealthChecker reports whether a dependency is healthy. Check returns nil
// when healthy and an error describing the failure otherwise.
type HealthChecker interface {
	Check(ctx context.Context) error
}

// HealthCheckerFunc adapts a plain function to the HealthChecker interface.
type HealthCheckerFunc func(ctx context.Context) error

// Check implements HealthChecker.
func (f HealthCheckerFunc) Check(ctx context.Context) error { return f(ctx) }

// NewHealthHandler returns an HTTP handler that reports the health of the
// named dependencies. All checkers run sequentially; if any fail the handler
// responds with 503.
func NewHealthHandler(deps map[string]HealthChecker) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		results := make(map[string]string, len(deps))
		overallOK := true
		for name, c := range deps {
			if err := c.Check(r.Context()); err != nil {
				results[name] = err.Error()
				overallOK = false
			} else {
				results[name] = "ok"
			}
		}
		status := "ok"
		code := http.StatusOK
		if !overallOK {
			status = "degraded"
			code = http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": status,
			"checks": results,
		})
	})
}
