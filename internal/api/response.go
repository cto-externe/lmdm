// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package api implements the REST API handlers for the LMDM server console.
// All endpoints live under /api/v1/ and are mounted on the existing HTTP mux.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
)

// listResponse wraps list results with a total count.
type listResponse struct {
	Data  any `json:"data"`
	Total int `json:"total"`
}

// writeJSON serializes v as JSON and writes it to w.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("api: json encode", "err", err)
	}
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg, "code": status})
}

// parseUUID extracts a UUID from a path parameter. Returns uuid.Nil + false
// if the value is not a valid UUID; the caller should writeError and return.
func parseUUID(r *http.Request, param string) (uuid.UUID, bool) {
	raw := r.PathValue(param)
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}
