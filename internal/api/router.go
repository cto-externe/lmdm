// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package api

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"

	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/profiles"
	"github.com/cto-externe/lmdm/internal/tokens"
)

// Deps holds the dependencies injected into API handlers.
type Deps struct {
	Pool           *db.Pool
	Devices        *devices.Repository
	Tokens         *tokens.Repository
	Profiles       *profiles.Repository
	NATS           *nats.Conn
	TenantID       uuid.UUID // Community default at MVP
	Auth           *auth.Service
	Signer         *auth.JWTSigner
	LoginRateLimit *auth.RateLimiter // 10 per 10 min
	MFARateLimit   *auth.RateLimiter // 60 per min
}

// Router returns an http.Handler with all /api/v1/ routes registered.
func Router(d *Deps) http.Handler {
	mux := http.NewServeMux()

	// Devices — implemented.
	mux.HandleFunc("GET /api/v1/devices", d.handleListDevices)
	mux.HandleFunc("GET /api/v1/devices/{id}", d.handleGetDevice)

	// Stubs — implemented in subsequent tasks.
	mux.HandleFunc("GET /api/v1/devices/{id}/inventory", d.handleGetInventory)
	mux.HandleFunc("GET /api/v1/devices/{id}/compliance", d.handleGetCompliance)
	mux.HandleFunc("GET /api/v1/profiles", d.handleListProfiles)
	mux.HandleFunc("GET /api/v1/profiles/{id}", d.handleGetProfile)
	mux.HandleFunc("POST /api/v1/profiles", d.handleCreateProfile)
	mux.HandleFunc("POST /api/v1/profiles/{id}/assign/{deviceID}", d.handleAssignProfile)
	mux.HandleFunc("POST /api/v1/tokens", d.handleCreateToken)
	mux.HandleFunc("GET /api/v1/tokens", d.handleListTokens)
	mux.HandleFunc("GET /api/v1/devices/{id}/updates", d.handleListUpdates)
	mux.HandleFunc("POST /api/v1/devices/{id}/updates/apply", d.handleApplyUpdates)

	return mux
}
