// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package api

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"

	"github.com/cto-externe/lmdm/internal/audit"
	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/db"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/profiles"
	"github.com/cto-externe/lmdm/internal/tokens"
	"github.com/cto-externe/lmdm/internal/users"
)

// Deps holds dependencies injected into API handlers.
type Deps struct {
	Pool     *db.Pool
	Devices  *devices.Repository
	Tokens   *tokens.Repository
	Profiles *profiles.Repository
	Users    *users.Repository
	Audit    *audit.Writer
	Auth     *auth.Service
	Signer   *auth.JWTSigner

	LoginRateLimit *auth.RateLimiter
	MFARateLimit   *auth.RateLimiter

	NATS     *nats.Conn
	TenantID uuid.UUID
}

// Router returns an http.Handler with all /api/v1/ routes registered.
// Public auth endpoints require no auth; everything else runs through RequireAuth
// followed by a permission guard.
func Router(d *Deps) http.Handler {
	mux := http.NewServeMux()
	authed := auth.RequireAuth(d.Signer)

	// ----- Public (no auth) -----
	mux.HandleFunc("POST /api/v1/auth/login", d.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/mfa/enroll", d.handleMFAEnroll)
	mux.HandleFunc("POST /api/v1/auth/mfa/verify", d.handleMFAVerify)
	mux.HandleFunc("POST /api/v1/auth/refresh", d.handleRefresh)

	// ----- Authenticated (any role) -----
	mux.Handle("POST /api/v1/auth/logout", authed(http.HandlerFunc(d.handleLogout)))
	mux.Handle("POST /api/v1/auth/logout-all", authed(http.HandlerFunc(d.handleLogoutAll)))
	mux.Handle("POST /api/v1/auth/password", authed(http.HandlerFunc(d.handlePassword)))
	mux.Handle("GET /api/v1/auth/me", authed(http.HandlerFunc(d.handleMe)))

	// ----- Devices -----
	mux.Handle("GET /api/v1/devices",
		authed(auth.RequirePermission(auth.PermDevicesRead, http.HandlerFunc(d.handleListDevices))))
	mux.Handle("GET /api/v1/devices/{id}",
		authed(auth.RequirePermission(auth.PermDevicesRead, http.HandlerFunc(d.handleGetDevice))))
	mux.Handle("GET /api/v1/devices/{id}/inventory",
		authed(auth.RequirePermission(auth.PermInventoryRead, http.HandlerFunc(d.handleGetInventory))))
	mux.Handle("GET /api/v1/devices/{id}/compliance",
		authed(auth.RequirePermission(auth.PermComplianceRead, http.HandlerFunc(d.handleGetCompliance))))
	mux.Handle("GET /api/v1/devices/{id}/updates",
		authed(auth.RequirePermission(auth.PermUpdatesRead, http.HandlerFunc(d.handleListUpdates))))
	mux.Handle("POST /api/v1/devices/{id}/updates/apply",
		authed(auth.RequirePermission(auth.PermUpdatesApply, http.HandlerFunc(d.handleApplyUpdates))))

	// ----- Profiles -----
	mux.Handle("GET /api/v1/profiles",
		authed(auth.RequirePermission(auth.PermProfilesRead, http.HandlerFunc(d.handleListProfiles))))
	mux.Handle("GET /api/v1/profiles/{id}",
		authed(auth.RequirePermission(auth.PermProfilesRead, http.HandlerFunc(d.handleGetProfile))))
	mux.Handle("POST /api/v1/profiles",
		authed(auth.RequirePermission(auth.PermProfilesCreate, http.HandlerFunc(d.handleCreateProfile))))
	mux.Handle("POST /api/v1/profiles/{id}/assign/{deviceID}",
		authed(auth.RequirePermission(auth.PermProfilesAssign, http.HandlerFunc(d.handleAssignProfile))))

	// ----- Enrollment tokens -----
	mux.Handle("GET /api/v1/tokens",
		authed(auth.RequirePermission(auth.PermTokensRead, http.HandlerFunc(d.handleListTokens))))
	mux.Handle("POST /api/v1/tokens",
		authed(auth.RequirePermission(auth.PermTokensCreate, http.HandlerFunc(d.handleCreateToken))))

	// ----- Users (admin only) -----
	mux.Handle("GET /api/v1/users",
		authed(auth.RequirePermission(auth.PermUsersRead, http.HandlerFunc(d.handleListUsers))))
	mux.Handle("GET /api/v1/users/{id}",
		authed(auth.RequirePermission(auth.PermUsersRead, http.HandlerFunc(d.handleGetUser))))
	mux.Handle("POST /api/v1/users",
		authed(auth.RequirePermission(auth.PermUsersManage, http.HandlerFunc(d.handleCreateUser))))
	mux.Handle("PATCH /api/v1/users/{id}",
		authed(auth.RequirePermission(auth.PermUsersManage, http.HandlerFunc(d.handlePatchUser))))
	mux.Handle("POST /api/v1/users/{id}/reset-password",
		authed(auth.RequirePermission(auth.PermUsersManage, http.HandlerFunc(d.handleResetPassword))))

	return mux
}
