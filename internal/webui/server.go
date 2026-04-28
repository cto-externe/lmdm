// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package webui bundles the LMDM web UI handlers, middlewares and embedded
// assets and exposes them via the Mount function called from cmd/lmdm-server.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"time"

	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/webui/csrf"
	"github.com/cto-externe/lmdm/internal/webui/handlers"
	"github.com/cto-externe/lmdm/internal/webui/i18n"
	"github.com/cto-externe/lmdm/internal/webui/ratelimit"
	"github.com/cto-externe/lmdm/internal/webui/security"
)

//go:embed assets
var embeddedAssets embed.FS

// Deps injects server-wide dependencies into the webui.
type Deps struct {
	Signer        *auth.JWTSigner
	AuthService   *auth.Service
	DevicesRepo   *devices.Repository
	CSRFKey       []byte
	SecureCookies bool
	EnableHSTS    bool
	DevAssetsDir  string // if non-empty, serve assets from disk (hot reload)
}

// Mount registers all /web/* routes onto mux. Call once at startup.
func Mount(mux *http.ServeMux, deps Deps) error {
	if err := i18n.Load(); err != nil {
		return err
	}

	csrfMW := csrf.New(deps.CSRFKey)
	secHeaders := security.Middleware(security.Options{EnableHSTS: deps.EnableHSTS})
	loginLimiter := ratelimit.New(5, 5*time.Minute)

	authDeps := &handlers.AuthDeps{
		Auth:          deps.AuthService,
		CSRF:          csrfMW,
		SecureCookies: deps.SecureCookies,
	}
	dashDeps := &handlers.DashboardDeps{CSRF: csrfMW}
	devDeps := &handlers.DevicesDeps{Repo: deps.DevicesRepo, CSRF: csrfMW}

	// Public: login pages.
	mux.Handle("GET /web/login",
		secHeaders(http.HandlerFunc(authDeps.HandleLoginGET)))
	mux.Handle("POST /web/login",
		secHeaders(loginLimiter.Protect(csrfMW.Protect(http.HandlerFunc(authDeps.HandleLoginPOST)))))
	mux.Handle("GET /web/login/mfa",
		secHeaders(http.HandlerFunc(authDeps.HandleMFAGET)))
	mux.Handle("POST /web/login/mfa",
		secHeaders(loginLimiter.Protect(csrfMW.Protect(http.HandlerFunc(authDeps.HandleMFAPOST)))))
	mux.Handle("POST /web/logout",
		secHeaders(csrfMW.Protect(http.HandlerFunc(authDeps.HandleLogout))))

	// Authenticated.
	requireAuth := auth.RequireAuth(deps.Signer)
	authed := func(h http.Handler) http.Handler {
		return secHeaders(requireAuth(csrfMW.Protect(h)))
	}
	readDevices := func(h http.Handler) http.Handler {
		return authed(auth.RequirePermission(auth.PermDevicesRead, h))
	}

	mux.Handle("GET /web/dashboard", authed(http.HandlerFunc(dashDeps.Handle)))
	mux.Handle("GET /web/devices", readDevices(http.HandlerFunc(devDeps.HandleList)))
	mux.Handle("GET /web/devices/fragment", readDevices(http.HandlerFunc(devDeps.HandleFragment)))

	// Root /web/ → /web/login.
	mux.Handle("GET /web/{$}", secHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/web/login", http.StatusSeeOther)
	})))

	// Static assets.
	mux.Handle("GET /web/static/", http.StripPrefix("/web/static/", staticHandler(deps.DevAssetsDir)))
	return nil
}

func staticHandler(devDir string) http.Handler {
	if devDir != "" {
		return http.FileServer(http.Dir(devDir)) //nolint:gosec // devDir is an explicit configuration input
	}
	sub, _ := fs.Sub(embeddedAssets, "assets")
	return http.FileServer(http.FS(sub))
}
