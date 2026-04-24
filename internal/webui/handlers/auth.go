// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package handlers exposes WebUI HTTP handlers. Each handler renders HTML
// via Templ (never JSON) and uses the same underlying auth/devices/... services
// as the REST API.
package handlers

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/webui/csrf"
	"github.com/cto-externe/lmdm/internal/webui/i18n"
	"github.com/cto-externe/lmdm/internal/webui/templates"
)

const (
	accessCookieTTL  = 15 * time.Minute
	refreshCookieTTL = 7 * 24 * time.Hour
	mfaPendingTTL    = 5 * time.Minute
)

const mfaPendingCookieName = "lmdm_mfa_pending"

// authService is the subset of auth.Service used by these handlers.
// *auth.Service satisfies this interface by structural typing.
type authService interface {
	Login(ctx context.Context, email, password string, ip net.IP) (*auth.LoginResult, error)
	VerifyMFA(ctx context.Context, stepUpToken, code, setupHandle, userAgent string, ip net.IP) (*auth.Tokens, error)
	Logout(ctx context.Context, plainRefresh string, actorUserID uuid.UUID, ip net.IP) error
}

// AuthDeps carries the auth-related dependencies the handlers need.
type AuthDeps struct {
	Auth          authService
	CSRF          *csrf.Middleware
	SecureCookies bool // true in prod (https), false on localhost dev
}

// HandleLoginGET renders the login form. Issues a fresh CSRF token cookie.
func (d *AuthDeps) HandleLoginGET(w http.ResponseWriter, r *http.Request) {
	lang := i18n.LocaleFromRequest(r)
	tok := d.CSRF.Issue()
	setCookie(w, csrf.CookieName, tok, 0, false, d.SecureCookies) // HttpOnly=false so HTMX can read.
	_ = templates.Login(lang, tok, "").Render(r.Context(), w)
}

// HandleLoginPOST verifies email+password, then either:
//   - MFA required → stores step-up token in lmdm_mfa_pending cookie, HX-Redirect /web/login/mfa
//   - MFA not required (setup needed, or must change password) → currently renders login page
//     with an error; full flows for those cases land in plan #2 (User settings).
func (d *AuthDeps) HandleLoginPOST(w http.ResponseWriter, r *http.Request) {
	lang := i18n.LocaleFromRequest(r)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<13) // 8 KiB cap against body-flood
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	email := r.PostForm.Get("email")
	password := r.PostForm.Get("password")
	ip := clientIP(r)

	res, err := d.Auth.Login(r.Context(), email, password, ip)
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		d.renderLoginError(w, r, lang, "login.error.invalid")
		return
	case errors.Is(err, auth.ErrAccountLocked):
		d.renderLoginError(w, r, lang, "login.error.locked")
		return
	case errors.Is(err, auth.ErrAccountInactive):
		d.renderLoginError(w, r, lang, "login.error.locked")
		return
	case err != nil:
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}

	// Store step-up token in a short-lived cookie so the MFA handler can consume it.
	setCookie(w, mfaPendingCookieName, res.StepUpToken, int(mfaPendingTTL.Seconds()), true, d.SecureCookies)
	// The WebUI MVP only supports the happy path where MFA is already set up.
	// MustChangePassword / NeedsMFASetup flows are out of scope for Foundations
	// — render an error pointing to the CLI as a workaround.
	if res.MustChangePassword || res.NeedsMFASetup {
		d.renderLoginError(w, r, lang, "login.error.invalid") // conservative: ask to use CLI until plan #2
		return
	}
	w.Header().Set("HX-Redirect", "/web/login/mfa")
	w.WriteHeader(http.StatusOK)
}

// HandleMFAGET renders the MFA form. Requires a valid lmdm_mfa_pending cookie.
func (d *AuthDeps) HandleMFAGET(w http.ResponseWriter, r *http.Request) {
	lang := i18n.LocaleFromRequest(r)
	c, err := r.Cookie(mfaPendingCookieName)
	if err != nil || c.Value == "" {
		http.Redirect(w, r, "/web/login", http.StatusSeeOther)
		return
	}
	tok := d.CSRF.Issue()
	setCookie(w, csrf.CookieName, tok, 0, false, d.SecureCookies)
	_ = templates.MFA(lang, tok, "").Render(r.Context(), w)
}

// HandleMFAPOST verifies the TOTP code, sets session+refresh cookies, HX-Redirect to dashboard.
func (d *AuthDeps) HandleMFAPOST(w http.ResponseWriter, r *http.Request) {
	lang := i18n.LocaleFromRequest(r)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<13) // 8 KiB cap against body-flood
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	code := r.PostForm.Get("code")
	c, err := r.Cookie(mfaPendingCookieName)
	if err != nil || c.Value == "" {
		http.Redirect(w, r, "/web/login", http.StatusSeeOther)
		return
	}

	tokens, err := d.Auth.VerifyMFA(r.Context(), c.Value, code, "", r.UserAgent(), clientIP(r))
	if err != nil {
		// Re-issue CSRF + render MFA form with error.
		csrfTok := d.CSRF.Issue()
		setCookie(w, csrf.CookieName, csrfTok, 0, false, d.SecureCookies)
		_ = templates.MFA(lang, csrfTok, i18n.T(lang, "mfa.error.invalid")).Render(r.Context(), w)
		return
	}

	// Clear pending cookie and emit session cookies.
	setCookie(w, mfaPendingCookieName, "", -1, true, d.SecureCookies)
	d.emitSession(w, tokens)
	w.Header().Set("HX-Redirect", "/web/dashboard")
	w.WriteHeader(http.StatusOK)
}

// HandleLogout revokes the refresh token and clears cookies.
func (d *AuthDeps) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("lmdm_refresh"); err == nil && c.Value != "" {
		if p := auth.PrincipalFrom(r.Context()); p != nil {
			_ = d.Auth.Logout(r.Context(), c.Value, p.UserID, clientIP(r))
		}
	}
	setCookie(w, auth.SessionCookieName, "", -1, true, d.SecureCookies)
	setCookie(w, "lmdm_refresh", "", -1, true, d.SecureCookies)
	setCookie(w, csrf.CookieName, "", -1, false, d.SecureCookies)
	http.Redirect(w, r, "/web/login", http.StatusSeeOther)
}

func (d *AuthDeps) renderLoginError(w http.ResponseWriter, r *http.Request, lang, errKey string) {
	csrfTok := d.CSRF.Issue()
	setCookie(w, csrf.CookieName, csrfTok, 0, false, d.SecureCookies)
	_ = templates.Login(lang, csrfTok, i18n.T(lang, errKey)).Render(r.Context(), w)
}

func (d *AuthDeps) emitSession(w http.ResponseWriter, tokens *auth.Tokens) {
	setCookie(w, auth.SessionCookieName, tokens.AccessToken, int(accessCookieTTL.Seconds()), true, d.SecureCookies)
	setCookie(w, "lmdm_refresh", tokens.RefreshToken, int(refreshCookieTTL.Seconds()), true, d.SecureCookies)
	setCookie(w, csrf.CookieName, d.CSRF.Issue(), 0, false, d.SecureCookies)
}

func setCookie(w http.ResponseWriter, name, value string, maxAge int, httpOnly, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: httpOnly,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// clientIP extracts the best-guess client IP (RemoteAddr or X-Forwarded-For).
// Identical to what internal/api does — inline here to avoid cross-package import.
func clientIP(r *http.Request) net.IP {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		// First IP in the list is the original client.
		for i := 0; i < len(xf); i++ {
			if xf[i] == ',' || xf[i] == ' ' {
				xf = xf[:i]
				break
			}
		}
		if ip := net.ParseIP(xf); ip != nil {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip
		}
	}
	return nil
}
