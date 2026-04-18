// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package api

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/cto-externe/lmdm/internal/auth"
)

// These handlers are wired into the router by Task 16; until then, the unused
// linter would flag every handler and request/response type in this file. The
// per-symbol nolint directives below suppress exactly that transitional noise.

// --- Login (step 1) ---

type loginReq struct { //nolint:unused // wired in Task 16
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResp struct { //nolint:unused // wired in Task 16
	StepUpToken        string `json:"step_up_token"`
	NeedsMFASetup      bool   `json:"needs_mfa_setup,omitempty"`
	NeedsMFAVerify     bool   `json:"needs_mfa_verify,omitempty"`
	MustChangePassword bool   `json:"must_change_password,omitempty"`
}

func (d *Deps) handleLogin(w http.ResponseWriter, r *http.Request) { //nolint:unused // wired in Task 16
	ip := clientIP(r)
	if d.LoginRateLimit != nil && !d.LoginRateLimit.Allow(ip.String()) {
		writeError(w, http.StatusTooManyRequests, "too many login attempts")
		return
	}
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	res, err := d.Auth.Login(r.Context(), req.Email, req.Password, ip)
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	case errors.Is(err, auth.ErrAccountLocked):
		writeError(w, http.StatusForbidden, "account locked")
		return
	case errors.Is(err, auth.ErrAccountInactive):
		writeError(w, http.StatusForbidden, "account inactive")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	writeJSON(w, http.StatusOK, loginResp{
		StepUpToken:        res.StepUpToken,
		NeedsMFASetup:      res.NeedsMFASetup,
		NeedsMFAVerify:     res.NeedsMFAVerify,
		MustChangePassword: res.MustChangePassword,
	})
}

// --- MFA enrolment ---

type mfaEnrollReq struct { //nolint:unused // wired in Task 16
	StepUpToken string `json:"step_up_token"`
	Email       string `json:"email"`
}

type mfaEnrollResp struct { //nolint:unused // wired in Task 16
	URI         string `json:"uri"`
	SetupHandle string `json:"setup_handle"`
}

func (d *Deps) handleMFAEnroll(w http.ResponseWriter, r *http.Request) { //nolint:unused // wired in Task 16
	var req mfaEnrollReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	result, err := d.Auth.EnrollMFA(r.Context(), req.StepUpToken, req.Email)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid step-up")
		return
	}
	writeJSON(w, http.StatusOK, mfaEnrollResp{URI: result.URI, SetupHandle: result.SetupHandle})
}

// --- MFA verification (finishes login) ---

type mfaVerifyReq struct { //nolint:unused // wired in Task 16
	StepUpToken string `json:"step_up_token"`
	Code        string `json:"code"`
	SetupHandle string `json:"setup_handle,omitempty"` // only for the enrolment flow
}

type tokensResp struct { //nolint:unused // wired in Task 16
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

func (d *Deps) handleMFAVerify(w http.ResponseWriter, r *http.Request) { //nolint:unused // wired in Task 16
	ip := clientIP(r)
	if d.MFARateLimit != nil && !d.MFARateLimit.Allow(ip.String()) {
		writeError(w, http.StatusTooManyRequests, "rate limit")
		return
	}
	var req mfaVerifyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	tks, err := d.Auth.VerifyMFA(r.Context(), req.StepUpToken, req.Code, req.SetupHandle, r.UserAgent(), ip)
	switch {
	case errors.Is(err, auth.ErrMFAInvalid),
		errors.Is(err, auth.ErrMFASetupRequired),
		errors.Is(err, auth.ErrUnauthorized):
		writeError(w, http.StatusUnauthorized, "invalid mfa")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "verify mfa failed")
		return
	}
	writeJSON(w, http.StatusOK, tokensResp{
		AccessToken:  tks.AccessToken,
		RefreshToken: tks.RefreshToken,
		ExpiresAt:    tks.ExpiresAt.Unix(),
	})
}

// --- Refresh ---

type refreshReq struct { //nolint:unused // wired in Task 16
	RefreshToken string `json:"refresh_token"`
}

func (d *Deps) handleRefresh(w http.ResponseWriter, r *http.Request) { //nolint:unused // wired in Task 16
	ip := clientIP(r)
	if d.MFARateLimit != nil && !d.MFARateLimit.Allow(ip.String()) {
		writeError(w, http.StatusTooManyRequests, "rate limit")
		return
	}
	var req refreshReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	tks, err := d.Auth.Refresh(r.Context(), req.RefreshToken, r.UserAgent(), ip)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid refresh")
		return
	}
	writeJSON(w, http.StatusOK, tokensResp{
		AccessToken:  tks.AccessToken,
		RefreshToken: tks.RefreshToken,
		ExpiresAt:    tks.ExpiresAt.Unix(),
	})
}

// --- Logout / LogoutAll ---

type logoutReq struct { //nolint:unused // wired in Task 16
	RefreshToken string `json:"refresh_token"`
}

func (d *Deps) handleLogout(w http.ResponseWriter, r *http.Request) { //nolint:unused // wired in Task 16
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req logoutReq
	_ = json.NewDecoder(r.Body).Decode(&req) // body is optional
	_ = d.Auth.Logout(r.Context(), req.RefreshToken, p.UserID, clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func (d *Deps) handleLogoutAll(w http.ResponseWriter, r *http.Request) { //nolint:unused // wired in Task 16
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	_ = d.Auth.LogoutAll(r.Context(), p.UserID, clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// --- Password change (self) ---

type passwordReq struct { //nolint:unused // wired in Task 16
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
	TOTPCode        string `json:"totp_code"`
}

func (d *Deps) handlePassword(w http.ResponseWriter, r *http.Request) { //nolint:unused // wired in Task 16
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req passwordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	err := d.Auth.ChangePassword(r.Context(), p.UserID, req.CurrentPassword, req.NewPassword, req.TOTPCode, clientIP(r))
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, "invalid current password")
		return
	case errors.Is(err, auth.ErrMFAInvalid), errors.Is(err, auth.ErrMFASetupRequired):
		writeError(w, http.StatusUnauthorized, "invalid mfa")
		return
	case err != nil:
		// Password policy errors, db errors — give a minimally informative 400.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Me ---

func (d *Deps) handleMe(w http.ResponseWriter, r *http.Request) { //nolint:unused // wired in Task 16
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":   p.UserID,
		"tenant_id": p.TenantID,
		"role":      p.Role,
		"email":     p.Email,
	})
}

// --- helpers ---

// clientIP returns the first IP found in X-Forwarded-For, or falls back to RemoteAddr.
func clientIP(r *http.Request) net.IP { //nolint:unused // wired in Task 16
	if fw := r.Header.Get("X-Forwarded-For"); fw != "" {
		if i := strings.IndexByte(fw, ','); i >= 0 {
			return net.ParseIP(strings.TrimSpace(fw[:i]))
		}
		return net.ParseIP(strings.TrimSpace(fw))
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return net.ParseIP(host)
}
