// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/cto-externe/lmdm/internal/audit"
	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/users"
)

// These handlers are wired into the router by Task 16; until then the unused
// linter would flag every handler and request/response type in this file. The
// per-symbol nolint directives below suppress exactly that transitional noise.

// userJSON is the API projection of a user row. Sensitive fields
// (password_hash, totp_secret_encrypted) are never serialized.
type userJSON struct { //nolint:unused // wired in Task 16
	ID                 uuid.UUID `json:"id"`
	Email              string    `json:"email"`
	Role               string    `json:"role"`
	Active             bool      `json:"active"`
	MustChangePassword bool      `json:"must_change_password"`
	TOTPEnrolled       bool      `json:"totp_enrolled"`
	LastLoginAt        any       `json:"last_login_at,omitempty"`
}

func toUserJSON(u *users.User) userJSON { //nolint:unused // wired in Task 16
	var ll any
	if u.LastLoginAt != nil {
		ll = u.LastLoginAt
	}
	return userJSON{
		ID:                 u.ID,
		Email:              u.Email,
		Role:               u.Role,
		Active:             u.Active,
		MustChangePassword: u.MustChangePassword,
		TOTPEnrolled:       u.TOTPSecretEncrypted != nil,
		LastLoginAt:        ll,
	}
}

func (d *Deps) handleListUsers(w http.ResponseWriter, r *http.Request) { //nolint:unused // wired in Task 16
	out, err := d.Users.List(r.Context(), d.TenantID, users.ListFilter{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	res := make([]userJSON, 0, len(out))
	for i := range out {
		res = append(res, toUserJSON(&out[i]))
	}
	writeJSON(w, http.StatusOK, listResponse{Data: res, Total: len(res)})
}

func (d *Deps) handleGetUser(w http.ResponseWriter, r *http.Request) { //nolint:unused // wired in Task 16
	id, ok := parseUUID(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	u, err := d.Users.FindByID(r.Context(), d.TenantID, id)
	if errors.Is(err, users.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toUserJSON(u))
}

type createUserReq struct { //nolint:unused // wired in Task 16
	Email    string `json:"email"`
	Role     string `json:"role"`
	Password string `json:"password"`
}

func (d *Deps) handleCreateUser(w http.ResponseWriter, r *http.Request) { //nolint:unused // wired in Task 16
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req createUserReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if !auth.Role(req.Role).IsValid() {
		writeError(w, http.StatusBadRequest, "invalid role")
		return
	}
	if len(req.Password) < auth.MinPasswordLen {
		writeError(w, http.StatusBadRequest, "password too short")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hash failed")
		return
	}
	u, err := d.Users.Create(r.Context(), d.TenantID, req.Email, hash, req.Role)
	if errors.Is(err, users.ErrDuplicateEmail) {
		writeError(w, http.StatusConflict, "email in use")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if d.Audit != nil {
		_ = d.Audit.Write(r.Context(), audit.Event{
			TenantID:     d.TenantID,
			Actor:        audit.ActorUser(p.UserID),
			Action:       audit.ActionUserCreated,
			ResourceType: "user",
			ResourceID:   u.ID.String(),
			SourceIP:     clientIP(r),
			Details:      map[string]any{"email": u.Email, "role": u.Role},
		})
	}
	writeJSON(w, http.StatusCreated, toUserJSON(u))
}

type patchUserReq struct { //nolint:unused // wired in Task 16
	Role   *string `json:"role,omitempty"`
	Active *bool   `json:"active,omitempty"`
}

func (d *Deps) handlePatchUser(w http.ResponseWriter, r *http.Request) { //nolint:unused // wired in Task 16
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id, ok := parseUUID(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var req patchUserReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.Role != nil {
		if !auth.Role(*req.Role).IsValid() {
			writeError(w, http.StatusBadRequest, "invalid role")
			return
		}
		if err := d.Users.SetRole(r.Context(), d.TenantID, id, *req.Role); err != nil {
			if errors.Is(err, users.ErrNotFound) {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if d.Audit != nil {
			_ = d.Audit.Write(r.Context(), audit.Event{
				TenantID:     d.TenantID,
				Actor:        audit.ActorUser(p.UserID),
				Action:       audit.ActionUserRoleChanged,
				ResourceType: "user",
				ResourceID:   id.String(),
				SourceIP:     clientIP(r),
				Details:      map[string]any{"new_role": *req.Role},
			})
		}
	}
	if req.Active != nil {
		if *req.Active {
			if err := d.Users.Reactivate(r.Context(), d.TenantID, id); err != nil {
				if errors.Is(err, users.ErrNotFound) {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if d.Audit != nil {
				_ = d.Audit.Write(r.Context(), audit.Event{
					TenantID: d.TenantID, Actor: audit.ActorUser(p.UserID),
					Action: audit.ActionUserReactivated, ResourceType: "user",
					ResourceID: id.String(), SourceIP: clientIP(r),
				})
			}
		} else {
			if err := d.Users.Deactivate(r.Context(), d.TenantID, id, p.UserID); err != nil {
				if errors.Is(err, users.ErrNotFound) {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			_ = d.Users.RevokeAllForUser(r.Context(), d.TenantID, id, "deactivation")
			if d.Audit != nil {
				_ = d.Audit.Write(r.Context(), audit.Event{
					TenantID: d.TenantID, Actor: audit.ActorUser(p.UserID),
					Action: audit.ActionUserDeactivated, ResourceType: "user",
					ResourceID: id.String(), SourceIP: clientIP(r),
				})
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

type resetPwdResp struct { //nolint:unused // wired in Task 16
	TemporaryPassword string `json:"temporary_password"`
}

func (d *Deps) handleResetPassword(w http.ResponseWriter, r *http.Request) { //nolint:unused // wired in Task 16
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id, ok := parseUUID(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	tempPw, err := d.Auth.ResetPasswordByAdmin(r.Context(), p.UserID, id, clientIP(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resetPwdResp{TemporaryPassword: tempPw})
}
