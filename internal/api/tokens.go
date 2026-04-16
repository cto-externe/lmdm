// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/cto-externe/lmdm/internal/tokens"
)

type tokenJSON struct {
	ID          uuid.UUID  `json:"id"`
	Description string     `json:"description"`
	GroupIDs    []string   `json:"group_ids"`
	MaxUses     int        `json:"max_uses"`
	UsedCount   int        `json:"used_count"`
	ExpiresAt   time.Time  `json:"expires_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CreatedBy   string     `json:"created_by"`
}

type createTokenRequest struct {
	Description string   `json:"description"`
	GroupIDs    []string `json:"group_ids"`
	MaxUses     int      `json:"max_uses"`
	TTLSeconds  int      `json:"ttl_seconds"`
	CreatedBy   string   `json:"created_by"`
}

func (d *Deps) handleListTokens(w http.ResponseWriter, r *http.Request) {
	list, err := d.Tokens.List(r.Context(), d.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]tokenJSON, 0, len(list))
	for _, t := range list {
		out = append(out, tokenJSON{
			ID: t.ID, Description: t.Description, GroupIDs: t.GroupIDs,
			MaxUses: t.MaxUses, UsedCount: t.UsedCount,
			ExpiresAt: t.ExpiresAt, RevokedAt: t.RevokedAt,
			CreatedAt: t.CreatedAt, CreatedBy: t.CreatedBy,
		})
	}
	writeJSON(w, http.StatusOK, listResponse{Data: out, Total: len(out)})
}

func (d *Deps) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req createTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.MaxUses <= 0 {
		req.MaxUses = 1
	}
	if req.TTLSeconds <= 0 {
		req.TTLSeconds = 86400 // 24h default
	}
	if req.CreatedBy == "" {
		req.CreatedBy = "api"
	}

	plaintext, tok, err := d.Tokens.Create(r.Context(), tokens.CreateRequest{
		TenantID:    d.TenantID,
		Description: req.Description,
		GroupIDs:    req.GroupIDs,
		MaxUses:     req.MaxUses,
		TTL:         time.Duration(req.TTLSeconds) * time.Second,
		CreatedBy:   req.CreatedBy,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Return plaintext ONCE — it's not stored and won't be retrievable.
	writeJSON(w, http.StatusCreated, map[string]any{
		"data": map[string]any{
			"token":       plaintext,
			"id":          tok.ID,
			"description": tok.Description,
			"max_uses":    tok.MaxUses,
			"expires_at":  tok.ExpiresAt,
		},
	})
}
