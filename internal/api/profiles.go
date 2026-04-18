// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/cto-externe/lmdm/internal/audit"
	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/profiles"
)

type profileJSON struct {
	ID          uuid.UUID       `json:"id"`
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Description string          `json:"description"`
	Source      string          `json:"source"`
	Locked      bool            `json:"locked"`
	CreatedAt   time.Time       `json:"created_at"`
	JSONContent json.RawMessage `json:"content,omitempty"`
}

func toProfileJSON(p *profiles.Profile, includeContent bool) profileJSON {
	pj := profileJSON{
		ID: p.ID, Name: p.Name, Version: p.Version,
		Description: p.Description, Source: p.Source,
		Locked: p.Locked, CreatedAt: p.CreatedAt,
	}
	if includeContent {
		pj.JSONContent = p.JSONContent
	}
	return pj
}

func (d *Deps) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	list, err := d.Profiles.List(r.Context(), d.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]profileJSON, 0, len(list))
	for i := range list {
		out = append(out, toProfileJSON(&list[i], false))
	}
	writeJSON(w, http.StatusOK, listResponse{Data: out, Total: len(out)})
}

func (d *Deps) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid profile id")
		return
	}
	p, err := d.Profiles.FindByID(r.Context(), d.TenantID, id)
	if err != nil {
		if errors.Is(err, profiles.ErrNotFound) {
			writeError(w, http.StatusNotFound, "profile not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]any{
			"id":          p.ID,
			"name":        p.Name,
			"version":     p.Version,
			"description": p.Description,
			"source":      p.Source,
			"locked":      p.Locked,
			"created_at":  p.CreatedAt,
			"yaml":        p.YAMLContent,
			"content":     p.JSONContent,
		},
	})
}

func (d *Deps) handleCreateProfile(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MiB max
	if err != nil {
		writeError(w, http.StatusBadRequest, "cannot read body")
		return
	}
	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, "empty body — send YAML profile content")
		return
	}
	p, err := d.Profiles.Create(r.Context(), d.TenantID, body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if pr := auth.PrincipalFrom(r.Context()); pr != nil && d.Audit != nil {
		_ = d.Audit.Write(r.Context(), audit.Event{
			TenantID:     d.TenantID,
			Actor:        audit.ActorUser(pr.UserID),
			Action:       audit.ActionProfileCreated,
			ResourceType: "profile",
			ResourceID:   p.ID.String(),
			SourceIP:     clientIP(r),
			Details:      map[string]any{"name": p.Name, "version": p.Version},
		})
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"data": toProfileJSON(p, false),
	})
}
