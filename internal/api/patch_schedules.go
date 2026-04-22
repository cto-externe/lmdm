// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/robfig/cron/v3"

	"github.com/cto-externe/lmdm/internal/audit"
	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/patchschedule"
)

type patchScheduleJSON struct {
	ID                    uuid.UUID  `json:"id"`
	TenantID              uuid.UUID  `json:"tenant_id"`
	DeviceID              *uuid.UUID `json:"device_id,omitempty"`
	CronExpr              string     `json:"cron_expr"`
	FilterSecurityOnly    bool       `json:"filter_security_only"`
	FilterIncludePackages []string   `json:"filter_include_packages,omitempty"`
	FilterExcludePackages []string   `json:"filter_exclude_packages,omitempty"`
	Enabled               bool       `json:"enabled"`
	NextFireAt            time.Time  `json:"next_fire_at"`
	LastRanAt             *time.Time `json:"last_ran_at,omitempty"`
	LastRunStatus         *string    `json:"last_run_status,omitempty"`
	SkippedRunsCount      int        `json:"skipped_runs_count"`
	CreatedAt             time.Time  `json:"created_at"`
}

func toPatchScheduleJSON(s patchschedule.Schedule) patchScheduleJSON {
	return patchScheduleJSON{
		ID:                    s.ID,
		TenantID:              s.TenantID,
		DeviceID:              s.DeviceID,
		CronExpr:              s.CronExpr,
		FilterSecurityOnly:    s.FilterSecurityOnly,
		FilterIncludePackages: s.FilterIncludePackages,
		FilterExcludePackages: s.FilterExcludePackages,
		Enabled:               s.Enabled,
		NextFireAt:            s.NextFireAt,
		LastRanAt:             s.LastRanAt,
		LastRunStatus:         s.LastRunStatus,
		SkippedRunsCount:      s.SkippedRunsCount,
		CreatedAt:             s.CreatedAt,
	}
}

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

type createPatchScheduleRequest struct {
	DeviceID              *uuid.UUID `json:"device_id,omitempty"`
	CronExpr              string     `json:"cron_expr"`
	FilterSecurityOnly    bool       `json:"filter_security_only"`
	FilterIncludePackages []string   `json:"filter_include_packages,omitempty"`
	FilterExcludePackages []string   `json:"filter_exclude_packages,omitempty"`
}

func (d *Deps) handleListPatchSchedules(w http.ResponseWriter, r *http.Request) {
	if d.PatchRepo == nil {
		writeError(w, http.StatusInternalServerError, "patch schedules repository not available")
		return
	}
	list, err := d.PatchRepo.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]patchScheduleJSON, 0, len(list))
	for _, s := range list {
		out = append(out, toPatchScheduleJSON(s))
	}
	writeJSON(w, http.StatusOK, listResponse{Data: out, Total: len(list)})
}

func (d *Deps) handleGetPatchSchedule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if d.PatchRepo == nil {
		writeError(w, http.StatusInternalServerError, "patch schedules repository not available")
		return
	}
	s, err := d.PatchRepo.FindByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, patchschedule.ErrNotFound) {
			writeError(w, http.StatusNotFound, "patch schedule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toPatchScheduleJSON(*s))
}

func (d *Deps) handleCreatePatchSchedule(w http.ResponseWriter, r *http.Request) {
	if d.PatchRepo == nil {
		writeError(w, http.StatusInternalServerError, "patch schedules repository not available")
		return
	}
	var req createPatchScheduleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if req.CronExpr == "" {
		writeError(w, http.StatusBadRequest, "cron_expr required")
		return
	}
	sched, err := cronParser.Parse(req.CronExpr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid cron_expr: "+err.Error())
		return
	}
	principal := auth.PrincipalFrom(r.Context())
	var creatorID *uuid.UUID
	if principal != nil {
		id := principal.UserID
		creatorID = &id
	}
	nextFire := sched.Next(time.Now().UTC())
	created, err := d.PatchRepo.Create(r.Context(), patchschedule.NewSchedule{
		TenantID:              d.TenantID,
		DeviceID:              req.DeviceID,
		CronExpr:              req.CronExpr,
		FilterSecurityOnly:    req.FilterSecurityOnly,
		FilterIncludePackages: req.FilterIncludePackages,
		FilterExcludePackages: req.FilterExcludePackages,
		CreatedByUserID:       creatorID,
	}, nextFire)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if d.Audit != nil && principal != nil {
		_ = d.Audit.Write(r.Context(), audit.Event{
			TenantID:     d.TenantID,
			Actor:        audit.ActorUser(principal.UserID),
			Action:       audit.ActionPatchScheduleCreated,
			ResourceType: "patch_schedule",
			ResourceID:   created.ID.String(),
			SourceIP:     clientIP(r),
		})
	}
	writeJSON(w, http.StatusCreated, toPatchScheduleJSON(*created))
}

func (d *Deps) handleDeletePatchSchedule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if d.PatchRepo == nil {
		writeError(w, http.StatusInternalServerError, "patch schedules repository not available")
		return
	}
	if err := d.PatchRepo.Delete(r.Context(), id); err != nil {
		if errors.Is(err, patchschedule.ErrNotFound) {
			writeError(w, http.StatusNotFound, "patch schedule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if pr := auth.PrincipalFrom(r.Context()); pr != nil && d.Audit != nil {
		_ = d.Audit.Write(r.Context(), audit.Event{
			TenantID:     d.TenantID,
			Actor:        audit.ActorUser(pr.UserID),
			Action:       audit.ActionPatchScheduleDeleted,
			ResourceType: "patch_schedule",
			ResourceID:   id.String(),
			SourceIP:     clientIP(r),
		})
	}
	w.WriteHeader(http.StatusNoContent)
}
