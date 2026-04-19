// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/deployments"
)

// createDeploymentReq is the request payload for POST /api/v1/deployments.
// The zero-value for ValidationMode/ValidationTimeoutS/FailureThresholdPct is
// passed through to the engine which applies sensible defaults (manual, 30m,
// 10%).
type createDeploymentReq struct {
	ProfileID           string   `json:"profile_id"`
	TargetDeviceIDs     []string `json:"target_device_ids"`
	CanaryDeviceID      string   `json:"canary_device_id"`
	ValidationMode      string   `json:"validation_mode,omitempty"`
	ValidationTimeoutS  int      `json:"validation_timeout_s,omitempty"`
	FailureThresholdPct int      `json:"failure_threshold_pct,omitempty"`
}

// deploymentJSON is the API projection of a deployments row. All time fields
// that are nullable at the DB layer are emitted as `*time.Time` + omitempty so
// callers can distinguish "not yet happened" from "happened at epoch".
type deploymentJSON struct {
	ID                       uuid.UUID   `json:"id"`
	ProfileID                uuid.UUID   `json:"profile_id"`
	TargetDeviceIDs          []uuid.UUID `json:"target_device_ids"`
	CanaryDeviceID           uuid.UUID   `json:"canary_device_id"`
	Status                   string      `json:"status"`
	ValidationMode           string      `json:"validation_mode"`
	ValidationTimeoutSeconds int         `json:"validation_timeout_s"`
	FailureThresholdPct      int         `json:"failure_threshold_pct"`
	CreatedByUserID          *uuid.UUID  `json:"created_by_user_id,omitempty"`
	CreatedAt                time.Time   `json:"created_at"`
	CanaryStartedAt          *time.Time  `json:"canary_started_at,omitempty"`
	CanaryFinishedAt         *time.Time  `json:"canary_finished_at,omitempty"`
	ValidatedAt              *time.Time  `json:"validated_at,omitempty"`
	CompletedAt              *time.Time  `json:"completed_at,omitempty"`
	Reason                   string      `json:"reason,omitempty"`
}

// deploymentWithResults is the GET /deployments/{id} response: the deployment
// row plus the per-device results. Canary rows come first (ListResults orders
// by is_canary DESC, device_id).
type deploymentWithResults struct {
	deploymentJSON
	Results []resultJSON `json:"results"`
}

// resultJSON is the API projection of a deployment_results row.
type resultJSON struct {
	DeviceID     uuid.UUID  `json:"device_id"`
	IsCanary     bool       `json:"is_canary"`
	Status       string     `json:"status"`
	SnapshotID   string     `json:"snapshot_id,omitempty"`
	ErrorMessage string     `json:"error_message,omitempty"`
	AppliedAt    *time.Time `json:"applied_at,omitempty"`
	RolledBackAt *time.Time `json:"rolled_back_at,omitempty"`
}

func toDeploymentJSON(d *deployments.Deployment) deploymentJSON {
	return deploymentJSON{
		ID:                       d.ID,
		ProfileID:                d.ProfileID,
		TargetDeviceIDs:          d.TargetDeviceIDs,
		CanaryDeviceID:           d.CanaryDeviceID,
		Status:                   string(d.Status),
		ValidationMode:           string(d.ValidationMode),
		ValidationTimeoutSeconds: d.ValidationTimeoutSeconds,
		FailureThresholdPct:      d.FailureThresholdPct,
		CreatedByUserID:          d.CreatedByUserID,
		CreatedAt:                d.CreatedAt,
		CanaryStartedAt:          d.CanaryStartedAt,
		CanaryFinishedAt:         d.CanaryFinishedAt,
		ValidatedAt:              d.ValidatedAt,
		CompletedAt:              d.CompletedAt,
		Reason:                   d.Reason,
	}
}

func toResultJSON(r *deployments.Result) resultJSON {
	return resultJSON{
		DeviceID:     r.DeviceID,
		IsCanary:     r.IsCanary,
		Status:       string(r.Status),
		SnapshotID:   r.SnapshotID,
		ErrorMessage: r.ErrorMessage,
		AppliedAt:    r.AppliedAt,
		RolledBackAt: r.RolledBackAt,
	}
}

// handleCreateDeployment is POST /api/v1/deployments. It decodes the spec,
// delegates to the Engine (which persists + pushes the canary), and returns
// the persisted deployment with its current status. The engine never returns
// a nil deployment on a validation-level failure, but it does return an error
// for bad input (missing canary, empty targets, etc.) which we surface as 400.
func (d *Deps) handleCreateDeployment(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req createDeploymentReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	profileID, err := uuid.Parse(req.ProfileID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid profile_id")
		return
	}
	canaryID, err := uuid.Parse(req.CanaryDeviceID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid canary_device_id")
		return
	}
	targets := make([]uuid.UUID, 0, len(req.TargetDeviceIDs))
	for _, s := range req.TargetDeviceIDs {
		id, err := uuid.Parse(s)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid target_device_ids element")
			return
		}
		targets = append(targets, id)
	}

	spec := deployments.DeploymentSpec{
		TenantID:                 d.TenantID,
		ProfileID:                profileID,
		TargetDeviceIDs:          targets,
		CanaryDeviceID:           canaryID,
		ValidationMode:           deployments.ValidationMode(req.ValidationMode),
		ValidationTimeoutSeconds: req.ValidationTimeoutS,
		FailureThresholdPct:      req.FailureThresholdPct,
		CreatedByUserID:          &p.UserID,
	}
	created, err := d.DeploymentsEngine.Create(r.Context(), spec)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, toDeploymentJSON(created))
}

// handleListDeployments is GET /api/v1/deployments. Supports ?status= for
// filtering; any other status string is passed through and will match zero
// rows at the repo layer.
func (d *Deps) handleListDeployments(w http.ResponseWriter, r *http.Request) {
	filter := deployments.ListFilter{
		Status: deployments.Status(r.URL.Query().Get("status")),
	}
	list, err := d.Deployments.List(r.Context(), d.TenantID, filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]deploymentJSON, 0, len(list))
	for i := range list {
		out = append(out, toDeploymentJSON(&list[i]))
	}
	writeJSON(w, http.StatusOK, listResponse{Data: out, Total: len(out)})
}

// handleGetDeployment is GET /api/v1/deployments/{id}. Returns the deployment
// row plus its per-device results (canary first) so a single round-trip is
// enough for the console's detail view.
func (d *Deps) handleGetDeployment(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	dep, err := d.Deployments.FindByID(r.Context(), d.TenantID, id)
	if errors.Is(err, deployments.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	results, err := d.Deployments.ListResults(r.Context(), d.TenantID, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := deploymentWithResults{
		deploymentJSON: toDeploymentJSON(dep),
		Results:        make([]resultJSON, 0, len(results)),
	}
	for i := range results {
		resp.Results = append(resp.Results, toResultJSON(&results[i]))
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleValidateDeployment is POST /api/v1/deployments/{id}/validate. Posts a
// Validate event on the engine channel; existence and state sanity are checked
// by the engine handler (no-op with a WARN log if the state is wrong). Returns
// 202 because the transition is asynchronous.
func (d *Deps) handleValidateDeployment(w http.ResponseWriter, r *http.Request) {
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
	d.DeploymentsEngine.Events() <- deployments.Validate{
		DeploymentID: id,
		ByUserID:     p.UserID,
	}
	w.WriteHeader(http.StatusAccepted)
}

// rollbackReq is the request payload for POST /deployments/{id}/rollback. The
// body is optional; callers may omit it entirely and the reason defaults to
// "".
type rollbackReq struct {
	Reason string `json:"reason,omitempty"`
}

// handleRollbackDeployment is POST /api/v1/deployments/{id}/rollback. Posts a
// Rollback event on the engine channel. Like validate, the engine handler
// does the existence + terminal-state checks. 202 Accepted.
func (d *Deps) handleRollbackDeployment(w http.ResponseWriter, r *http.Request) {
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
	var req rollbackReq
	_ = json.NewDecoder(r.Body).Decode(&req) // body is optional
	d.DeploymentsEngine.Events() <- deployments.Rollback{
		DeploymentID: id,
		ByUserID:     p.UserID,
		Reason:       req.Reason,
	}
	w.WriteHeader(http.StatusAccepted)
}
