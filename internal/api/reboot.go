// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package api

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/audit"
	"github.com/cto-externe/lmdm/internal/auth"
)

// allowedRebootPolicies is the set of accepted reboot_policy values.
var allowedRebootPolicies = map[string]struct{}{
	"admin_only":               {},
	"immediate_after_apply":    {},
	"next_maintenance_window":  {},
}

// rebootDeviceRequest is the optional JSON body for POST /devices/{id}/reboot.
type rebootDeviceRequest struct {
	Reason             string `json:"reason"`
	GracePeriodSeconds int    `json:"grace_period_seconds"`
	Force              bool   `json:"force"`
}

func (d *Deps) handleRebootDevice(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := parseUUID(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}

	if d.NATS == nil {
		writeError(w, http.StatusInternalServerError, "NATS not available")
		return
	}

	var req rebootDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Empty or invalid body → use all zero values (defaults applied below).
		req = rebootDeviceRequest{}
	}

	reason := req.Reason
	if reason == "" {
		reason = "admin_triggered"
	}
	grace := req.GracePeriodSeconds
	if grace == 0 {
		grace = 300
	}

	commandID := "reboot-" + deviceID.String() + "-" + uuid.NewString()[:8]
	env := &lmdmv1.CommandEnvelope{
		CommandId: commandID,
		Command: &lmdmv1.CommandEnvelope_Reboot{
			Reboot: &lmdmv1.RebootCommand{
				Reason:             reason,
				GracePeriodSeconds: uint32(grace),
				Force:              req.Force,
			},
		},
	}

	data, err := proto.Marshal(env)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "marshal: "+err.Error())
		return
	}

	subject := "fleet.agent." + deviceID.String() + ".commands"
	if err := d.NATS.Publish(subject, data); err != nil {
		writeError(w, http.StatusInternalServerError, "nats: "+err.Error())
		return
	}
	_ = d.NATS.Flush()

	if pr := auth.PrincipalFrom(r.Context()); pr != nil && d.Audit != nil {
		_ = d.Audit.Write(r.Context(), audit.Event{
			TenantID:     d.TenantID,
			Actor:        audit.ActorUser(pr.UserID),
			Action:       audit.ActionDeviceReboot,
			ResourceType: "device",
			ResourceID:   deviceID.String(),
			SourceIP:     clientIP(r),
			Details: map[string]any{
				"reason": reason,
				"force":  req.Force,
				"grace":  grace,
			},
		})
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"command_id": commandID,
		"status":     "published",
	})
}

// patchTenantPolicyRequest is the JSON body for PATCH /tenants/current/reboot-policy.
type patchTenantPolicyRequest struct {
	RebootPolicy      string  `json:"reboot_policy"`
	MaintenanceWindow *string `json:"maintenance_window"`
}

func (d *Deps) handlePatchTenantPolicy(w http.ResponseWriter, r *http.Request) {
	if d.PatchRepo == nil {
		writeError(w, http.StatusInternalServerError, "patch repository not available")
		return
	}

	var req patchTenantPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	if _, ok := allowedRebootPolicies[req.RebootPolicy]; !ok {
		writeError(w, http.StatusBadRequest, "invalid reboot_policy: must be one of admin_only, immediate_after_apply, next_maintenance_window")
		return
	}

	// Treat empty string as "clear" → nil (NULL in DB).
	var windowPtr *string
	if req.MaintenanceWindow != nil {
		if *req.MaintenanceWindow != "" {
			if _, err := cronParser.Parse(*req.MaintenanceWindow); err != nil {
				writeError(w, http.StatusBadRequest, "invalid maintenance_window cron: "+err.Error())
				return
			}
			windowPtr = req.MaintenanceWindow
		}
		// Empty string → windowPtr stays nil (clear).
	}

	if err := d.PatchRepo.UpdateTenantPolicy(r.Context(), d.TenantID, req.RebootPolicy, windowPtr); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if pr := auth.PrincipalFrom(r.Context()); pr != nil && d.Audit != nil {
		_ = d.Audit.Write(r.Context(), audit.Event{
			TenantID:     d.TenantID,
			Actor:        audit.ActorUser(pr.UserID),
			Action:       audit.ActionTenantPolicyUpdated,
			ResourceType: "tenant",
			ResourceID:   d.TenantID.String(),
			SourceIP:     clientIP(r),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"reboot_policy":      req.RebootPolicy,
		"maintenance_window": windowPtr,
	})
}

// patchDevicePolicyOverrideRequest is the JSON body for PATCH /devices/{id}/reboot-policy.
// Using *string so null/absent means "clear override".
type patchDevicePolicyOverrideRequest struct {
	RebootPolicyOverride      *string `json:"reboot_policy_override"`
	MaintenanceWindowOverride *string `json:"maintenance_window_override"`
}

func (d *Deps) handlePatchDevicePolicyOverride(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := parseUUID(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}

	if d.Devices == nil {
		writeError(w, http.StatusInternalServerError, "devices repository not available")
		return
	}

	var req patchDevicePolicyOverrideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	var rebootPtr *string
	if req.RebootPolicyOverride != nil {
		if _, ok := allowedRebootPolicies[*req.RebootPolicyOverride]; !ok {
			writeError(w, http.StatusBadRequest, "invalid reboot_policy_override: must be one of admin_only, immediate_after_apply, next_maintenance_window")
			return
		}
		rebootPtr = req.RebootPolicyOverride
	}

	var windowPtr *string
	if req.MaintenanceWindowOverride != nil {
		if *req.MaintenanceWindowOverride != "" {
			if _, err := cronParser.Parse(*req.MaintenanceWindowOverride); err != nil {
				writeError(w, http.StatusBadRequest, "invalid maintenance_window_override cron: "+err.Error())
				return
			}
			windowPtr = req.MaintenanceWindowOverride
		}
		// Empty string → windowPtr stays nil (clear).
	}

	if err := d.Devices.UpdateRebootOverrides(r.Context(), d.TenantID, deviceID, rebootPtr, windowPtr); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if pr := auth.PrincipalFrom(r.Context()); pr != nil && d.Audit != nil {
		_ = d.Audit.Write(r.Context(), audit.Event{
			TenantID:     d.TenantID,
			Actor:        audit.ActorUser(pr.UserID),
			Action:       audit.ActionDevicePolicyOverrideUpdated,
			ResourceType: "device",
			ResourceID:   deviceID.String(),
			SourceIP:     clientIP(r),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"reboot_policy_override":      rebootPtr,
		"maintenance_window_override": windowPtr,
	})
}
