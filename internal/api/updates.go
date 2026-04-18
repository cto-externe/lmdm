// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/audit"
	"github.com/cto-externe/lmdm/internal/auth"
)

type updateJSON struct {
	PackageName      string    `json:"package_name"`
	CurrentVersion   string    `json:"current_version"`
	AvailableVersion string    `json:"available_version"`
	IsSecurity       bool      `json:"is_security"`
	Source           string    `json:"source"`
	DetectedAt       time.Time `json:"detected_at"`
}

func (d *Deps) handleListUpdates(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	updates, reboot, err := d.Devices.ListUpdates(r.Context(), d.TenantID, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]updateJSON, 0, len(updates))
	for _, u := range updates {
		out = append(out, updateJSON{
			PackageName: u.PackageName, CurrentVersion: u.CurrentVersion,
			AvailableVersion: u.AvailableVersion, IsSecurity: u.IsSecurity,
			Source: u.Source, DetectedAt: u.DetectedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data":            out,
		"total":           len(out),
		"reboot_required": reboot,
	})
}

type applyUpdatesRequest struct {
	SecurityOnly    bool     `json:"security_only"`
	IncludePackages []string `json:"include_packages"`
	ExcludePackages []string `json:"exclude_packages"`
}

func (d *Deps) handleApplyUpdates(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := parseUUID(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}

	var req applyUpdatesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Empty body = apply all updates.
		req = applyUpdatesRequest{}
	}

	// Build an ApplyPatchesCommand and publish via NATS.
	cmd := &lmdmv1.CommandEnvelope{
		CommandId: "patch-" + deviceID.String() + "-" + uuid.NewString()[:8],
		Command: &lmdmv1.CommandEnvelope_ApplyPatches{
			ApplyPatches: &lmdmv1.ApplyPatchesCommand{
				Filter: &lmdmv1.PatchFilter{
					SecurityOnly:    req.SecurityOnly,
					IncludePackages: req.IncludePackages,
					ExcludePackages: req.ExcludePackages,
				},
			},
		},
	}
	data, err := proto.Marshal(cmd)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "marshal: "+err.Error())
		return
	}
	subject := "fleet.agent." + deviceID.String() + ".commands"
	if d.NATS != nil {
		if err := d.NATS.Publish(subject, data); err != nil {
			writeError(w, http.StatusInternalServerError, "nats: "+err.Error())
			return
		}
		_ = d.NATS.Flush()
	}
	if pr := auth.PrincipalFrom(r.Context()); pr != nil && d.Audit != nil {
		_ = d.Audit.Write(r.Context(), audit.Event{
			TenantID:     d.TenantID,
			Actor:        audit.ActorUser(pr.UserID),
			Action:       audit.ActionDeviceUpdatesApplied,
			ResourceType: "device",
			ResourceID:   deviceID.String(),
			SourceIP:     clientIP(r),
			Details: map[string]any{
				"security_only":  req.SecurityOnly,
				"packages_count": len(req.IncludePackages),
			},
		})
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"message": "patch apply command sent",
		"device":  deviceID,
	})
}
