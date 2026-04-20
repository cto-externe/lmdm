// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/cto-externe/lmdm/internal/audit"
	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/revocation"
)

// deviceJSON is the API representation of a device.
type deviceJSON struct {
	ID           uuid.UUID  `json:"id"`
	Type         string     `json:"type"`
	Hostname     string     `json:"hostname"`
	SerialNumber *string    `json:"serial_number,omitempty"`
	Manufacturer *string    `json:"manufacturer,omitempty"`
	Model        *string    `json:"model,omitempty"`
	Status       string     `json:"status"`
	LastSeen     *time.Time `json:"last_seen,omitempty"`
	AgentVersion *string    `json:"agent_version,omitempty"`
	EnrolledAt   time.Time  `json:"enrolled_at"`
}

func toDeviceJSON(d *devices.Device) deviceJSON {
	return deviceJSON{
		ID: d.ID, Type: string(d.Type), Hostname: d.Hostname,
		SerialNumber: d.SerialNumber, Manufacturer: d.Manufacturer, Model: d.Model,
		Status: string(d.Status), LastSeen: d.LastSeen,
		AgentVersion: d.AgentVersion, EnrolledAt: d.EnrolledAt,
	}
}

func (d *Deps) handleListDevices(w http.ResponseWriter, r *http.Request) {
	if d.Devices == nil {
		writeError(w, http.StatusInternalServerError, "devices repository not available")
		return
	}
	filter := devices.ListFilter{
		Status:   r.URL.Query().Get("status"),
		Type:     r.URL.Query().Get("type"),
		Hostname: r.URL.Query().Get("hostname"),
	}
	list, total, err := d.Devices.ListDevices(r.Context(), d.TenantID, filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]deviceJSON, 0, len(list))
	for i := range list {
		out = append(out, toDeviceJSON(&list[i]))
	}
	writeJSON(w, http.StatusOK, listResponse{Data: out, Total: total})
}

func (d *Deps) handleGetDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	if d.Devices == nil {
		writeError(w, http.StatusInternalServerError, "devices repository not available")
		return
	}
	dev, err := d.Devices.FindByID(r.Context(), d.TenantID, id)
	if err != nil {
		if errors.Is(err, devices.ErrNotFound) {
			writeError(w, http.StatusNotFound, "device not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	dj := toDeviceJSON(dev)
	writeJSON(w, http.StatusOK, map[string]any{"data": dj})
}

// revokeDeviceReq is the optional JSON body for POST /devices/{id}/revoke.
type revokeDeviceReq struct {
	Reason string `json:"reason,omitempty"`
}

// handleRevokeDevice revokes the currently issued agent certificate for a
// device, broadcasts the serial on NATS so every server node invalidates its
// cache, and records an audit event. Admin-only — see PermDevicesRevoke.
// Idempotent: a second call on an already-revoked serial returns 204.
func (d *Deps) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFrom(r.Context())
	if p == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id, ok := parseUUID(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	if d.Devices == nil {
		writeError(w, http.StatusInternalServerError, "devices repository not available")
		return
	}
	if d.Revocation == nil {
		writeError(w, http.StatusInternalServerError, "revocation repository not available")
		return
	}

	var req revokeDeviceReq
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req) // body optional
	}

	// Look up the current cert serial for this device.
	serial, err := d.Devices.FindCurrentCertSerial(r.Context(), d.TenantID, id)
	if errors.Is(err, devices.ErrNotFound) {
		writeError(w, http.StatusNotFound, "device not found or has no issued certificate")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Insert the revocation row.
	if err := d.Revocation.Revoke(r.Context(), d.TenantID, serial, &id, &p.UserID, req.Reason); err != nil {
		if errors.Is(err, revocation.ErrAlreadyRevoked) {
			// Idempotent: consider this a success.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Broadcast so every server node invalidates its cache immediately.
	if d.NATS != nil {
		_ = revocation.Publish(d.NATS, serial)
	}

	// Audit.
	if d.Audit != nil {
		_ = d.Audit.Write(r.Context(), audit.Event{
			TenantID:     d.TenantID,
			Actor:        audit.ActorUser(p.UserID),
			Action:       audit.ActionDeviceCertRevoked,
			ResourceType: "device",
			ResourceID:   id.String(),
			SourceIP:     clientIP(r),
			Details:      map[string]any{"serial": serial, "reason": req.Reason},
		})
	}

	w.WriteHeader(http.StatusNoContent)
}
