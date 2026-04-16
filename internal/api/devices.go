// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/cto-externe/lmdm/internal/devices"
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
