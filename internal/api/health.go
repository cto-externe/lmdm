// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/cto-externe/lmdm/internal/devices"
)

// handleGetHealth returns the latest HealthSnapshot for the device as JSON.
// Permission: PermInventoryRead (health is treated as an extension of inventory).
//
// Response body:
//
//	{
//	  "observed_at": "2026-04-18T10:00:00Z",
//	  "snapshot": {
//	    "deviceId": {"id": "..."},
//	    "timestamp": "...",
//	    "disks": [...],
//	    "battery": {...},
//	    "temperatures": {...},
//	    "firmwareUpdates": [...],
//	    "overallScore": "HEALTH_SCORE_GREEN"
//	  }
//	}
//
// The snapshot is the protojson-encoded HealthSnapshot stored verbatim by the
// healthingester. Returns 404 when the device has no snapshot yet.
func (d *Deps) handleGetHealth(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	if d.Devices == nil {
		writeError(w, http.StatusInternalServerError, "devices repository not available")
		return
	}
	payload, ts, err := d.Devices.FindLatestHealth(r.Context(), d.TenantID, id)
	if errors.Is(err, devices.ErrNoHealthSnapshot) {
		writeError(w, http.StatusNotFound, "no health snapshot")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"observed_at": ts.UTC().Format(time.RFC3339),
		"snapshot":    json.RawMessage(payload),
	})
}
