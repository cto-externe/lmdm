// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package api

import (
	"errors"
	"net/http"

	"github.com/cto-externe/lmdm/internal/devices"
)

func (d *Deps) handleGetInventory(w http.ResponseWriter, r *http.Request) {
	id, ok := parseUUID(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid device id")
		return
	}
	report, receivedAt, err := d.Devices.GetInventoryJSON(r.Context(), d.TenantID, id)
	if err != nil {
		if errors.Is(err, devices.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no inventory for this device")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data":        report,
		"received_at": receivedAt,
	})
}
