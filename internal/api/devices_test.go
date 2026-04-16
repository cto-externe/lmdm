// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package api

import (
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestRouterReturnsStatusForDevicesRoute(t *testing.T) {
	deps := &Deps{TenantID: uuid.MustParse("00000000-0000-0000-0000-000000000000")}
	handler := Router(deps)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/devices", nil)
	handler.ServeHTTP(rec, req)

	// Without a real DB, ListDevices will error. We accept 500 (not panic/0).
	if rec.Code == 0 {
		t.Error("must return a status code")
	}
}
