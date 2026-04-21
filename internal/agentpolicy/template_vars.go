// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentpolicy

import (
	"os"

	"github.com/cto-externe/lmdm/internal/policy"
)

// InjectTemplateVars walks actions and sets TemplateVars on any
// *policy.FileTemplate. For MVP, SiteID and GroupIDs are empty strings /
// nil — the agent does not yet track its site or group memberships.
// Hostname is resolved via os.Hostname(); on error, falls back to "unknown".
func InjectTemplateVars(actions []policy.TypedAction, deviceID, tenantID string) {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}
	vars := policy.TemplateVars{
		Hostname: hostname,
		DeviceID: deviceID,
		TenantID: tenantID,
		// SiteID and GroupIDs are not tracked by the agent in MVP.
	}
	for _, ta := range actions {
		if ft, ok := ta.Action.(*policy.FileTemplate); ok {
			ft.SetVars(vars)
		}
	}
}
