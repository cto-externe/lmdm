// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package handlers

import (
	"net/http"

	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/webui/csrf"
	"github.com/cto-externe/lmdm/internal/webui/i18n"
	"github.com/cto-externe/lmdm/internal/webui/templates"
)

// DashboardDeps holds the deps for the dashboard page (placeholder for now).
// Real stats widgets land in WebUI plan #3.
type DashboardDeps struct {
	CSRF *csrf.Middleware
}

// Handle renders the dashboard page.
func (d *DashboardDeps) Handle(w http.ResponseWriter, r *http.Request) {
	lang := i18n.LocaleFromRequest(r)
	p := auth.PrincipalFrom(r.Context())
	props := templates.LayoutProps{
		Lang:      lang,
		CSRFToken: d.CSRF.Issue(),
		Principal: p,
		PageTitle: i18n.T(lang, "dashboard.title"),
		ActiveNav: "dashboard",
	}
	_ = templates.Dashboard(props).Render(r.Context(), w)
}
