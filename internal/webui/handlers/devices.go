// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package handlers

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/cto-externe/lmdm/internal/auth"
	"github.com/cto-externe/lmdm/internal/devices"
	"github.com/cto-externe/lmdm/internal/webui/csrf"
	"github.com/cto-externe/lmdm/internal/webui/i18n"
	"github.com/cto-externe/lmdm/internal/webui/templates"
	tdevices "github.com/cto-externe/lmdm/internal/webui/templates/devices"
)

// DevicesDeps holds deps for the devices list page.
type DevicesDeps struct {
	Repo *devices.Repository
	CSRF *csrf.Middleware
}

// HandleList renders the full page (layout + filters + table fragment).
func (d *DevicesDeps) HandleList(w http.ResponseWriter, r *http.Request) {
	lang := i18n.LocaleFromRequest(r)
	p := auth.PrincipalFrom(r.Context())
	filters, table, err := d.fetch(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	props := tdevices.ListProps{
		Layout: templates.LayoutProps{
			Lang:      lang,
			CSRFToken: d.CSRF.Issue(),
			Principal: p,
			PageTitle: i18n.T(lang, "devices.title"),
			ActiveNav: "devices",
		},
		Filters: filters,
		Table:   table,
	}
	props.Table.Lang = lang
	_ = tdevices.List(props).Render(r.Context(), w)
}

// HandleFragment returns only the table fragment (HTMX polling + filter change).
func (d *DevicesDeps) HandleFragment(w http.ResponseWriter, r *http.Request) {
	_, table, err := d.fetch(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	table.Lang = i18n.LocaleFromRequest(r)
	_ = tdevices.Table(table).Render(r.Context(), w)
}

func (d *DevicesDeps) fetch(r *http.Request) (tdevices.FilterValues, tdevices.TableProps, error) {
	p := auth.PrincipalFrom(r.Context())
	filters := tdevices.FilterValues{
		Hostname: r.URL.Query().Get("hostname"),
		Status:   r.URL.Query().Get("status"),
		Type:     r.URL.Query().Get("type"),
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize <= 0 {
		pageSize = 25
	}
	if pageSize > 100 {
		pageSize = 100
	}
	lf := devices.ListFilter{
		Hostname: filters.Hostname,
		Status:   filters.Status,
		Type:     filters.Type,
		Offset:   (page - 1) * pageSize,
		Limit:    pageSize,
	}
	list, total, err := d.Repo.ListDevices(r.Context(), p.TenantID, lf)
	if err != nil {
		return filters, tdevices.TableProps{}, err
	}
	qp := url.Values{}
	if filters.Hostname != "" {
		qp.Set("hostname", filters.Hostname)
	}
	if filters.Status != "" {
		qp.Set("status", filters.Status)
	}
	if filters.Type != "" {
		qp.Set("type", filters.Type)
	}
	return filters, tdevices.TableProps{
		Devices:     list,
		Total:       total,
		Page:        page,
		PageSize:    pageSize,
		QueryParams: qp.Encode(),
	}, nil
}
