// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package i18n

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestT_ReturnsTranslation(t *testing.T) {
	if err := Load(); err != nil {
		t.Fatal(err)
	}
	got := T("fr", "dashboard.title")
	if got != "Tableau de bord" {
		t.Errorf("T=%q, want %q", got, "Tableau de bord")
	}
}

func TestT_UnknownKey_ReturnsKey(t *testing.T) {
	if err := Load(); err != nil {
		t.Fatal(err)
	}
	got := T("fr", "no.such.key")
	if got != "no.such.key" {
		t.Errorf("unknown key should echo key, got %q", got)
	}
}

func TestLocaleFromRequest_Cookie(t *testing.T) {
	if err := Load(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	// Use an unknown code — since only fr is loaded, cookie should fall through
	r.AddCookie(&http.Cookie{Name: "lmdm_locale", Value: "fr"})
	if got := LocaleFromRequest(r); got != "fr" {
		t.Errorf("cookie locale = %q", got)
	}
}

func TestLocaleFromRequest_DefaultFR(t *testing.T) {
	if err := Load(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	if got := LocaleFromRequest(r); got != "fr" {
		t.Errorf("default = %q, want fr", got)
	}
}

func TestLocaleFromRequest_UnknownCookie_FallsBackToDefault(t *testing.T) {
	if err := Load(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "lmdm_locale", Value: "de"})
	if got := LocaleFromRequest(r); got != "fr" {
		t.Errorf("unknown locale cookie = %q, want fr", got)
	}
}
