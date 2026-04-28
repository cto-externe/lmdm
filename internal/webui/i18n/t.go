// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package i18n provides a minimal translation helper for WebUI templates.
// Strings are loaded at startup from embedded JSON files and looked up by key.
// Missing keys echo the key (so the site remains readable during development).
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

//go:embed locales/*.json
var localesFS embed.FS

var (
	mu    sync.RWMutex
	langs = map[string]map[string]string{}
)

// Load reads all locales/*.json at startup. Safe to call multiple times.
func Load() error {
	entries, err := localesFS.ReadDir("locales")
	if err != nil {
		return fmt.Errorf("i18n: read locales dir: %w", err)
	}
	mu.Lock()
	defer mu.Unlock()
	langs = map[string]map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if len(name) < 6 || name[len(name)-5:] != ".json" {
			continue
		}
		code := name[:len(name)-5]
		raw, err := localesFS.ReadFile("locales/" + name)
		if err != nil {
			return fmt.Errorf("i18n: read %s: %w", name, err)
		}
		var m map[string]string
		if err := json.Unmarshal(raw, &m); err != nil {
			return fmt.Errorf("i18n: parse %s: %w", name, err)
		}
		langs[code] = m
	}
	return nil
}

// T returns the translated string for key in lang. If lang or key is missing,
// returns the key itself (readable fallback).
func T(lang, key string) string {
	mu.RLock()
	defer mu.RUnlock()
	if m, ok := langs[lang]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	return key
}

// LocaleFromRequest returns the locale code to use. Precedence:
//  1. Cookie lmdm_locale (if a known locale)
//  2. Accept-Language header (first primary subtag we recognize)
//  3. "fr" (default)
func LocaleFromRequest(r *http.Request) string {
	if c, err := r.Cookie("lmdm_locale"); err == nil && isKnown(c.Value) {
		return c.Value
	}
	if h := r.Header.Get("Accept-Language"); h != "" {
		for i, c := 0, len(h); i+1 < c; i++ {
			if h[i] >= 'a' && h[i] <= 'z' && h[i+1] >= 'a' && h[i+1] <= 'z' {
				tag := h[i : i+2]
				if isKnown(tag) {
					return tag
				}
				break
			}
		}
	}
	return "fr"
}

func isKnown(code string) bool {
	mu.RLock()
	defer mu.RUnlock()
	_, ok := langs[code]
	return ok
}
