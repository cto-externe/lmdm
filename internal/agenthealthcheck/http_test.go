// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenthealthcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

func TestCheckHTTP_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	res := checkHTTP(context.Background(), "h", &lmdmv1.HTTPGetCheck{Url: srv.URL, ExpectedStatus: 200}, 5)
	if !res.Passed {
		t.Fatalf("want passed: %s", res.Detail)
	}
}

func TestCheckHTTP_DefaultExpected200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	res := checkHTTP(context.Background(), "h", &lmdmv1.HTTPGetCheck{Url: srv.URL}, 5)
	if !res.Passed {
		t.Fatalf("want passed with default 200")
	}
}

func TestCheckHTTP_WrongStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	res := checkHTTP(context.Background(), "h", &lmdmv1.HTTPGetCheck{Url: srv.URL, ExpectedStatus: 200}, 5)
	if res.Passed {
		t.Fatalf("want failed on 500")
	}
	if !strings.Contains(res.Detail, "500") {
		t.Errorf("detail missing status: %s", res.Detail)
	}
}

func TestCheckHTTP_BadURL(t *testing.T) {
	res := checkHTTP(context.Background(), "h", &lmdmv1.HTTPGetCheck{Url: "://bad"}, 5)
	if res.Passed {
		t.Fatalf("want failed on bad url")
	}
}
