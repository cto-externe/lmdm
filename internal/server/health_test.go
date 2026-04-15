// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type okChecker struct{}

func (okChecker) Check(context.Context) error { return nil }

type failChecker struct{ msg string }

func (f failChecker) Check(context.Context) error { return errors.New(f.msg) }

func TestHealthHandlerAllGreen(t *testing.T) {
	h := NewHealthHandler(map[string]HealthChecker{
		"db":   okChecker{},
		"nats": okChecker{},
		"s3":   okChecker{},
	})
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q", body.Status)
	}
	if body.Checks["db"] != "ok" || body.Checks["nats"] != "ok" || body.Checks["s3"] != "ok" {
		t.Errorf("checks: %+v", body.Checks)
	}
}

func TestHealthHandlerOneFailure(t *testing.T) {
	h := NewHealthHandler(map[string]HealthChecker{
		"db":   okChecker{},
		"nats": failChecker{"nats down"},
	})
	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	var body struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Status != "degraded" {
		t.Errorf("status = %q", body.Status)
	}
	if body.Checks["nats"] == "ok" {
		t.Errorf("nats check should not be ok")
	}
}
