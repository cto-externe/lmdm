// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentpolicy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cto-externe/lmdm/internal/policy"
)

// newTestFileTemplateAction is a helper that builds a *policy.FileTemplate
// wrapped as policy.Action with a temp-dir target path.
func newTestFileTemplateAction(t *testing.T, content string) (policy.Action, string) {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "out.conf")
	params := map[string]any{
		"name":    "test-tpl",
		"path":    target,
		"content": content,
	}
	a, err := policy.NewFileTemplate(params)
	if err != nil {
		t.Fatalf("NewFileTemplate: %v", err)
	}
	return a, target
}

func TestInjectTemplateVars_SetsHostnameAndDeviceID(t *testing.T) {
	a, target := newTestFileTemplateAction(t, "host={{.Hostname}} dev={{.DeviceID}}")

	InjectTemplateVars([]policy.TypedAction{{Type: "file_template", Action: a}}, "device-42", "")

	if err := a.(*policy.FileTemplate).Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	data, err := os.ReadFile(target) //nolint:gosec
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	got := string(data)

	// Hostname must match os.Hostname() (or "unknown" on error).
	wantHostname, hErr := os.Hostname()
	if hErr != nil || wantHostname == "" {
		wantHostname = "unknown"
	}
	if !strings.Contains(got, "host="+wantHostname) {
		t.Errorf("expected host=%s in output, got %q", wantHostname, got)
	}
	if !strings.Contains(got, "dev=device-42") {
		t.Errorf("expected dev=device-42 in output, got %q", got)
	}
}

func TestInjectTemplateVars_IgnoresNonTemplateActions(t *testing.T) {
	// FileContent action — does not implement SetVars.
	dir := t.TempDir()
	fcAction, err := policy.NewFileContent(map[string]any{
		"path":    filepath.Join(dir, "fc.conf"),
		"content": "static",
	})
	if err != nil {
		t.Fatalf("NewFileContent: %v", err)
	}

	ftAction, target := newTestFileTemplateAction(t, "id={{.DeviceID}}")

	actions := []policy.TypedAction{
		{Type: "file_content", Action: fcAction},
		{Type: "file_template", Action: ftAction},
	}

	// Must not panic on the FileContent action.
	InjectTemplateVars(actions, "dev-99", "tenant-x")

	// FileTemplate should have received the vars.
	if err := ftAction.(*policy.FileTemplate).Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	data, _ := os.ReadFile(target) //nolint:gosec
	if !strings.Contains(string(data), "id=dev-99") {
		t.Errorf("expected id=dev-99 in output, got %q", string(data))
	}
}

func TestInjectTemplateVars_EmptyActionsNoPanic(t *testing.T) {
	// Must be a pure no-op and not panic.
	InjectTemplateVars([]policy.TypedAction{}, "dev-1", "")
	InjectTemplateVars(nil, "dev-1", "")
}

func TestInjectTemplateVars_UsesTenantIDFromCommand(t *testing.T) {
	a, target := newTestFileTemplateAction(t, "tenant={{.TenantID}} dev={{.DeviceID}}")

	InjectTemplateVars([]policy.TypedAction{{Type: "file_template", Action: a}}, "dev-1", "tenant-42")

	if err := a.(*policy.FileTemplate).Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	data, err := os.ReadFile(target) //nolint:gosec
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, "tenant=tenant-42") {
		t.Errorf("expected tenant=tenant-42 in output, got %q", got)
	}
	if !strings.Contains(got, "dev=dev-1") {
		t.Errorf("expected dev=dev-1 in output, got %q", got)
	}
}
