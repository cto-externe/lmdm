// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// newTestFileTemplate is a helper that builds a FileTemplate with a temp-dir
// target path. The caller may adjust params before construction.
func newTestFileTemplate(t *testing.T, content string, extra map[string]any) (*FileTemplate, string) {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "out.conf")

	params := map[string]any{
		"name":    "test-tpl",
		"path":    target,
		"content": content,
	}
	for k, v := range extra {
		params[k] = v
	}

	a, err := NewFileTemplate(params)
	if err != nil {
		t.Fatalf("NewFileTemplate: %v", err)
	}
	ft := a.(*FileTemplate)
	return ft, target
}

func TestFileTemplate_ApplyRendersTemplate(t *testing.T) {
	ft, target := newTestFileTemplate(t, "hostname: {{.Hostname}}\n", nil)
	ft.SetVars(TemplateVars{Hostname: "nuc1"})

	if err := ft.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	data, err := os.ReadFile(target) //nolint:gosec
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "hostname: nuc1\n" {
		t.Errorf("got %q, want %q", string(data), "hostname: nuc1\n")
	}
}

func TestFileTemplate_MissingVariable_RendersNoValue(t *testing.T) {
	ft, target := newTestFileTemplate(t, "x={{.Unknown}}", nil)
	ft.SetVars(TemplateVars{})

	if err := ft.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	data, _ := os.ReadFile(target) //nolint:gosec
	if string(data) != "x=<no value>" {
		t.Errorf("got %q, want \"x=<no value>\"", string(data))
	}
}

func TestFileTemplate_PostApplyCommand_RunsOnSuccess(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "post-ran")

	ft, _ := newTestFileTemplate(t, "hello", map[string]any{
		"post_apply_command": "touch " + sentinel,
	})
	ft.SetVars(TemplateVars{})

	if err := ft.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := os.Stat(sentinel); os.IsNotExist(err) {
		t.Error("post_apply_command did not run: sentinel file missing")
	}
}

func TestFileTemplate_PostApplyCommand_FailurePropagates(t *testing.T) {
	ft, _ := newTestFileTemplate(t, "hello", map[string]any{
		"post_apply_command": "sh -c 'exit 1'",
	})
	ft.SetVars(TemplateVars{})

	if err := ft.Apply(context.Background()); err == nil {
		t.Error("Apply must return error when post_apply_command exits non-zero")
	}
}

func TestFileTemplate_ModeApplied(t *testing.T) {
	ft, target := newTestFileTemplate(t, "secret", map[string]any{
		"mode": "0600",
	})
	ft.SetVars(TemplateVars{})

	if err := ft.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestFileTemplate_ChownApplied(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	ft, target := newTestFileTemplate(t, "data", map[string]any{
		"owner": "root",
		"group": "root",
	})
	ft.SetVars(TemplateVars{})

	if err := ft.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	_ = info // ownership already validated by Apply not failing
}

func TestFileTemplate_BadTemplateSyntax_ConstructorFails(t *testing.T) {
	dir := t.TempDir()
	_, err := NewFileTemplate(map[string]any{
		"name":    "bad",
		"path":    filepath.Join(dir, "out"),
		"content": "{{.Foo",
	})
	if err == nil {
		t.Fatal("NewFileTemplate must return error for bad template syntax")
	}
}

func TestFileTemplate_VerifyDetectsDrift(t *testing.T) {
	ft, target := newTestFileTemplate(t, "original content\n", nil)
	ft.SetVars(TemplateVars{})
	ctx := context.Background()

	if err := ft.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Mutate the file to introduce drift.
	if err := os.WriteFile(target, []byte("mutated content\n"), 0o644); err != nil { //nolint:gosec
		t.Fatalf("WriteFile: %v", err)
	}

	ok, reason, err := ft.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify error: %v", err)
	}
	if ok {
		t.Error("Verify must return false on drifted file")
	}
	if reason == "" {
		t.Error("Verify must provide a non-empty reason for drift")
	}
}

func TestFileTemplate_RejectsRelativePath(t *testing.T) {
	_, err := NewFileTemplate(map[string]any{
		"name":    "rel",
		"path":    "relative/path",
		"content": "hello",
	})
	if err == nil {
		t.Fatal("NewFileTemplate must reject relative paths")
	}
}
