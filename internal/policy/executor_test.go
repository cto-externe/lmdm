// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"context"
	"testing"
)

// stubAction records calls for testing.
type stubAction struct {
	typeName     string
	snapshotted  bool
	applied      bool
	verified     bool
	applyErr     error
	verifyResult bool
}

func (s *stubAction) Validate() error { return nil }
func (s *stubAction) Snapshot(_ context.Context, _ string) error {
	s.snapshotted = true
	return nil
}
func (s *stubAction) Apply(_ context.Context) error {
	s.applied = true
	return s.applyErr
}
func (s *stubAction) Verify(_ context.Context) (bool, string, error) {
	s.verified = true
	return s.verifyResult, "", nil
}

func TestExecutorOrdersActionsByType(t *testing.T) {
	// Create actions out of order. Executor must apply in:
	// package_ensure → service_ensure → file_content → sysctl
	sysctl := &stubAction{typeName: "sysctl", verifyResult: true}
	pkg := &stubAction{typeName: "package_ensure", verifyResult: true}
	svc := &stubAction{typeName: "service_ensure", verifyResult: true}
	file := &stubAction{typeName: "file_content", verifyResult: true}

	actions := []TypedAction{
		{Type: "sysctl", Action: sysctl},
		{Type: "package_ensure", Action: pkg},
		{Type: "file_content", Action: file},
		{Type: "service_ensure", Action: svc},
	}

	snapRoot := t.TempDir()
	result := Execute(context.Background(), actions, snapRoot, "test-deploy")

	if !result.AllCompliant {
		t.Errorf("expected all compliant, got: %+v", result)
	}
	for _, a := range []*stubAction{pkg, svc, file, sysctl} {
		if !a.snapshotted || !a.applied || !a.verified {
			t.Errorf("action %s: snap=%v apply=%v verify=%v",
				a.typeName, a.snapshotted, a.applied, a.verified)
		}
	}
}

func TestExecutorStopsOnApplyError(t *testing.T) {
	failing := &stubAction{typeName: "package_ensure", applyErr: context.DeadlineExceeded}
	skipped := &stubAction{typeName: "service_ensure", verifyResult: true}

	actions := []TypedAction{
		{Type: "package_ensure", Action: failing},
		{Type: "service_ensure", Action: skipped},
	}

	result := Execute(context.Background(), actions, t.TempDir(), "test-fail")

	if result.AllCompliant {
		t.Error("must not be compliant on apply failure")
	}
	if result.Error == "" {
		t.Error("error must be set")
	}
	if skipped.applied {
		t.Error("subsequent actions must not be applied after a failure")
	}
}
