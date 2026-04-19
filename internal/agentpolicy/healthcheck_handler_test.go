// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentpolicy

import (
	"context"
	"testing"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/agenthealthcheck"
)

// fakeHCRunner is a canned HealthCheckRunner. It returns f.user for Run (unless
// the input slice is empty, in which case it returns nil), and f.builtin for
// RunBuiltins.
type fakeHCRunner struct {
	user    []agenthealthcheck.HealthCheckResult
	builtin []agenthealthcheck.HealthCheckResult
}

func (f *fakeHCRunner) Run(_ context.Context, checks []*lmdmv1.HealthCheckDefinition) []agenthealthcheck.HealthCheckResult {
	if len(checks) == 0 {
		return nil
	}
	return f.user
}

func (f *fakeHCRunner) RunBuiltins(_ context.Context) []agenthealthcheck.HealthCheckResult {
	return f.builtin
}

func fourBuiltinsAllPass() []agenthealthcheck.HealthCheckResult {
	return []agenthealthcheck.HealthCheckResult{
		{Name: "system.nats_reachable", Passed: true, Detail: "ack ok"},
		{Name: "system.agent_service_active", Passed: true, Detail: "active"},
		{Name: "system.networking", Passed: true, Detail: "up"},
		{Name: "system.ssh", Passed: true, Detail: "listening"},
	}
}

func TestHealthCheckHandler_Handle_AllPassed_Success(t *testing.T) {
	pub := &fakePublisher{}
	runner := &fakeHCRunner{
		user: []agenthealthcheck.HealthCheckResult{
			{Name: "user.http", Passed: true, Detail: "200 OK"},
			{Name: "user.tcp", Passed: true, Detail: "connected"},
		},
		builtin: fourBuiltinsAllPass(),
	}
	h := NewHealthCheckHandler(pub, runner, "dev-1")
	cmd := &lmdmv1.RunHealthCheckCommand{
		Checks: []*lmdmv1.HealthCheckDefinition{
			{Name: "user.http"}, {Name: "user.tcp"},
		},
	}
	h.Handle(context.Background(), "cmd-1", cmd)

	subj, res := pub.last()
	if subj != "fleet.agent.dev-1.command-result" {
		t.Errorf("wrong subject: %q", subj)
	}
	if res == nil {
		t.Fatal("no CommandResult published")
	}
	if !res.Success {
		t.Errorf("expected Success=true, got %+v", res)
	}
	if res.Error != "" {
		t.Errorf("expected empty Error, got %q", res.Error)
	}
	if got := len(res.HealthChecks); got != 6 {
		t.Fatalf("expected 6 health checks, got %d", got)
	}
	// Order: user first, builtins after.
	wantOrder := []string{"user.http", "user.tcp", "system.nats_reachable", "system.agent_service_active", "system.networking", "system.ssh"}
	for i, want := range wantOrder {
		if got := res.HealthChecks[i].GetName(); got != want {
			t.Errorf("HealthChecks[%d].Name = %q, want %q", i, got, want)
		}
	}
	if res.GetCommandId() != "cmd-1" {
		t.Errorf("command_id not echoed: %q", res.GetCommandId())
	}
	if res.GetDeviceId().GetId() != "dev-1" {
		t.Errorf("device_id wrong: %q", res.GetDeviceId().GetId())
	}
}

func TestHealthCheckHandler_Handle_OneFailed_SuccessFalse(t *testing.T) {
	pub := &fakePublisher{}
	runner := &fakeHCRunner{
		user: []agenthealthcheck.HealthCheckResult{
			{Name: "user.http", Passed: true, Detail: "200 OK"},
			{Name: "user.tcp", Passed: false, Detail: "connection refused"},
		},
		builtin: fourBuiltinsAllPass(),
	}
	h := NewHealthCheckHandler(pub, runner, "dev-1")
	cmd := &lmdmv1.RunHealthCheckCommand{
		Checks: []*lmdmv1.HealthCheckDefinition{
			{Name: "user.http"}, {Name: "user.tcp"},
		},
	}
	h.Handle(context.Background(), "cmd-2", cmd)

	_, res := pub.last()
	if res == nil {
		t.Fatal("no CommandResult published")
	}
	if res.Success {
		t.Errorf("expected Success=false, got true")
	}
	if res.Error == "" {
		t.Errorf("expected non-empty Error on failed check")
	}
	if got := len(res.HealthChecks); got != 6 {
		t.Fatalf("expected 6 health checks, got %d", got)
	}
}

func TestHealthCheckHandler_Handle_EmptyUserChecks_RunsOnlyBuiltins(t *testing.T) {
	pub := &fakePublisher{}
	runner := &fakeHCRunner{
		user:    []agenthealthcheck.HealthCheckResult{{Name: "should-not-appear", Passed: true}},
		builtin: fourBuiltinsAllPass(),
	}
	h := NewHealthCheckHandler(pub, runner, "dev-1")
	h.Handle(context.Background(), "cmd-3", &lmdmv1.RunHealthCheckCommand{})

	_, res := pub.last()
	if res == nil {
		t.Fatal("no CommandResult published")
	}
	if !res.Success {
		t.Errorf("expected Success=true, got %+v", res)
	}
	if got := len(res.HealthChecks); got != 4 {
		t.Fatalf("expected 4 builtin results, got %d", got)
	}
	for i, want := range []string{"system.nats_reachable", "system.agent_service_active", "system.networking", "system.ssh"} {
		if got := res.HealthChecks[i].GetName(); got != want {
			t.Errorf("HealthChecks[%d].Name = %q, want %q", i, got, want)
		}
	}
}

// emptyRunner returns no results for either method. The handler should still
// publish a CommandResult with Success=true and an empty HealthChecks slice.
type emptyRunner struct{}

func (emptyRunner) Run(_ context.Context, _ []*lmdmv1.HealthCheckDefinition) []agenthealthcheck.HealthCheckResult {
	return nil
}

func (emptyRunner) RunBuiltins(_ context.Context) []agenthealthcheck.HealthCheckResult {
	return nil
}

func TestHealthCheckHandler_Handle_EmptyRunner_StillPublishes(t *testing.T) {
	pub := &fakePublisher{}
	h := NewHealthCheckHandler(pub, emptyRunner{}, "dev-1")
	h.Handle(context.Background(), "cmd-4", &lmdmv1.RunHealthCheckCommand{})

	subj, res := pub.last()
	if subj != "fleet.agent.dev-1.command-result" {
		t.Errorf("wrong subject: %q", subj)
	}
	if res == nil {
		t.Fatal("no CommandResult published")
	}
	if !res.Success {
		t.Errorf("expected Success=true with zero checks, got %+v", res)
	}
	if len(res.HealthChecks) != 0 {
		t.Errorf("expected no health checks, got %d", len(res.HealthChecks))
	}
}
