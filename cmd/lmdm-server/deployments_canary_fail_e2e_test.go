// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// TestIntegrationDeploymentCanaryFails_RestUntouched is the negative twin of
// TestIntegrationDeploymentHappyPath: when the canary device reports a
// failure, the engine must short-circuit the rollout entirely. Concretely:
//
//  1. POST /deployments → engine pushes the canary command to the canary
//     subject.
//  2. Simulated canary agent publishes a failed CommandResult (success=false,
//     snapshot_id set so the ingester maps it to RolledBack).
//  3. Deployment must transition to "rolled_back" within the polling window
//     and carry a reason that mentions the agent's error message.
//  4. CRITICAL: no command may be published to the rollout devices. We
//     subscribe to dev-a / dev-b BEFORE creating the deployment and assert
//     NextMsg times out after 3s on each.
//  5. GET /deployments/{id} reports exactly one result row (the canary,
//     marked is_canary, status rolled_back or failed depending on the engine
//     mapping). No result row must exist for the rollout devices.
func TestIntegrationDeploymentCanaryFails_RestUntouched(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	deps, signer, tenantID, baseURL, bus, cleanup := setupDeploymentE2EStack(t, ctx)
	defer cleanup()

	// Seed the same fixture set as the happy path: profile + 3 devices + 1
	// user (FK target for created_by_user_id).
	userID := seedUserForDeploymentE2E(t, ctx, deps.Pool, tenantID)
	canary := seedDeviceForDeploymentE2E(t, ctx, deps.Pool, tenantID, "canary-host")
	devA := seedDeviceForDeploymentE2E(t, ctx, deps.Pool, tenantID, "device-a")
	devB := seedDeviceForDeploymentE2E(t, ctx, deps.Pool, tenantID, "device-b")
	profileID := seedProfileForDeploymentE2E(t, ctx, deps.Pool, tenantID, "e2e-profile")

	bearer := mintAccessTokenForUser(t, signer, userID, tenantID)

	// Subscribe to all 3 device command subjects BEFORE the POST so we don't
	// race the synchronous canary push, AND so we can later assert that no
	// rollout commands were ever published to dev-a / dev-b.
	nc := bus.NC()
	canarySub := mustSubscribeCommands(t, nc, canary)
	defer func() { _ = canarySub.Unsubscribe() }()
	devASub := mustSubscribeCommands(t, nc, devA)
	defer func() { _ = devASub.Unsubscribe() }()
	devBSub := mustSubscribeCommands(t, nc, devB)
	defer func() { _ = devBSub.Unsubscribe() }()

	// 1. Create deployment in manual validation mode (matches happy path so
	//    we exercise the same handler code path).
	body := map[string]any{
		"profile_id":        profileID.String(),
		"canary_device_id":  canary.String(),
		"target_device_ids": []string{canary.String(), devA.String(), devB.String()},
		"validation_mode":   "manual",
	}
	resp := authedPost(t, baseURL+"/api/v1/deployments", bearer,
		"application/json", string(marshalJSONForE2E(t, body)))
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("create deployment got %d: %s", resp.StatusCode, b)
	}
	var created struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	// 2. Read the canary's ApplyProfile command.
	canaryCmd := readCommandWithin(t, canarySub, 5*time.Second)
	if canaryCmd == nil {
		t.Fatal("canary did not receive ApplyProfile command")
	}

	// 3. Publish a failed CommandResult on the canary's command-result
	//    subject. We pass a non-empty snapshot_id (the deployment ID) so the
	//    ingester's heuristic maps it to RolledBack, which in turn lands as
	//    Result.Status = ResultRolledBack in the per-device row.
	publishDeploymentResult(t, ctx, bus, canary, canaryCmd.GetCommandId(), created.ID, false, "disk full")

	// 4. Engine must transition straight to rolled_back. The intermediate
	//    canary_failed status carries the "canary failed: disk full" reason
	//    which UpdateStatus preserves on the second status transition (empty
	//    new reason → keep the existing one).
	waitForDeploymentStatus(t, baseURL, bearer, created.ID, "rolled_back", 10*time.Second)

	// 5. CRITICAL ASSERTION: no command must reach dev-a or dev-b. A 3-second
	//    timeout is comfortably longer than the engine's synchronous push
	//    path; if either NextMsg succeeds, the short-circuit is broken.
	if msg, err := devASub.NextMsg(3 * time.Second); err == nil {
		n := min(32, len(msg.Data))
		t.Fatalf("dev-a unexpectedly received a command (first %d bytes: %x)", n, msg.Data[:n])
	} else if !errors.Is(err, nats.ErrTimeout) {
		t.Fatalf("dev-a subscription error: %v", err)
	}
	if msg, err := devBSub.NextMsg(3 * time.Second); err == nil {
		n := min(32, len(msg.Data))
		t.Fatalf("dev-b unexpectedly received a command (first %d bytes: %x)", n, msg.Data[:n])
	} else if !errors.Is(err, nats.ErrTimeout) {
		t.Fatalf("dev-b subscription error: %v", err)
	}

	// 6. Final state assertions on GET /deployments/{id}: status rolled_back,
	//    reason mentions the agent error, exactly 1 result row (the canary).
	resp2 := authedGet(t, baseURL+"/api/v1/deployments/"+created.ID, bearer)
	var detail struct {
		Status  string `json:"status"`
		Reason  string `json:"reason"`
		Results []struct {
			DeviceID string `json:"device_id"`
			Status   string `json:"status"`
			IsCanary bool   `json:"is_canary"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&detail); err != nil {
		_ = resp2.Body.Close()
		t.Fatal(err)
	}
	_ = resp2.Body.Close()

	if detail.Status != "rolled_back" {
		t.Errorf("final status: got %s, want rolled_back", detail.Status)
	}
	if !strings.Contains(detail.Reason, "disk full") {
		t.Errorf("final reason: got %q, want substring %q", detail.Reason, "disk full")
	}
	if len(detail.Results) != 1 {
		t.Fatalf("expected exactly 1 result (canary only), got %d: %+v", len(detail.Results), detail.Results)
	}
	r := detail.Results[0]
	if r.DeviceID != canary.String() {
		t.Errorf("expected canary result, got device %s", r.DeviceID)
	}
	if !r.IsCanary {
		t.Error("result should be marked is_canary=true")
	}
	// Engine maps !success+snapshot_id-set to ResultRolledBack, but stay
	// flexible: ResultFailed is also a legitimate per-device terminal state
	// for a canary that errored out.
	if r.Status != "rolled_back" && r.Status != "failed" {
		t.Errorf("canary result status: got %s, want rolled_back or failed", r.Status)
	}
}
