// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentpolicy

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/agenthealthcheck"
)

// HealthCheckRunner is the subset of agenthealthcheck.Runner that HealthCheckHandler depends on.
// Kept as an interface so tests can inject a canned runner without spinning up NATS / command infra.
type HealthCheckRunner interface {
	Run(ctx context.Context, checks []*lmdmv1.HealthCheckDefinition) []agenthealthcheck.HealthCheckResult
	RunBuiltins(ctx context.Context) []agenthealthcheck.HealthCheckResult
}

// HealthCheckHandler processes RunHealthCheckCommand messages: it runs the
// user-defined checks followed by the 4 built-in system checks, aggregates
// results, and publishes a CommandResult on the command-result subject.
type HealthCheckHandler struct {
	publisher ResultPublisher
	runner    HealthCheckRunner
	deviceID  string
}

// NewHealthCheckHandler wires a HealthCheckHandler.
func NewHealthCheckHandler(publisher ResultPublisher, runner HealthCheckRunner, deviceID string) *HealthCheckHandler {
	return &HealthCheckHandler{publisher: publisher, runner: runner, deviceID: deviceID}
}

// Handle processes a single RunHealthCheckCommand. Never returns an error —
// all failures surface as CommandResult{Success: false, Error: ...}.
// Success = every returned HealthCheckResult has Passed=true.
func (h *HealthCheckHandler) Handle(ctx context.Context, commandID string, cmd *lmdmv1.RunHealthCheckCommand) {
	start := time.Now()

	userResults := h.runner.Run(ctx, cmd.GetChecks())
	builtinResults := h.runner.RunBuiltins(ctx)

	all := make([]agenthealthcheck.HealthCheckResult, 0, len(userResults)+len(builtinResults))
	all = append(all, userResults...)
	all = append(all, builtinResults...)

	pbResults := make([]*lmdmv1.HealthCheckResult, 0, len(all))
	success := true
	for _, r := range all {
		pbResults = append(pbResults, &lmdmv1.HealthCheckResult{
			Name:   r.Name,
			Passed: r.Passed,
			Detail: r.Detail,
		})
		if !r.Passed {
			success = false
		}
	}

	result := &lmdmv1.CommandResult{
		CommandId:    commandID,
		DeviceId:     &lmdmv1.DeviceID{Id: h.deviceID},
		Timestamp:    timestamppb.Now(),
		Success:      success,
		HealthChecks: pbResults,
		DurationMs:   uint32(time.Since(start).Milliseconds()), //nolint:gosec // bounded
	}
	if !success {
		result.Error = "one or more health checks failed"
	}

	subject := "fleet.agent." + h.deviceID + ".command-result"
	data, err := proto.Marshal(result)
	if err != nil {
		slog.Error("agentpolicy: marshal HealthCheck CommandResult failed", "err", err)
		return
	}
	if err := h.publisher.Publish(subject, data); err != nil {
		slog.Warn("agentpolicy: publish HealthCheck CommandResult failed", "subject", subject, "err", err)
	}
}
