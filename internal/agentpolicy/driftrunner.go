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
	"github.com/cto-externe/lmdm/internal/policy"
)

// Publisher is the minimal publish interface for NATS. Satisfied by
// *nats.Conn and *agentbus.Bus.
type Publisher interface {
	Publish(subject string, data []byte) error
}

// DriftRunner periodically re-verifies all applied profiles and publishes
// a ComplianceReport. It reads the ProfileStore, parses each YAML into
// actions via the Registry, runs Verify() on each action, and reports the
// aggregate result.
type DriftRunner struct {
	pub      Publisher
	registry *policy.Registry
	store    *ProfileStore
	deviceID string
	interval time.Duration
}

// NewDriftRunner wires a DriftRunner.
func NewDriftRunner(pub Publisher, reg *policy.Registry, store *ProfileStore, deviceID string, interval time.Duration) *DriftRunner {
	return &DriftRunner{
		pub:      pub,
		registry: reg,
		store:    store,
		deviceID: deviceID,
		interval: interval,
	}
}

// Run loops until ctx is cancelled. Each tick re-verifies all applied
// profiles and publishes a ComplianceReport.
func (d *DriftRunner) Run(ctx context.Context) error {
	if ctx.Err() != nil {
		return nil
	}
	d.check(ctx)

	t := time.NewTicker(d.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			d.check(ctx)
		}
	}
}

func (d *DriftRunner) check(ctx context.Context) {
	profiles, err := d.store.List()
	if err != nil {
		slog.Warn("drift: list profiles", "err", err)
		return
	}

	allCompliant := true
	var totalChecks, passedChecks, failedChecks uint32

	for profileID, yamlContent := range profiles {
		_, actions, err := policy.ParseProfile(yamlContent, d.registry)
		if err != nil {
			slog.Warn("drift: parse profile", "id", profileID, "err", err)
			allCompliant = false
			failedChecks++
			totalChecks++
			continue
		}
		for _, ta := range actions {
			totalChecks++
			ok, reason, err := ta.Action.Verify(ctx)
			if err != nil {
				slog.Warn("drift: verify error", "type", ta.Type, "err", err)
				allCompliant = false
				failedChecks++
				continue
			}
			if !ok {
				slog.Info("drift: non-compliant", "type", ta.Type, "reason", reason)
				allCompliant = false
				failedChecks++
			} else {
				passedChecks++
			}
		}
	}

	status := lmdmv1.ComplianceStatus_COMPLIANCE_STATUS_COMPLIANT
	if !allCompliant {
		status = lmdmv1.ComplianceStatus_COMPLIANCE_STATUS_NON_COMPLIANT
	}

	report := &lmdmv1.ComplianceReport{
		DeviceId:      &lmdmv1.DeviceID{Id: d.deviceID},
		Timestamp:     timestamppb.New(time.Now().UTC()),
		OverallStatus: status,
		TotalChecks:   totalChecks,
		PassedChecks:  passedChecks,
		FailedChecks:  failedChecks,
	}
	data, err := proto.Marshal(report)
	if err != nil {
		slog.Error("drift: marshal report", "err", err)
		return
	}
	subject := "fleet.agent." + d.deviceID + ".compliance"
	if err := d.pub.Publish(subject, data); err != nil {
		slog.Error("drift: publish", "err", err)
	}
}
