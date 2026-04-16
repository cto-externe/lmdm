// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package agentpatchrunner periodically detects available updates via the
// injected PatchManager and publishes a PatchReport on NATS.
package agentpatchrunner

import (
	"context"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/distro"
)

// Publisher is the minimal NATS publish surface.
type Publisher interface {
	Publish(subject string, data []byte) error
}

// Runner ticks at `interval`, calls PatchManager.DetectUpdates, marshals a
// PatchReport, and publishes it on `fleet.agent.{deviceID}.patches`.
type Runner struct {
	pub      Publisher
	pm       distro.PatchManager
	deviceID string
	interval time.Duration
}

// New wires a Runner.
func New(pub Publisher, pm distro.PatchManager, deviceID string, interval time.Duration) *Runner {
	return &Runner{pub: pub, pm: pm, deviceID: deviceID, interval: interval}
}

// Run loops until ctx is cancelled.
func (r *Runner) Run(ctx context.Context) error {
	if ctx.Err() != nil {
		return nil
	}
	r.detect(ctx)

	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			r.detect(ctx)
		}
	}
}

func (r *Runner) detect(ctx context.Context) {
	updates, reboot, err := r.pm.DetectUpdates(ctx)
	if err != nil {
		return // non-fatal; next tick will retry
	}

	protoUpdates := make([]*lmdmv1.AvailableUpdate, 0, len(updates))
	for _, u := range updates {
		protoUpdates = append(protoUpdates, &lmdmv1.AvailableUpdate{
			Name:             u.Name,
			CurrentVersion:   u.CurrentVersion,
			AvailableVersion: u.AvailableVersion,
			Security:         u.Security,
			Source:           u.Source,
		})
	}

	report := &lmdmv1.PatchReport{
		DeviceId:       &lmdmv1.DeviceID{Id: r.deviceID},
		Timestamp:      timestamppb.New(time.Now().UTC()),
		Updates:        protoUpdates,
		RebootRequired: reboot,
	}
	data, err := proto.Marshal(report)
	if err != nil {
		return
	}
	subject := "fleet.agent." + r.deviceID + ".patches"
	_ = r.pub.Publish(subject, data)
}
