// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentstatus

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// ToHeartbeat builds the wire Heartbeat message from a Snapshot. The
// device_id is supplied by the agent runner from the persisted identity.
func ToHeartbeat(s *Snapshot, deviceID, agentVersion string) *lmdmv1.Heartbeat {
	return &lmdmv1.Heartbeat{
		DeviceId:      &lmdmv1.DeviceID{Id: deviceID},
		Timestamp:     timestamppb.New(time.Now().UTC()),
		UptimeSeconds: s.UptimeSeconds,
		LoadAvg_1M:    s.LoadAvg1m,
		LoadAvg_5M:    s.LoadAvg5m,
		LoadAvg_15M:   s.LoadAvg15m,
		RamUsedMb:     s.RAMUsedMB,
		RamTotalMb:    s.RAMTotalMB,
		DiskUsedGb:    s.DiskUsedGB,
		DiskTotalGb:   s.DiskTotalGB,
		DiskUsedPct:   s.DiskUsedPct,
		AgentVersion:  agentVersion,
	}
}
