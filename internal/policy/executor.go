// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"context"
	"fmt"
	"sort"
)

// TypedAction pairs an Action with its type name (from the YAML `type:` field).
type TypedAction struct {
	Type   string
	Action Action
}

// ExecutionResult is the outcome of applying a set of actions.
type ExecutionResult struct {
	AllCompliant bool
	Error        string // non-empty if Apply failed
	Actions      []ActionResult
}

// ActionResult is the per-action outcome.
type ActionResult struct {
	Type      string
	Compliant bool
	Reason    string
	Error     string
}

// typeOrder defines the implicit application order. Lower = first.
var typeOrder = map[string]int{
	"package_ensure": 0,
	"service_ensure": 1,
	"file_content":   2,
	"sysctl":         3,
}

// Execute runs actions in implicit type order: snapshot all → apply in
// order → verify all. If any Apply fails, execution stops.
func Execute(ctx context.Context, actions []TypedAction, snapRoot, deploymentID string) ExecutionResult {
	sorted := make([]TypedAction, len(actions))
	copy(sorted, actions)
	sort.SliceStable(sorted, func(i, j int) bool {
		oi, oki := typeOrder[sorted[i].Type]
		oj, okj := typeOrder[sorted[j].Type]
		if !oki {
			oi = 999
		}
		if !okj {
			oj = 999
		}
		if oi != oj {
			return oi < oj
		}
		return sorted[i].Type < sorted[j].Type
	})

	snapDir, err := CreateSnapshotDir(snapRoot, deploymentID)
	if err != nil {
		return ExecutionResult{Error: fmt.Sprintf("snapshot dir: %v", err)}
	}

	// Phase 1: Snapshot all.
	for _, ta := range sorted {
		if err := ta.Action.Snapshot(ctx, snapDir); err != nil {
			return ExecutionResult{Error: fmt.Sprintf("snapshot %s: %v", ta.Type, err)}
		}
	}

	// Phase 2: Apply in order. Stop on first failure.
	applied := make([]TypedAction, 0, len(sorted))
	for _, ta := range sorted {
		if err := ta.Action.Apply(ctx); err != nil {
			results := verifyApplied(ctx, applied)
			results = append(results, ActionResult{
				Type: ta.Type, Error: err.Error(),
			})
			return ExecutionResult{
				AllCompliant: false,
				Error:        fmt.Sprintf("apply %s: %v", ta.Type, err),
				Actions:      results,
			}
		}
		applied = append(applied, ta)
	}

	// Phase 3: Verify all applied.
	results := verifyApplied(ctx, applied)
	allOK := true
	for _, r := range results {
		if !r.Compliant {
			allOK = false
		}
	}
	return ExecutionResult{AllCompliant: allOK, Actions: results}
}

func verifyApplied(ctx context.Context, applied []TypedAction) []ActionResult {
	results := make([]ActionResult, 0, len(applied))
	for _, ta := range applied {
		ok, reason, err := ta.Action.Verify(ctx)
		r := ActionResult{Type: ta.Type, Compliant: ok, Reason: reason}
		if err != nil {
			r.Error = err.Error()
		}
		results = append(results, r)
	}
	return results
}
