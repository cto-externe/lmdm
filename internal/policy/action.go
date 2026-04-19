// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package policy implements the profile action engine. Actions are the
// atomic units of system change that a profile prescribes. Each action type
// implements the Action interface; the Executor orchestrates them in a fixed
// order with snapshot-before-apply and verification-after-apply guarantees.
package policy

import "context"

// Action is the contract every policy primitive must satisfy.
//
//   - Validate checks that the action's parameters are well-formed before
//     any system state is touched.
//   - Snapshot saves the current state so Apply can be rolled back later.
//     snapDir is the snapshot directory for this deployment.
//   - Apply makes the system change (install a package, write a file, etc.).
//   - Verify checks whether the desired state holds right now. Returns
//     (true, "", nil) when compliant, (false, reason, nil) when drifted,
//     or (false, "", err) on unexpected failures.
type Action interface {
	Validate() error
	Snapshot(ctx context.Context, snapDir string) error
	Apply(ctx context.Context) error
	Verify(ctx context.Context) (ok bool, reason string, err error)
}

// ActionConstructor builds an Action from the YAML params map.
type ActionConstructor func(params map[string]any) (Action, error)

// Registry maps action type strings (e.g. "package_ensure") to their
// constructors. Thread-safe for read after initial registration.
type Registry struct {
	types map[string]ActionConstructor
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{types: map[string]ActionConstructor{}}
}

// Register adds a constructor for the given type name.
func (r *Registry) Register(typeName string, ctor ActionConstructor) {
	r.types[typeName] = ctor
}

// Lookup returns the constructor for typeName and whether it was found.
func (r *Registry) Lookup(typeName string) (ActionConstructor, bool) {
	ctor, ok := r.types[typeName]
	return ctor, ok
}

// DefaultRegistry returns a Registry pre-loaded with the MVP action types.
// Called once at agent startup. Action types are registered in Tasks 3-4.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register("package_ensure", NewPackageEnsure)
	r.Register("service_ensure", NewServiceEnsure)
	r.Register("file_content", NewFileContent)
	r.Register("sysctl", NewSysctl)
	return r
}

// RollbackProvider is an optional interface an Action may implement to provide
// its own rollback logic. When the deployment-level RollbackWithProviders runs,
// it first invokes every provider in reverse apply order, then falls back to
// the central Rollback for snapshot artifacts left untouched.
//
// The 4 MVP action types (package_ensure, service_ensure, file_content, sysctl)
// rely entirely on the central rollback and do NOT implement this interface.
// Future action types with non-file/non-package state (e.g. nftables_rules,
// udev_rule) can opt in.
type RollbackProvider interface {
	Rollback(ctx context.Context, snapDir string) error
}
