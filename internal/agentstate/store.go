// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package agentstate persists small agent-local state (pending deployment,
// future store-and-forward queue) in a BoltDB file. Single-writer: the agent
// is the only process accessing the DB.
package agentstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// ErrNotFound indicates the requested key is absent.
var ErrNotFound = errors.New("agentstate: not found")

// PendingDeployment is the row written before Apply and cleared after the
// server acknowledges the result. Persisted across crashes so the watchdog
// can roll back at the next agent start if the apply was interrupted.
type PendingDeployment struct {
	DeploymentID string    `json:"deployment_id"`
	ProfileID    string    `json:"profile_id"`
	SnapDir      string    `json:"snap_dir"`
	StartedAt    time.Time `json:"started_at"`
}

// Store wraps a *bolt.DB with typed accessors.
type Store struct {
	db *bolt.DB
}

// Open returns a Store backed by the given path. The file is created with
// 0600 permissions if absent. Caller must Close().
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("agentstate: open %s: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketPendingDeployment)
		return err
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("agentstate: init buckets: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the DB handle.
func (s *Store) Close() error { return s.db.Close() }

// SetPending writes the pending deployment under a fixed key (single slot).
func (s *Store) SetPending(p PendingDeployment) error {
	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("agentstate: marshal pending: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPendingDeployment).Put(keyCurrent, data)
	})
}

// GetPending returns the pending deployment or ErrNotFound.
func (s *Store) GetPending() (*PendingDeployment, error) {
	var out *PendingDeployment
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketPendingDeployment).Get(keyCurrent)
		if raw == nil {
			return ErrNotFound
		}
		var p PendingDeployment
		if err := json.Unmarshal(raw, &p); err != nil {
			return fmt.Errorf("agentstate: decode pending: %w", err)
		}
		out = &p
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ClearPending removes the pending deployment row. No-op if already absent.
func (s *Store) ClearPending() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPendingDeployment).Delete(keyCurrent)
	})
}

// RebootDeferState persists the consecutive defer count between agent restarts
// so we can force a reboot after N user-active defers (per brainstorm Q5=C).
type RebootDeferState struct {
	Count          int       `json:"count"`
	LastDeferredAt time.Time `json:"last_deferred_at"`
}

// GetRebootDefer returns the current defer state, or zero values when absent.
func (s *Store) GetRebootDefer() (RebootDeferState, error) {
	var state RebootDeferState
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPatchDefer)
		if b == nil {
			return nil
		}
		raw := b.Get(keyDeferCounter)
		if raw == nil {
			return nil
		}
		return json.Unmarshal(raw, &state)
	})
	return state, err
}

// SetRebootDefer overwrites the defer state.
func (s *Store) SetRebootDefer(state RebootDeferState) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketPatchDefer)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(state)
		if err != nil {
			return err
		}
		return b.Put(keyDeferCounter, raw)
	})
}

// ClearRebootDefer resets the counter after a successful reboot.
func (s *Store) ClearRebootDefer() error {
	return s.SetRebootDefer(RebootDeferState{})
}
