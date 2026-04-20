// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenttls

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNoCredentials indicates the agent hasn't been enrolled yet (no cert
// files on disk). Use errors.Is to detect.
var ErrNoCredentials = errors.New("agenttls: no credentials on disk")

// Store persists the agent's X.509 credentials (client cert + key + CA chain)
// under a dedicated directory. All writes are atomic (temp file + rename).
type Store struct {
	dir string
}

// NewStore ensures dir exists with permissions 0700 and returns a Store.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("agenttls: mkdir %s: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

// Paths the store manages. Exported for the mTLS dialer to build its *tls.Config
// via paths (e.g. NATS nats.ClientCert + nats.RootCAs take paths).
func (s *Store) CertPath() string { return filepath.Join(s.dir, "agent.crt") }
func (s *Store) KeyPath() string  { return filepath.Join(s.dir, "agent.key") }
func (s *Store) CAPath() string   { return filepath.Join(s.dir, "ca.crt") }

// SaveCredentials writes cert + key + CA atomically. Each file is written
// to a temp file first, then renamed. If any step fails, previously-written
// temp files are cleaned up but any already-renamed files remain in place.
// Caller should treat partial-save failures as "re-enroll required".
func (s *Store) SaveCredentials(certPEM, keyPEM, caPEM []byte) error {
	if err := writeAtomic(s.CertPath(), certPEM, 0o644); err != nil {
		return err
	}
	if err := writeAtomic(s.KeyPath(), keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(s.CAPath(), caPEM, 0o644); err != nil {
		return err
	}
	return nil
}

// LoadCredentials reads cert + key + CA. Returns ErrNoCredentials when any
// of the three files is missing (i.e. the agent hasn't been enrolled).
func (s *Store) LoadCredentials() (certPEM, keyPEM, caPEM []byte, err error) {
	if !s.HasCredentials() {
		return nil, nil, nil, ErrNoCredentials
	}
	certPEM, err = os.ReadFile(s.CertPath()) //nolint:gosec // path under controlled dir
	if err != nil {
		return nil, nil, nil, fmt.Errorf("agenttls: read cert: %w", err)
	}
	keyPEM, err = os.ReadFile(s.KeyPath()) //nolint:gosec // path under controlled dir
	if err != nil {
		return nil, nil, nil, fmt.Errorf("agenttls: read key: %w", err)
	}
	caPEM, err = os.ReadFile(s.CAPath()) //nolint:gosec // path under controlled dir
	if err != nil {
		return nil, nil, nil, fmt.Errorf("agenttls: read ca: %w", err)
	}
	return certPEM, keyPEM, caPEM, nil
}

// HasCredentials reports whether all three files exist. A partial store
// (e.g. only cert + key but no CA) is treated as absent — the agent must
// re-enroll to recover.
func (s *Store) HasCredentials() bool {
	for _, p := range []string{s.CertPath(), s.KeyPath(), s.CAPath()} {
		if _, err := os.Stat(p); err != nil {
			return false
		}
	}
	return true
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("agenttls: create temp: %w", err)
	}
	tmpPath := f.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("agenttls: write %s: %w", path, err)
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("agenttls: chmod %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return fmt.Errorf("agenttls: close: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("agenttls: rename: %w", err)
	}
	return nil
}
