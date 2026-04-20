// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agenttls

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStore_SaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	cert := []byte("-----BEGIN CERTIFICATE-----\ncert-bytes\n-----END CERTIFICATE-----\n")
	key := []byte("-----BEGIN PRIVATE KEY-----\nkey-bytes\n-----END PRIVATE KEY-----\n")
	ca := []byte("-----BEGIN CERTIFICATE-----\nca-bytes\n-----END CERTIFICATE-----\n")

	if err := s.SaveCredentials(cert, key, ca); err != nil {
		t.Fatalf("SaveCredentials: %v", err)
	}

	gotCert, gotKey, gotCA, err := s.LoadCredentials()
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if !bytes.Equal(gotCert, cert) {
		t.Errorf("cert mismatch: got %q want %q", gotCert, cert)
	}
	if !bytes.Equal(gotKey, key) {
		t.Errorf("key mismatch: got %q want %q", gotKey, key)
	}
	if !bytes.Equal(gotCA, ca) {
		t.Errorf("ca mismatch: got %q want %q", gotCA, ca)
	}
}

func TestStore_HasCredentials_EmptyDir_ReturnsFalse(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if s.HasCredentials() {
		t.Error("HasCredentials on empty dir: got true, want false")
	}

	_, _, _, err = s.LoadCredentials()
	if !errors.Is(err, ErrNoCredentials) {
		t.Errorf("LoadCredentials on empty dir: got %v, want ErrNoCredentials", err)
	}
}

func TestStore_SaveCredentials_Overwrite(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if err := s.SaveCredentials([]byte("cert1"), []byte("key1"), []byte("ca1")); err != nil {
		t.Fatalf("first SaveCredentials: %v", err)
	}
	if err := s.SaveCredentials([]byte("cert2"), []byte("key2"), []byte("ca2")); err != nil {
		t.Fatalf("second SaveCredentials: %v", err)
	}

	gotCert, gotKey, gotCA, err := s.LoadCredentials()
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if string(gotCert) != "cert2" {
		t.Errorf("cert: got %q want %q", gotCert, "cert2")
	}
	if string(gotKey) != "key2" {
		t.Errorf("key: got %q want %q", gotKey, "key2")
	}
	if string(gotCA) != "ca2" {
		t.Errorf("ca: got %q want %q", gotCA, "ca2")
	}
}

func TestStore_SaveCredentials_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if err := s.SaveCredentials([]byte("cert"), []byte("key"), []byte("ca")); err != nil {
		t.Fatalf("SaveCredentials: %v", err)
	}

	cases := []struct {
		path string
		want os.FileMode
	}{
		{s.CertPath(), 0o644},
		{s.KeyPath(), 0o600},
		{s.CAPath(), 0o644},
	}
	for _, tc := range cases {
		info, err := os.Stat(tc.path)
		if err != nil {
			t.Fatalf("stat %s: %v", tc.path, err)
		}
		if got := info.Mode().Perm(); got != tc.want {
			t.Errorf("%s: mode = %o, want %o", tc.path, got, tc.want)
		}
	}
}

func TestStore_HasCredentials_PartialStore_ReturnsFalse(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "agent.crt"), []byte("cert"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if s.HasCredentials() {
		t.Error("HasCredentials with only cert present: got true, want false")
	}
}
