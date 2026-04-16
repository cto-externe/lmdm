// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentpolicy

import (
	"testing"
)

func TestProfileStoreSaveAndList(t *testing.T) {
	dir := t.TempDir()
	s := NewProfileStore(dir)

	if err := s.Save("prof-1", []byte("yaml1")); err != nil {
		t.Fatal(err)
	}
	if err := s.Save("prof-2", []byte("yaml2")); err != nil {
		t.Fatal(err)
	}

	profiles, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 {
		t.Fatalf("len = %d, want 2", len(profiles))
	}
	if string(profiles["prof-1"]) != "yaml1" {
		t.Errorf("prof-1 = %q", profiles["prof-1"])
	}
}

func TestProfileStoreRemove(t *testing.T) {
	dir := t.TempDir()
	s := NewProfileStore(dir)

	_ = s.Save("prof-1", []byte("yaml1"))
	if err := s.Remove("prof-1"); err != nil {
		t.Fatal(err)
	}
	profiles, _ := s.List()
	if len(profiles) != 0 {
		t.Errorf("after remove: len = %d", len(profiles))
	}
}

func TestProfileStoreRemoveNonExistentIsOK(t *testing.T) {
	dir := t.TempDir()
	s := NewProfileStore(dir)
	if err := s.Remove("nonexistent"); err != nil {
		t.Fatalf("Remove of nonexistent should be a no-op, got %v", err)
	}
}

func TestProfileStoreListEmptyDir(t *testing.T) {
	dir := t.TempDir()
	s := NewProfileStore(dir)
	profiles, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 0 {
		t.Errorf("empty store should return 0 profiles")
	}
}
