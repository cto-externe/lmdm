// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package policy

import (
	"context"
	"testing"
)

type fakeAction struct {
	validateErr error
	applyErr    error
	verified    bool
}

func (f *fakeAction) Validate() error                            { return f.validateErr }
func (f *fakeAction) Snapshot(_ context.Context, _ string) error { return nil }
func (f *fakeAction) Apply(_ context.Context) error              { return f.applyErr }
func (f *fakeAction) Verify(_ context.Context) (bool, string, error) {
	return f.verified, "", nil
}

func TestRegistryLookup(t *testing.T) {
	r := NewRegistry()
	r.Register("fake", func(params map[string]any) (Action, error) {
		return &fakeAction{verified: true}, nil
	})
	ctor, ok := r.Lookup("fake")
	if !ok {
		t.Fatal("lookup must find registered type")
	}
	a, err := ctor(nil)
	if err != nil {
		t.Fatal(err)
	}
	ok, _, _ = a.Verify(context.Background())
	if !ok {
		t.Error("Verify should return true for fakeAction")
	}
}

func TestRegistryLookupMissing(t *testing.T) {
	r := NewRegistry()
	_, ok := r.Lookup("nonexistent")
	if ok {
		t.Error("lookup should return false for unregistered type")
	}
}
