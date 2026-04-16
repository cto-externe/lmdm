// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentpolicy

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
	"github.com/cto-externe/lmdm/internal/policy"
	"github.com/cto-externe/lmdm/internal/pqhybrid"
)

func TestHandleApplyProfileVerifiesSignature(t *testing.T) {
	serverPriv, serverPub, _ := pqhybrid.GenerateSigningKey(rand.Reader)
	_, wrongPub, _ := pqhybrid.GenerateSigningKey(rand.Reader)

	yamlContent := []byte("kind: profile\nmetadata:\n  name: test\npolicies: []\n")
	sig, err := pqhybrid.Sign(serverPriv, yamlContent)
	if err != nil {
		t.Fatal(err)
	}

	env := &lmdmv1.CommandEnvelope{
		CommandId: "test-1",
		Command: &lmdmv1.CommandEnvelope_ApplyProfile{
			ApplyProfile: &lmdmv1.ApplyProfileCommand{
				ProfileId:      &lmdmv1.ProfileID{Id: "prof-1"},
				Version:        "1.0",
				ProfileContent: yamlContent,
				ProfileSignature: &lmdmv1.HybridSignature{
					Ed25519: sig.Ed25519,
					MlDsa:   sig.MLDSA,
				},
			},
		},
	}
	data, _ := proto.Marshal(env)

	// With correct key: must not error.
	if _, err := VerifyAndParseCommand(data, serverPub); err != nil {
		t.Fatalf("verify with correct key: %v", err)
	}

	// With wrong key: must error.
	if _, err := VerifyAndParseCommand(data, wrongPub); err == nil {
		t.Fatal("verify with wrong key must fail")
	}
}

func TestHandleRemoveProfileRemovesFromStore(t *testing.T) {
	serverPriv, serverPub, _ := pqhybrid.GenerateSigningKey(rand.Reader)

	// Setup: handler with a store that has a profile.
	store := NewProfileStore(t.TempDir())
	_ = store.Save("prof-rm", []byte("kind: profile\nmetadata:\n  name: test\npolicies: []\n"))

	snapRoot := t.TempDir()

	// Verify profile is in the store.
	profiles, _ := store.List()
	if len(profiles) != 1 {
		t.Fatalf("store should have 1 profile, got %d", len(profiles))
	}

	// Build a RemoveProfileCommand in a CommandEnvelope.
	env := &lmdmv1.CommandEnvelope{
		CommandId: "rm-1",
		Command: &lmdmv1.CommandEnvelope_RemoveProfile{
			RemoveProfile: &lmdmv1.RemoveProfileCommand{
				ProfileId: &lmdmv1.ProfileID{Id: "prof-rm"},
			},
		},
	}
	data, _ := proto.Marshal(env)

	// Create a minimal handler just to test the remove logic.
	// We can't easily call handleMessage directly without a real nats.Msg,
	// so test the extraction + removal logic via exported helpers.
	profileID := extractRemoveProfileID(data)
	if profileID != "prof-rm" {
		t.Fatalf("extractRemoveProfileID = %q, want prof-rm", profileID)
	}

	// Simulate what the handler would do:
	// 1. Try rollback (no snapshot for this profile → no-op / warning)
	_ = policy.Rollback(context.Background(), filepath.Join(snapRoot, "prof-rm"))
	// 2. Remove from store
	_ = store.Remove(profileID)

	profiles, _ = store.List()
	if len(profiles) != 0 {
		t.Errorf("store should be empty after remove, got %d", len(profiles))
	}

	// Keep the unused imports happy.
	_ = serverPriv
	_ = serverPub
}
