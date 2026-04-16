// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentpolicy

import (
	"crypto/rand"
	"testing"

	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
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
