package pqhybrid

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// SigningPrivateKey holds the classical and post-quantum private key material
// used to produce hybrid signatures.
type SigningPrivateKey struct {
	Ed25519 ed25519.PrivateKey
	MLDSA   []byte // Serialized ML-DSA-65 private key.
}

// SigningPublicKey holds the classical and post-quantum public key material
// used to verify hybrid signatures.
type SigningPublicKey struct {
	Ed25519 ed25519.PublicKey
	MLDSA   []byte // Serialized ML-DSA-65 public key.
}

// HybridSignature is the concatenated Ed25519 + ML-DSA-65 signature tuple.
type HybridSignature struct {
	Ed25519 []byte
	MLDSA   []byte
}

// GenerateSigningKey creates a new hybrid signing keypair.
// The reader is used for both components (typically crypto/rand.Reader).
func GenerateSigningKey(r io.Reader) (*SigningPrivateKey, *SigningPublicKey, error) {
	if r == nil {
		return nil, nil, errors.New("pqhybrid: nil random reader")
	}

	edPub, edPriv, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, nil, fmt.Errorf("pqhybrid: ed25519 keygen: %w", err)
	}

	mlPub, mlPriv, err := mldsa65.GenerateKey(r)
	if err != nil {
		return nil, nil, fmt.Errorf("pqhybrid: ml-dsa keygen: %w", err)
	}

	mlPrivBytes, err := mlPriv.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("pqhybrid: ml-dsa marshal priv: %w", err)
	}
	mlPubBytes, err := mlPub.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("pqhybrid: ml-dsa marshal pub: %w", err)
	}

	priv := &SigningPrivateKey{Ed25519: edPriv, MLDSA: mlPrivBytes}
	pub := &SigningPublicKey{Ed25519: edPub, MLDSA: mlPubBytes}
	return priv, pub, nil
}
