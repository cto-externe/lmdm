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

// Sign produces a hybrid signature over msg using both the Ed25519 and
// ML-DSA-65 private keys. Both signatures cover the same payload.
func Sign(priv *SigningPrivateKey, msg []byte) (*HybridSignature, error) {
	if priv == nil || len(priv.Ed25519) == 0 || len(priv.MLDSA) == 0 {
		return nil, errors.New("pqhybrid: incomplete signing private key")
	}

	edSig := ed25519.Sign(priv.Ed25519, msg)

	var mlKey mldsa65.PrivateKey
	if err := mlKey.UnmarshalBinary(priv.MLDSA); err != nil {
		return nil, fmt.Errorf("pqhybrid: ml-dsa unmarshal priv: %w", err)
	}
	mlSig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(&mlKey, msg, nil, false, mlSig); err != nil {
		return nil, fmt.Errorf("pqhybrid: ml-dsa sign: %w", err)
	}

	return &HybridSignature{Ed25519: edSig, MLDSA: mlSig}, nil
}

// Verify validates both signature components against the hybrid public key.
// It returns nil on success and an error describing the first failure
// otherwise. Both components MUST validate for Verify to succeed.
func Verify(pub *SigningPublicKey, msg []byte, sig *HybridSignature) error {
	if pub == nil || len(pub.Ed25519) == 0 || len(pub.MLDSA) == 0 {
		return errors.New("pqhybrid: incomplete signing public key")
	}
	if sig == nil || len(sig.Ed25519) == 0 || len(sig.MLDSA) == 0 {
		return errors.New("pqhybrid: incomplete hybrid signature")
	}

	if !ed25519.Verify(pub.Ed25519, msg, sig.Ed25519) {
		return errors.New("pqhybrid: ed25519 signature invalid")
	}

	var mlPub mldsa65.PublicKey
	if err := mlPub.UnmarshalBinary(pub.MLDSA); err != nil {
		return fmt.Errorf("pqhybrid: ml-dsa unmarshal pub: %w", err)
	}
	if !mldsa65.Verify(&mlPub, msg, nil, sig.MLDSA) {
		return errors.New("pqhybrid: ml-dsa signature invalid")
	}
	return nil
}
