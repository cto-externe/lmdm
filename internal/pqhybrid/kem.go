package pqhybrid

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"errors"
	"fmt"
	"io"
)

// KEMPrivateKey holds both classical (X25519) and post-quantum (ML-KEM-768)
// decapsulation keys.
type KEMPrivateKey struct {
	X25519 *ecdh.PrivateKey
	MLKEM  *mlkem.DecapsulationKey768
}

// KEMPublicKey holds both classical and post-quantum encapsulation keys in
// serialized form (ready to be sent on the wire).
type KEMPublicKey struct {
	X25519 []byte // 32-byte X25519 public key.
	MLKEM  []byte // ML-KEM-768 encapsulation key bytes.
}

// GenerateKEMKey generates a hybrid KEM keypair. The X25519 half uses r for
// randomness; the ML-KEM half uses crypto/rand internally (stdlib API does
// not accept a reader).
func GenerateKEMKey(r io.Reader) (*KEMPrivateKey, *KEMPublicKey, error) {
	if r == nil {
		return nil, nil, errors.New("pqhybrid: nil random reader")
	}
	xPriv, err := ecdh.X25519().GenerateKey(r)
	if err != nil {
		return nil, nil, fmt.Errorf("pqhybrid: x25519 keygen: %w", err)
	}
	mlPriv, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, fmt.Errorf("pqhybrid: ml-kem keygen: %w", err)
	}
	priv := &KEMPrivateKey{X25519: xPriv, MLKEM: mlPriv}
	pub := &KEMPublicKey{
		X25519: xPriv.PublicKey().Bytes(),
		MLKEM:  mlPriv.EncapsulationKey().Bytes(),
	}
	return priv, pub, nil
}
