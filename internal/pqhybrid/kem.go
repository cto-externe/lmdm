package pqhybrid

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// SharedSecretSize is the length of the derived hybrid shared secret.
const SharedSecretSize = 32

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

// HybridCiphertext is the pair of ciphertexts produced by Encapsulate and
// consumed by Decapsulate.
type HybridCiphertext struct {
	X25519EphemeralPub []byte // 32-byte X25519 ephemeral public key.
	MLKEMCiphertext    []byte // ML-KEM-768 ciphertext.
}

// cryptoRand is the randomness source used by Encapsulate. Tests may
// override it; in production it is crypto/rand.Reader.
var cryptoRand = rand.Reader

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

// Encapsulate generates a fresh X25519 ephemeral keypair and an ML-KEM-768
// encapsulation. It returns the wire-format ciphertexts and the derived
// shared secret.
func Encapsulate(pub *KEMPublicKey) (*HybridCiphertext, []byte, error) {
	if pub == nil || len(pub.X25519) == 0 || len(pub.MLKEM) == 0 {
		return nil, nil, errors.New("pqhybrid: incomplete KEM public key")
	}
	peerX, err := ecdh.X25519().NewPublicKey(pub.X25519)
	if err != nil {
		return nil, nil, fmt.Errorf("pqhybrid: x25519 peer pub: %w", err)
	}
	ephX, err := ecdh.X25519().GenerateKey(cryptoRand)
	if err != nil {
		return nil, nil, fmt.Errorf("pqhybrid: x25519 ephemeral: %w", err)
	}
	xShared, err := ephX.ECDH(peerX)
	if err != nil {
		return nil, nil, fmt.Errorf("pqhybrid: x25519 ecdh: %w", err)
	}

	mlPub, err := mlkem.NewEncapsulationKey768(pub.MLKEM)
	if err != nil {
		return nil, nil, fmt.Errorf("pqhybrid: ml-kem encap key: %w", err)
	}
	mlShared, mlCT := mlPub.Encapsulate()

	salt := computeKEMSalt(pub.X25519, pub.MLKEM, ephX.PublicKey().Bytes(), mlCT)
	combined := deriveSharedSecret(salt, xShared, mlShared)
	ct := &HybridCiphertext{
		X25519EphemeralPub: ephX.PublicKey().Bytes(),
		MLKEMCiphertext:    mlCT,
	}
	return ct, combined, nil
}

// Decapsulate derives the shared secret from the ciphertext pair using the
// hybrid private key.
func Decapsulate(priv *KEMPrivateKey, ct *HybridCiphertext) ([]byte, error) {
	if priv == nil || priv.X25519 == nil || priv.MLKEM == nil {
		return nil, errors.New("pqhybrid: incomplete KEM private key")
	}
	if ct == nil || len(ct.X25519EphemeralPub) == 0 || len(ct.MLKEMCiphertext) == 0 {
		return nil, errors.New("pqhybrid: incomplete hybrid ciphertext")
	}
	peerX, err := ecdh.X25519().NewPublicKey(ct.X25519EphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("pqhybrid: x25519 ephemeral pub: %w", err)
	}
	xShared, err := priv.X25519.ECDH(peerX)
	if err != nil {
		return nil, fmt.Errorf("pqhybrid: x25519 ecdh: %w", err)
	}
	mlShared, err := priv.MLKEM.Decapsulate(ct.MLKEMCiphertext)
	if err != nil {
		return nil, fmt.Errorf("pqhybrid: ml-kem decapsulate: %w", err)
	}
	ourStaticX25519 := priv.X25519.PublicKey().Bytes()
	ourStaticMLKEM := priv.MLKEM.EncapsulationKey().Bytes()
	salt := computeKEMSalt(ourStaticX25519, ourStaticMLKEM, ct.X25519EphemeralPub, ct.MLKEMCiphertext)
	return deriveSharedSecret(salt, xShared, mlShared), nil
}

// computeKEMSalt returns a 32-byte SHA-256 digest of the four session-context
// inputs concatenated in order: peer static X25519 pub, peer static ML-KEM pub,
// ephemeral X25519 pub, ML-KEM ciphertext. Both Encapsulate and Decapsulate
// compute the same value, binding the derived secret to the intended recipient
// and the full session transcript.
func computeKEMSalt(peerStaticX25519, peerStaticMLKEM, ephX25519Pub, mlkemCT []byte) []byte {
	h := sha256.New()
	h.Write(peerStaticX25519)
	h.Write(peerStaticMLKEM)
	h.Write(ephX25519Pub)
	h.Write(mlkemCT)
	return h.Sum(nil)
}

// deriveSharedSecret combines the classical and post-quantum shared secrets
// via HKDF-SHA256. The salt binds the derivation to the session transcript
// (peer static pubkeys + ephemeral pub + ciphertext), ruling out cross-session
// secret reuse. The info label "LMDM-hybrid-kem-v1" provides domain separation.
func deriveSharedSecret(salt, classical, pq []byte) []byte {
	input := make([]byte, 0, len(classical)+len(pq))
	input = append(input, classical...)
	input = append(input, pq...)
	reader := hkdf.New(sha256.New, input, salt, []byte("LMDM-hybrid-kem-v1"))
	out := make([]byte, SharedSecretSize)
	_, _ = reader.Read(out)
	return out
}
