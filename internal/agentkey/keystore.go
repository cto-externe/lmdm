// Package agentkey loads or generates the agent's hybrid signing keypair
// and persists it to disk. Mirrors the server-side keystore but is owned
// by the agent. File mode 0600 is enforced.
package agentkey

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cto-externe/lmdm/internal/pqhybrid"
)

const (
	fileMode = 0o600
	dirMode  = 0o700
	magic    = "LMDMAK01" // 8 bytes — agent key, version 1
)

// LoadOrGenerate returns the signing keypair persisted at path. If no file
// exists, a new keypair is generated and saved. Subsequent calls return the
// same keys.
func LoadOrGenerate(path string) (*pqhybrid.SigningPrivateKey, *pqhybrid.SigningPublicKey, error) {
	if data, err := os.ReadFile(path); err == nil { //nolint:gosec // path is an explicit configuration input
		return parse(data)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("agentkey: read %s: %w", path, err)
	}

	priv, pub, err := pqhybrid.GenerateSigningKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("agentkey: generate: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return nil, nil, fmt.Errorf("agentkey: mkdir: %w", err)
	}
	if err := os.WriteFile(path, serialize(priv, pub), fileMode); err != nil {
		return nil, nil, fmt.Errorf("agentkey: write %s: %w", path, err)
	}
	return priv, pub, nil
}

func serialize(priv *pqhybrid.SigningPrivateKey, pub *pqhybrid.SigningPublicKey) []byte {
	var out []byte
	out = append(out, []byte(magic)...)
	out = appendBytes(out, priv.Ed25519)
	out = appendBytes(out, priv.MLDSA)
	out = appendBytes(out, pub.Ed25519)
	out = appendBytes(out, pub.MLDSA)
	return out
}

func parse(data []byte) (*pqhybrid.SigningPrivateKey, *pqhybrid.SigningPublicKey, error) {
	if len(data) < len(magic) || string(data[:len(magic)]) != magic {
		return nil, nil, fmt.Errorf("agentkey: bad magic header")
	}
	r := readerOver(data[len(magic):])
	edPriv, err := readBytes(r)
	if err != nil {
		return nil, nil, fmt.Errorf("agentkey: parse ed25519 priv: %w", err)
	}
	mlPriv, err := readBytes(r)
	if err != nil {
		return nil, nil, fmt.Errorf("agentkey: parse ml-dsa priv: %w", err)
	}
	edPub, err := readBytes(r)
	if err != nil {
		return nil, nil, fmt.Errorf("agentkey: parse ed25519 pub: %w", err)
	}
	mlPub, err := readBytes(r)
	if err != nil {
		return nil, nil, fmt.Errorf("agentkey: parse ml-dsa pub: %w", err)
	}
	return &pqhybrid.SigningPrivateKey{Ed25519: edPriv, MLDSA: mlPriv},
		&pqhybrid.SigningPublicKey{Ed25519: edPub, MLDSA: mlPub}, nil
}

func appendBytes(out, b []byte) []byte {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b))) //nolint:gosec // payload lengths are bounded to realistic key/cert sizes far below 4GiB
	out = append(out, hdr[:]...)
	out = append(out, b...)
	return out
}

type byteReader struct {
	data []byte
	pos  int
}

func readerOver(b []byte) *byteReader { return &byteReader{data: b} }

func readBytes(r *byteReader) ([]byte, error) {
	if r.pos+4 > len(r.data) {
		return nil, io.ErrUnexpectedEOF
	}
	n := binary.BigEndian.Uint32(r.data[r.pos : r.pos+4])
	r.pos += 4
	if r.pos+int(n) > len(r.data) {
		return nil, io.ErrUnexpectedEOF
	}
	out := make([]byte, n)
	copy(out, r.data[r.pos:r.pos+int(n)])
	r.pos += int(n)
	return out, nil
}
