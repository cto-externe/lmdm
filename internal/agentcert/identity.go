// Package agentcert persists the agent identity bundle: the SignedAgentCert
// returned by enrollment plus the server's hybrid signing pubkey (used to
// verify future server messages).
package agentcert

import (
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
	magic    = "LMDMAI01" // agent identity, version 1
)

// Identity is what the agent persists after a successful enrollment.
type Identity struct {
	SignedCert []byte                     // raw lmdmv1.SignedAgentCert proto bytes
	ServerPub  *pqhybrid.SigningPublicKey // server's signing pubkey, for verifying messages
}

// Save writes the identity to disk with 0600 mode.
func Save(path string, id *Identity) error {
	if id == nil || id.ServerPub == nil {
		return errors.New("agentcert: incomplete identity")
	}
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return fmt.Errorf("agentcert: mkdir: %w", err)
	}
	if err := os.WriteFile(path, serialize(id), fileMode); err != nil {
		return fmt.Errorf("agentcert: write %s: %w", path, err)
	}
	return nil
}

// Load reads the identity from disk. Returns os.ErrNotExist (wrapped) if
// the file is absent — callers can check with `errors.Is(err, os.ErrNotExist)`.
func Load(path string) (*Identity, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is an explicit configuration input
	if err != nil {
		// Return the original error so os.IsNotExist() works correctly
		return nil, err
	}
	return parse(data)
}

func serialize(id *Identity) []byte {
	var out []byte
	out = append(out, []byte(magic)...)
	out = appendBytes(out, id.SignedCert)
	out = appendBytes(out, id.ServerPub.Ed25519)
	out = appendBytes(out, id.ServerPub.MLDSA)
	return out
}

func parse(data []byte) (*Identity, error) {
	if len(data) < len(magic) || string(data[:len(magic)]) != magic {
		return nil, fmt.Errorf("agentcert: bad magic header")
	}
	r := readerOver(data[len(magic):])
	cert, err := readBytes(r)
	if err != nil {
		return nil, fmt.Errorf("agentcert: parse cert: %w", err)
	}
	edPub, err := readBytes(r)
	if err != nil {
		return nil, fmt.Errorf("agentcert: parse ed25519 pub: %w", err)
	}
	mlPub, err := readBytes(r)
	if err != nil {
		return nil, fmt.Errorf("agentcert: parse ml-dsa pub: %w", err)
	}
	return &Identity{
		SignedCert: cert,
		ServerPub:  &pqhybrid.SigningPublicKey{Ed25519: edPub, MLDSA: mlPub},
	}, nil
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
