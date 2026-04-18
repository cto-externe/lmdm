// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// lmdm-keygen generates the JWT ECDSA P-256 keypair (used by internal/auth.JWTSigner)
// and the AES-256 master key (used by internal/auth.Encrypt/Decrypt for TOTP secrets).
//
// Output files (written to --out, default "."):
//   jwt-priv.pem   ECDSA P-256 private key, PEM-encoded, chmod 0600
//   jwt-pub.pem    corresponding public key, chmod 0644 (for future JWKS)
//   enc-key.b64    32-byte random AES master key, base64 + trailing newline, chmod 0600
//
// Once written, export LMDM_JWT_PRIVATE_KEY_PATH and LMDM_ENC_KEY_PATH to the
// server so the AuthService can load them at boot.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	out := flag.String("out", ".", "directory to write keys into")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o700); err != nil {
		fail("mkdir: " + err.Error())
	}

	// ECDSA P-256 keypair
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	privDER, err := x509.MarshalECPrivateKey(priv)
	must(err)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	must(writeFile(filepath.Join(*out, "jwt-priv.pem"), privPEM, 0o600))

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	must(err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	must(writeFile(filepath.Join(*out, "jwt-pub.pem"), pubPEM, 0o644))

	// AES-256 master key, base64-encoded
	encKey := make([]byte, 32)
	_, err = rand.Read(encKey)
	must(err)
	b64 := base64.StdEncoding.EncodeToString(encKey) + "\n"
	must(writeFile(filepath.Join(*out, "enc-key.b64"), []byte(b64), 0o600))

	fmt.Println("Wrote:")
	fmt.Println("  jwt-priv.pem  (ECDSA P-256 private key, chmod 0600)")
	fmt.Println("  jwt-pub.pem   (public key, chmod 0644)")
	fmt.Println("  enc-key.b64   (AES-256 master key, base64, chmod 0600)")
	fmt.Println()
	fmt.Println("Export (or mount as secrets):")
	fmt.Printf("  LMDM_JWT_PRIVATE_KEY_PATH=%s\n", filepath.Join(*out, "jwt-priv.pem"))
	fmt.Printf("  LMDM_ENC_KEY_PATH=%s\n", filepath.Join(*out, "enc-key.b64"))
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	return os.WriteFile(path, data, mode)
}

func must(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "lmdm-keygen:", msg)
	os.Exit(1)
}
