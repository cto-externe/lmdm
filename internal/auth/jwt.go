// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Role is one of admin, operator, viewer.
type Role string

// Known role values.
const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

// IsValid reports whether r is one of the known roles.
func (r Role) IsValid() bool {
	return r == RoleAdmin || r == RoleOperator || r == RoleViewer
}

// JWTSigner issues and verifies ES256 access tokens.
type JWTSigner struct {
	priv *ecdsa.PrivateKey
	ttl  time.Duration
}

// NewJWTSigner returns a signer using the ECDSA P-256 key for signing and its public key for verification.
func NewJWTSigner(priv *ecdsa.PrivateKey, ttl time.Duration) *JWTSigner {
	return &JWTSigner{priv: priv, ttl: ttl}
}

// LoadJWTSigner reads a PEM-encoded ECDSA P-256 private key from path.
func LoadJWTSigner(path string, ttl time.Duration) (*JWTSigner, error) {
	b, err := os.ReadFile(path) //nolint:gosec // path is an explicit configuration input
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("jwt: pem decode failed")
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		return nil, errors.New("jwt: encrypted PEM not supported")
	}
	if _, enc := block.Headers["DEK-Info"]; enc {
		return nil, errors.New("jwt: encrypted PEM not supported")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// try PKCS8
		k, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse ec key: %w", errors.Join(err, err2))
		}
		eck, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("jwt: key is not ECDSA")
		}
		key = eck
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("jwt: unsupported curve %s, want P-256", key.Curve.Params().Name)
	}
	return NewJWTSigner(key, ttl), nil
}

// accessClaims are the JWT custom claims for access tokens.
type accessClaims struct {
	TenantID string `json:"tid"`
	Role     string `json:"rol"`
	Email    string `json:"eml"`
	jwt.RegisteredClaims
}

// IssueAccess signs a short-lived access token.
func (s *JWTSigner) IssueAccess(userID, tenantID uuid.UUID, role Role, email string) (string, error) {
	now := time.Now().UTC()
	claims := accessClaims{
		TenantID: tenantID.String(),
		Role:     string(role),
		Email:    email,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
			Issuer:    "lmdm",
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return tok.SignedString(s.priv)
}

// VerifyAccess parses and validates a token; returns the Principal.
func (s *JWTSigner) VerifyAccess(raw string) (*Principal, error) {
	parsed, err := jwt.ParseWithClaims(raw, &accessClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodES256 {
			return nil, fmt.Errorf("unexpected alg: %v", t.Method.Alg())
		}
		return &s.priv.PublicKey, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithIssuer("lmdm"),
	)
	if err != nil {
		return nil, err
	}
	claims, ok := parsed.Claims.(*accessClaims)
	if !ok || !parsed.Valid {
		return nil, errors.New("jwt: invalid claims")
	}
	uid, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, fmt.Errorf("sub: %w", err)
	}
	tid, err := uuid.Parse(claims.TenantID)
	if err != nil {
		return nil, fmt.Errorf("tid: %w", err)
	}
	role := Role(claims.Role)
	if !role.IsValid() {
		return nil, fmt.Errorf("unknown role %q", claims.Role)
	}
	return &Principal{UserID: uid, TenantID: tid, Role: role, Email: claims.Email}, nil
}
