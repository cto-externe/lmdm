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

// IssueStepUp signs a short-lived token that conveys "password was verified,
// MFA/password-change step pending". It is NOT an access token and MUST NOT
// be accepted by the auth middleware.
//
// The step-up audience is set to ["stepup", tenantID.String()] so a step-up
// token cannot be used as an access token (VerifyAccess does not check
// audience, but the claims type differs — step-up uses the standard
// RegisteredClaims only, no role/email/tenantID custom claims that access
// tokens carry).
func (s *JWTSigner) IssueStepUp(userID, tenantID uuid.UUID, ttl time.Duration) (string, error) {
	now := time.Now().UTC()
	claims := jwt.RegisteredClaims{
		Subject:   userID.String(),
		Issuer:    "lmdm",
		Audience:  []string{"stepup", tenantID.String()},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return tok.SignedString(s.priv)
}

// VerifyStepUp parses a step-up token and returns (userID, tenantID, nil)
// when the token is valid. Audience and issuer are checked.
func (s *JWTSigner) VerifyStepUp(raw string) (userID, tenantID uuid.UUID, err error) {
	parsed, err := jwt.ParseWithClaims(raw, &jwt.RegisteredClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodES256 {
			return nil, fmt.Errorf("unexpected alg: %v", t.Method.Alg())
		}
		return &s.priv.PublicKey, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithIssuer("lmdm"),
		jwt.WithAudience("stepup"),
	)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	claims, ok := parsed.Claims.(*jwt.RegisteredClaims)
	if !ok || !parsed.Valid {
		return uuid.Nil, uuid.Nil, errors.New("stepup: invalid claims")
	}
	uid, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("stepup sub: %w", err)
	}
	if len(claims.Audience) < 2 {
		return uuid.Nil, uuid.Nil, errors.New("stepup: missing tenant audience")
	}
	tid, err := uuid.Parse(claims.Audience[1])
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("stepup tid: %w", err)
	}
	return uid, tid, nil
}

// TTL returns the access token TTL configured on this signer.
func (s *JWTSigner) TTL() time.Duration { return s.ttl }
