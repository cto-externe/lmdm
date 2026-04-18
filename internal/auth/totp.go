// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTP parameters pinned at the LMDM layer. Do not rely on library defaults.
const (
	totpAlgorithm  = otp.AlgorithmSHA1
	totpDigits     = otp.DigitsSix
	totpPeriod     = uint(30) // seconds
	totpSkew       = uint(1)  // ±1 period tolerance
	totpSecretSize = uint(20) // 160-bit per RFC 4226 / Google Authenticator
)

// TOTPEnrollment is the output of an enrollment.
//
// SECURITY: both Secret and URI contain the raw TOTP seed (URI embeds it as ?secret=...).
// They MUST be encrypted with auth.Encrypt before persistence (the server's MFA-secret KEK)
// and MUST NOT be logged, JSON-encoded, or included in error messages. The String() method
// is overridden to redact, and MarshalJSON refuses to serialize.
type TOTPEnrollment struct {
	Secret string // base32-encoded seed — sensitive
	URI    string // otpauth://totp/... — embeds the secret in its query string, equally sensitive
}

// String redacts the secret material so accidental log statements
// like log.Printf("%v", enrollment) don't leak the seed.
func (e *TOTPEnrollment) String() string {
	if e == nil {
		return "<nil>"
	}
	return "TOTPEnrollment{Secret:[REDACTED], URI:[REDACTED]}"
}

// MarshalJSON refuses to serialize a TOTPEnrollment. Callers that need to send
// the URI to a client (for QR rendering at first enrolment) must do so explicitly
// via a dedicated DTO that encodes only the URI field, not via generic JSON encoding.
func (e *TOTPEnrollment) MarshalJSON() ([]byte, error) {
	return nil, errors.New("TOTPEnrollment must not be JSON-encoded; use an explicit DTO")
}

// EnrollTOTP generates a fresh TOTP seed for accountEmail under the given issuer.
//
// SECURITY: caller MUST encrypt the returned Secret (and treat the URI with the same care)
// before persistence. See TOTPEnrollment.
func EnrollTOTP(accountEmail, issuer string) (*TOTPEnrollment, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountEmail,
		Period:      totpPeriod,
		SecretSize:  totpSecretSize,
		Digits:      totpDigits,
		Algorithm:   totpAlgorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("totp generate: %w", err)
	}
	return &TOTPEnrollment{Secret: key.Secret(), URI: key.URL()}, nil
}

// VerifyTOTP checks a TOTP code against the base32 secret.
//
// Returns (true, nil) on a match within the ±1 period skew window.
// Returns (false, nil) when inputs are well-formed but the code does not match.
// Returns (false, non-nil) when the secret is not valid base32 or the code is malformed
// (callers can distinguish "user typo" from "stored secret corrupted" for logging/metrics).
//
// This function does NOT prevent replay of a still-valid code in a different request — the
// AuthService is responsible for tracking last-used time-step and rejecting reuse.
func VerifyTOTP(secret, code string) (bool, error) {
	ok, err := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:      totpSkew,
		Digits:    totpDigits,
		Algorithm: totpAlgorithm,
	})
	if err != nil {
		return false, fmt.Errorf("totp verify: %w", err)
	}
	return ok, nil
}
