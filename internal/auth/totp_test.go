// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package auth

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func TestEnrollTOTP_ReturnsSecretAndURI(t *testing.T) {
	e, err := EnrollTOTP("alice@example.org", "LMDM")
	if err != nil {
		t.Fatal(err)
	}
	if e.Secret == "" {
		t.Error("empty secret")
	}
	if !strings.HasPrefix(e.URI, "otpauth://totp/") {
		t.Errorf("unexpected URI: %s", e.URI)
	}
}

func TestVerifyTOTP_AcceptsCurrentCode(t *testing.T) {
	e, err := EnrollTOTP("alice@example.org", "LMDM")
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(e.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyTOTP(e.Secret, code)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !ok {
		t.Error("current code should verify")
	}
}

func TestVerifyTOTP_RejectsWrongCode(t *testing.T) {
	e, err := EnrollTOTP("alice@example.org", "LMDM")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyTOTP(e.Secret, "123456")
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if ok {
		t.Error("wrong code must not verify")
	}
}

func TestVerifyTOTP_AcceptsPreviousPeriodWithinSkew(t *testing.T) {
	e, err := EnrollTOTP("alice@example.org", "LMDM")
	if err != nil {
		t.Fatal(err)
	}
	prev := time.Now().UTC().Add(-30 * time.Second)
	code, err := totp.GenerateCode(e.Secret, prev)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyTOTP(e.Secret, code)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !ok {
		t.Error("code from previous 30s period should verify under skew=1")
	}
}

func TestVerifyTOTP_RejectsCodeBeyondSkew(t *testing.T) {
	e, _ := EnrollTOTP("alice@example.org", "LMDM")
	stale := time.Now().UTC().Add(-90 * time.Second) // 3 periods ago, beyond skew=1
	code, _ := totp.GenerateCode(e.Secret, stale)
	ok, err := VerifyTOTP(e.Secret, code)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if ok {
		t.Error("code 90s old must be rejected (beyond skew window)")
	}
}

func TestVerifyTOTP_RejectsMalformedSecret(t *testing.T) {
	ok, err := VerifyTOTP("not-base32!!!", "123456")
	if err == nil {
		t.Error("malformed secret should produce an error, not silent false")
	}
	if ok {
		t.Error("malformed secret must not produce a verify success")
	}
}

func TestEnrollTOTP_URI_EncodesEmailWithReservedChars(t *testing.T) {
	e, err := EnrollTOTP("user+tag@example.org", "LMDM")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(e.URI)
	if err != nil {
		t.Fatalf("uri unparseable: %v", err)
	}
	if parsed.Query().Get("secret") == "" {
		t.Error("uri missing secret query param")
	}
	// Round-trip via otp.NewKeyFromURL preserves account name including the '+' char.
	k, err := otp.NewKeyFromURL(e.URI)
	if err != nil {
		t.Fatal(err)
	}
	if k.AccountName() != "user+tag@example.org" {
		t.Errorf("account name not preserved: got %q", k.AccountName())
	}
}

func TestTOTPEnrollment_StringRedacts(t *testing.T) {
	e := &TOTPEnrollment{Secret: "JBSWY3DPEHPK3PXP", URI: "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"} //nolint:gosec // test fixture, public RFC 6238 example secret
	s := e.String()
	if strings.Contains(s, "JBSWY3DPEHPK3PXP") {
		t.Errorf("String() leaked secret: %s", s)
	}
	if strings.Contains(s, "REDACTED") == false {
		t.Errorf("expected REDACTED marker, got %s", s)
	}
	if fmt.Sprintf("%v", e) != s {
		t.Errorf("%%v should match String()")
	}
}

func TestTOTPEnrollment_MarshalJSONRefuses(t *testing.T) {
	e := &TOTPEnrollment{Secret: "JBSWY3DPEHPK3PXP", URI: "otpauth://x"} //nolint:gosec // test fixture, public RFC 6238 example secret
	if _, err := json.Marshal(e); err == nil {                           //nolint:gosec // asserting MarshalJSON refuses serialisation
		t.Error("MarshalJSON should refuse to serialize")
	}
}
