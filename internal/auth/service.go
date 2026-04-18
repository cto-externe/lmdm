// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/cto-externe/lmdm/internal/audit"
	"github.com/cto-externe/lmdm/internal/users"
)

// MinPasswordLen is the minimum password length enforced by NIST 800-63B
// (no complexity rules).
const MinPasswordLen = 12

var (
	dummyArgonHashOnce sync.Once
	dummyArgonHash     string
)

// dummyHash returns a pre-computed argon2id hash used to equalize the timing
// of Login's "unknown email" branch with the "wrong password" branch.
// Without this, an attacker could distinguish these two states via the ~150 ms
// argon2 verify latency.
func dummyHash() string {
	dummyArgonHashOnce.Do(func() {
		h, err := HashPassword("timing-equalization-dummy-password")
		if err != nil {
			// Fall back to a fixed PHC-valid string; VerifyPassword against it
			// will still burn the argon2 compute cycles.
			dummyArgonHash = "$argon2id$v=19$m=65536,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"
			_ = err
			return
		}
		dummyArgonHash = h
	})
	return dummyArgonHash
}

// StepUpTokenTTL caps the window between password verification and
// MFA/password-change completion.
const StepUpTokenTTL = 5 * time.Minute

// Service orchestrates auth flows against a users.Repository and audit.Writer.
type Service struct {
	Users    *users.Repository
	Audit    *audit.Writer
	Signer   *JWTSigner
	EncKey   []byte // 32-byte AES-256 key for TOTP secrets
	TenantID uuid.UUID
	Issuer   string // used in the TOTP otpauth URI ("LMDM" by default)

	// lastTOTPStep prevents replay of a TOTP code within the same 30-second step window.
	// Key: user UUID (uuid.UUID as comparable). Value: int64 (unix-step of the most recent
	// successful verification for that user).
	lastTOTPStep sync.Map
}

// registerTOTPUse returns true if the current step is accepted (not a replay of a
// previously-seen step for this user) and records it. Returns false if the same
// user has already verified at the current step — i.e. the code is being replayed
// within the same 30-second window.
//
// Limitations: this only catches replays within the same TOTP period. A code
// observed at step N and replayed at step N+1 (still within the ±1 skew window)
// is not caught at the service layer. For full coverage we would need to know
// which step the library matched, which pquerna/otp does not expose.
func (s *Service) registerTOTPUse(userID uuid.UUID) bool {
	step := time.Now().Unix() / 30
	prev, loaded := s.lastTOTPStep.LoadOrStore(userID, step)
	if !loaded {
		return true
	}
	if prev.(int64) >= step {
		return false // replay: already verified in this or a future step
	}
	s.lastTOTPStep.Store(userID, step)
	return true
}

// LoginResult is returned from Login when password verification succeeds.
// Exactly one of NeedsMFAVerify / NeedsMFASetup / MustChangePassword is true.
type LoginResult struct {
	StepUpToken        string
	UserID             uuid.UUID
	NeedsMFAVerify     bool
	NeedsMFASetup      bool
	MustChangePassword bool
}

// Tokens is the access+refresh pair returned on a successful MFA verification.
type Tokens struct {
	AccessToken  string
	RefreshToken string // plaintext; shown once
	ExpiresAt    time.Time
}

// Login checks email+password. On success returns a short-lived step-up token
// and flags indicating which next step (MFA setup / MFA verify / password change)
// the caller must complete. On failure returns one of: ErrInvalidCredentials,
// ErrAccountLocked, ErrAccountInactive.
func (s *Service) Login(ctx context.Context, email, password string, ip net.IP) (*LoginResult, error) {
	u, err := s.Users.FindByEmail(ctx, s.TenantID, email)
	if errors.Is(err, users.ErrNotFound) {
		// Equalize timing with the wrong-password path so the response time does not
		// leak whether the email exists.
		_ = VerifyPassword(password, dummyHash())
		s.writeAudit(ctx, audit.ActorSystem, ip, audit.ActionUserLoginFailure, "user", email,
			map[string]any{"reason": "unknown_email"})
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if !u.Active {
		s.writeAudit(ctx, audit.ActorUser(u.ID), ip, audit.ActionUserLoginFailure, "user", u.ID.String(),
			map[string]any{"reason": "inactive"})
		return nil, ErrAccountInactive
	}
	if u.IsLocked(time.Now()) {
		s.writeAudit(ctx, audit.ActorUser(u.ID), ip, audit.ActionUserLoginFailure, "user", u.ID.String(),
			map[string]any{"reason": "locked"})
		return nil, ErrAccountLocked
	}
	if !VerifyPassword(password, u.PasswordHash) {
		cnt, lock, _ := s.Users.RecordLoginFailure(ctx, s.TenantID, u.ID)
		s.writeAudit(ctx, audit.ActorUser(u.ID), ip, audit.ActionUserLoginFailure, "user", u.ID.String(),
			map[string]any{"reason": "bad_password", "failed_count": cnt})
		if lock != nil {
			s.writeAudit(ctx, audit.ActorUser(u.ID), ip, audit.ActionUserLocked, "user", u.ID.String(),
				map[string]any{"until": lock})
		}
		return nil, ErrInvalidCredentials
	}
	stepUp, err := s.Signer.IssueStepUp(u.ID, s.TenantID, StepUpTokenTTL)
	if err != nil {
		return nil, err
	}
	res := &LoginResult{StepUpToken: stepUp, UserID: u.ID}
	switch {
	case u.MustChangePassword:
		res.MustChangePassword = true
	case u.TOTPSecretEncrypted == nil:
		res.NeedsMFASetup = true
	default:
		res.NeedsMFAVerify = true
	}
	return res, nil
}

// MFAEnrollResult is returned from EnrollMFA. The URI is to be rendered as a QR
// code or copied by the user into their authenticator app. The SetupHandle is
// an opaque encrypted-secret blob that the caller MUST echo back in VerifyMFA
// so the server can complete enrolment (we avoid round-tripping the plaintext
// secret via the client).
type MFAEnrollResult struct {
	URI         string
	SetupHandle string
}

// EnrollMFA is step 2 of the first-login flow for a user that has no TOTP yet.
// stepUpToken must come from a successful Login; the email is the user's email
// (used only to label the otpauth URI for the authenticator app — the caller
// should pass the email from the repository, not from untrusted input).
func (s *Service) EnrollMFA(_ context.Context, stepUpToken, email string) (*MFAEnrollResult, error) {
	if _, _, err := s.Signer.VerifyStepUp(stepUpToken); err != nil {
		return nil, ErrUnauthorized
	}
	enr, err := EnrollTOTP(email, s.Issuer)
	if err != nil {
		return nil, err
	}
	ct, err := Encrypt(s.EncKey, []byte(enr.Secret))
	if err != nil {
		return nil, err
	}
	return &MFAEnrollResult{
		URI:         enr.URI,
		SetupHandle: base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// VerifyMFA completes either (a) mfa-setup when setupHandle != "" or (b) mfa-verify
// against the user's stored secret. On success, records the login and returns
// a fresh access + refresh token pair (the refresh token is the start of a new family).
func (s *Service) VerifyMFA(ctx context.Context, stepUpToken, code, setupHandle, userAgent string, ip net.IP) (*Tokens, error) {
	uid, tid, err := s.Signer.VerifyStepUp(stepUpToken)
	if err != nil {
		return nil, ErrUnauthorized
	}
	u, err := s.Users.FindByID(ctx, tid, uid)
	if err != nil {
		return nil, err
	}
	var ctBlob []byte
	if setupHandle != "" {
		ctBlob, err = base64.StdEncoding.DecodeString(setupHandle)
		if err != nil {
			return nil, ErrMFAInvalid
		}
	} else {
		if u.TOTPSecretEncrypted == nil {
			return nil, ErrMFASetupRequired
		}
		ctBlob = u.TOTPSecretEncrypted
	}
	plain, err := Decrypt(s.EncKey, ctBlob)
	if err != nil {
		return nil, ErrMFAInvalid
	}
	ok, err := VerifyTOTP(string(plain), code)
	if err != nil || !ok {
		return nil, ErrMFAInvalid
	}
	// Replay guard: reject the same TOTP step for this user within its 30s window.
	// Applied even during setup — if a dev test ran two setups in the same second,
	// it's still correct to reject the second one.
	if !s.registerTOTPUse(u.ID) {
		return nil, ErrMFAInvalid
	}
	if setupHandle != "" {
		if err := s.Users.SetTOTP(ctx, tid, u.ID, ctBlob); err != nil {
			return nil, err
		}
		s.writeAudit(ctx, audit.ActorUser(u.ID), ip, audit.ActionUserMFAEnrolled, "user", u.ID.String(), nil)
	}
	if err := s.Users.RecordLoginSuccess(ctx, tid, u.ID, ip); err != nil {
		return nil, err
	}
	s.writeAudit(ctx, audit.ActorUser(u.ID), ip, audit.ActionUserLoginSuccess, "user", u.ID.String(), nil)
	return s.issuePair(ctx, u, userAgent, ip)
}

// issuePair creates access + refresh tokens, records the refresh row (new family), and returns them.
func (s *Service) issuePair(ctx context.Context, u *users.User, ua string, ip net.IP) (*Tokens, error) {
	access, err := s.Signer.IssueAccess(u.ID, u.TenantID, Role(u.Role), u.Email)
	if err != nil {
		return nil, err
	}
	plain, hash, err := users.NewOpaqueToken()
	if err != nil {
		return nil, err
	}
	uaPtr := optStr(ua)
	ipPtr := ipOrNil(ip)
	if _, err := s.Users.CreateRefreshToken(ctx, u.TenantID, u.ID, hash, uuid.Nil, nil, uaPtr, ipPtr); err != nil {
		return nil, err
	}
	return &Tokens{
		AccessToken:  access,
		RefreshToken: plain,
		ExpiresAt:    time.Now().Add(s.Signer.TTL()),
	}, nil
}

// Refresh validates the opaque refresh token, rotates it, and returns a new pair.
// On reuse of a previously-rotated or revoked token, revokes the entire family
// and returns ErrUnauthorized.
func (s *Service) Refresh(ctx context.Context, plain, ua string, ip net.IP) (*Tokens, error) {
	hash := users.HashToken(plain)
	rt, err := s.Users.FindRefreshByHash(ctx, s.TenantID, hash)
	if errors.Is(err, users.ErrRefreshTokenNotFound) {
		return nil, ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	if rt.RevokedAt != nil || rt.ExpiresAt.Before(time.Now()) {
		_ = s.Users.RevokeFamily(ctx, s.TenantID, rt.FamilyID, "reuse_detected")
		_ = s.Users.RevokeAllForUser(ctx, s.TenantID, rt.UserID, "reuse_detected")
		s.writeAudit(ctx, audit.ActorUser(rt.UserID), ip, audit.ActionTokenRefreshReuseDetect,
			"refresh_token", rt.ID.String(), nil)
		return nil, ErrUnauthorized
	}
	u, err := s.Users.FindByID(ctx, s.TenantID, rt.UserID)
	if err != nil {
		return nil, err
	}
	if !u.Active {
		return nil, ErrAccountInactive
	}
	_ = s.Users.RevokeRefresh(ctx, s.TenantID, rt.ID, "rotation")
	access, err := s.Signer.IssueAccess(u.ID, u.TenantID, Role(u.Role), u.Email)
	if err != nil {
		return nil, err
	}
	newPlain, newHash, err := users.NewOpaqueToken()
	if err != nil {
		return nil, err
	}
	if _, err := s.Users.CreateRefreshToken(ctx, u.TenantID, u.ID, newHash, rt.FamilyID, &rt.ID, optStr(ua), ipOrNil(ip)); err != nil {
		return nil, err
	}
	s.writeAudit(ctx, audit.ActorUser(u.ID), ip, audit.ActionTokenRefreshRotated,
		"refresh_token", rt.ID.String(), nil)
	return &Tokens{
		AccessToken:  access,
		RefreshToken: newPlain,
		ExpiresAt:    time.Now().Add(s.Signer.TTL()),
	}, nil
}

// Logout revokes the specified refresh token (by its plaintext value).
// Idempotent on unknown/already-revoked tokens.
func (s *Service) Logout(ctx context.Context, plainRefresh string, actorUserID uuid.UUID, ip net.IP) error {
	if plainRefresh != "" {
		hash := users.HashToken(plainRefresh)
		rt, err := s.Users.FindRefreshByHash(ctx, s.TenantID, hash)
		if err == nil && rt.RevokedAt == nil {
			_ = s.Users.RevokeRefresh(ctx, s.TenantID, rt.ID, "logout")
		}
	}
	s.writeAudit(ctx, audit.ActorUser(actorUserID), ip, audit.ActionUserLogout,
		"user", actorUserID.String(), nil)
	return nil
}

// LogoutAll revokes every active refresh token for actorUserID.
func (s *Service) LogoutAll(ctx context.Context, actorUserID uuid.UUID, ip net.IP) error {
	if err := s.Users.RevokeAllForUser(ctx, s.TenantID, actorUserID, "logout_all"); err != nil {
		return err
	}
	s.writeAudit(ctx, audit.ActorUser(actorUserID), ip, audit.ActionUserLogoutAll,
		"user", actorUserID.String(), nil)
	return nil
}

// ChangePassword is self-service: requires current password + TOTP code + new password.
// On success, revokes every existing refresh token (user must re-login).
func (s *Service) ChangePassword(ctx context.Context, userID uuid.UUID, current, next, totpCode string, ip net.IP) error {
	u, err := s.Users.FindByID(ctx, s.TenantID, userID)
	if err != nil {
		return err
	}
	if !VerifyPassword(current, u.PasswordHash) {
		return ErrInvalidCredentials
	}
	if u.TOTPSecretEncrypted == nil {
		return ErrMFASetupRequired
	}
	// Validate the new password policy up-front so a rejected password does not
	// consume the per-user TOTP step (replay guard).
	if err := validatePasswordPolicy(next); err != nil {
		return err
	}
	plain, err := Decrypt(s.EncKey, u.TOTPSecretEncrypted)
	if err != nil {
		return err
	}
	ok, err := VerifyTOTP(string(plain), totpCode)
	if err != nil || !ok {
		return ErrMFAInvalid
	}
	if !s.registerTOTPUse(u.ID) {
		return ErrMFAInvalid
	}
	h, err := HashPassword(next)
	if err != nil {
		return err
	}
	if err := s.Users.SetPasswordAndRevokeAll(ctx, s.TenantID, u.ID, h, false, "password_change"); err != nil {
		return err
	}
	s.writeAudit(ctx, audit.ActorUser(u.ID), ip, audit.ActionUserPasswordChanged,
		"user", u.ID.String(), nil)
	return nil
}

// ResetPasswordByAdmin generates a random temporary password for the target user,
// marks must_change_password=true, revokes all existing sessions, and returns the
// plaintext temporary password (shown once to the admin).
func (s *Service) ResetPasswordByAdmin(ctx context.Context, adminID, userID uuid.UUID, ip net.IP) (tempPassword string, err error) {
	tempPassword, err = RandomPassword(16)
	if err != nil {
		return "", err
	}
	h, err := HashPassword(tempPassword)
	if err != nil {
		return "", err
	}
	if err := s.Users.SetPasswordAndRevokeAll(ctx, s.TenantID, userID, h, true, "password_reset"); err != nil {
		return "", err
	}
	s.writeAudit(ctx, audit.ActorUser(adminID), ip, audit.ActionUserPasswordResetByAdmin,
		"user", userID.String(), nil)
	return tempPassword, nil
}

// writeAudit is the fail-open helper used by all Service methods.
func (s *Service) writeAudit(ctx context.Context, actor string, ip net.IP, a audit.Action, resType, resID string, details map[string]any) {
	if s.Audit == nil {
		return
	}
	_ = s.Audit.Write(ctx, audit.Event{
		TenantID:     s.TenantID,
		Actor:        actor,
		Action:       a,
		ResourceType: resType,
		ResourceID:   resID,
		SourceIP:     ip,
		Details:      details,
	})
}

func optStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func ipOrNil(ip net.IP) *net.IP {
	if ip == nil {
		return nil
	}
	return &ip
}

// validatePasswordPolicy enforces length only (NIST 800-63B).
func validatePasswordPolicy(p string) error {
	if len(p) < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	return nil
}

// RandomPassword returns a URL-safe random password of length n.
func RandomPassword(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	s := base64.RawURLEncoding.EncodeToString(buf)
	if len(s) > n {
		s = s[:n]
	}
	return s, nil
}
