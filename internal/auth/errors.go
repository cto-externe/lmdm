// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package auth

import "errors"

// Sentinel errors surfaced by the auth service and middleware.
var (
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrMFARequired        = errors.New("mfa required")
	ErrMFAInvalid         = errors.New("invalid mfa code")
	ErrMFASetupRequired   = errors.New("mfa setup required")
	ErrAccountLocked      = errors.New("account locked")
	ErrAccountInactive    = errors.New("account inactive")
	ErrMustChangePassword = errors.New("password change required")
	ErrTooManyRequests    = errors.New("too many requests")
)
