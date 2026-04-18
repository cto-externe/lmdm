// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package users is the repository for console users and refresh tokens.
package users

import (
	"net"
	"time"

	"github.com/google/uuid"
)

// User is a console account row.
type User struct {
	ID                  uuid.UUID
	TenantID            uuid.UUID
	Email               string
	PasswordHash        string
	Role                string
	TOTPSecretEncrypted []byte
	TOTPEnrolledAt      *time.Time
	MustChangePassword  bool
	Active              bool
	FailedLoginCount    int
	LockedUntil         *time.Time
	LastLoginAt         *time.Time
	LastLoginIP         *net.IP
	DeactivatedAt       *time.Time
	DeactivatedByUserID *uuid.UUID
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// IsLocked returns true if the account is currently locked.
func (u *User) IsLocked(now time.Time) bool {
	return u.LockedUntil != nil && u.LockedUntil.After(now)
}

// ListFilter is used by List().
type ListFilter struct {
	Role       string
	ActiveOnly bool
	Limit      int
	Offset     int
}
