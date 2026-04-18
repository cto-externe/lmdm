// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package auth

import (
	"context"

	"github.com/google/uuid"
)

// Principal is the authenticated caller extracted from a valid JWT.
type Principal struct {
	UserID   uuid.UUID
	TenantID uuid.UUID
	Role     Role
	Email    string
}

type ctxKey struct{}

// WithPrincipal stores p on ctx.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// PrincipalFrom returns the principal if present, or nil.
func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}
