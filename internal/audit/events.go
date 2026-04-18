// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

// Package audit writes append-only events into the audit_log table.
package audit

// Action is a stable identifier for an audit event.
// Use one of the constants below rather than free-form strings, so grep / dashboards
// can rely on a known vocabulary.
type Action string

// Known audit actions. Add new values here rather than passing raw strings so
// downstream consumers (SIEM dashboards, grep audits) can enumerate the full
// vocabulary.
const (
	ActionUserLoginSuccess         Action = "user.login.success"
	ActionUserLoginFailure         Action = "user.login.failure"
	ActionUserLogout               Action = "user.logout"
	ActionUserLogoutAll            Action = "user.logout_all"
	ActionUserLocked               Action = "user.locked"
	ActionUserUnlocked             Action = "user.unlocked"
	ActionUserCreated              Action = "user.created"
	ActionUserDeactivated          Action = "user.deactivated"
	ActionUserReactivated          Action = "user.reactivated"
	ActionUserRoleChanged          Action = "user.role_changed"
	ActionUserPasswordChanged      Action = "user.password_changed"
	ActionUserPasswordResetByAdmin Action = "user.password_reset_by_admin"
	ActionUserMFAEnrolled          Action = "user.mfa.enrolled"
	ActionUserMFAReset             Action = "user.mfa.reset"
	ActionTokenRefreshRotated      Action = "token.refresh.rotated"
	ActionTokenRefreshReuseDetect  Action = "token.refresh.reuse_detected"
	ActionProfileCreated           Action = "profile.created"
	ActionProfileAssigned          Action = "profile.assigned"
	ActionEnrollmentTokenCreated   Action = "enrollment_token.created"
	ActionDeviceUpdatesApplied     Action = "device_updates.applied"
)
