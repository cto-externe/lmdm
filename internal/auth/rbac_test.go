// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package auth

import "testing"

func TestHasPermission_Admin_FullSet(t *testing.T) {
	all := []Permission{
		PermDevicesRead, PermInventoryRead, PermComplianceRead,
		PermUpdatesRead, PermUpdatesApply,
		PermProfilesRead, PermProfilesCreate, PermProfilesAssign,
		PermTokensRead, PermTokensCreate,
		PermUsersRead, PermUsersManage,
	}
	for _, p := range all {
		if !HasPermission(RoleAdmin, p) {
			t.Errorf("admin missing %s", p)
		}
	}
}

func TestHasPermission_ViewerIsReadOnly(t *testing.T) {
	if HasPermission(RoleViewer, PermUpdatesApply) {
		t.Error("viewer should not apply updates")
	}
	if HasPermission(RoleViewer, PermProfilesCreate) {
		t.Error("viewer should not create profiles")
	}
	if HasPermission(RoleViewer, PermUsersManage) {
		t.Error("viewer should not manage users")
	}
}

func TestHasPermission_OperatorCannotCreateProfiles(t *testing.T) {
	if HasPermission(RoleOperator, PermProfilesCreate) {
		t.Error("operator should not create profiles (admin-only per matrix)")
	}
	if !HasPermission(RoleOperator, PermProfilesAssign) {
		t.Error("operator should assign profiles")
	}
}

func TestHasPermission_UnknownRoleDenied(t *testing.T) {
	if HasPermission(Role("owner"), PermDevicesRead) {
		t.Error("unknown role should be denied")
	}
}
