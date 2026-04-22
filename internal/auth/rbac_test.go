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
		PermDeploymentsRead, PermDeploymentsManage,
		PermDevicesRevoke,
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

func TestHasPermission_DevicesRevoke_AdminOnly(t *testing.T) {
	if !HasPermission(RoleAdmin, PermDevicesRevoke) {
		t.Error("admin should be able to revoke devices")
	}
	if HasPermission(RoleOperator, PermDevicesRevoke) {
		t.Error("operator must not revoke devices (admin-only lockout action)")
	}
	if HasPermission(RoleViewer, PermDevicesRevoke) {
		t.Error("viewer must not revoke devices")
	}
}

func TestHasPermission_DeploymentsPerOperatorAndViewer(t *testing.T) {
	if !HasPermission(RoleOperator, PermDeploymentsManage) {
		t.Error("operator should be able to manage deployments")
	}
	if !HasPermission(RoleViewer, PermDeploymentsRead) {
		t.Error("viewer should be able to read deployments")
	}
	if HasPermission(RoleViewer, PermDeploymentsManage) {
		t.Error("viewer must not manage deployments")
	}
}

func TestHasPermission_PatchManagementRoles(t *testing.T) {
	// Admin has all three patch management permissions.
	if !HasPermission(RoleAdmin, PermPatchSchedulesRead) {
		t.Error("admin must have patch_schedules.read")
	}
	if !HasPermission(RoleAdmin, PermPatchSchedulesManage) {
		t.Error("admin must have patch_schedules.manage")
	}
	if !HasPermission(RoleAdmin, PermDevicesReboot) {
		t.Error("admin must have devices.reboot")
	}

	// Operator has all three patch management permissions (can plan + trigger reboots).
	if !HasPermission(RoleOperator, PermPatchSchedulesRead) {
		t.Error("operator must have patch_schedules.read")
	}
	if !HasPermission(RoleOperator, PermPatchSchedulesManage) {
		t.Error("operator must have patch_schedules.manage")
	}
	if !HasPermission(RoleOperator, PermDevicesReboot) {
		t.Error("operator must have devices.reboot")
	}

	// Viewer has only read access — no manage or reboot.
	if !HasPermission(RoleViewer, PermPatchSchedulesRead) {
		t.Error("viewer must have patch_schedules.read")
	}
	if HasPermission(RoleViewer, PermPatchSchedulesManage) {
		t.Error("viewer must NOT have patch_schedules.manage")
	}
	if HasPermission(RoleViewer, PermDevicesReboot) {
		t.Error("viewer must NOT have devices.reboot")
	}
}
