// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package auth

// Permission is an abstract right keyed to concrete routes.
type Permission string

// Permission values recognized by the RBAC matrix. Each maps 1:1 to a concrete
// HTTP route (see spec §6.4.3 and the auth/RBAC brainstorm).
const (
	PermDevicesRead    Permission = "devices.read"
	PermInventoryRead  Permission = "inventory.read"
	PermComplianceRead Permission = "compliance.read"
	PermUpdatesRead    Permission = "updates.read"
	PermUpdatesApply   Permission = "updates.apply"
	PermProfilesRead   Permission = "profiles.read"
	PermProfilesCreate Permission = "profiles.create"
	PermProfilesAssign Permission = "profiles.assign"
	PermTokensRead     Permission = "tokens.read"
	PermTokensCreate   Permission = "tokens.create"
	PermUsersRead      Permission = "users.read"
	PermUsersManage    Permission = "users.manage"

	PermDeploymentsRead   Permission = "deployments.read"
	PermDeploymentsManage Permission = "deployments.manage"

	// PermDevicesRevoke authorizes revoking a device's agent certificate.
	// Admin-only: revocation is an irreversible lockout that forces the device
	// to re-enroll before it can reconnect.
	PermDevicesRevoke Permission = "devices.revoke"
)

// rolePerms maps each role to the set of permissions it holds.
// See spec §6.4.3 + the matrix finalized in the auth/RBAC brainstorm.
var rolePerms = map[Role]map[Permission]struct{}{
	RoleAdmin: {
		PermDevicesRead: {}, PermInventoryRead: {}, PermComplianceRead: {},
		PermUpdatesRead: {}, PermUpdatesApply: {},
		PermProfilesRead: {}, PermProfilesCreate: {}, PermProfilesAssign: {},
		PermTokensRead: {}, PermTokensCreate: {},
		PermUsersRead: {}, PermUsersManage: {},
		PermDeploymentsRead: {}, PermDeploymentsManage: {},
		PermDevicesRevoke: {},
	},
	RoleOperator: {
		PermDevicesRead: {}, PermInventoryRead: {}, PermComplianceRead: {},
		PermUpdatesRead: {}, PermUpdatesApply: {},
		PermProfilesRead: {}, PermProfilesAssign: {},
		PermTokensRead: {}, PermTokensCreate: {},
		PermDeploymentsRead: {}, PermDeploymentsManage: {},
	},
	RoleViewer: {
		PermDevicesRead: {}, PermInventoryRead: {}, PermComplianceRead: {},
		PermUpdatesRead:     {},
		PermProfilesRead:    {},
		PermDeploymentsRead: {},
	},
}

// HasPermission returns true iff role is allowed to exercise perm.
func HasPermission(role Role, perm Permission) bool {
	perms, ok := rolePerms[role]
	if !ok {
		return false
	}
	_, ok = perms[perm]
	return ok
}
