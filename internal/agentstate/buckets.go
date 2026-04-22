// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package agentstate

// Bucket names for the BoltDB file.
var (
	bucketPendingDeployment = []byte("pending_deployment")
)

// Single-slot key for the current pending deployment.
var keyCurrent = []byte("current")

var bucketPatchDefer = []byte("patch_defer")
var keyDeferCounter = []byte("reboot_defer")
