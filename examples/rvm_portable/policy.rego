# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package example.authz

import rego.v1

default allow := false

# Allow when the caller holds a role that grants the requested action on the
# requested resource.
allow if {
	some role in data.roles[input.user]
	some permission in data.role_permissions[role]
	permission.action == input.action
	permission.resource == input.resource
}

# Every role granted to the caller, as a set.
user_roles contains role if {
	some role in data.roles[input.user]
}

# A human readable reason, useful for checking string handling in a loader.
reason := sprintf("user %v requested %v on %v", [input.user, input.action, input.resource])

# Exercises numbers, arrays and objects in the literal table.
limits := {
	"max_items": 128,
	"ratio": 0.25,
	"tiers": [1, 2, 3],
}
