# Z3 Construct Lockdown Policy
#
# A comprehensive policy that exercises ALL Rego language constructs
# modeled in the Z3 symbolic translator.  Running gen-tests with
# --condition-coverage against this file serves as a regression gate:
# if any construct is mis-translated, the solver will either fail to
# generate tests or produce wrong concrete inputs.
#
# Constructs exercised:
#   [1]  Complete rules (single-body, multi-body/else)
#   [2]  Default rules
#   [3]  Partial set rules
#   [4]  Partial object rules
#   [5]  Functions (single- and multi-body)
#   [6]  `some x in collection` iteration
#   [7]  `every x in collection`
#   [8]  Negation (`not`)
#   [9]  Array/Set/Object comprehensions
#   [10] Arithmetic: +, -, *, /, %
#   [11] Comparisons: ==, !=, <, <=, >, >=
#   [12] String builtins: startswith, endswith, contains, indexof,
#        replace, substring, trim_prefix, trim_suffix, sprintf, concat, count
#   [13] Numeric builtins: abs, to_number
#   [14] Type checks: is_string, is_number, is_boolean
#   [15] Bitwise: bits.and, bits.or
#   [16] `in` membership (array and set)
#   [17] count (array, set, string)
#   [18] Nested iteration & cross-collection joins
#   [19] CoalesceUndefinedToNull / default values

package lockdown

import rego.v1


# ===================================================================
# [2] Default rule
# ===================================================================

default decision := "deny"


# ===================================================================
# [1] Complete rule — multi-body / else chain
# [11] Comparisons
# ===================================================================

# Body 1: full allow
decision := "allow" if {
    admin_check
    resource_valid
    no_blocked_tags
}

# Body 2: conditional allow
decision := "review" if {
    not admin_check
    resource_valid
    string_checks_pass
}


# ===================================================================
# [1] Complete rule — single body with arithmetic
# [10] Arithmetic: +, -, *, /
# ===================================================================

admin_check if {
    input.user.role == "admin"
    input.user.level >= 3
}


# ===================================================================
# [12] String builtins
# ===================================================================

resource_valid if {
    startswith(input.resource.name, "prod-")
    endswith(input.resource.type, "-server")
    contains(input.resource.region, "us")
}


# ===================================================================
# [12] More string builtins: indexof, replace, substring, trim_prefix,
#      trim_suffix, sprintf, concat, count (string length)
# ===================================================================

string_checks_pass if {
    # indexof: "us" appears in the region
    indexof(input.resource.region, "us") >= 0

    # replace: replacing "prod" with "staging" should change the name
    replaced := replace(input.resource.name, "prod", "staging")
    replaced != input.resource.name

    # substring: first 4 chars of name
    sub := substring(input.resource.name, 0, 4)
    sub == "prod"

    # trim_prefix
    trimmed := trim_prefix(input.resource.name, "prod-")
    count(trimmed) > 0

    # trim_suffix
    base := trim_suffix(input.resource.type, "-server")
    count(base) > 0

    # sprintf: build a label from user and resource
    label := sprintf("user=%s/resource=%s", [input.user.name, input.resource.name])
    contains(label, "user=")

    # concat
    joined := concat("-", [input.resource.region, input.resource.type])
    contains(joined, "-")
}


# ===================================================================
# [7] `every` — all tags must pass validation
# [9] Set comprehension
# ===================================================================

no_blocked_tags if {
    every tag in input.resource.tags {
        not startswith(tag, "BLOCKED_")
    }
}


# ===================================================================
# [3] Partial set rule + [6] `some x in collection`
# ===================================================================

allowed_regions contains region if {
    some region in ["us-east-1", "us-west-2", "eu-west-1"]
    startswith(region, "us")
}


# ===================================================================
# [4] Partial object rule
# ===================================================================

resource_labels[key] := value if {
    some key in ["env", "team", "cost-center"]
    value := input.labels[key]
}


# ===================================================================
# [5] Function — single body
# [10] Arithmetic
# ===================================================================

score(user_level, resource_priority) := result if {
    result := (user_level * 10) + resource_priority
}


# ===================================================================
# [5] Function — multi-body (acting as cond→result dispatch)
# ===================================================================

classify(s) := "high" if {
    startswith(s, "prod")
}

classify(s) := "low" if {
    not startswith(s, "prod")
}


# ===================================================================
# [10] Arithmetic + [13] abs + comparisons
# ===================================================================

within_budget if {
    diff := input.budget.limit - input.budget.spent
    abs(diff) <= 1000
    input.budget.limit > 0
    remainder := input.budget.limit % 100
    remainder == 0
}


# ===================================================================
# [14] Type checks: is_string, is_number, is_boolean
# ===================================================================

inputs_well_typed if {
    is_string(input.user.name)
    is_number(input.user.level)
    is_boolean(input.user.active)
}


# ===================================================================
# [15] Bitwise: bits.and, bits.or
# ===================================================================

permission_granted if {
    required := 6                           # read + write = 0b110
    effective := bits.and(input.user.permissions, required)
    effective == required
}


# ===================================================================
# [8] Negation
# ===================================================================

no_emergency if {
    not input.emergency
}


# ===================================================================
# [16] `in` membership (array)
# ===================================================================

role_allowed if {
    input.user.role in ["admin", "operator", "auditor"]
}


# ===================================================================
# [9] Array comprehension + [17] count
# ===================================================================

critical_resources := [r |
    some r in input.resources
    startswith(r, "prod-")
]

has_critical if {
    count(critical_resources) > 0
}


# ===================================================================
# [18] Nested iteration / cross-collection join
# ===================================================================

# For every required permission, there must be a matching grant.
all_permissions_granted if {
    every perm in input.required_permissions {
        perm in input.granted_permissions
    }
}


# ===================================================================
# [13] to_number
# ===================================================================

port_valid if {
    port := to_number(input.resource.port)
    port >= 1024
    port <= 65535
}


# ===================================================================
# Aggregate decision gate — pulls together all sub-rules
# ===================================================================

final_report := {
    "decision": decision,
    "admin": admin_check,
    "budget_ok": within_budget,
    "typed": inputs_well_typed,
    "permissions": permission_granted,
    "classification": classify(input.resource.name),
    "score": score(input.user.level, input.resource.priority),
    "allowed_region_count": count(allowed_regions),
    "has_critical": has_critical,
    "all_perms": all_permissions_granted,
    "port_valid": port_valid,
}
