package graph.elm_governance_group_membership

# ============================================================
# Azure Graph Service — ELM Group Governance Policy
# ============================================================
#
# Scenario
# --------
# Azure Graph Service (AGS) evaluates this policy when a caller
# attempts to create or update an Entra group's membership or
# ownership.  The policy enforces that only authorized governance
# applications (identified by appId) may modify groups that are
# under Entra Identity Governance (ELM) management.
#
# Input
# -----
#   input.request.authContext.appid  – caller application UUID
#   input.fetchResponse              – pre-fetched governance settings
#       .code                        – HTTP status code (integer)
#       .data.managedState           – "enforced" | "reportOnly"
#
# The fetchResponse is modeled as input rather than calling
# fetch() at analysis time, so Z3 can reason symbolically about
# all possible fetch outcomes.
#
# Decision matrix
# ---------------
#   Allowed app (in list)         → not applicable (allow)
#   200 + enforced                → applicable, denied
#   200 + reportOnly              → applicable, allowed (audit only)
#   403 / 404                     → not applicable (allow)
#   null or unexpected HTTP code  → applicable, denied (fail-closed)
#
# Why this is interesting for Z3
# ------------------------------
# The policy has 5 distinct decision paths combining caller
# identity (in/not-in allowed list) with fetch outcomes (success
# with two states, expected errors, unexpected errors, null).
# Z3 can enumerate all reachable paths, prove subsumption
# between policy variants, and generate a minimal test suite
# covering every branch.
# ============================================================

default effect := "deny"

default params_allowed_list := [
    "ff177ae3-6045-4264-8733-f1364466bf47",
    "5c8e7a0b-1d9b-4cbd-8cbd-1c3fbbd9e5c0",
    "de8bc8b5-d9f9-48b1-a8ad-b748da725064",
]

# ---------------------------------------------------------------------------
# Helper rules
# ---------------------------------------------------------------------------

# Fetch returned HTTP 200
default isFetchSuccess := false
isFetchSuccess if {
    not input.fetchResponse == null
    input.fetchResponse.code == 200
}

# managedState is "enforced"
default isManagedStateEnforced := false
isManagedStateEnforced if {
    isFetchSuccess
    input.fetchResponse.data.managedState == "enforced"
}

# managedState is "reportOnly"
default isManagedStateReportOnly := false
isManagedStateReportOnly if {
    isFetchSuccess
    input.fetchResponse.data.managedState == "reportOnly"
}

# Response is neither 200 nor 403/404 (unexpected error → fail-closed)
default isUnexpectedError := false
isUnexpectedError if {
    input.fetchResponse == null
}
isUnexpectedError if {
    not input.fetchResponse == null
    not input.fetchResponse.code == 200
    not input.fetchResponse.code == 403
    not input.fetchResponse.code == 404
}

# ---------------------------------------------------------------------------
# applicable = (appId NOT in allowed list)
#   AND [ (isFetchSuccess AND (enforced OR reportOnly))
#          OR isUnexpectedError ]
# ---------------------------------------------------------------------------
default applicable := false
applicable if {
    not input.request.authContext.appid in params_allowed_list
    isFetchSuccess
    isManagedStateEnforced
}
applicable if {
    not input.request.authContext.appid in params_allowed_list
    isFetchSuccess
    isManagedStateReportOnly
}
applicable if {
    not input.request.authContext.appid in params_allowed_list
    isUnexpectedError
}

# ---------------------------------------------------------------------------
# deny = applicable AND (enforced OR unexpected error)
# (reportOnly → applicable but NOT denied)
# ---------------------------------------------------------------------------
default deny := {"result": false, "reasons": []}
deny := {"result": true, "reasons": [
    "Entra Group Member/Owner management is governed by Entra Identity Governance and cannot be modified by other applications",
]} if {
    applicable
    isManagedStateEnforced
} else := {"result": true, "reasons": [
    "Governance settings check failed with unexpected error",
]} if {
    applicable
    isUnexpectedError
}

# Boolean projection for Z3 analysis (Z3 cannot yet select between
# concrete objects conditionally; this mirrors the deny decision as
# a plain boolean without depending on the object-valued deny rule).
default deny_result := false
deny_result if {
    applicable
    isManagedStateEnforced
}
deny_result if {
    applicable
    isUnexpectedError
}
