package graph.elm_governance_group_membership_9

__target__ := "microsoft.graph.policy"

__metadata__ := {
    "title": "ELM Only Group Member/Owner Governance Policy 8",
    "description": "Limit Entra Group Member/Owner management to authorized governance applications.",
    "version": "1.0.0"
}

__applicable__ := {
    "resourceName": "microsoft.graph.group",
    "operations": ["create", "updateOrUpsert"]
}

default effect := "deny"
default params.allowed_list := [
    "ff177ae3-6045-4264-8733-f1364466bf47",
    "5c8e7a0b-1d9b-4cbd-8cbd-1c3fbbd9e5c0",
    "de8bc8b5-d9f9-48b1-a8ad-b748da725064",
]

# ---------------------------------------------------------------------------
# Key path for fetch URL (supports alternate key)
# ---------------------------------------------------------------------------
key_path := sprintf("('%s')", [input.request.resourceKeys.id]) if {
    input.request.resourceKeys.id
} else := sprintf("(uniqueName='%s')", [input.request.resourceKeys.uniqueName]) if {
    input.request.resourceKeys.uniqueName
}

# ---------------------------------------------------------------------------
# Fetch governance settings for the group
# ---------------------------------------------------------------------------
fetchResponse := fetch({"relativePathUri": sprintf("/groups%s/governanceSettings", [key_path])})

# ---------------------------------------------------------------------------
# Helper rules
# ---------------------------------------------------------------------------

# Fetch returned HTTP 200
default isFetchSuccess := false
isFetchSuccess if {
    not fetchResponse == null
    fetchResponse.code == 200
}

# managedState is "enforced"
default isManagedStateEnforced := false
isManagedStateEnforced if {
    isFetchSuccess
    fetchResponse.data.managedState == "enforced"
}

# managedState is "reportOnly"
default isManagedStateReportOnly := false
isManagedStateReportOnly if {
    isFetchSuccess
    fetchResponse.data.managedState == "reportOnly"
}

# Response is neither 200 nor 403/404 (unexpected error)
default isNot200AndNot403 := false
isNot200AndNot403 if {
    fetchResponse == null
}
isNot200AndNot403 if {
    not fetchResponse == null
    not fetchResponse.code == 200
    not fetchResponse.code == 403
    not fetchResponse.code == 404
}

# ---------------------------------------------------------------------------
# applicable = (appId NOT in allowed list)
#   AND [ (isFetchSuccess AND (isManagedStateEnforced OR isManagedStateReportOnly))
#          OR isNot200AndNot403 ]
#
# - Allowed app          → not applicable (no block)
# - 200 + enforced       → applicable, denied
# - 200 + reportOnly     → applicable, not denied
# - 403 / 404            → not applicable (no block)
# - Any other error      → applicable, denied with error details
# ---------------------------------------------------------------------------
default applicable := false

applicable if {
    not input.request.authContext.appid in params.allowed_list
    isFetchSuccess
    isManagedStateEnforced
}

applicable if {
    not input.request.authContext.appid in params.allowed_list
    isFetchSuccess
    isManagedStateReportOnly
}

applicable if {
    not input.request.authContext.appid in params.allowed_list
    isNot200AndNot403
}

# ---------------------------------------------------------------------------
# deny = isManagedStateEnforced OR isNot200AndNot403
# (reportOnly → applicable but NOT denied)
# ---------------------------------------------------------------------------
default deny := {"result": false, "reasons": []}

deny := {"result": true, "reasons": [
    "Entra Group Member/Owner management is governed by Entra Identity Governance and cannot be modified by other applications",
]} if {
    isManagedStateEnforced
} else := {"result": true, "reasons": [
    sprintf("Governance settings check failed with unexpected error: %v", [fetchResponse]),
]} if {
    isNot200AndNot403
}
