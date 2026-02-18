# Host-Side Features — Out of Compiler Scope

This document describes Azure Policy features that are **not part of the
compiler**. They are handled by the host orchestration layer — the system that
decides *which* policies to evaluate, *when* to evaluate them, and *how* to
present results.

The compiler's job ends at producing an RVM program from a policy rule JSON.
Everything below happens before or after that compiled program runs.

See also: [compiler.md §1.4](compiler.md#14-feature-complexity-tiers) for
the in-scope complexity tiers.

---

## 1. Policy Exemptions

**What**: An exemption is an Azure Resource Manager (ARM) resource
(`Microsoft.Authorization/policyExemptions`) that grants a specific resource or
scope a waiver from one or more policy assignments.

**Exemption categories**:
- **Waiver** — the resource is known to violate the policy, but the violation
  is accepted (temporarily or permanently). Compliance state shows as "Waived."
- **Mitigated** — the resource violates the policy's condition, but a
  compensating control exists outside the policy's visibility. Compliance state
  shows as "Mitigated."

**Why it's host-side**: The host checks exemptions *before* invoking the
compiled program. If an exemption applies, the policy is never evaluated — the
host short-circuits and records the appropriate compliance state directly.
The compiler has no knowledge of exemptions; it simply compiles the policy rule.

**Relevant ARM properties**:
- `policyAssignmentId` — which assignment is exempted
- `policyDefinitionReferenceIds` — which policies within an initiative
- `exemptionCategory` — `"Waiver"` or `"Mitigated"`
- `expiresOn` — optional expiration timestamp

---

## 2. Resource Selectors

**What**: Resource selectors (`resourceSelectors`) are an assignment-level
feature that lets administrators narrow which resources a policy applies to,
based on attributes like resource location or resource type.

**Structure**:
```json
{
  "resourceSelectors": [
    {
      "name": "LocationSelector",
      "selectors": [
        { "kind": "resourceLocation", "in": ["eastus", "westus2"] }
      ]
    }
  ]
}
```

**Selector kinds**:
- `resourceLocation` — filter by Azure region
- `resourceType` — filter by ARM resource type
- `resourceWithoutLocation` — match resources that have no location

**Why it's host-side**: Selectors are evaluated by the host *before* policy
evaluation begins. They filter the set of resources that reach the compiler's
output program. The compiled program itself is unaware of these filters — it
evaluates whatever resource it receives.

---

## 3. Policy Mode

**What**: The `mode` property on a policy definition controls which resource
types are evaluated.

**Standard modes**:
- **`All`** — evaluates all resource types and resource groups
- **`Indexed`** — evaluates only resource types that support tags and location
  (the vast majority of policies use this mode)

**Resource Provider modes** (for specialized scenarios):
- `Microsoft.Kubernetes.Data` — Kubernetes admission control via Gatekeeper
- `Microsoft.KeyVault.Data` — Key Vault certificate/key/secret policies
- `Microsoft.Network.Data` — custom network security rules
- `Microsoft.ManagedHSM.Data` — managed HSM key policies
- `Microsoft.DataFactory.Data` — Data Factory link restrictions
- `Microsoft.MachineLearningServices.v2.Data` — ML workspace policies

**Why it's host-side**: The mode determines *which resources enter the
evaluation pipeline*. The host uses the mode to filter the resource inventory.
Once a resource reaches the compiled program, the mode has already served its
purpose. Resource Provider modes also fundamentally change the evaluation model
(e.g., Kubernetes mode sends admission review payloads, not ARM resources) —
this compiler targets standard ARM resource evaluation only.

---

## 4. Assignment Overrides

**What**: Policy assignment overrides let administrators change the effect of a
policy *at the assignment level* without modifying the policy definition.

**Structure**:
```json
{
  "overrides": [
    {
      "kind": "policyEffect",
      "value": "Disabled",
      "selectors": [
        { "kind": "resourceLocation", "in": ["westus"] }
      ]
    }
  ]
}
```

**How they work**: An override replaces the policy's declared effect (e.g.,
`deny` → `audit`, or `audit` → `disabled`) for resources matching optional
selectors. The `selectors` in overrides use the same mechanism as resource
selectors (§2 above).

**Why it's host-side**: The compiled program produces a *requested* effect. The
host intercepts this output and applies overrides before taking action. The
compiler doesn't need to know about overrides — it simply compiles the policy
as-is. Effect resolution at runtime is: `override effect > assignment parameter
effect > definition default effect`.

---

## 5. Non-Compliance Messages

**What**: The `nonComplianceMessages` property on a policy assignment provides
custom human-readable text that appears when a resource is non-compliant.

**Structure**:
```json
{
  "nonComplianceMessages": [
    {
      "message": "Virtual machines must use managed disks — contact your cloud team.",
      "policyDefinitionReferenceId": "diskPolicyRef"
    }
  ]
}
```

**Key points**:
- Messages are purely display text — they don't affect evaluation logic
- For initiative assignments, `policyDefinitionReferenceId` targets a specific
  policy within the initiative
- A message without `policyDefinitionReferenceId` becomes the default for all
  policies in the assignment

**Why it's host-side**: Non-compliance messages are metadata attached to the
assignment, not the policy rule. The compiler produces a compliance result
(compliant/non-compliant + effect); the host enriches that result with the
message text for display in the portal, API responses, and compliance reports.

---

## 6. Compliance Reason Codes

**What**: When a resource is non-compliant, the compliance record can include
structured reason codes that explain *why* — e.g., which specific field
condition failed.

**Why it's host-side**: Reason codes are assembled by the host from the
evaluation trace, not emitted by the compiled program. The compiler's output
is a boolean compliance result plus an effect. The host maps failing conditions
back to the policy definition structure to produce human-readable reasons.

---

## 7. Initiatives (Policy Sets)

**What**: An initiative (`Microsoft.Authorization/policySetDefinitions`) groups
multiple policy definitions and passes shared parameters to each.

**Structure** (simplified):
```json
{
  "policyDefinitions": [
    {
      "policyDefinitionId": "/providers/.../policyDefinitions/require-tag",
      "policyDefinitionReferenceId": "requireTagRef",
      "parameters": {
        "tagName": { "value": "[parameters('requiredTag')]" }
      }
    }
  ],
  "parameters": {
    "requiredTag": { "type": "String", "defaultValue": "CostCenter" }
  }
}
```

**Why it's host-side**: Each policy in an initiative compiles individually — the
compiler receives a single policy definition at a time. The host is responsible
for:
- Resolving initiative-level parameters and passing them through to each policy
- Dispatching the resource to each compiled program
- Aggregating per-policy results into an initiative-level compliance state
- Applying exemptions and overrides scoped to specific policies within the
  initiative (via `policyDefinitionReferenceId`)

---

## Summary

| Feature | Host responsibility | Compiler impact |
|:--------|:-------------------|:----------------|
| Exemptions | Skip evaluation entirely | None |
| Resource selectors | Filter resources before evaluation | None |
| Policy mode | Determine which resources are in scope | None |
| Assignment overrides | Override effect after evaluation | None |
| Non-compliance messages | Enrich compliance results with text | None |
| Compliance reason codes | Map failures to policy structure | None |
| Initiatives | Dispatch + aggregate across policies | None (compiles one policy at a time) |
