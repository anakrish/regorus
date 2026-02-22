# Azure Policy Effects — Design and Compilation Strategy

This document specifies how the Azure Policy compiler handles effects: what
each effect means, what the compiled rule returns, and how the host acts on
the result. For condition compilation, see [compiler.md](compiler.md). For
alias normalization, see [alias-normalization.md](alias-normalization.md).

---

## 1. Design Principles

### 1.1 Opaque result object

The compiled rule returns a single JSON object (or `undefined` if the condition
didn't match):

```json
{ "effect": "<name>", "details": { ... } }
```

The host extracts the effect name from the returned object and determines the
appropriate action. The compiler does not need to know what the host will do
with each effect — it just ensures the returned object contains all the data
the host needs.

### 1.2 Why not the Target pipeline

The existing regorus Target/`CompiledPolicy`/`resolve_effect` infrastructure
requires knowing which single effect a policy produces **at compile time**. It
scans rules for `data.package.deny`, `data.package.audit`, etc., and enforces
exactly one effect has rules.

This doesn't work for Azure Policy because:

- **Parameterized effects**: ~40% of Azure Policy definitions use
  `"effect": "[parameters('effect')]"`. The effect name resolves at evaluation
  time from `input.parameters.effect`. The compiler cannot know which effect
  will fire.
- **Single rule model**: Azure Policy is one condition → one effect. There is
  no multi-rule dispatch. The compiled rule always returns the same structure.
- **Details are unconditional**: When the effect is parameterized, the `details`
  block is compiled and returned regardless. If the effect resolves to `audit`,
  the host ignores the details. If it resolves to `modify`, the host acts on
  them.

### 1.3 Host responsibility

The host is responsible for:

1. **Effect interpretation** — examining `result.effect` and deciding what to do
2. **Precedence** — when multiple policies match the same resource, applying
   effects in the correct order (§5)
3. **Cross-resource queries** — for `auditIfNotExists`/`deployIfNotExists`,
   fetching the related resource and evaluating the existence condition
4. **Mutation application** — for `modify`/`append`, applying the operations
   to the resource request
5. **Disabled short-circuit** — skipping evaluation entirely when the effect
   parameter resolves to `"disabled"`

---

## 2. Effect Reference

### 2.1 Disabled

**Category**: No-op

```json
{ "then": { "effect": "disabled" } }
```

The policy is completely inactive. The `if` condition is not evaluated.

**Compiler behavior**: If the effect is statically `"disabled"`, the compiler
can emit a trivially-undefined result (the rule body is empty — it never
produces a value). If the effect is parameterized, the compiler emits the full
rule and the host checks the resolved effect at runtime.

**Compiled output**: Not reached (or `undefined`). If returned for any reason:

```json
{ "effect": "disabled" }
```

The host ignores it.

### 2.2 Deny

**Category**: Blocking

```json
{ "then": { "effect": "deny" } }
{ "then": { "effect": "deny", "details": { "message": "HTTPS required" } } }
```

If the `if` condition matches, the resource create/update request is rejected
(403 Forbidden). During compliance scans, matching resources are flagged
`NonCompliant` but not deleted.

**Details fields**:

| Field | Type | Required | Description |
|:------|:-----|:---------|:------------|
| `message` | string | No | Custom denial message in the error response |

**Compiled output**:

```json
{ "effect": "deny" }
{ "effect": "deny", "details": { "message": "HTTPS required" } }
```

**Data carried**: Signal + optional message string. No mutation data.

### 2.3 Audit

**Category**: Informational

```json
{ "then": { "effect": "audit" } }
```

If the `if` condition matches, a non-compliance event is logged. The resource
operation is not blocked.

**Details fields**: None.

**Compiled output**:

```json
{ "effect": "audit" }
```

**Data carried**: Signal only.

### 2.4 Manual

**Category**: Informational (manual attestation)

```json
{ "then": { "effect": "manual" } }
```

The `if` condition determines which resources are in scope. Compliance is not
automatically evaluated — it's set manually by the user through attestations.
Resources in scope start as `Unknown` compliance state.

**Details fields**: None.

**Compiled output**:

```json
{ "effect": "manual" }
```

**Data carried**: Signal only. The host handles attestation logic externally.

### 2.5 DenyAction

**Category**: Blocking (action-specific)

```json
{
  "then": {
    "effect": "denyAction",
    "details": {
      "actionNames": ["delete"],
      "cascadeBehaviors": {
        "resourceGroup": "deny"
      }
    }
  }
}
```

Unlike `deny` (which blocks create/update when properties match), `denyAction`
blocks **specific named actions** on matching resources. Currently only
`"delete"` is supported as an action name.

**Details fields**:

| Field | Type | Required | Description |
|:------|:-----|:---------|:------------|
| `actionNames` | string[] | Yes | Actions to deny (currently only `["delete"]`) |
| `cascadeBehaviors` | object | No | Controls cascade behavior |
| `cascadeBehaviors.resourceGroup` | string | No | `"deny"` to also block parent resource group deletion |

**Compiled output**:

```json
{
  "effect": "denyAction",
  "details": {
    "actionNames": ["delete"],
    "cascadeBehaviors": { "resourceGroup": "deny" }
  }
}
```

**Data carried**: Action names + cascade configuration. The host must know the
current action being performed and compare it against `actionNames`.

### 2.6 Modify

**Category**: Mutating

```json
{
  "then": {
    "effect": "modify",
    "details": {
      "roleDefinitionIds": [
        "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-..."
      ],
      "conflictEffect": "audit",
      "operations": [
        { "operation": "addOrReplace", "field": "tags['environment']", "value": "production" },
        { "operation": "add", "field": "tags['costCenter']", "value": "[parameters('costCenter')]" },
        { "operation": "remove", "field": "tags['deprecated']" }
      ]
    }
  }
}
```

If the `if` condition matches, the resource request is mutated by applying the
specified operations before the resource provider sees it. At request time,
modify runs **before** deny — a modify might fix a resource so that a deny
condition no longer triggers.

**Details fields**:

| Field | Type | Required | Description |
|:------|:-----|:---------|:------------|
| `roleDefinitionIds` | string[] | Yes | RBAC roles the managed identity needs |
| `operations` | array | Yes | Ordered array of modification operations |
| `conflictEffect` | string | No | `"audit"` (default) or `"deny"` — what happens when two modify policies conflict on the same field |

**Operation types**:

| Operation | Behavior | `value` required |
|:----------|:---------|:----------------|
| `add` | Set field only if it doesn't exist (set-default) | Yes |
| `addOrReplace` | Set field unconditionally (upsert) | Yes |
| `remove` | Remove field if it exists | No |

There is no standalone `replace` — `addOrReplace` covers that case.

**`[*]` in modify field targets**: When a modify operation's field contains
`[*]`, the operation applies to **each existing element** of the array:

```json
{ "operation": "addOrReplace", "field": "securityRules[*].protocol", "value": "Tcp" }
```

This iterates over all elements of `securityRules` and sets `protocol` to
`"Tcp"` on each. If the array is empty, nothing happens.

**Template expressions in `value`**: The `value` field can contain
`[parameters('...')]`, `[field('...')]`, etc. These are resolved at evaluation
time.

**Compiled output**:

```json
{
  "effect": "modify",
  "details": {
    "roleDefinitionIds": ["..."],
    "conflictEffect": "audit",
    "operations": [
      { "operation": "addOrReplace", "field": "tags.environment", "value": "production" },
      { "operation": "add", "field": "tags.costCenter", "value": "CC-1234" },
      { "operation": "remove", "field": "tags.deprecated" }
    ]
  }
}
```

The compiled output resolves template expressions in operation values at
evaluation time (e.g., `[parameters('costCenter')]` becomes `"CC-1234"`).
Field paths are emitted as normalized alias short names (per
[alias-normalization.md](alias-normalization.md)).

**Data carried**: Ordered operation array with resolved values. The host applies
each operation in order.

### 2.7 Append (legacy)

**Category**: Mutating (deprecated — Microsoft recommends `modify` instead)

```json
{
  "then": {
    "effect": "append",
    "details": [
      { "field": "networkAcls.defaultAction", "value": "Deny" }
    ]
  }
}
```

Adds or replaces fields on the resource request. Unlike `modify`, `append` does
not require `roleDefinitionIds` and has no `conflictEffect` handling.

**Note**: `details` is an **array** of `{field, value}` pairs, not an object.
This is different from every other effect where `details` is an object.

**Details fields** (array items):

| Field | Type | Required | Description |
|:------|:-----|:---------|:------------|
| `field` | string | Yes | Alias or field path to set |
| `value` | any | Yes | Value to set (literal or template expression) |

**Compiled output**:

```json
{
  "effect": "append",
  "details": [
    { "field": "networkAcls.defaultAction", "value": "Deny" }
  ]
}
```

**Data carried**: Array of field-value pairs. The host applies them to the
resource request.

### 2.8 AuditIfNotExists

**Category**: Informational (cross-resource)

```json
{
  "then": {
    "effect": "auditIfNotExists",
    "details": {
      "type": "Microsoft.Compute/virtualMachines/extensions",
      "name": "MicrosoftMonitoringAgent",
      "existenceCondition": {
        "allOf": [
          { "field": "Microsoft.Compute/virtualMachines/extensions/publisher",
            "equals": "Microsoft.EnterpriseCloud.Monitoring" },
          { "field": "Microsoft.Compute/virtualMachines/extensions/provisioningState",
            "equals": "Succeeded" }
        ]
      },
      "existenceScope": "subscription",
      "resourceGroupName": "myResourceGroup",
      "evaluationDelay": "AfterProvisioning"
    }
  }
}
```

Two-phase evaluation:

1. **Primary condition**: The `if` clause is evaluated against the primary
   resource. If it doesn't match, the policy doesn't apply.
2. **Existence check**: The host queries for the related resource specified by
   `details.type` (and optionally `details.name`). If the related resource
   exists and satisfies `existenceCondition`, the resource is compliant.
   Otherwise, a non-compliance event is logged.

**Details fields**:

| Field | Type | Required | Description |
|:------|:-----|:---------|:------------|
| `type` | string | Yes | Related resource type to check |
| `name` | string | No | Specific resource name to look for |
| `existenceCondition` | condition | No | Condition the related resource must satisfy (same grammar as `if`). Defaults to "exists." |
| `existenceScope` | string | No | `"subscription"` or implicitly scoped to parent |
| `resourceGroupName` | string | No | Resource group to search in |
| `evaluationDelay` | string | No | `"AfterProvisioning"`, `"AfterProvisioningSuccess"`, `"AfterProvisioningFailure"`, or ISO 8601 duration |

**Compiled output**: See §3.2 (cross-resource compilation approaches).

**Data carried**: Related resource query specification + existence condition
(compiled inline or as separate rule depending on approach — see §3.2).

### 2.9 DeployIfNotExists (DINE)

**Category**: Remediation (cross-resource)

Same two-phase evaluation as `auditIfNotExists`, plus a deployment phase:

3. **Deployment**: If the related resource is missing or fails
   `existenceCondition`, Azure triggers an ARM deployment using the specified
   template (only during remediation — not during compliance scans).

**Additional details fields** (beyond `auditIfNotExists`):

| Field | Type | Required | Description |
|:------|:-----|:---------|:------------|
| `roleDefinitionIds` | string[] | Yes | RBAC roles for the managed identity |
| `deployment` | object | Yes | ARM deployment specification |
| `deployment.properties.mode` | string | Yes | `"incremental"` (almost always) |
| `deployment.properties.template` | object | Yes | Full ARM template JSON |
| `deployment.properties.parameters` | object | No | ARM template parameters (may use `[field('...')]` to reference primary resource) |

**Compiled output**: See §3.2. The deployment template is passed through
opaquely — the compiler does not interpret ARM templates.

**Data carried**: Related resource query spec + existence condition (per §3.2) +
full ARM deployment template (opaque passthrough).

---

## 3. Compilation Strategy

### 3.1 Simple effects (signal-only and mutating)

For effects where all the data is known at evaluation time (deny, audit,
manual, denyAction, modify, append), the compiler builds the result object
directly from RVM instructions.

**deny**:

```
compile(then: { effect: "deny" }):
    Load { dest: r_effect, literal_idx: <"deny"> }
    ObjectCreate { dest: r_result, fields: [("effect", r_effect)] }
```

**deny with message**:

```
compile(then: { effect: "deny", details: { message: "HTTPS required" } }):
    Load { dest: r_effect, literal_idx: <"deny"> }
    Load { dest: r_msg, literal_idx: <"HTTPS required"> }
    ObjectCreate { dest: r_details, fields: [("message", r_msg)] }
    ObjectCreate { dest: r_result, fields: [("effect", r_effect), ("details", r_details)] }
```

**audit**:

```
compile(then: { effect: "audit" }):
    Load { dest: r_effect, literal_idx: <"audit"> }
    ObjectCreate { dest: r_result, fields: [("effect", r_effect)] }
```

**denyAction**:

```
compile(then: { effect: "denyAction", details: { actionNames: ["delete"],
                cascadeBehaviors: { resourceGroup: "deny" } } }):
    Load { dest: r_effect, literal_idx: <"denyAction"> }
    Load { dest: r_delete, literal_idx: <"delete"> }
    ArrayCreate { elements: [r_delete] } → r_actions
    Load { dest: r_rg_key, literal_idx: <"resourceGroup"> }
    Load { dest: r_deny, literal_idx: <"deny"> }
    ObjectCreate { dest: r_cascade, fields: [(r_rg_key, r_deny)] }
    ObjectCreate { dest: r_details, fields: [("actionNames", r_actions),
                                              ("cascadeBehaviors", r_cascade)] }
    ObjectCreate { dest: r_result, fields: [("effect", r_effect), ("details", r_details)] }
```

**modify**:

```
compile(then: { effect: "modify", details: { roleDefinitionIds: [...],
                operations: [{ operation: "addOrReplace", field: "tags['env']",
                               value: "[parameters('env')]" }] } }):

    // Effect name
    Load { dest: r_effect, literal_idx: <"modify"> }

    // roleDefinitionIds — passthrough as literal
    Load { dest: r_role, literal_idx: <"/providers/.../b24988ac-..."> }
    ArrayCreate { elements: [r_role] } → r_roles

    // Compile each operation
    Load { dest: r_op_type, literal_idx: <"addOrReplace"> }
    Load { dest: r_field, literal_idx: <"tags.env"> }
    // Resolve template expression for value
    LoadInput { dest: r_input }
    ChainedIndex { root: r_input, path: ["parameters", "env"] } → r_value
    ObjectCreate { dest: r_op, fields: [("operation", r_op_type),
                                         ("field", r_field),
                                         ("value", r_value)] }
    ArrayCreate { elements: [r_op] } → r_operations

    // Build details
    ObjectCreate { dest: r_details, fields: [("roleDefinitionIds", r_roles),
                                              ("operations", r_operations)] }

    // Build result
    ObjectCreate { dest: r_result, fields: [("effect", r_effect), ("details", r_details)] }
```

**append**:

```
compile(then: { effect: "append", details: [{ field: "...", value: "..." }] }):
    Load { dest: r_effect, literal_idx: <"append"> }
    Load { dest: r_field, literal_idx: <"networkAcls.defaultAction"> }
    Load { dest: r_value, literal_idx: <"Deny"> }
    ObjectCreate { dest: r_item, fields: [("field", r_field), ("value", r_value)] }
    ArrayCreate { elements: [r_item] } → r_details
    ObjectCreate { dest: r_result, fields: [("effect", r_effect), ("details", r_details)] }
```

### 3.2 Cross-resource effects (auditIfNotExists, deployIfNotExists)

Cross-resource effects require a two-phase evaluation: the primary condition
(which the compiler handles normally) and an existence check against a related
resource (which requires the host to fetch it).

This section documents **all considered approaches**, their trade-offs, and
the recommended default. The design may be revisited as the implementation
matures.

#### 3.2.1 Approach A — HostAwait (single-rule, inline existence check)

The RVM provides a `HostAwait { dest, arg, id }` instruction that **suspends**
the VM, yields control to the host with an argument value and an identifier,
and resumes when the host provides a response value in `dest`. This allows the
entire cross-resource flow to compile into a single rule:

```
compile(auditIfNotExists):
    // ── Phase 1: evaluate the "if" condition ──
    <compile condition> → r_cond
    AssertCondition { r_cond }

    // ── Phase 2: request the related resource from the host ──
    // Build query object: { type, name, existenceScope, resourceGroupName }
    Load { dest: r_type,  literal_idx: <"Microsoft.Compute/virtualMachines/extensions"> }
    Load { dest: r_name,  literal_idx: <"MicrosoftMonitoringAgent"> }
    Load { dest: r_scope, literal_idx: <"subscription"> }
    ObjectCreate { dest: r_query, fields: [("type", r_type),
                                            ("name", r_name),
                                            ("existenceScope", r_scope)] }

    // Suspend: host fetches the related resource and resumes with it
    Load { dest: r_id, literal_idx: <"existence_query"> }
    HostAwait { dest: r_related, arg: r_query, id: r_id }

    // ── Phase 3: evaluate existenceCondition against the related resource ──
    // r_related now holds the related resource (or Undefined if not found)
    //
    // If existenceCondition is present:
    <compile existenceCondition against r_related> → r_exists
    // If no existenceCondition, just check if the resource was found:
    // IsNotUndefined { dest: r_exists, src: r_related }

    // ── Phase 4: produce the result ──
    // If r_exists is true → resource is compliant → return Undefined (no effect)
    // If r_exists is false → non-compliant → return the effect object
    Not { dest: r_not_exists, operand: r_exists }
    AssertCondition { r_not_exists }

    Load { dest: r_effect, literal_idx: <"auditIfNotExists"> }
    ObjectCreate { dest: r_result, fields: [("effect", r_effect), ("details", r_details)] }
```

The VM supports two execution modes for `HostAwait`:

| Mode | Behavior | Use case |
|:-----|:---------|:---------|
| **Suspendable** | VM yields `SuspendReason::HostAwait { dest, argument, identifier }`. Host calls `resume(value)` with the related resource. | Production: host performs async resource query |
| **RunToCompletion** | Host pre-loads responses via `set_host_await_responses()`, keyed by identifier. VM consumes them without suspending. | Testing: deterministic, no async needed |

**Strengths**:

- Single rule, simple host protocol — just evaluate and handle suspension
- Context preservation: all registers (including primary resource values) are
  live across the suspension. `[field('...')]` in `existenceCondition` can
  reference the primary resource without re-loading it
- Testing is straightforward with `set_host_await_responses()`
- No second rule to discover or invoke

**Weaknesses**:

- Suspendable mode may have performance overhead vs. straight run-to-completion
  (context saving, suspend/resume state machine)
- All policies must be evaluated in Suspendable mode if the host doesn't know
  whether a given program uses `HostAwait` (solved by §3.2.5)
- Parameterized effects: if the effect resolves to `"audit"` at runtime but the
  program has `HostAwait` compiled in, the cross-resource query fires
  unnecessarily

#### 3.2.2 Approach B — Two-rule (result-driven discovery)

Compile the existence condition as a **separate rule** within the same RVM
program. The host evaluates the primary rule first, inspects the result, and
decides whether to call the existence rule:

```
Program contains two rules:
  Rule 0 (data.policy.eval):      primary "if" condition → result object
  Rule 1 (data.policy.existence): existenceCondition → bool
```

**Primary rule** returns the effect object with query metadata when the `if`
condition matches:

```
compile(primary rule):
    <compile "if" condition> → r_cond
    AssertCondition { r_cond }
    Load { dest: r_effect, literal_idx: <"auditIfNotExists"> }
    Load { dest: r_type, literal_idx: <"Microsoft.Compute/.../extensions"> }
    ObjectCreate { dest: r_details, fields: [("type", r_type), ("name", r_name), ...] }
    ObjectCreate { dest: r_result, fields: [("effect", r_effect), ("details", r_details)] }
```

**Existence rule** is compiled separately and evaluates `existenceCondition`
against the related resource:

```
compile(existence rule):
    RuleInit { result_reg: r_result, rule_index: 1 }
    // Related resource is now input.resource
    <compile existenceCondition against input fields> → r_match
    AssertCondition { r_match }
    LoadTrue { dest: r_result }
    RuleReturn
```

**Host protocol** (result-driven):

```
1. Host evaluates Rule 0 (primary) in RunToCompletion mode
2. If result is undefined → policy doesn't apply, done
3. Host examines result.details:
   - If details contains "type" field → cross-resource effect
     a. Host queries for related resource using details.type/name/scope
     b. Host sets related resource as new input.resource
     c. Host evaluates Rule 1 (existence) in RunToCompletion mode
     d. If Rule 1 returns truthy → resource is compliant, no effect
     e. If Rule 1 returns undefined → non-compliant, effect applies
   - If details has no "type" → simple effect, act on result directly
```

**Strengths**:

- Both rules run in RunToCompletion mode — no suspension overhead
- Host explicitly controls resource query between the two calls
- Clean separation: each rule has a single responsibility

**Weaknesses**:

- Host must understand result structure to know when to call Rule 1
- Context not preserved: existence rule can't access primary resource registers.
  If `existenceCondition` uses `[field('primaryResource.field')]`, the host must
  inject it into the input
- Two-call orchestration adds host complexity
- Parameterized effects: host must decide whether Rule 1 applies based on the
  resolved effect name

#### 3.2.3 Approach C — Rule probing (metadata-driven discovery)

Same two-rule compilation as Approach B, but instead of inspecting the result,
the host checks the program's metadata or structure before evaluation:

```rust
// Before evaluation, host probes for existence of the second rule
if program.entry_points.contains_key("data.policy.existence") {
    // This program has a cross-resource check — prepare for two-phase eval
    ...
}
```

Or using the rule tree:

```rust
if program.rule_tree["policy"]["existence"].is_defined() {
    // Cross-resource program
}
```

**Host protocol**:

```
1. Host probes program for existence rule entry point
2. If found:
   a. Evaluate primary rule → result
   b. If result defined → query related resource → evaluate existence rule
3. If not found:
   a. Evaluate primary rule → result (simple effect)
```

**Strengths**:

- Host knows the program shape before evaluation begins
- Can optimize execution plan upfront (e.g., pre-allocate for two evaluations)
- No runtime inspection of result structure needed

**Weaknesses**:

- Couples the host to specific rule naming conventions
- Same context loss problem as Approach B
- Probing is fragile — if the naming convention changes, the host breaks
- Doesn't handle the case where the existence rule was compiled for a
  parameterized effect that resolves to a non-cross-resource effect at runtime
  (host must still check result.effect to decide whether to act)

#### 3.2.4 Comparison

| Concern | A: HostAwait | B: Two-rule (result-driven) | C: Two-rule (probing) |
|:--------|:-------------|:---------------------------|:----------------------|
| Number of rules | 1 | 2 | 2 |
| Execution mode | Suspendable (or auto-selected) | RunToCompletion | RunToCompletion |
| Host complexity | Handle suspension | Inspect result, orchestrate 2 calls | Probe program, orchestrate 2 calls |
| Context preservation | Full (registers live across await) | Lost (separate rule, separate input) | Lost |
| Discovery mechanism | Implicit (suspension happens or doesn't) | Result structure (`details.type`) | Entry point probing |
| Performance | Suspendable overhead (mitigated by §3.2.5) | No overhead — pure RunToCompletion | No overhead — pure RunToCompletion |
| Testing | `set_host_await_responses()` | Two `eval` calls | Two `eval` calls |
| Parameterized effects | HostAwait fires even if effect resolves to audit | Host skips Rule 1 if effect ≠ AINE/DINE | Host skips Rule 1 if effect ≠ AINE/DINE |

#### 3.2.5 Program metadata: `has_host_await`

Regardless of which approach is chosen, the compiled program should declare
whether it contains `HostAwait` instructions. This is a static property —
known at compile time — and belongs in the program metadata:

```rust
/// Azure Policy program metadata (stored alongside ProgramMetadata)
pub struct AzurePolicyProgramInfo {
    /// Whether the compiled program contains HostAwait instructions.
    /// When false, the host can evaluate in RunToCompletion mode for
    /// maximum performance. When true, Suspendable mode is required
    /// (or RunToCompletion with pre-loaded responses for testing).
    pub has_host_await: bool,

    /// Whether the program has a separate existence-check rule
    /// (only relevant for Approach B/C — two-rule compilation)
    pub has_existence_rule: bool,
}
```

**Automatic execution mode selection**: The evaluation function should inspect
this flag and choose the optimal execution mode:

```rust
pub fn eval_azure_policy(
    program: &Program,
    info: &AzurePolicyProgramInfo,
    input: Value,
    host: Option<&dyn HostAwaitHandler>,
) -> Result<Option<Value>> {
    let mode = if info.has_host_await {
        // Program requires host interaction — must use Suspendable
        // (or RunToCompletion with pre-loaded responses)
        ExecutionMode::Suspendable
    } else {
        // No HostAwait — use faster RunToCompletion mode
        ExecutionMode::RunToCompletion
    };
    // ...
}
```

This way:

- **~95% of policies** (deny, audit, modify, append, etc.) are evaluated in
  fast RunToCompletion mode with zero suspension overhead
- **~5% of policies** with cross-resource effects (`auditIfNotExists`,
  `deployIfNotExists`) are evaluated in Suspendable mode only when needed
- The host doesn't need to guess — the compiled program tells it

The compiler sets `has_host_await = true` when:

- The effect is statically `auditIfNotExists` or `deployIfNotExists`
- The effect is parameterized AND the details contain `type` (indicating
  a potential cross-resource check)

#### 3.2.6 Current recommendation

**Approach A (HostAwait)** is the recommended starting point:

- Simplest host protocol — no multi-call orchestration
- Context preservation avoids the need to re-inject primary resource data
- `has_host_await` metadata (§3.2.5) eliminates the Suspendable performance
  concern for the vast majority of policies
- Clean testing story with `set_host_await_responses()`

However, Approach B (two-rule, result-driven) is a viable alternative if:

- Suspendable mode proves to have unacceptable overhead even for the 5% case
- The host architecture strongly favors synchronous request-response patterns
- `existenceCondition` never actually references the primary resource (so
  context loss is not a problem in practice)

The design keeps all three approaches documented so we can revisit the decision
during implementation.

#### 3.2.7 deployIfNotExists specifics

Regardless of approach, `deployIfNotExists` compiles identically to
`auditIfNotExists` for the existence check, with additional fields in the
result object:

```json
{
  "effect": "deployIfNotExists",
  "details": {
    "type": "...",
    "name": "...",
    "roleDefinitionIds": ["..."],
    "evaluationDelay": "AfterProvisioning",
    "deployment": { /* ARM template — opaque passthrough */ }
  }
}
```

The deployment template is included as a literal value in the result object.
The compiler does not interpret ARM templates — they pass through as opaque
JSON. Template expressions within `deployment.properties.parameters` that
reference `[field('...')]` on the primary resource are resolved at evaluation
time by the compiler (since the primary resource is the current input).

#### 3.2.8 Parameterized cross-resource effects

When the effect is parameterized and the details contain `type` (indicating a
potential cross-resource check), the cross-resource path is compiled in
regardless.

**With Approach A (HostAwait)**: The `HostAwait` fires even if the effect
resolves to `"audit"` at runtime. This is slightly wasteful (unnecessary
cross-resource query), but correct. An optimization: the compiler could emit
a guard before the `HostAwait` that checks the resolved effect name and skips
the cross-resource path for non-AINE/DINE effects.

**With Approaches B/C**: The host evaluates the primary rule, resolves the
effect name from the result, and only calls the existence rule if the effect
is `auditIfNotExists` or `deployIfNotExists`. This is more efficient for the
non-cross-resource case but requires additional host logic.

### 3.3 Parameterized effects

When the effect comes from a parameter:

```json
{ "then": { "effect": "[parameters('effect')]", "details": { ... } } }
```

The compiler does not know which effect will fire. It compiles the details
unconditionally and lets the host interpret based on the resolved effect name:

```
compile(then: { effect: "[parameters('effect')]", details: { ... } }):
    // Resolve effect name from parameter at runtime
    LoadInput { dest: r_input }
    ChainedIndex { root: r_input, path: ["parameters", "effect"] } → r_effect_name

    // Compile details unconditionally
    <compile details> → r_details

    // Build result object
    ObjectCreate { dest: r_result, fields: [("effect", r_effect_name), ("details", r_details)] }
```

The host examines `result.effect` at runtime:

- `"disabled"` → ignore the result entirely
- `"deny"` → reject the request, ignore details (or use `details.message` if
  present)
- `"audit"` → log non-compliance, ignore details
- `"modify"` → apply `details.operations`
- etc.

**Disabled short-circuit**: When the effect is parameterized, the host should
check the resolved effect **before** evaluating the condition. If the parameter
resolves to `"disabled"`, skip evaluation entirely. This optimization is the
host's responsibility — the compiler can't perform it because it doesn't know
the parameter value at compile time.

Alternatively, the compiler could emit a guard at the start of the rule body:

```
// Optional: compiler emits disabled guard
LoadInput { dest: r_input }
ChainedIndex { root: r_input, path: ["parameters", "effect"] } → r_eff
Load { dest: r_disabled, literal_idx: <"disabled"> }
Eq { dest: r_is_disabled, left: r_eff, right: r_disabled }
Not { dest: r_not_disabled, operand: r_is_disabled }
AssertCondition { condition: r_not_disabled }
// ... rest of rule body
```

This makes the rule return `undefined` when the effect is `"disabled"`,
avoiding unnecessary condition evaluation. However, this approach doesn't
handle case-insensitive matching (`"Disabled"`, `"DISABLED"`). The host-side
short-circuit is more robust.

### 3.4 Modify with `[*]` in field targets

When a modify operation targets a field with `[*]`, the operations apply per
element. The compiler has two strategies:

**Strategy A: Emit resolved operations** — resolve `[*]` at evaluation time and
emit individual operations per element:

```
// For: { operation: "addOrReplace", field: "securityRules[*].protocol", value: "Tcp" }

LoadInput { dest: r_input }
ChainedIndex { root: r_input, path: ["resource", "securityRules"] } → r_arr
Count { dest: r_count, collection: r_arr }

// Build one operation per element, with indexed field paths
LoopStart(ForEach) { collection: r_arr, key_reg: r_idx, value_reg: r_elem }
  // Build: { operation: "addOrReplace", field: "securityRules.<idx>.protocol", value: "Tcp" }
  ...
LoopNext
```

**Strategy B: Pass `[*]` through** — include the `[*]` in the field path and
let the host handle per-element expansion:

```json
{
  "effect": "modify",
  "details": {
    "operations": [
      { "operation": "addOrReplace", "field": "securityRules[*].protocol", "value": "Tcp" }
    ]
  }
}
```

**Strategy B is recommended.** The host already needs to understand how to
apply modify operations to the resource. Keeping `[*]` in the field path is
simpler for the compiler and gives the host full control over element iteration.
The compiler's job is to evaluate the condition and resolve template expressions
in values — not to pre-expand array operations.

---

## 4. AST Types

The effect AST types from [compiler.md](compiler.md) §3.6, updated to cover
all effects fully:

```rust
/// The effect to apply when a policy condition matches
pub struct Effect {
    /// Effect name (deny, audit, modify, etc.)
    pub name: EffectName,
    /// Effect details (specific to each effect type)
    pub details: Option<EffectDetails>,
}

pub enum EffectName {
    Deny,
    Audit,
    AuditIfNotExists,
    DeployIfNotExists,
    Modify,
    Append,
    Disabled,
    Manual,
    DenyAction,
    /// Parameterized: the effect name comes from a parameter
    Parameterized(Expression),
}

/// Effect-specific details
///
/// When the effect is parameterized, the parser picks the EffectDetails
/// variant based on the presence of details fields (operations → Modify,
/// details.type → ExistenceCheck, actionNames → DenyAction, etc.).
/// The host ignores irrelevant details for the resolved effect.
pub enum EffectDetails {
    /// Deny details: optional message
    Deny {
        message: Option<Expression>,
    },

    /// Modify details: mutation operations
    Modify {
        role_definition_ids: Vec<String>,
        conflict_effect: Option<String>,
        operations: Vec<ModifyOperation>,
    },

    /// Append details: array of field-value pairs (legacy)
    Append {
        fields: Vec<AppendField>,
    },

    /// AuditIfNotExists / DeployIfNotExists details
    ExistenceCheck {
        /// Related resource type to query
        resource_type: String,
        /// Specific resource name (optional)
        name: Option<Expression>,
        /// Condition the related resource must satisfy
        existence_condition: Option<Box<Condition>>,
        /// Query scope
        existence_scope: Option<String>,
        /// Resource group to search
        resource_group_name: Option<Expression>,
        /// Evaluation delay
        evaluation_delay: Option<String>,
        /// RBAC roles (required for DINE)
        role_definition_ids: Vec<String>,
        /// ARM deployment spec (DINE only, opaque JSON)
        deployment: Option<Value>,
    },

    /// DenyAction details
    DenyAction {
        action_names: Vec<String>,
        cascade_behaviors: Option<Value>,
    },
}

pub struct ModifyOperation {
    pub operation: ModifyOp,
    pub field: FieldPath,
    pub value: Option<Expression>,
}

pub enum ModifyOp {
    Add,
    AddOrReplace,
    Remove,
}

pub struct AppendField {
    pub field: FieldPath,
    pub value: Expression,
}
```

### 4.1 Parsing the effect

The parser determines the `EffectDetails` variant by inspecting the `details`
object's keys:

```rust
fn parse_effect(then_clause: &serde_json::Value) -> Result<Effect> {
    let obj = then_clause.as_object().ok_or(ParseError::ExpectedObject)?;
    let effect_value = obj.get("effect").ok_or(ParseError::MissingEffect)?;
    let name = parse_effect_name(effect_value)?;
    let details = obj.get("details")
        .map(|d| parse_effect_details(d, &name))
        .transpose()?;
    Ok(Effect { name, details })
}

fn parse_effect_details(
    details: &serde_json::Value,
    name: &EffectName,
) -> Result<EffectDetails> {
    // Append has array details
    if details.is_array() {
        return parse_append_details(details);
    }

    let obj = details.as_object().ok_or(ParseError::ExpectedObject)?;

    // Dispatch by recognizable keys (not by effect name — effect may be parameterized)
    if obj.contains_key("operations") {
        return parse_modify_details(obj);
    }
    if obj.contains_key("actionNames") {
        return parse_deny_action_details(obj);
    }
    if obj.contains_key("type") {
        return parse_existence_check_details(obj);
    }
    if obj.contains_key("message") {
        return parse_deny_details(obj);
    }

    // Unknown details structure — for parameterized effects, preserve as-is
    Err(ParseError::UnrecognizedEffectDetails)
}
```

Key insight: the parser dispatches on **details structure**, not on effect name.
This handles parameterized effects where the compiler doesn't know the effect
but can still parse the details by their shape.

---

## 5. Effect Precedence

When multiple policies match the same resource, the host applies effects in
this order:

| Priority | Phase | Effects |
|:---------|:------|:--------|
| 1 | Short-circuit | `disabled` — skip evaluation entirely |
| 2 | Mutation | `modify`, `append` — mutate the request |
| 3 | Blocking | `deny`, `denyAction` — reject if still non-compliant |
| 4 | Informational | `audit` — log non-compliance |
| 5 | Cross-resource | `auditIfNotExists` — check related resources |
| 6 | Remediation | `deployIfNotExists` — schedule deployment |
| 7 | Manual | `manual` — human attestation |

**Mutation before blocking**: Modify/append run first. A modify policy might
fix a resource so that a deny condition no longer triggers. Since deny evaluates
the (post-mutation) resource, the deny policy sees the corrected state.

**Multiple denies**: All denial reasons are reported.

**Modify conflicts**: When two modify policies change the same field,
`conflictEffect` determines behavior: `"audit"` (default — first wins, conflict
logged) or `"deny"` (conflict causes denial).

The compiler does not implement precedence — it compiles one policy at a time.
Precedence is entirely the host's responsibility.

---

## 6. Evaluation Timing

Effects behave differently depending on when evaluation occurs:

| Effect | Request time | Compliance scan | Remediation |
|:-------|:------------|:----------------|:------------|
| `disabled` | Skip | Skip | N/A |
| `deny` | Block request (403) | Flag non-compliant | N/A |
| `denyAction` | Block specific action | Flag | N/A |
| `modify` | Mutate request payload | Flag if unmodified | Apply tag changes to existing resources |
| `append` | Mutate request payload | Flag | N/A |
| `audit` | Log warning, allow | Flag non-compliant | N/A |
| `auditIfNotExists` | Log if related missing | Flag if related missing | N/A |
| `deployIfNotExists` | Log if related missing | Flag if related missing | Execute ARM deployment |
| `manual` | N/A | `Unknown` status | N/A |

The compiler produces the same output regardless of timing. The host determines
the action based on evaluation context (request-time vs. compliance scan vs.
remediation).

---

## 7. Data-Carrying vs. Signal-Only Classification

| Effect | Classification | Data in result |
|:-------|:--------------|:---------------|
| `deny` | Signal (+ optional message) | `{ message }` |
| `audit` | Signal only | — |
| `manual` | Signal only | — |
| `disabled` | Signal only (no-op) | — |
| `denyAction` | Carries data | `{ actionNames, cascadeBehaviors }` |
| `modify` | Carries data | `{ roleDefinitionIds, conflictEffect, operations[] }` |
| `append` | Carries data | `[{ field, value }]` |
| `auditIfNotExists` | Carries data + cross-resource | `{ type, name, existenceScope, ... }` — cross-resource compilation per §3.2 |
| `deployIfNotExists` | Carries data + cross-resource + opaque template | `{ type, name, roleDefinitionIds, deployment, ... }` — same cross-resource pattern + opaque ARM template |

For signal-only effects, the compiler just builds a small object. For
data-carrying effects, the compiler resolves template expressions in values and
builds the full data structure. For cross-resource effects, see §3.2 for the
three documented approaches (HostAwait, two-rule result-driven, two-rule
probing).

---

## 8. Implementation Mapping to Compiler Phases

From [compiler.md](compiler.md) §15:

| Phase | Effects handled |
|:------|:---------------|
| **Phase 2: Core Compiler** | `deny` (no message), `audit`, `disabled` — simple `ObjectCreate` |
| **Phase 3: Full Conditions** | `deny` with message, `manual` — still simple objects |
| **Phase 5: Template Expressions** | Parameterized effects (`[parameters('effect')]`), template expressions in detail values |
| **Phase 6: Advanced Effects** | `modify` (all operations, `[*]` passthrough), `append`, `denyAction` |
| **Phase 8: Cross-Resource** | `auditIfNotExists`, `deployIfNotExists` (cross-resource compilation per §3.2, opaque deployment passthrough) |

---

## 9. Design Decisions

| Decision | Rationale |
|:---------|:---------|
| Opaque result object | Parameterized effects mean the compiler can't know the effect at compile time. A single `{ "effect": "<name>", "details": {...} }` object covers all cases uniformly. |
| No Target pipeline | The existing `resolve_effect` infrastructure requires compile-time effect knowledge (exactly one effect with rules). Parameterized effects break this. |
| Host interprets effect | The host knows the evaluation context (request-time vs. compliance scan vs. remediation). The compiler can't — it just produces the data. |
| Host handles precedence | Multi-policy precedence is a host orchestration concern. The compiler processes one policy at a time. |
| Details parsed by structure not name | Since the effect may be parameterized, the parser recognizes `EffectDetails` variants by their fields (`operations` → Modify, `type` → ExistenceCheck, etc.), not by the effect name. |
| Modify `[*]` passed through | The compiler doesn't expand `[*]` in modify field targets. The host handles per-element expansion. Simpler compiler, host already has mutation logic. |
| Deployment templates opaque | ARM deployment templates in `deployIfNotExists` are not interpreted by the compiler. They pass through as literal JSON values. |
| HostAwait recommended for cross-resource | Three approaches documented (§3.2): HostAwait single-rule, two-rule result-driven, two-rule probing. HostAwait is recommended for context preservation and simpler host protocol, but all are kept as options. |
| `has_host_await` program metadata | Compiled program declares whether it contains `HostAwait` instructions. Eval function auto-selects RunToCompletion (fast) for ~95% of policies and Suspendable only when needed. |
| Result-driven host protocol | Host doesn't probe for rule count or entry points. It evaluates one rule; if `HostAwait` fires, handle it; then inspect the result. Applies to Approach A. |
| Disabled guard is optional | The compiler can emit a disabled guard for parameterized effects, but host-side short-circuit is more robust (handles case-insensitive matching). |
