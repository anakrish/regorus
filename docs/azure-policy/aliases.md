# Azure Policy Field Aliases — Design Discussion

This document captures the design discussion around handling Azure Policy field
aliases in the Regorus compiler infrastructure, covering the problem space,
approaches evaluated, and the chosen design.

---

## 1. What Are Azure Policy Aliases?

In Azure Policy JSON, conditions reference resource fields using
**provider-qualified alias names** rather than raw ARM JSON property paths:

```json
{ "field": "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly", "equals": true }
```

The alias `Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly` maps to
the actual ARM JSON path `properties.supportsHttpsTrafficOnly`. Aliases serve as
a stable abstraction layer between policy authors and the underlying ARM resource
structure.

### Alias tiers

**Simple (scalar) aliases** — map a qualified name to a single JSON path:

```
Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly
  → properties.supportsHttpsTrafficOnly

Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType
  → properties.storageProfile.osDisk.osType
```

**Array aliases** — paths containing `[*]` denoting iteration over arrays:

```
Microsoft.Network/networkSecurityGroups/securityRules[*]
  → properties.securityRules[*]

Microsoft.Network/networkSecurityGroups/securityRules[*].protocol
  → properties.securityRules[*].properties.protocol
```

Note that aliases hide intermediate `properties` wrappers present in ARM JSON.
The alias path and the actual JSON path may differ non-trivially.

**Modifiable aliases** — aliases flagged as supporting `modify` effect
operations. Only modifiable aliases can appear in `modify` effect
`operations[].field` values.

### Alias data source

In Azure, alias tables are maintained per resource provider and per API version.
A single resource provider can have hundreds of aliases. The full Azure alias
table across all providers has tens of thousands of entries. Alias names are
stable identifiers — they don't change across versions. Only the underlying ARM
JSON path may change.

---

## 2. Design Constraints

The alias design must satisfy all of the following:

1. **OPA compatibility**: Rego policies must work unmodified with standard OPA
   tooling (no custom builtins, no magic namespaces that OPA doesn't know
   about).

2. **No recompilation on alias evolution**: Compiled policy bytecode must remain
   valid even if the alias-to-ARM-path mapping changes (new API versions, schema
   restructuring).

3. **Shared alias model**: Both Azure Policy JSON policies and Rego policies
   targeting the same Azure Policy target should use the same field reference
   model so that the notion of aliases maps consistently between the two
   languages.

4. **Composability**: In Rego, intermediate values must be usable naturally:
   ```rego
   x := input.resource.securityRules
   some rule in x
   rule.protocol == "Tcp"    # must work — no hidden properties wrappers
   ```

---

## 3. Approaches Evaluated

### Approach 1: Normalize the entire `input`

Transform `input` itself so alias paths work as direct field paths.

```rego
input.supportsHttpsTrafficOnly == true
```

- **Pro**: Both languages see identical `input`. Simplest compiler.
- **Con**: Rego authors see a shape different from raw ARM JSON (`az resource
  show` output). Changing the normalization contract breaks existing Rego
  policies. Ambiguity between resource fields and metadata fields at the
  `input` root.

### Approach 2: Aliases as runtime functions / builtins

Provide a `field()` function in both languages that resolves aliases at runtime.

```rego
field("supportsHttpsTrafficOnly") == true
```

- **Pro**: Both languages use the same abstraction. Raw `input` stays as-is.
- **Con**: OPA doesn't have `field()`. Violates the OPA compatibility
  constraint. Two ways to access the same data causes confusion.

### Approach 3: Aliases defined in the Target, resolved at compile time

The `Target` definition includes an alias table. Both compilers resolve aliases
to concrete ARM paths at compile time.

- **Pro**: Single source of truth. Both compilers share logic.
- **Con**: Bytecode contains concrete ARM paths. Recompilation required if alias
  mappings change. Violates constraint #2.

### Approach 4: Schema-derived alias namespace as `input` overlay

Provide a virtual `input._alias` namespace alongside raw `input`.

- **Pro**: Raw `input` untouched. Alias namespace explicit.
- **Con**: OPA doesn't know about `_alias`. Odd convention. Requires runtime
  construction.

### Approach 5: Aliases live in `data`, resolved at runtime

Alias-to-path table in `data._aliases`. A `resolve_field` builtin uses it.

- **Pro**: No recompilation. Clean separation.
- **Con**: runtime overhead. OPA can't use the builtin. Only works if Rego
  policies don't need aliases (they'd use raw paths instead).

### Approach 6: Two namespaces — `input` (raw) and `data.resource` (projected)

Host builds a projected view from raw input + alias table, puts it in
`data.resource`.

- **Pro**: Composability works. Raw `input` untouched. No recompilation.
- **Con**: Rego policies referencing `data.resource` can't also use the same
  paths in OPA unless the OPA setup replicates the projection. Two different
  access patterns for two languages.

### Approach 7: JSON and Rego produce different bytecode

JSON policies use runtime alias resolution (ok — they never run in OPA). Rego
policies use raw ARM paths (works in OPA). The two don't share an alias model.

- **Pro**: Each language gets optimal behavior.
- **Con**: Violates constraint #3 (shared alias model). A JSON policy and Rego
  policy expressing the same logic use different field reference patterns.

---

## 4. Chosen Design: `input.resource` as Normalized View

### Structure

The `input` to both JSON and Rego policies is a well-defined envelope:

```json
{
  "resource": {
    "type": "Microsoft.Network/networkSecurityGroups",
    "name": "myNsg",
    "securityRules": [
      { "name": "rule1", "protocol": "Tcp", "access": "Allow" }
    ]
  },
  "context": {
    "resourceGroup": { "name": "myRg", "location": "eastus" },
    "subscription": { "subscriptionId": "..." }
  },
  "parameters": {
    "effect": "Deny"
  }
}
```

**`input.resource`** — the alias-normalized resource. `properties` wrappers
stripped. Alias-named fields are directly accessible. Both Rego and JSON
policies reference fields here.

**`input.context`** — runtime context (resource group, subscription, request
info). Provides the data behind ARM template functions like `resourceGroup()`
and `subscription()`.

**`input.parameters`** — policy parameters. Provides the data behind
`[parameters('effect')]` template expressions.

### How it works

A **normalizer** (outside the compiler and VM) transforms raw ARM JSON into the
`input.resource` structure using the alias table:

```
Raw ARM JSON → normalizer(alias_table) → input.resource
Runtime context → input.context
Policy parameters → input.parameters
```

The normalizer is the only component that knows about the alias-to-ARM-path
mapping. It runs once per evaluation, before the VM executes.

### Both languages

**Rego** (standard — works in OPA, Conftest, Regorus):
```rego
some rule in input.resource.securityRules
rule.protocol == "Tcp"

input.parameters.effect == "Deny"
```

**Azure Policy JSON**:
```json
{ "field": "securityRules[*].protocol", "equals": "Tcp" }
```

The JSON compiler translates `"field": "x.y.z"` to `input.resource.x.y.z`:

```
LoadInput r_input
ChainedIndex { root: r_input, path: ["resource", "securityRules"] } → r_array
LoopStart(Any) { collection: r_array, ... }
  ChainedIndex { root: r_element, path: ["protocol"] } → r_field
  ...
LoopNext
```

### Template function mapping

ARM template expressions in JSON policies map naturally to `input` sub-paths:

| Template expression | `input` path |
|:-------------------|:-------------|
| `[parameters('effect')]` | `input.parameters.effect` |
| `[resourceGroup().location]` | `input.context.resourceGroup.location` |
| `[subscription().subscriptionId]` | `input.context.subscription.subscriptionId` |
| `[field('securityRules[*].protocol')]` | `input.resource.securityRules[*].protocol` |

The JSON compiler prepends the appropriate `input.*` prefix for each function
type.

### Why this satisfies all constraints

| Constraint | How it's satisfied |
|:-----------|:-------------------|
| OPA compatibility | `input.resource.x` is standard Rego field access. No custom builtins. Works in any Rego engine. |
| No recompilation on alias evolution | Bytecode references alias names as paths on `input.resource`. Alias names are stable. If ARM restructures the underlying JSON, the normalizer adapts — it produces a different `input.resource` from the raw ARM data, but the field names stay the same. |
| Shared alias model | Both JSON and Rego policies reference the same `input.resource.x` paths. A JSON `"field": "x"` and a Rego `input.resource.x` mean the same thing. |
| Composability | `input.resource` subtrees are pre-normalized. `x := input.resource.securityRules; x[0].protocol` works because `properties` wrappers are already stripped. |

### Where the alias table lives

The alias table is owned by the **normalizer**, not the compiler or VM. It maps
alias names to ARM JSON paths and is used exclusively to build `input.resource`
from raw ARM data. The table can be:

- Loaded from Azure via `Get-AzPolicyAlias` or the ARM provider metadata API
- Bundled with the target definition
- Auto-derived from the target's resource schemas for common patterns

The compiler never sees it. The VM never sees it. Policies (both JSON and Rego)
never reference raw ARM paths — they reference alias-named paths on
`input.resource`.

### No-alias case

For `input.resource` root-level fields that aren't under `properties` in ARM
JSON (e.g., `name`, `type`, `location`, `tags`, `identity`, `sku`, `kind`),
the normalizer copies them directly since their alias name matches the ARM field
name.

### What about alias evolution?

When alias-to-ARM-path mappings change:

1. **Policies**: Unchanged. They reference alias names (`input.resource.supportsHttpsTrafficOnly`), which are stable.
2. **Bytecode**: Unchanged. Same `ChainedIndex` paths.
3. **Normalizer**: Updated with the new alias table. It now builds `input.resource` differently from the raw ARM JSON, but the output shape (alias-named fields) is the same.
4. **Rego in OPA**: Unchanged. Same `input.resource.x` paths.

### Trade-offs accepted

- Rego authors cannot paste raw `az resource show` output directly as test
  `input`. The input must use the `{ resource, context, parameters }` envelope
  with `resource` in normalized form. A helper tool or library function performs
  this conversion.
- The normalized shape is a documented contract tied to the Azure Policy target.
  Authors must know that `input.resource` is alias-shaped, not raw-ARM-shaped.
- The normalizer is an additional component that must be maintained alongside
  the alias table. However, its logic is straightforward (flatten `properties`
  wrappers according to the alias table) and it runs once per evaluation.

### Normalize once, evaluate many

A single Azure resource deployment can trigger evaluation of hundreds of
policies. With pre-normalization, the resource is normalized **once** and all
policies run against the same normalized `input`:

```
resource ──→ normalize(alias_defs) ──→ normalized_resource
                                             │
                                     ┌───────┼───────┐
                                     ▼       ▼       ▼
                                  policy₁  policy₂  policy_N
```

Compare with runtime alias resolution (e.g., a `field()` builtin or per-policy
normalization):

```
resource ──┬──→ policy₁(resource, alias_defs)  // resolves aliases
           ├──→ policy₂(resource, alias_defs)  // resolves same aliases again
           └──→ policy_N(resource, alias_defs) // and again...
```

Benefits:

1. **Performance**: Alias resolution involves path traversal, `[*]` expansion,
   and `properties` unwrapping. Doing it once vs. N times matters at scale.
2. **Caching**: The normalized resource is a plain JSON value — trivially
   cacheable between evaluation batches.
3. **Consistency**: All policies see the exact same normalized view. No risk of
   subtle differences in how two policies resolve the same alias.
4. **Simpler VM**: The RVM needs no alias-awareness at all — just indexing into
   a plain object. Fewer instructions, faster execution, easier to debug.

This also provides a clean separation of concerns:

| Component      | Responsibility |
|:---------------|:---------------|
| **Normalizer** | Alias definitions, ARM resource structure, `properties` wrappers, `[*]` expansion |
| **Compiler**   | Policy conditions, effects, RVM instructions — aliases are just field names |
| **VM**         | Nothing about Azure — just register operations on input data |

### Alias naming strategy for Rego

Azure Policy aliases are fully qualified:

```
Microsoft.Network/networkSecurityGroups/securityRules[*].protocol
```

This is unsuitable as a Rego path. The naming strategy is:

1. **Strip the resource type prefix**: The prefix
   `Microsoft.Provider/resourceType/` is removed. What remains becomes the path
   on `input.resource`:

   | Alias | `input.resource` path |
   |:------|:----------------------|
   | `Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly` | `input.resource.supportsHttpsTrafficOnly` |
   | `Microsoft.Network/networkSecurityGroups/securityRules[*].protocol` | `input.resource.securityRules[*].protocol` |
   | `Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType` | `input.resource.storageProfile.osDisk.osType` |

2. **Dot-separated segments become chained field access**: The alias
   `storageProfile.osDisk.osType` naturally maps to the Rego chain
   `input.resource.storageProfile.osDisk.osType`.

3. **`[*]` becomes iteration**: `securityRules[*].protocol` in Rego becomes:
   ```rego
   some rule in input.resource.securityRules
   rule.protocol == "Tcp"
   ```

4. **Root-level fields pass through**: `name`, `type`, `location`, `tags`,
   `identity`, `sku`, `kind` are the same in alias namespace and ARM JSON.
   They appear directly on `input.resource`.

The JSON compiler applies the same rule: `"field": "securityRules[*].protocol"`
translates to instructions that index `input.resource.securityRules[i].protocol`.

This means the normalizer's job is precisely: for each alias, strip the type
prefix to get the **alias short name**, and place the resolved ARM JSON value at
that path within `input.resource`.

---

## 5. Alternative: Per-Type Alias Libraries in Rego

An alternative to pre-normalization is to express alias mappings as **Rego
libraries** — one package per resource type, with rules that resolve alias names
to ARM JSON paths.

### Structure

For a given resource type, a generated Rego library defines a rule for each
alias:

```rego
package azure.aliases.Microsoft_Network_networkSecurityGroups

import rego.v1

# Simple scalar alias
supports_https := input.properties.supportsHttpsTrafficOnly

# Root-level field (pass-through)
location := input.location
name := input.name

# Array alias — flattened view of nested objects
security_rules[i] := object.union(
    object.remove(input.properties.securityRules[i], ["properties"]),
    input.properties.securityRules[i].properties,
) if {
    input.properties.securityRules[i]
}
```

A policy then imports the library for its resource type:

```rego
package policy.deny_non_tcp

import rego.v1
import data.azure.aliases.Microsoft_Network_networkSecurityGroups as resource

deny if {
    some rule in resource.security_rules
    rule.protocol != "Tcp"
}
```

### How it works

1. A **code generator** reads the alias table and produces one `.rego` file per
   resource type containing alias→path resolution rules.
2. Policies import the appropriate alias package for their target resource type.
3. The host loads the generated alias library files alongside policy files.
4. At evaluation time, Rego's memoization ensures each alias rule is evaluated
   **at most once** per query, regardless of how many policies reference it.

### Handling `[*]` (array aliases)

Array aliases require flattening intermediate `properties` objects. The library
rule merges the nested `properties` fields into each array element:

```rego
# Alias: securityRules[*].protocol
# ARM:   properties.securityRules[*].properties.protocol

# The library exposes flattened array elements
security_rules[i] := merged if {
    elem := input.properties.securityRules[i]
    merged := object.union(
        object.remove(elem, ["properties"]),
        object.get(elem, "properties", {}),
    )
}
```

Now `resource.security_rules[0].protocol` resolves correctly — the `properties`
nesting is hidden by the rule.

### Advantages

- **Raw `input` preserved**: `input` is the unmodified ARM JSON. Rego authors
  can inspect both the raw resource and the aliased view.
- **Pure Rego**: The alias library is standard Rego. Works in OPA, Conftest,
  Regorus, any engine.
- **No pre-normalization step**: No separate normalizer component needed. The
  Rego evaluation engine IS the normalizer.
- **Memoization = normalize once (conditionally)**: Rego evaluates each rule
  once *within a single query*. If 10 policies are loaded into the same engine
  and evaluated together, `resource.security_rules` is computed once. However,
  **this only works if all policies are loaded together**. If policies are
  compiled or evaluated independently (e.g., separate engine instances or
  separate queries), each evaluation re-runs the alias rules from scratch —
  losing the "normalize once" benefit entirely. Pre-normalization avoids this
  problem because the normalized data is computed outside the engine regardless
  of how policies are loaded or evaluated.
- **Update without recompilation**: Replace the alias library `.rego` files —
  no recompilation of policy bytecode needed.
- **Self-documenting**: The alias library IS the alias documentation. Rego
  authors can read the library to see what aliases are available.

### Challenges

1. **Naming conventions**: Rego identifiers can't contain `/`, `.`, or `[*]`.
   Alias names need transformation:
   - `Microsoft.Network/networkSecurityGroups` → `Microsoft_Network_networkSecurityGroups`
   - `securityRules[*].protocol` → access via `security_rules[i].protocol`
   (the `[*]` becomes the rule index parameter)

2. **Deeply nested `properties` unwrapping**: Multi-level `properties` nesting
   requires recursive flattening in the library. Possible but generates complex
   rules.

3. **JSON policy compilation**: The JSON→RVM compiler would need to emit code
   that calls into the alias library rules (via `VirtualDataDocumentLookup`)
   rather than directly indexing `input`. This adds complexity to both the
   compiler and the execution path.

4. **Policy must know its type**: Each policy imports the correct type-specific
   package. The host or compiler must ensure the right library is loaded.

5. **Performance**: Rego rule evaluation has overhead compared to direct field
   indexing on a pre-normalized object. For simple field access, the library
   adds function-call overhead that pre-normalization avoids.

### Comparison with pre-normalization

| Dimension | Pre-normalization (`input.resource`) | Rego alias library |
|:----------|:-------------------------------------|:-------------------|
| `input` shape | Normalized envelope | Raw ARM JSON |
| OPA compatible | Yes | Yes |
| No recompilation | Yes (normalizer adapts) | Yes (swap library files) |
| Shared model | Both use `input.resource.x` | Both use `resource.x` via import |
| Composability | Direct — subtrees are flat | Via library — rules flatten on access |
| Runtime cost | Zero (pre-normalized) | Rule evaluation (memoized) |
| Tooling needed | Normalizer (outside Rego) | Code generator (produces Rego) |
| Raw ARM access | Not in `input.resource` | Available in `input` directly |
| JSON→RVM compilation | Direct `ChainedIndex` on input | `VirtualDataDocumentLookup` into library |

### When to prefer each

**Pre-normalization** when:
- Maximum evaluation performance matters (hot path, many policies per resource)
- The JSON→RVM compiler should emit simple, direct field access instructions
- The architecture already has a host component that prepares `input`

**Rego alias library** when:
- Preserving raw ARM JSON in `input` is important (debugging, dual access)
- You want alias resolution to live entirely in the Rego ecosystem
- Policies are authored primarily in Rego and authors want to see the mapping
