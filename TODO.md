# Azure Policy Compiler — TODO

## Current Status

The compiler handles full Azure Policy definitions (both wrapped and unwrapped
forms) and `policyRule` evaluation with all 20 operators, logical combinators,
field/value/count LHS, count loops (field `[*]` and value count with
`name`/`where`/`current()`), 26 ARM template functions, all effect types
(returned as strings), type coercion, and null/undefined semantics.

The Azure Policy builtins are split into logically grouped files (<300 lines each):
`helpers.rs`, `operators.rs`, `template_functions.rs`.

The policy definition parser extracts typed fields (`displayName`, `description`,
`mode`, `parameters` with type/defaultValue/allowedValues, `metadata`) and
collects unknown fields into a catch-all map. Parameter defaults are stored in
the compiler's literal table and applied at runtime via the
`azure.policy.get_parameter` builtin (falls back to `defaultValue` when a
parameter is not supplied in `input.parameters`).

The alias system (`src/languages/azure_policy/aliases/`) supports:
- Loading alias catalogs from JSON, resolving FQ aliases to short names
- Versioned ARM paths with `select_path(api_version)`
- Normalization: ARM JSON → flat `input.resource` with sub-resource array
  flattening (including nested 2-level), per-element versioned field remapping
- Nested wildcard count paths (e.g., `rules[*].targets[*]`)

5 end-to-end tests use real Azure Policy JSON definitions.
~464 test cases across 22 YAML suites pass.

---

## P0 — Core (required for real-world policy evaluation)

### Alias System
- [x] Design alias mapping table format (provider → alias → resource property path)
- [x] Load alias data at compile time or runtime
- [x] Resolve simple aliases (e.g., `Microsoft.Compute/virtualMachines/imagePublisher` → `properties.storageProfile.imageReference.publisher`)
- [x] Handle array aliases with `[*]` (interact with `count.field`)
- [x] Handle sub-path expressions after alias names
- [x] Wire alias resolution into `compile_field_path_expression` / `classify_field`
- [x] Versioned alias paths with `select_path(api_version)`
- [x] Case-insensitive alias lookup
- [x] Sub-resource array detection and `properties` flattening during normalization
- [x] Nested sub-resource arrays (2-level flattening)
- [x] Per-element alias resolution (versioned field name remapping inside arrays)
- [x] Nested wildcard count paths (e.g., `rules[*].targets[*]`)
- [x] `[*]` with `field` condition outside `count` — implicit `allOf` semantics (all elements must match)
- [x] `field()` function on `[*]` aliases — should return array of selected values
- [x] Missing array → empty collection for `[*]` alias in `field()` context

### Common ARM Template Functions
- [x] `split(string, delimiter)` — split string into array
- [x] `empty(value)` — check if string/array/object is empty
- [x] `first(array)` — first element
- [x] `last(array)` — last element
- [x] `createArray(...)` — create array from arguments
- [x] `startsWith(string, prefix)` — case-insensitive prefix check
- [x] `endsWith(string, suffix)` — case-insensitive suffix check
- [x] `int(value)` — convert to integer
- [x] `string(value)` — convert to string
- [x] `bool(value)` — convert to boolean

### Parameter Defaults
- [x] Parse `defaultValue` from parameter schema
- [x] Store defaults in compiler literal table (`build_parameter_defaults()`)
- [x] `azure.policy.get_parameter(params, defaults, name)` builtin with fallback
- [x] Apply default when parameter is not provided in input

### Policy-Specific Functions
- [x] `field('alias')` — returns value of a field
- [x] `current('name')` — access current value in count loop
- [x] `current()` — zero-arg form (innermost count element when no nesting)
- [ ] `requestContext().apiVersion` — API version of the triggering request
- [ ] `policy()` — returns assignmentId, definitionId, setDefinitionId, definitionReferenceId
- [ ] `ipRangeContains(range, targetRange)` — CIDR/IP range containment check

---

## P1 — Important (needed for full effect fidelity)

### Effect Details Compilation
- [ ] **Modify**: Compile `details.operations` array (`addOrReplace`, `add`, `remove` with field/value)
- [ ] **Append**: Compile `details` array (field/value pairs to append)
- [ ] Return structured effect result (not just effect name string) when details are present
- [ ] Parse and validate `details.roleDefinitionIds` for modify/deployIfNotExists
- [ ] Check `DefaultMetadata.Attributes = 'Modifiable'` before allowing modify operations on aliases

### Parameter Validation
- [ ] Parse parameter `type` constraints (`String`, `Integer`, `Boolean`, `Array`, `Object`, `Float`, `DateTime`)
- [ ] Enforce `allowedValues` constraints
- [ ] Type-check parameter values against declared types

### Cross-Resource Evaluation
- [ ] `auditIfNotExists`: Evaluate `existenceCondition` against related resource
- [ ] `deployIfNotExists`: Evaluate `existenceCondition` against related resource
- [ ] Resolve related resource from `details.type` / `details.name` / `details.resourceGroupName`
- [ ] Define interface for related-resource lookup (external data source)

---

## P2 — Nice-to-Have

### Policy Definition Envelope
- [x] Parse full policy definition JSON (both wrapped `{ "properties": ... }` and unwrapped forms)
- [x] Extract and surface `mode` (`All`, `Indexed`, Resource Provider modes)
- [x] Extract `displayName`, `description`, `metadata` for diagnostics
- [x] Parse parameter definitions (`type`, `defaultValue`, `allowedValues`, `metadata`)
- [x] Collect unknown/extra fields in catch-all map
- [ ] Parse parameter schema with `strongType` metadata

### Additional ARM Template Functions (~40 remaining)

**String:**
- [ ] `indexOf(string, search)`
- [ ] `lastIndexOf(string, search)`
- [ ] `padLeft(string, length, char)`
- [ ] `trim(string)`
- [ ] `format(formatString, args...)`
- [ ] `base64(string)`
- [ ] `base64ToString(base64)`
- [ ] `base64ToJson(base64)`
- [ ] `uri(baseUri, relativeUri)`
- [ ] `uriComponent(string)`
- [ ] `uriComponentToString(encoded)`
- [ ] `dataUri(string)`
- [ ] `dataUriToString(dataUri)`

**Array/Object:**
- [ ] `intersection(array1, array2, ...)`
- [ ] `union(array1, array2, ...)`
- [ ] `take(array, count)`
- [ ] `skip(array, count)`
- [ ] `range(start, count)`
- [ ] `array(value)` — convert to array
- [ ] `coalesce(value1, value2, ...)`
- [ ] `createObject(key1, val1, ...)`

**Numeric:**
- [ ] `sub(a, b)`
- [ ] `mul(a, b)`
- [ ] `div(a, b)`
- [ ] `mod(a, b)`
- [ ] `min(a, b, ...)`
- [ ] `max(a, b, ...)`
- [ ] `float(value)`

**Date/Time:**
- [ ] `utcNow(format?)`
- [ ] `dateTimeAdd(base, duration, format?)`
- [ ] `dateTimeFromEpoch(epoch)`
- [ ] `dateTimeToEpoch(dateTime)`

**Resource:**
- [ ] `reference(resourceName)`
- [ ] `resourceId(type, name, ...)`
- [ ] `extensionResourceId(baseId, type, name)`
- [ ] `subscriptionResourceId(type, name)`
- [ ] `tenantResourceId(type, name)`

**Unique ID:**
- [ ] `newGuid()`
- [ ] `guid(baseString, ...)`
- [ ] `uniqueString(baseString, ...)`

**Other:**
- [ ] `copyIndex(loopName?, offset?)`
- [ ] `environment()`
- [ ] `deployment()`
- [ ] `variables(name)`
- [ ] `providers(namespace, type?)`
- [ ] `tenant()`

### Field Path Edge Cases
- [ ] General bracket notation in field paths (e.g., `properties['network-acls']`)
- [ ] Array index access outside count (e.g., `properties.ipConfigurations[0].name`)

### Expression Parser
- [ ] Unary minus for negative number literals in expressions (e.g., `[add(-1, 5)]`)

### String Comparison
- [ ] Unicode case-insensitivity (currently ASCII-only via `to_ascii_lowercase()`)

---

## Regolator Policy Analysis

Analysis of ~4,860 real Azure Policy JSON definitions in `regolator/policyDefinitions/`.

### Alias Usage Statistics

**Top resource types:** Compute (~7,700 refs), Insights (~2,100), Network (~200),
Storage (~70), KeyVault (~65), SQL (~40).

**Array alias `[*]` patterns — 196 distinct aliases found:**
- `Microsoft.Insights/diagnosticSettings/logs[*]` (688 occurrences) — most common
- `...logs[*].enabled`, `...logs[*].categoryGroup`, `...logs[*].retentionPolicy.*`
- `...privateLinkServiceConnections[*].groupIds[*]` — doubly-nested `[*][*]` (87)
- `...automations/sources[*].ruleSets[*].rules[*].expectedValue` — triply-nested (22)
- `...networkAcls.ipRules[*]`, `...ipRules[*].value` — storage/key vault firewalls
- `...securityRules/destinationPortRanges[*]` — NSG sub-resource arrays

### `[*]` Implicit allOf (field outside count) — ~150 occurrences

**This is a critical gap.** When a `[*]` field appears in a bare condition (not inside
`count`), Azure Policy applies implicit allOf semantics: ALL elements must
satisfy the condition (empty arrays → true).

**The compiler currently fails** on these patterns with
`"wildcard field paths are not supported in this context"`.

**Real-world patterns:**
```json
{"not": {"field": "...destinationPortRanges[*]", "notEquals": "*"}}
```
Meaning: "at least one element equals '*'" (NOT all-are-different).

Used in: NSG RDP/SSH policies (NetworkSecurityGroup_RDPAccess_Audit.json),
ActivityLog_CaptureAllRegions.json (49× region checks), storage/SQL
auditingSettings, Front Door endpoints, CORS origins.

### `field()` Function with `[*]` Aliases — ~30 occurrences

```json
{"value": "[length(field('...ipRules[*]'))]", "greater": 0}
{"value": "[first(field('...destinationPortRanges[*]'))]", ...}
{"value": "[empty(field('...subnets[*].ipConfigurations[*].id'))]", ...}
```

`field('alias[*]')` should return an array of selected values. Our `field()`
currently reads a single path — it doesn't collect values from array elements.

### `current()` Usage — 116 occurrences, zero-arg NOT used

All real policies use `current('name')` with an explicit name argument.
Zero-arg `current()` is never used in practice, so this gap is low priority.

### `requestContext().apiVersion` — 98 occurrences

Used in ~30 modify-effect policies (gating on API version for safe modification)
and ~68 audit policies. Key Vault, Portal, Azure Arc, ML Workspace, etc.

### `ipRangeContains` — 4 occurrences

Used in Key Vault FirewallEnabled_Audit policies only. Always inside nested
count with `current('parameterName')`.

### `padLeft` — 16 occurrences

Used in diagnostic log retention policies:
```json
{"value": "[padLeft(current('...retentionPolicy.days'), 3, '0')]",
 "greaterOrEquals": "[padLeft(parameters('requiredRetentionDays'), 3, '0')]"}
```

### Nested Count — 32 occurrences

Count inside `count.where`: Key Vault firewall, Media Services, Security
Center, Network routing, Kubernetes data connectors.

### Recommended Real-Policy E2E Test Cases

#### Completed (5 YAML files, 35 test cases)

| Policy | YAML File | Features Exercised |
|--------|-----------|-------------------|
| **Compute/VMSkusAllowed_Deny.json** | `e2e_vm_skus_allowed.yaml` | type + `not` + `in` parameter, parameter defaults |
| **Compute/DoubleEncryptionRequired_Deny.json** | `e2e_double_encryption.yaml` | type + notEquals, parameter defaults |
| **Compute/VMRequireManagedDisk_Audit.json** | `e2e_vm_managed_disk.yaml` | anyOf + allOf nesting, `exists`, multiple types |
| **Storage/StorageAccountOnlyVnetRulesEnabled_Audit.json** | `e2e_storage_vnet_rules.yaml` | `count.field` ipRules + virtualNetworkRules, alias resolution |
| **Resilience/ContainerService_managedclusters_ZoneRedundant_Audit.json** | `e2e_aks_zone_redundant.yaml` | Nested count (agentPoolProfiles → availabilityZones) |

#### Remaining (5 — blocked on missing features)

| Policy | Blocking Features |
|--------|-------------------|
| **Network/NetworkSecurityGroup_RDPAccess_Audit.json** | `and()`, `not()`, `lessOrEquals()`, `greaterOrEquals()` as **callable template functions** (currently only condition operators) |
| **Key Vault/FirewallEnabled_Audit.json** | `ipRangeContains()` template function, named `count.value` over parameters |
| **SQL/SqlServerAuditing_Audit.json** | AuditIfNotExists / `existenceCondition` cross-resource evaluation |
| **Service Bus/AuditDiagnosticLog_Audit.json** | AuditIfNotExists, `padLeft()` template function |
| **Monitoring/ActivityLog_CaptureAllRegions.json** | AuditIfNotExists (subscription-scope `logProfiles` existence check) |

**Closest to ready:** NSG/RDP — only needs 4 template functions (`and`, `not`, `lessOrEquals`, `greaterOrEquals`).
**Biggest blocker:** AuditIfNotExists cross-resource evaluation (blocks 3 policies).

---

## Out of Scope

These are handled by the evaluation platform, not the policy compiler:

- **Policy assignments** (scope, exclusions, identity, non-compliance messages)
- **Policy exemptions** (applied at assignment level)
- **Policy initiatives / policy sets** (higher-level composition)
- **Regulatory compliance mapping** (metadata/reporting)
- **ARM template deployment** for deployIfNotExists (Azure control plane)
- **Resource graph queries** (compiler evaluates a single resource)
- **Role-based access** for modify/deployIfNotExists (authorization)
- **Policy evaluation ordering/precedence** (orchestration layer)
- **Remediation tasks** (post-evaluation Azure service)
- **resourceGroup/subscription context enrichment** (comes from evaluation platform)
