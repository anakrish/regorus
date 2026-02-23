# ARM Template Functions in Azure Policy

Comprehensive coverage analysis for the Azure Policy compiler's handling of
ARM template expression functions.

## Official Documentation

- **Azure Policy definition structure — policy rule:**
  https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule
- **ARM template functions (all categories):**
  https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-functions
  - [String](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-functions-string)
  - [Numeric](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-functions-numeric)
  - [Comparison](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-functions-comparison)
  - [Logical](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-functions-logical)
  - [Array and object](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-functions-array)
  - [Date](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-functions-date)
  - [Deployment value](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-functions-deployment)
  - [Resource](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-functions-resource)
  - [Lambda](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-functions-lambda)

---

## Functions Blocked in Policy Rules

From the [Azure Policy docs](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/definition-structure-policy-rule#policy-functions):

> All Resource Manager template functions are available to use within a policy
> rule, **except the following functions and user-defined functions:**

| Blocked Function            | Category          | Notes                                      |
|-----------------------------|-------------------|--------------------------------------------|
| `copyIndex()`               | Numeric           | Loop construct, N/A outside deployments    |
| `dateTimeAdd()`             | Date              | See note below†                            |
| `dateTimeFromEpoch`         | Date              | See note below†                            |
| `dateTimeToEpoch`           | Date              | See note below†                            |
| `deployment()`              | Deployment value  | Runtime deployment info                    |
| `environment()`             | Deployment value  | Azure cloud endpoints                      |
| `extensionResourceId()`     | Resource          | Build resource IDs at deploy time          |
| `lambda()`                  | Lambda            | Lambda expression support                  |
| `listAccountSas()`          | Resource          | Runtime SAS token retrieval                |
| `listKeys()`                | Resource          | Runtime key retrieval                      |
| `listSecrets()`             | Resource          | Runtime secret retrieval                   |
| `list*`                     | Resource          | All list operations                        |
| `managementGroup()`         | Scope             | Scope function                             |
| `newGuid()`                 | String            | Non-deterministic                          |
| `pickZones()`               | Resource          | Availability zone selection                |
| `providers()`               | Resource          | Provider metadata                          |
| `reference()`               | Resource          | Runtime resource lookup                    |
| `resourceId()`              | Resource          | Build resource IDs at deploy time          |
| `subscriptionResourceId()`  | Resource          | Build resource IDs at deploy time          |
| `tenantResourceId()`        | Resource          | Build resource IDs at deploy time          |
| `tenant()`                  | Scope             | Scope function                             |
| `variables()`               | Deployment value  | Template variables, N/A in policy rules    |

> †**Note on dateTime functions:** The docs list `dateTimeAdd`, `dateTimeFromEpoch`,
> and `dateTimeToEpoch` as blocked. However, we implement them because:
> 1. The policy-only `addDays(dateTime, days)` function requires dateTime parsing
>    infrastructure shared with these functions.
> 2. Some policies may use them in practice despite the documented restriction.
> 3. We've confirmed they work in our evaluation engine.

### Policy-Only Functions (not in ARM templates)

These functions are **exclusive to Azure Policy** and don't exist in ARM templates:

| Function                       | Status | Notes                                   |
|--------------------------------|--------|-----------------------------------------|
| `field(fieldName)`             | ✅     | Access resource field values             |
| `requestContext()`             | ✅     | `.apiVersion`, `.identity` etc.          |
| `policy()`                     | ✅     | Policy assignment metadata               |
| `ipRangeContains(range, ip)`   | ✅     | IP/CIDR range check                      |
| `current(indexName)`           | ✅     | Current element in `count` iteration     |
| `addDays(dateTime, days)`      | ✅     | Date arithmetic                          |
| `utcNow(format?)`              | ✅     | Current UTC time (via context loading)   |

---

## Complete Function Coverage Matrix

Legend:
- ✅ Implemented
- 🚫 Blocked (not available in policy rules per docs)
- ❌ Missing (available in policy rules but not yet implemented)
- 🔧 Handled specially (not in `template_dispatch.rs`)

### String Functions

| Function              | Status | Dispatch Name      | Notes                               |
|-----------------------|--------|--------------------|-------------------------------------|
| `base64()`            | ✅     | `base64`           |                                     |
| `base64ToJson()`      | ✅     | `base64tojson`     |                                     |
| `base64ToString()`    | ✅     | `base64tostring`   |                                     |
| `concat()`            | ✅     | `concat`           | Handles both string & array concat  |
| `contains()`          | ✅     | `contains`         | Native instruction                  |
| `dataUri()`           | ✅     | `datauri`          |                                     |
| `dataUriToString()`   | ✅     | `datauritostring`  |                                     |
| `empty()`             | ✅     | `empty`            |                                     |
| `endsWith()`          | ✅     | `endswith`         |                                     |
| `first()`             | ✅     | `first`            |                                     |
| `format()`            | ✅     | `format`           |                                     |
| `guid()`              | ✅     | `guid`             | Deterministic v5 UUID (SHA-1)       |
| `indexOf()`           | ✅     | `indexof`          |                                     |
| `join()`              | ✅     | `join`             | Join array elements with delimiter  |
| `json()`              | ✅     | `json`             | Parse string as JSON value          |
| `last()`              | ✅     | `last`             |                                     |
| `lastIndexOf()`       | ✅     | `lastindexof`      |                                     |
| `length()`            | ✅     | `length`           | Maps to `count` builtin             |
| `newGuid()`           | 🚫     | —                  | Blocked in policy rules             |
| `padLeft()`           | ✅     | `padleft`          |                                     |
| `replace()`           | ✅     | `replace`          |                                     |
| `skip()`              | ✅     | `skip`             |                                     |
| `split()`             | ✅     | `split`            |                                     |
| `startsWith()`        | ✅     | `startswith`       |                                     |
| `string()`            | ✅     | `string`           |                                     |
| `substring()`         | ✅     | `substring`        |                                     |
| `take()`              | ✅     | `take`             |                                     |
| `toLower()`           | ✅     | `tolower`          |                                     |
| `toUpper()`           | ✅     | `toupper`          |                                     |
| `trim()`              | ✅     | `trim`             |                                     |
| `uniqueString()`      | ✅     | `uniquestring`     | 13-char deterministic hash          |
| `uri()`               | ✅     | `uri`              |                                     |
| `uriComponent()`      | ✅     | `uricomponent`     |                                     |
| `uriComponentToString()` | ✅  | `uricomponenttostring` |                                 |

### Numeric Functions

| Function       | Status | Dispatch Name | Notes                         |
|----------------|--------|---------------|-------------------------------|
| `add()`        | ✅     | `add`         | Native instruction             |
| `copyIndex()`  | 🚫     | —             | Blocked in policy rules        |
| `div()`        | ✅     | `div`         | Integer division via builtin   |
| `float()`      | ✅     | `float`       |                                |
| `int()`        | ✅     | `int`         |                                |
| `max()`        | ✅     | `max`         |                                |
| `min()`        | ✅     | `min`         |                                |
| `mod()`        | ✅     | `mod`         | Integer modulo via builtin     |
| `mul()`        | ✅     | `mul`         | Native instruction             |
| `sub()`        | ✅     | `sub`         | Native instruction             |

### Comparison Functions

| Function            | Status | Dispatch Name      | Notes                               |
|---------------------|--------|--------------------|-------------------------------------|
| `coalesce()`        | ✅     | `coalesce`         |                                     |
| `equals()`          | ✅     | `equals`           | Native instruction                  |
| `greater()`         | ✅     | `greater`            | Native instruction                  |
| `greaterOrEquals()` | ✅     | `greaterorequals`  | Native instruction                  |
| `less()`            | ✅     | `less`               | Native instruction                  |
| `lessOrEquals()`    | ✅     | `lessorequals`     | Native instruction                  |

### Logical Functions

| Function   | Status | Dispatch Name | Notes                                       |
|------------|--------|---------------|---------------------------------------------|
| `and()`    | ✅     | `and`         | Via `azure.policy.logic_all` builtin         |
| `bool()`   | ✅     | `bool`        |                                              |
| `false()`  | ✅     | (literal)     | Emits `LoadLiteral(false)`                       |
| `if()`     | ✅     | `if`          | Via `azure.policy.if` builtin                |
| `not()`    | ✅     | `not`         | Native `PolicyNot` instruction               |
| `or()`     | ✅     | `or`          | Via `azure.policy.logic_any` builtin         |
| `true()`   | ✅     | (literal)     | Emits `LoadLiteral(true)`                        |

### Array and Object Functions

| Function            | Status | Dispatch Name    | Notes                               |
|---------------------|--------|------------------|-------------------------------------|
| `array()`           | ✅     | `array`          | Convert value to array               |
| `concat()`          | ✅     | `concat`         | Array concatenation (shared w/ string)|
| `contains()`        | ✅     | `contains`       | Check array/object/string membership |
| `createArray()`     | ✅     | `createarray`    | Native `ArrayCreate` instruction     |
| `createObject()`    | ✅     | `createobject`   |                                      |
| `empty()`           | ✅     | `empty`          |                                      |
| `first()`           | ✅     | `first`          |                                      |
| `indexOf()`         | ✅     | `indexof`        | Array overload                       |
| `indexFromEnd()`    | ✅     | `indexfromend`   | Reverse array indexing               |
| `intersection()`    | ✅     | `intersection`   |                                      |
| `items()`           | ✅     | `items`          | Object to [{key,value}] array        |
| `join()`            | ✅     | `join`           | Join array with delimiter            |
| `json()`            | ✅     | `json`           | Parse JSON string to value           |
| `last()`            | ✅     | `last`           |                                      |
| `lastIndexOf()`     | ✅     | `lastindexof`    | Array overload                       |
| `length()`          | ✅     | `length`         |                                      |
| `max()`             | ✅     | `max`            |                                      |
| `min()`             | ✅     | `min`            |                                      |
| `range()`           | ✅     | `range`          |                                      |
| `skip()`            | ✅     | `skip`           |                                      |
| `take()`            | ✅     | `take`           |                                      |
| `tryGet()`          | ✅     | `tryget`         | Safe property access                 |
| `tryIndexFromEnd()` | ✅     | `tryindexfromend` | Safe reverse indexing               |
| `union()`           | ✅     | `union`          |                                      |

### Date Functions

| Function              | Status | Dispatch Name        | Notes                          |
|-----------------------|--------|----------------------|--------------------------------|
| `dateTimeAdd()`       | ✅†    | `datetimeadd`        | Listed as blocked; works anyway|
| `dateTimeFromEpoch()` | ✅†    | `datetimefromepoch`   | Listed as blocked; works anyway|
| `dateTimeToEpoch()`   | ✅†    | `datetimetoepoch`     | Listed as blocked; works anyway|
| `utcNow()`            | ✅     | 🔧 (LoadContext)      | Handled in compiler, not dispatch |
| `addDays()`           | ✅     | `adddays`             | Policy-only function           |

### Deployment Value Functions

| Function         | Status | Notes                                  |
|------------------|--------|----------------------------------------|
| `deployer()`     | 🚫     | Blocked; deployment identity info      |
| `deployment()`   | 🚫     | Blocked in policy rules                |
| `environment()`  | 🚫     | Blocked in policy rules                |
| `parameters()`   | ✅     | 🔧 Handled in compiler (`compile_parameters_call`) |
| `variables()`    | 🚫     | Blocked in policy rules                |

### Resource Functions

| Function                  | Status | Notes                               |
|---------------------------|--------|-------------------------------------|
| `extensionResourceId()`   | 🚫     | Blocked in policy rules             |
| `list*()`                 | 🚫     | Blocked in policy rules             |
| `pickZones()`             | 🚫     | Blocked in policy rules             |
| `providers()`             | 🚫     | Blocked in policy rules             |
| `reference()`             | 🚫     | Blocked in policy rules             |
| `resourceGroup()`         | ✅     | 🔧 Handled via LoadContext           |
| `resourceId()`            | 🚫     | Blocked in policy rules             |
| `subscription()`          | ✅     | 🔧 Handled via LoadContext           |
| `subscriptionResourceId()`| 🚫     | Blocked in policy rules             |
| `tenantResourceId()`      | 🚫     | Blocked in policy rules             |

### Scope Functions

| Function            | Status | Notes                               |
|---------------------|--------|-------------------------------------|
| `managementGroup()` | 🚫     | Blocked in policy rules             |
| `resourceGroup()`   | ✅     | 🔧 Via LoadContext                   |
| `subscription()`    | ✅     | 🔧 Via LoadContext                   |
| `tenant()`          | 🚫     | Blocked in policy rules             |

### Lambda Functions

| Function       | Status | Notes                                    |
|----------------|--------|------------------------------------------|
| `filter()`     | 🚫     | Blocked (lambda expressions)             |
| `groupBy()`    | 🚫     | Blocked                                  |
| `map()`        | 🚫     | Blocked                                  |
| `mapValues()`  | 🚫     | Blocked                                  |
| `reduce()`     | 🚫     | Blocked                                  |
| `sort()`       | 🚫     | Blocked                                  |
| `toObject()`   | 🚫     | Blocked                                  |

---

## Usage Analysis (regolator corpus, ~4,860 definitions)

Analysis performed by `scripts/check_fn_context.py`, which distinguishes
between functions appearing in `policyRule.if` (policy evaluation path) vs
`policyRule.then` (DINE deployment templates, not evaluated by our compiler).

| Function       | Files | In policyRule.if | In policyRule.then | Status |
|----------------|-------|------------------|--------------------|--------|
| `less()`       | 1     | **1**            | 0                  | ✅     |
| `greater()`    | 5     | 0                | 5                  | ✅     |
| `or()`         | 4     | 0                | 4                  | ✅     |
| `json()`       | 36    | 0                | 36                 | ✅     |
| `uniqueString()` | 141 | 0                | 141                | ✅     |
| `guid()`       | 5     | 0                | 5                  | ✅     |
| `join()`       | 0     | 0                | 0                  | ✅     |
| `false()`      | 1     | 0                | 1                  | ✅     |
| `true()`       | 0     | 0                | 0                  | ✅     |
| `null`†        | 2     | 0                | 2                  | ✅‡    |
| `items()`      | 0     | 0                | 0                  | ✅     |
| `indexFromEnd()`| 0    | 0                | 0                  | ✅     |
| `tryGet()`     | 0     | 0                | 0                  | ✅     |
| `tryIndexFromEnd()` | 0 | 0               | 0                  | ✅     |

> †`null` is not a standalone function; it's typically `json('null')`.
> ‡Handled via `json('null')` which is now implemented.

### Notable policyRule.if Usage: `less()`

The single policy using `less()` in `policyRule.if`:

**File:** `HostingEnvironment_StrongestTLSCipher_Audit.json`

```json
"value": "[less(length(field('Microsoft.Web/HostingEnvironments/clusterSettings[*].value')), 80)]"
```

This checks whether the length of a field value array is less than 80.

---

## Implementation Notes

### New Builtin File: `template_functions_misc.rs`

All newly-added functions are in `src/builtins/azure_policy/template_functions_misc.rs`:

| Function           | Builtin Name                            | Approach                               |
|--------------------|----------------------------------------|----------------------------------------|
| `json()`           | `azure.policy.fn.json`                  | `Value::from_json_str()`               |
| `join()`           | `azure.policy.fn.join`                  | `Vec::join()` with delimiter           |
| `items()`          | `azure.policy.fn.items`                 | Object → `[{key, value}]` array       |
| `indexFromEnd()`   | `azure.policy.fn.index_from_end`        | 1-based reverse indexing               |
| `tryGet()`         | `azure.policy.fn.try_get`              | Safe access, returns null on miss      |
| `tryIndexFromEnd()`| `azure.policy.fn.try_index_from_end`   | Safe reverse, returns null on OOB      |
| `guid()`           | `azure.policy.fn.guid`                  | RFC 4122 v5 UUID with inline SHA-1     |
| `uniqueString()`   | `azure.policy.fn.unique_string`         | SHA-1 + base-32 encoding to 13 chars  |

### Functions Using Native Instructions (no builtin)

| Function    | Instruction          | Dispatch Entry | Notes                              |
|-------------|---------------------|----------------|------------------------------------|
| `less()`    | `PolicyLess`        | `less`         | Already existed in RVM             |
| `greater()` | `PolicyGreater`     | `greater`      | Already existed in RVM             |

### Functions Using Existing Patterns

| Function   | Approach                                                    |
|------------|-------------------------------------------------------------|
| `or()`     | `azure.policy.logic_any` builtin (mirrors `logic_all`)      |
| `true()`   | `LoadLiteral(Value::Bool(true))` — no builtin needed        |
| `false()`  | `LoadLiteral(Value::Bool(false))` — no builtin needed       |

### `guid()` Algorithm Details

- RFC 4122 §4.3 version 5 UUID (SHA-1 based)
- Namespace: `11fb06fb-712d-4ddd-98c7-e71bbd588830`
- Parameters joined with `-` before hashing
- Inline SHA-1 implementation (no external crate dependency)
- Output format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

### `uniqueString()` Algorithm Details

- SHA-1 hash of null-separated concatenated inputs
- First 8 bytes taken as u64
- Base-32 encoded (a-z, 2-7) to 13 characters
- Note: Azure's exact algorithm is undocumented; our implementation is
  deterministic but may not produce identical output to Azure

---

## Summary Statistics

| Category                          | Count |
|-----------------------------------|-------|
| **Total ARM template functions**  | ~80   |
| **Blocked in policy rules**       | ~25   |
| **Available in policy rules**     | ~55   |
| **Implemented**                   | ~60   |
| **Policy-only functions**         | 7 (all implemented) |
| **Missing (available)**           | 0     |
| **All available functions covered** | ✅ |
