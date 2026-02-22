# Azure Policy — Semantic Behaviors

This document defines the detailed runtime semantics of Azure Policy condition
evaluation. These are edge cases, type interactions, and implicit behaviors
that the Azure Policy service implements but that are only partially documented
in public docs. Getting these wrong produces incorrect compliance results.

See also:
- [builtins.md](builtins.md) — builtin signatures and type dispatch tables
- [compiler.md §6.2.1](compiler.md) — undefined field handling in the compiler
- [comparison-strategy.md](comparison-strategy.md) — why custom builtins were chosen

---

## Table of Contents

1. [Type Coercion](#1-type-coercion)
2. [Null vs Undefined vs Empty String](#2-null-vs-undefined-vs-empty-string)
3. [String Ordering (`greater`/`less` on Strings)](#3-string-ordering)
4. [Date/Time Comparison](#4-datetime-comparison)
5. [`containsKey` on Nested Paths](#5-containskey-on-nested-paths)
6. [Boolean Semantics](#6-boolean-semantics)
7. [Array Semantics](#7-array-semantics)
8. [Numeric Edge Cases](#8-numeric-edge-cases)
9. [`like` and `match` Pattern Semantics](#9-like-and-match-pattern-semantics)
10. [Summary: Operator × Type Matrix](#10-summary-operator--type-matrix)

---

## 1. Type Coercion

Azure Policy operates on ARM resource JSON, where property types are defined by
the resource provider schema. However, the *actual* values in a resource payload
don't always match the schema — and the policy condition must still evaluate.

### 1.1 String ↔ Number coercion

When one operand is a string and the other is a number (or vice versa), Azure
Policy **attempts to parse the string as a number** before comparing.

| Field value | Condition value | Behavior |
|:------------|:----------------|:---------|
| `"80"` (string) | `80` (number) | String `"80"` parses to `80` → **equal** |
| `"80"` (string) | `443` (number) | String `"80"` parses to `80` → **not equal** |
| `"not-a-number"` | `80` | Parse fails → **not equal** (positive operators return false) |
| `80` (number) | `"80"` (string) | Symmetric: string side is parsed → **equal** |

**Why this matters**: ARM resource properties like `destinationPortRange` in
NSG rules are strings (`"80"`, `"443"`, `"*"`), but policy authors often write
numeric comparisons like `"greater": 1024`. Without coercion, the comparison
would always fail.

**Compiler impact**: The `azure.policy.compare` builtin handles this internally.
When types differ, it attempts `string.parse::<f64>()`. See
[builtins.md §compare type dispatch](builtins.md#type-dispatch-rules).

### 1.2 String ↔ Boolean coercion

Azure Policy does **not** coerce strings to booleans or vice versa for standard
comparison operators.

| Field value | Condition value | Behavior |
|:------------|:----------------|:---------|
| `"true"` (string) | `true` (bool) | **Not equal** — different types, no coercion |
| `"false"` (string) | `false` (bool) | **Not equal** |

**Exception**: The `exists` operator does not compare types — it only checks
whether a field is defined. See [§2 Undefined](#2-null-vs-undefined-vs-empty-string).

### 1.3 Coercion in `in` / `notIn`

When using `in` or `notIn`, coercion applies **per-element**. The field value
is compared against each element in the array, and string↔number parsing
is attempted for each pair.

```json
{ "field": "destinationPortRange", "in": [80, 443, 8080] }
```

If `destinationPortRange` is `"443"` (string), the `azure.policy.in` builtin
compares `"443"` against each array element. When it reaches `443` (number),
string→number coercion succeeds and the match is found.

### 1.4 Coercion in `contains` / `notContains`

For string-mode `contains` (haystack is a string, needle is a string), no
numeric coercion applies — both operands are treated as strings.

For array-mode `contains` (haystack is an array), each element is compared to
the needle using the same coercion rules as `azure.policy.compare`.

### 1.5 No coercion for `like`, `match`, `matchInsensitively`

Pattern-matching operators always treat both operands as strings. If the field
value is not a string, the condition evaluates to **false** (non-matching).

### 1.6 Design decision

The compiler does **not** emit explicit coercion instructions. All coercion
logic lives inside the `azure.policy.*` builtins, keeping the compiled
instruction stream simple and pushing type-aware behavior into Rust functions.

---

## 2. Null vs Undefined vs Empty String

These three states are distinct in Azure Policy and must not be conflated.

### 2.1 Definitions

| State | JSON representation | Meaning |
|:------|:-------------------|:--------|
| **Defined** | Any JSON value (`"eastus"`, `42`, `true`, `[]`, `{}`) | Field exists with a value |
| **Null** | `null` | Field exists but has an explicit null value |
| **Undefined** | Key absent from object | Field does not exist in the resource |
| **Empty string** | `""` | Field exists with an empty string value |

### 2.2 `exists` operator

The `exists` operator is the **only** operator that directly tests for
undefined:

| Condition | Field undefined | Field null | Field `""` | Field `"value"` |
|:----------|:---------------|:-----------|:-----------|:----------------|
| `"exists": true` | false | **true** | **true** | **true** |
| `"exists": false` | **true** | false | false | false |

**Key point**: `null` is considered to "exist." The `exists` operator tests
whether the key is present in the JSON, not whether the value is non-null.

### 2.3 Undefined field behavior across operators

When a field is **undefined** (key absent), Azure Policy short-circuits before
any comparison. See [compiler.md §6.2.1](compiler.md) for the full table.

Summary:
- **Positive operators** (`equals`, `greater`, `contains`, `in`, `like`,
  `match`, `matchInsensitively`, `containsKey`, `exists: true`):
  undefined → **false**
- **Negative operators** (`notEquals`, `notIn`, `notContains`, `notContainsKey`,
  `notLike`, `notMatch`, `notMatchInsensitively`, `exists: false`):
  undefined → **true**

The compiler implements this via `IsUndefined` + branch (see §6.2.1), not via
builtin behavior. The builtins never receive undefined values.

### 2.4 Null behavior across operators

When a field is **null** (key present, value `null`), the value reaches the
builtins. Behavior:

| Operator | Field `null`, condition `"eastus"` | Result |
|:---------|:----------------------------------|:-------|
| `equals` | `null ≠ "eastus"` | **false** |
| `notEquals` | `null ≠ "eastus"` | **true** |
| `greater` | `null` sorts before all values | **false** |
| `contains` (string mode) | `null` is not a string | **false** |
| `contains` (array mode) | `null` is not an array | **false** |
| `in` | `null` ∉ `["eastus", "westus"]` | **false** |
| `like` | `null` is not a string | **false** |
| `match` | `null` is not a string | **false** |
| `containsKey` | `null` is not an object | **false** |

**Key point**: For `azure.policy.compare`, `null` sorts before all non-null
values (returns `-1` when comparing null to any non-null value). This means
`null` is "less than" everything, so `greater: 0` on a null field is false.

### 2.5 Empty string behavior

An empty string `""` is a valid string value. It is **not** the same as null or
undefined.

| Operator | Field `""`, condition `""` | Result |
|:---------|:--------------------------|:-------|
| `equals` | `"" == ""` | **true** |
| `equals` | `"" == "eastus"` | **false** |
| `contains` | `"" contains ""` → yes | **true** |
| `contains` | `"" contains "east"` → no | **false** |
| `like` | `""` vs pattern `"*"` → matches | **true** |
| `exists: true` | `""` is a defined value | **true** |
| `exists: false` | `""` is a defined value | **false** |

### 2.6 Null vs empty string in equals

```json
{ "field": "someField", "equals": "" }
```

- If `someField` is `""` → **true** (string equals string)
- If `someField` is `null` → **false** (null ≠ string)
- If `someField` is undefined → **false** (positive operator, undefined → false)

These three cases must produce different results. The compiler's undefined check
handles the undefined case; the `azure.policy.compare` builtin distinguishes
null from empty string because they are different `Value` variants.

### 2.7 Interaction with `[*]` iteration

When `[*]` iterates over an array:
- Missing elements don't occur (arrays don't have "holes")
- `null` elements DO occur: `[1, null, 3]`
- The null element is iterated and compared normally (per §2.4 rules)

When a `[*]` field reference points to a field that is an array with some
elements containing the sub-field and others not:

```json
{ "securityRules": [{ "protocol": "Tcp" }, { "noProtocol": true }] }
```

Accessing `securityRules[*].protocol` on the second element yields **undefined**
for that element. In a bare `[*]` condition (universal quantifier: `Every`
mode), this undefined element causes the condition to fail (for positive
operators). In a `count.where`, the undefined element simply isn't counted.

---

## 3. String Ordering

The `greater`, `greaterOrEquals`, `less`, and `lessOrEquals` operators perform
**case-insensitive lexicographic** comparison on strings.

### 3.1 Ordering algorithm

1. Both strings are lowered with `to_ascii_lowercase()`
2. Lowered strings are compared using standard lexicographic (byte-by-byte)
   ordering (Rust `Ord` on `&str`)

This is equivalent to ordinal comparison on ASCII-lowered strings — the same
as .NET's `StringComparer.OrdinalIgnoreCase`.

### 3.2 Examples

| a | b | `azure.policy.compare(a, b)` | Notes |
|:--|:--|:-----------------------------|:------|
| `"apple"` | `"Banana"` | `-1` (less) | `"apple" < "banana"` |
| `"Zebra"` | `"apple"` | `1` (greater) | `"zebra" > "apple"` |
| `"abc"` | `"ABC"` | `0` (equal) | case-insensitive |
| `"abc"` | `"abcd"` | `-1` (less) | prefix is less than longer string |
| `""` | `"a"` | `-1` (less) | empty string sorts before everything |
| `""` | `""` | `0` (equal) | |

### 3.3 Numeric strings

When both operands are strings that look like numbers, they are compared
**as strings**, not as numbers:

| a | b | Result | Why |
|:--|:--|:-------|:----|
| `"9"` | `"10"` | `"9" > "10"` (greater) | Lexicographic: `'9' > '1'` |
| `"80"` | `"443"` | `"80" > "443"` (greater) | Lexicographic: `'8' > '4'` |

This is only relevant when **both** operands are strings. If the policy
condition uses a numeric literal, string→number coercion applies (see §1.1)
and the comparison is numeric.

### 3.4 Unicode behavior

Azure Policy resource property values are overwhelmingly ASCII. The lowering
uses `to_ascii_lowercase()`, which only affects bytes 0x41–0x5A (A–Z). Non-ASCII
characters pass through unchanged. This means:

- `"café"` and `"CAFÉ"` would NOT compare as equal (the `é` byte differs from
  `É` byte — `0xC3A9` vs `0xC389` in UTF-8)
- This matches Azure's behavior — ARM resource fields use ASCII identifiers

### 3.5 Implications for the compiler

The compiler emits `azure.policy.compare(field, value)` which returns `-1`, `0`,
or `1`, then uses `Gt`/`Lt`/`Ge`/`Le` against `0` to produce the boolean result.
No special ordering instructions are needed.

---

## 4. Date/Time Comparison

Some Azure resource properties contain date/time values as **strings** in
ISO 8601 format (e.g., `"2024-01-15T08:30:00Z"`).

### 4.1 How Azure Policy handles dates

Azure Policy does **not** have a dedicated date type or date comparison
operator. Date/time values are:

1. Stored as strings in the resource JSON
2. Compared **as strings** using the standard `greater`/`less`/`equals`
   operators

### 4.2 Why string comparison works for ISO 8601

ISO 8601 timestamps in UTC (`Z` suffix) are **lexicographically sortable**:

```
"2024-01-15T08:30:00Z" < "2024-06-20T12:00:00Z"  ✓ (correct)
"2023-12-31T23:59:59Z" < "2024-01-01T00:00:00Z"  ✓ (correct)
```

This works because:
- Year digits sort before month digits, etc.
- Fixed-length zero-padded fields ensure correct ordering
- `Z` suffix is the same for all UTC timestamps

### 4.3 When string comparison breaks

| Scenario | Problem |
|:---------|:--------|
| Mixed timezone offsets | `"2024-01-15T08:30:00+05:30"` vs `"2024-01-15T08:30:00Z"` — string comparison doesn't account for offset |
| Missing seconds | `"2024-01-15T08:30Z"` vs `"2024-01-15T08:30:00Z"` — different string lengths |
| Date-only vs datetime | `"2024-01-15"` vs `"2024-01-15T00:00:00Z"` — incompatible formats |
| Non-ISO formats | `"01/15/2024"` — US date format, does not sort correctly |

### 4.4 Affected resource properties

Common date/time properties in Azure resources:

| Property | Resource type | Format |
|:---------|:-------------|:-------|
| `createdTime` | Various | ISO 8601 UTC |
| `lastModifiedTime` | Various | ISO 8601 UTC |
| `expirationDate` | Key Vault certificates | ISO 8601 UTC |
| `validityInMonths` | Key Vault certificates | Integer (not date) |
| `attributes.expires` | Key Vault keys/secrets | Unix timestamp (integer) |
| `properties.startDate` | Various | ISO 8601 UTC |

### 4.5 Design decision

The compiler treats date/time values as **plain strings**. No date-parsing
builtin is needed because:

1. ARM resources consistently use ISO 8601 UTC, which is lexicographically
   sortable
2. Azure Policy itself does string comparison (no special date logic)
3. Adding date-aware builtins would be over-engineering for a problem that
   doesn't exist in practice

If a future scenario requires date-aware comparison (e.g., timezone
normalization), it would be a new builtin (`azure.policy.compare_datetime`)
rather than a change to the existing `azure.policy.compare`.

### 4.6 Example policy

```json
{
  "field": "Microsoft.KeyVault/vaults/certificates/attributes.expires",
  "less": "2025-01-01T00:00:00Z"
}
```

Compiled as a regular `less` comparison — `azure.policy.compare(field, value)`,
then `Lt` vs `0`. No special handling.

---

## 5. `containsKey` on Nested Paths

### 5.1 Basic behavior

`containsKey` checks whether a JSON object contains a specific **top-level
key** (case-insensitive):

```json
{ "field": "tags", "containsKey": "Environment" }
```

Resource: `{ "tags": { "environment": "prod", "team": "infra" } }`
→ **true** (case-insensitive match: `"Environment"` ≈ `"environment"`)

### 5.2 It checks leaf keys, not paths

`containsKey` does **not** traverse nested paths. The value is a single key
name, not a dot-separated path:

```json
{ "field": "properties", "containsKey": "networkProfile.networkInterfaces" }
```

This checks whether the `properties` object has a key literally named
`"networkProfile.networkInterfaces"` — it does **not** check
`properties.networkProfile.networkInterfaces` as a nested path.

| Resource structure | Condition | Result |
|:-------------------|:----------|:-------|
| `{ "properties": { "networkProfile.networkInterfaces": [...] } }` | Match | **true** |
| `{ "properties": { "networkProfile": { "networkInterfaces": [...] } } }` | No match | **false** |

### 5.3 Case-insensitivity

Key comparison is case-insensitive. The `azure.policy.contains` builtin
iterates the object's keys and compares each case-insensitively to the needle.

```json
{ "field": "tags", "containsKey": "CostCenter" }
```

Matches any of: `"costcenter"`, `"CostCenter"`, `"COSTCENTER"`, `"costCenter"`.

### 5.4 When field value is not an object

If the field value is not a JSON object (e.g., it's a string, array, number,
null):

- `containsKey` → **false** (not an object, so no keys)
- `notContainsKey` → **true**

This is consistent with `contains` on a non-string/non-array field.

### 5.5 Interaction with `[*]`

```json
{
  "field": "securityRules[*]",
  "containsKey": "sourceAddressPrefix"
}
```

In a bare field condition (universal), each element of `securityRules` is
individually checked for the key `"sourceAddressPrefix"`. ALL must contain
the key for the condition to pass.

### 5.6 Compiler implementation

`containsKey` uses the `azure.policy.contains` builtin with an object haystack.
The builtin detects the haystack type:
- String haystack → string substring search
- Array haystack → element membership check
- Object haystack → key existence check

All three modes are case-insensitive.

---

## 6. Boolean Semantics

### 6.1 Boolean comparison

Booleans compare as: `false < true`.

| Operator | Field `false`, condition `true` | Result |
|:---------|:-------------------------------|:-------|
| `equals` | **false** |
| `notEquals` | **true** |
| `greater` | `false < true` → **false** |
| `less` | `false < true` → **true** |

### 6.2 Boolean ↔ string

There is **no** coercion between booleans and strings:

- `{ "field": "enabled", "equals": "true" }` where `enabled` is `true` (bool)
  → **false** (type mismatch)

Policy authors must use the correct JSON type:
- `"equals": true` (bool literal) — not `"equals": "true"` (string)

### 6.3 Boolean ↔ number

There is **no** coercion between booleans and numbers:

- `{ "field": "count", "equals": true }` where `count` is `1` (number)
  → **false** (type mismatch)

### 6.4 Boolean in `in` / `notIn`

```json
{ "field": "properties.supportsHttpsTrafficOnly", "in": [true] }
```

Works as expected — boolean `true` equals boolean `true`.

```json
{ "field": "properties.supportsHttpsTrafficOnly", "in": ["true", true] }
```

Mixed array: if the field is `true` (bool), it matches the `true` (bool)
element. If the field is `"true"` (string), it matches the `"true"` (string)
element. No cross-type coercion.

---

## 7. Array Semantics

### 7.1 `contains` on arrays

```json
{ "field": "allowedLocations", "contains": "eastus" }
```

The `azure.policy.contains` builtin iterates the array and compares each
element to the needle using `azure.policy.compare` semantics (case-insensitive
for strings, coercion for string↔number).

### 7.2 `in` with an array field

```json
{ "field": "location", "in": ["eastus", "westus2", "centralus"] }
```

The `azure.policy.in` builtin iterates the condition array and compares each
element to the field value. First match returns true.

### 7.3 Empty arrays

| Operator | Field `[]` | Condition | Result |
|:---------|:-----------|:----------|:-------|
| `contains` | `[]` | `"eastus"` | **false** — empty array contains nothing |
| `notContains` | `[]` | `"eastus"` | **true** |
| `equals` | `[]` | `[]` | **true** — arrays are equal if structurally equal |
| `Count` (simple) | `[]` | `"equals": 0` | **true** — count is 0 |

### 7.4 Nested arrays

`contains` does **not** recurse into nested arrays:

```json
{ "field": "nestedArray", "contains": "value" }
```

Resource: `{ "nestedArray": [["value"]] }`
→ **false** — the top-level element is `["value"]` (an array), not `"value"`
(a string).

### 7.5 Array equality

`equals` / `notEquals` on arrays uses **structural equality** (deep comparison,
case-insensitive for string elements):

```json
{ "field": "allowedValues", "equals": ["A", "B", "C"] }
```

The field value must be an array with the same elements in the same order.
`["a", "b", "c"]` matches `["A", "B", "C"]` due to case-insensitivity.
`["B", "A", "C"]` does **not** match (order matters).

---

## 8. Numeric Edge Cases

### 8.1 Integer vs float

ARM resource JSON doesn't distinguish integers from floats (`42` and `42.0`
are the same JSON number). Azure Policy follows JSON semantics:

- `42 == 42.0` → **true** (same numeric value)
- `42 > 41.9` → **true**

### 8.2 Large integers

JSON numbers can be arbitrarily large, but ARM resources typically use values
within the i64/f64 range. The `azure.policy.compare` builtin uses Rust's
`PartialOrd` on the `Number` type, which handles i64 and f64 comparisons.

### 8.3 String port ranges

NSG rules use string port ranges like `"80"`, `"443"`, `"*"`, `"80-100"`.
For individual ports, string↔number coercion handles the common case:

```json
{ "field": "destinationPortRange", "greater": 1024 }
```

Field `"443"` → parses to `443` → `443 > 1024` → false.
Field `"*"` → parse fails → not comparable → **false** for `greater`.

Port **ranges** like `"80-100"` do not parse as numbers — the comparison returns
false. Policies that need to handle port ranges typically use `like` or `match`
with pattern matching, or check specific known ports with `in`.

---

## 9. `like` and `match` Pattern Semantics

### 9.1 `like` patterns

`like` uses **Azure Policy wildcard patterns** (not glob, not regex):

| Wildcard | Meaning |
|:---------|:--------|
| `*` | Matches zero or more characters |

That is the **only** wildcard. There is no `?` (single character), no character
classes, no escaping. The `*` can appear anywhere in the pattern: beginning,
middle, or end.

| Pattern | Input | Matches? |
|:--------|:------|:---------|
| `"*eastus*"` | `"eastus2"` | **true** |
| `"Microsoft.*"` | `"Microsoft.Compute"` | **true** |
| `"*"` | anything | **true** |
| `"exact"` | `"exact"` | **true** |
| `"exact"` | `"Exact"` | **true** (case-insensitive) |
| `"pre*suf"` | `"pre-middle-suf"` | **true** |
| `""` | `""` | **true** |
| `""` | `"nonempty"` | **false** |

**Case-insensitivity**: `like` comparisons are case-insensitive by default (this
is Azure Policy's standard behavior, same as all other operators).

### 9.2 `match` patterns

`match` uses **Azure Policy pattern matching** (not regex):

| Placeholder | Meaning |
|:------------|:--------|
| `#` | Matches a single digit (0–9) |
| `?` | Matches a single letter (a–z, A–Z) |
| `.` | Matches a single character (any) |

All other characters are matched literally.

| Pattern | Input | Matches? |
|:--------|:------|:---------|
| `"##-##-####"` | `"01-15-2024"` | **true** |
| `"???_##"` | `"abc_42"` | **true** |
| `"???_##"` | `"ab_42"` | **false** (too few letters) |
| `"a.c"` | `"abc"` | **true** (`.` matches `b`) |
| `"a.c"` | `"a.c"` | **true** (`.` matches `.`) |

**Case-sensitivity**: `match` is **case-sensitive** — it is the one exception
to Azure Policy's usual case-insensitivity. The pattern character `?` matches
any letter, but literal characters must match exactly.

### 9.3 `matchInsensitively` patterns

Same placeholder language as `match`, but the literal character matching is
**case-insensitive**:

| Pattern | Input | `match` | `matchInsensitively` |
|:--------|:------|:--------|:---------------------|
| `"Abc"` | `"ABC"` | **false** | **true** |
| `"Abc"` | `"abc"` | **false** | **true** |
| `"Abc"` | `"Abc"` | **true** | **true** |

### 9.4 Non-string field values

If the field value is not a string (number, bool, null, array, object):

- `like` → **false**
- `match` / `matchInsensitively` → **false**

No type coercion is attempted for pattern-matching operators.

### 9.5 Compiler builtins

| Operator | Builtin |
|:---------|:--------|
| `like` / `notLike` | `azure.policy.like(input, pattern) → bool` |
| `match` / `notMatch` | `azure.policy.match(input, pattern) → bool` |
| `matchInsensitively` / `notMatchInsensitively` | `azure.policy.match_insensitively(input, pattern) → bool` |

---

## 10. Summary: Operator × Type Matrix

This matrix shows what happens when each operator encounters different value
types. "U" = undefined (handler per §2.3), "‒" = always false for this type
combination.

### Equality operators (`equals` / `notEquals`)

| Field type ↓ \ Condition type → | string | number | bool | null | array | object |
|:-------------------------------|:-------|:-------|:-----|:-----|:------|:-------|
| string | Case-insensitive equal | Coerce string→number | ‒ | ‒ | ‒ | ‒ |
| number | Coerce string→number | Numeric equal | ‒ | ‒ | ‒ | ‒ |
| bool | ‒ | ‒ | Direct compare | ‒ | ‒ | ‒ |
| null | ‒ | ‒ | ‒ | Equal | ‒ | ‒ |
| array | ‒ | ‒ | ‒ | ‒ | Structural equal | ‒ |
| object | ‒ | ‒ | ‒ | ‒ | ‒ | Structural equal |
| undefined | U | U | U | U | U | U |

### Ordering operators (`greater` / `less` / `greaterOrEquals` / `lessOrEquals`)

| Field type ↓ \ Condition type → | string | number | bool | null |
|:-------------------------------|:-------|:-------|:-----|:-----|
| string | Case-insensitive lexicographic | Coerce string→number | ‒ | string > null |
| number | Coerce string→number | Numeric compare | ‒ | number > null |
| bool | ‒ | ‒ | `false < true` | bool > null |
| null | null < string | null < number | null < bool | null == null |
| undefined | U | U | U | U |

### Membership operators (`in` / `notIn`)

The condition is always an array. The field value is compared against each
element using `azure.policy.compare` semantics (case-insensitive, with
string↔number coercion).

### Containment operators (`contains` / `notContains`)

| Field type | Behavior |
|:-----------|:---------|
| string | Case-insensitive substring search |
| array | Per-element comparison via `azure.policy.compare` |
| other | **false** |

### Key operators (`containsKey` / `notContainsKey`)

| Field type | Behavior |
|:-----------|:---------|
| object | Case-insensitive key membership |
| other | **false** |

### Pattern operators (`like` / `match` / `matchInsensitively`)

| Field type | Behavior |
|:-----------|:---------|
| string | Pattern match per §9 rules |
| other | **false** |

### Existence operator (`exists`)

| Condition | Field undefined | Field null | Field any other |
|:----------|:---------------|:-----------|:----------------|
| `true` | false | true | true |
| `false` | true | false | false |

---

## Open Questions

These require validation against the Azure Policy service during implementation:

| # | Question | Current assumption | Risk |
|:--|:---------|:-------------------|:-----|
| Q1 | Does string↔number coercion use integer or float parsing? | `f64` parsing via `str::parse::<f64>()` | Low — covers both integer and decimal strings |
| Q2 | What happens when `greater`/`less` receives mismatched non-coercible types (e.g., string vs bool)? | Returns "not comparable" → operator returns false | Medium — need to verify Azure's behavior |
| Q3 | Is array equality order-sensitive? | Yes — `["a","b"] ≠ ["b","a"]` | Medium — Azure docs don't explicitly state this |
| Q4 | Does `containsKey` recurse into nested objects? | No — top-level keys only | Low — consistent with `contains` non-recursion |
| Q5 | Are there any resource properties that use non-UTC ISO 8601? | Assumed no (all ARM APIs return UTC) | Low |
| Q6 | Unicode handling — does Azure use locale-aware or ordinal comparison? | Ordinal (ASCII lowercase) | Low — ARM properties are ASCII |
| Q7 | Does `equals` on objects do deep structural comparison or identity? | Deep structural comparison | Medium — rarely used in practice |
