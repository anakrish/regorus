# Azure Policy Builtins

Custom builtin functions registered under `#[cfg(feature = "azure_policy")]`
for evaluating Azure Policy conditions in the RVM. These builtins are emitted
**only** by the Azure Policy JSON compiler — the Rego compiler uses standard
RVM instructions (`Eq`, `Lt`, etc.) with case-sensitive semantics.

For the rationale behind using custom builtins (vs `lower()` + standard ops,
vs input normalization, vs VM-level modes), see
[comparison-strategy.md](comparison-strategy.md).

---

## Design Principles

1. **Rego semantics are untouched.** The RVM's core instructions remain
   case-sensitive. Azure Policy case-insensitivity is handled entirely in
   the builtin layer.
2. **Undefined handling is the compiler's job.** Builtins assume their
   arguments are defined values. The compiler emits `IsUndefined` + branch
   or `AssertNotUndefined` *before* calling the builtin (see §6.2.1 in
   [compiler.md](compiler.md)).
3. **Bool-returning.** All builtins except `azure.policy.compare` return
   `bool`. The `not*` variants (`notEquals`, `notIn`, etc.) are handled by
   the compiler emitting `Not` after the positive builtin call — no separate
   negated builtins are needed.
4. **Type-safe mixed comparisons.** When comparing values of different types
   (string vs number vs bool), builtins define explicit behavior rather than
   failing with a type error.

---

## Builtin Reference

### `azure.policy.compare(a, b) → i64`

**Returns**: `-1` if a < b, `0` if a == b, `1` if a > b.

**Used by operators**: `equals`, `notEquals`, `greater`, `greaterOrEquals`,
`less`, `lessOrEquals`.

The compiler uses the return value with a standard RVM comparison against `0`:

```
BuiltinCall("azure.policy.compare", r_field, r_value) → r_cmp
Load { dest: r_zero, literal_idx: <0> }
Eq  { dest: r_result, left: r_cmp, right: r_zero }   // equals
Gt  { dest: r_result, left: r_cmp, right: r_zero }   // greater
Lt  { dest: r_result, left: r_cmp, right: r_zero }   // less
Ge  { dest: r_result, left: r_cmp, right: r_zero }   // greaterOrEquals
Le  { dest: r_result, left: r_cmp, right: r_zero }   // lessOrEquals
```

#### Type dispatch rules

| a type | b type | Behavior |
|:-------|:-------|:---------|
| string | string | Case-insensitive lexicographic comparison (`a.to_lowercase()` vs `b.to_lowercase()`) |
| number | number | Standard numeric comparison |
| bool   | bool   | `false < true` |
| string | number | Attempt to parse the string as a number. If parseable, numeric comparison. Otherwise, the values are not comparable → return `0` for equality checks, behavior TBD for ordering (see [Open Questions](#open-questions)). |
| number | string | Same as above (symmetric) |
| null   | null   | `0` (equal) |
| null   | any    | `-1` (null sorts before all values) |
| any    | null   | `1` |
| mismatched types (other) | | `0` for equality, TBD for ordering |

#### String comparison details

- Both operands are lowered with Unicode-unaware ASCII lowering
  (`to_ascii_lowercase`). Azure Policy operates on resource properties
  which are ASCII-safe identifiers, locations, SKU names, etc.
- Comparison is **lexicographic** on the lowered strings using Rust's
  standard `Ord` implementation on `&str`.
- Empty string equals empty string.

#### Numeric comparison details

- Integer and float values follow standard Rust `PartialOrd`.
- `NaN` is not expected in Azure Policy resource values. If encountered,
  comparisons return `0` (not comparable).

#### Implementation sketch

```rust
fn azure_policy_compare(a: &Value, b: &Value) -> Value {
    let ord = match (a, b) {
        (Value::String(a), Value::String(b)) => {
            a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase())
        }
        (Value::Number(a), Value::Number(b)) => {
            a.partial_cmp(b).unwrap_or(Ordering::Equal)
        }
        (Value::Bool(a), Value::Bool(b)) => a.cmp(b),
        (Value::Null, Value::Null) => Ordering::Equal,
        (Value::Null, _) => Ordering::Less,
        (_, Value::Null) => Ordering::Greater,
        // String ↔ number coercion
        (Value::String(s), Value::Number(n)) => {
            match s.parse::<f64>() {
                Ok(sn) => sn.partial_cmp(&n.as_f64()).unwrap_or(Ordering::Equal),
                Err(_) => Ordering::Equal, // not comparable
            }
        }
        (Value::Number(n), Value::String(s)) => {
            match s.parse::<f64>() {
                Ok(sn) => n.as_f64().partial_cmp(&sn).unwrap_or(Ordering::Equal),
                Err(_) => Ordering::Equal,
            }
        }
        _ => Ordering::Equal, // mismatched types
    };
    Value::Number(match ord {
        Ordering::Less => (-1).into(),
        Ordering::Equal => 0.into(),
        Ordering::Greater => 1.into(),
    })
}
```

---

### `azure.policy.contains(haystack, needle) → bool`

**Used by operators**: `contains`, `notContains`.

Dual-mode: behavior depends on the runtime type of `haystack`.

#### String mode

When `haystack` is a string: **case-insensitive substring check**.

```
"FooBarBaz" contains "bar"  → true
"hello"     contains "HELLO" → true
"hello"     contains "xyz"   → false
```

Both `haystack` and `needle` are lowered before the substring search. If
`needle` is not a string, returns `false`.

#### Array mode

When `haystack` is an array: **case-insensitive element membership**.

```
["East", "West"] contains "east"  → true
[1, 2, 3]        contains 2       → true
["a", "b"]       contains "c"     → false
```

Each element is compared to `needle` using `azure.policy.compare`-equivalent
case-insensitive equality. For non-string elements, standard equality applies.

#### Other types

Returns `false` if `haystack` is not a string or array.

#### Implementation sketch

```rust
fn azure_policy_contains(haystack: &Value, needle: &Value) -> Value {
    Value::Bool(match haystack {
        Value::String(s) => match needle {
            Value::String(n) => {
                s.to_ascii_lowercase().contains(&n.to_ascii_lowercase())
            }
            _ => false,
        },
        Value::Array(arr) => {
            arr.iter().any(|elem| azure_policy_values_equal(elem, needle))
        }
        _ => false,
    })
}
```

---

### `azure.policy.in(element, array) → bool`

**Used by operators**: `in`, `notIn`.

Case-insensitive element membership check. Equivalent to
`azure.policy.contains(array, element)` in array mode, but with arguments
in the order matching Azure Policy's `"in"` semantics:

```json
{ "field": "location", "in": ["eastus", "westus"] }
```

compiles to:

```
BuiltinCall("azure.policy.in", r_field, r_set) → r_result
```

#### Behavior

- Iterates `array` elements, comparing each to `element` using
  case-insensitive string equality (or standard equality for non-strings).
- Returns `true` on first match, `false` if exhausted.
- If `array` is not an array, returns `false`.

#### Why separate from `azure.policy.contains`?

Argument order clarity. Azure Policy's `contains` is
`haystack contains needle` while `in` is `element in collection`. Keeping
them as separate builtins makes the compiler's emitted code self-documenting
and avoids argument-swapping confusion.

#### Implementation sketch

```rust
fn azure_policy_in(element: &Value, array: &Value) -> Value {
    Value::Bool(match array {
        Value::Array(arr) => {
            arr.iter().any(|item| azure_policy_values_equal(element, item))
        }
        _ => false,
    })
}
```

---

### `azure.policy.like(input, pattern) → bool`

**Used by operators**: `like`, `notLike`.

Case-insensitive glob-style pattern matching.

#### Pattern syntax

| Character | Meaning |
|:----------|:--------|
| `*` | Matches zero or more characters |
| `?` | Matches exactly one character (any character) |
| All others | Literal match |

**Note**: Azure Policy `like`'s `?` matches *any single character*, unlike
`match`'s `?` which matches only letters.

#### Case-insensitivity

Both `input` and the literal characters in `pattern` are compared
case-insensitively. Wildcards (`*`, `?`) are inherently case-insensitive.

#### Examples

```
"FooBar"    like "foo*"     → true
"test123"   like "test???"  → true
"hello"     like "HELLO"    → true
"abc"       like "a*c"      → true
"abc"       like "a?c"      → true
"abdc"      like "a?c"      → false
```

#### Implementation sketch

```rust
fn azure_policy_like(input: &Value, pattern: &Value) -> Value {
    Value::Bool(match (input, pattern) {
        (Value::String(s), Value::String(p)) => {
            glob_match_case_insensitive(s, p)
        }
        _ => false,
    })
}

/// Glob match with case-insensitive literal comparison.
/// '*' matches zero or more chars, '?' matches exactly one char.
fn glob_match_case_insensitive(input: &str, pattern: &str) -> bool {
    let s: Vec<char> = input.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    let (mut si, mut pi) = (0, 0);
    let (mut star_pi, mut star_si) = (usize::MAX, 0);

    while si < s.len() {
        if pi < p.len() && p[pi] == '?' {
            si += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_pi = pi;
            star_si = si;
            pi += 1;
        } else if pi < p.len()
            && s[si].to_ascii_lowercase() == p[pi].to_ascii_lowercase()
        {
            si += 1;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_si += 1;
            si = star_si;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}
```

---

### `azure.policy.match(input, pattern) → bool`

**Used by operators**: `match`, `notMatch`.

Custom pattern matching using Azure Policy's pattern language.

#### Pattern syntax

| Character | Meaning |
|:----------|:--------|
| `#` | Matches exactly one ASCII digit (`0`–`9`) |
| `?` | Matches exactly one ASCII letter (`a`–`z`, `A`–`Z`) |
| All others | Literal match (**case-sensitive**) |

**Important**: This is NOT regex. Not glob. It's a fixed-width
character-by-character pattern where `#` and `?` are the only wildcards.

#### Length constraint

The input and pattern must have the **same character count**. If lengths
differ, the match fails immediately. This is a defining characteristic of
Azure Policy's `match` — it's always an exact-length match.

#### Case sensitivity

Literal characters are compared **case-sensitively**. To get case-insensitive
matching, use `matchInsensitively` (→ `azure.policy.match_insensitively`).

#### Examples

```
"contoso-vm-12" match "contoso-vm-##"  → true
"contoso-vm-1"  match "contoso-vm-##"  → false  (length mismatch)
"contoso-VM-12" match "contoso-vm-##"  → false  (case-sensitive: 'V' ≠ 'v')
"abc123"        match "???###"         → true
"abc12"         match "???###"         → false  (length)
"ab1123"        match "???###"         → false  ('1' is not a letter)
```

#### Runtime pattern

The pattern can come from a runtime parameter:

```json
{ "field": "name", "match": "[parameters('namePattern')]" }
```

This is why the pattern cannot be translated to regex at compile time.

#### Implementation

```rust
fn azure_policy_match(input: &Value, pattern: &Value) -> Value {
    Value::Bool(match (input, pattern) {
        (Value::String(s), Value::String(p)) => {
            let s: Vec<char> = s.chars().collect();
            let p: Vec<char> = p.chars().collect();
            s.len() == p.len()
                && s.iter().zip(p.iter()).all(|(i, p)| match p {
                    '#' => i.is_ascii_digit(),
                    '?' => i.is_ascii_alphabetic(),
                    _ => i == p,
                })
        }
        _ => false,
    })
}
```

---

### `azure.policy.match_insensitively(input, pattern) → bool`

**Used by operators**: `matchInsensitively`, `notMatchInsensitively`.

Identical to `azure.policy.match` except literal characters are compared
**case-insensitively**. The `#` and `?` wildcards are inherently
case-insensitive (they match character classes, not specific characters).

#### Examples

```
"contoso-VM-12" match_insensitively "contoso-vm-##"  → true
"CONTOSO-VM-12" match_insensitively "contoso-vm-##"  → true
"contoso-vm-AB" match_insensitively "contoso-vm-##"  → false ('#' needs digit)
```

#### Implementation

```rust
fn azure_policy_match_insensitively(input: &Value, pattern: &Value) -> Value {
    Value::Bool(match (input, pattern) {
        (Value::String(s), Value::String(p)) => {
            let s: Vec<char> = s.chars().collect();
            let p: Vec<char> = p.chars().collect();
            s.len() == p.len()
                && s.iter().zip(p.iter()).all(|(i, p)| match p {
                    '#' => i.is_ascii_digit(),
                    '?' => i.is_ascii_alphabetic(),
                    _ => i.to_ascii_lowercase() == p.to_ascii_lowercase(),
                })
        }
        _ => false,
    })
}
```

---

## Shared Helper: `azure_policy_values_equal`

Used internally by `azure.policy.contains` (array mode) and `azure.policy.in`
for case-insensitive element comparison:

```rust
/// Case-insensitive equality for Azure Policy.
/// Strings compared case-insensitively; other types use standard equality.
fn azure_policy_values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::String(a), Value::String(b)) => {
            a.to_ascii_lowercase() == b.to_ascii_lowercase()
        }
        _ => a == b,
    }
}
```

---

## Negation and Undefined Handling

### Negation

The `not*` variants of each operator (`notEquals`, `notIn`, `notContains`,
`notLike`, `notMatch`, `notMatchInsensitively`, `notContainsKey`) are handled
by the **compiler** emitting a `Not` instruction after the positive builtin
call. No separate negated builtins are needed.

```
// notEquals:
BuiltinCall("azure.policy.compare", r_field, r_value) → r_cmp
Load { dest: r_zero, literal_idx: <0> }
Eq  { dest: r_eq, left: r_cmp, right: r_zero }
Not { dest: r_result, operand: r_eq }
AssertCondition { condition: r_result }
```

### Undefined field handling

Builtins assume their arguments are **defined** values. Undefined-field
semantics are enforced by the **compiler** before the builtin call:

| Field status | Positive operators (equals, in, contains, ...) | Negative operators (notEquals, notIn, ...) |
|:-------------|:------------------------------------------------|:-------------------------------------------|
| Defined      | Call builtin normally                           | Call builtin + `Not`                       |
| Undefined    | Rule fails (`AssertNotUndefined`)               | Rule succeeds (skip to success via `IsUndefined` + branch) |

This design keeps the builtins simple (no undefined awareness) while
correctly implementing Azure Policy's undefined semantics. See
[compiler.md](compiler.md) §6.2.1 for the full undefined-behavior table and
emitted instruction patterns.

---

## Registration

All builtins are registered under the `azure_policy` Cargo feature gate:

```rust
#[cfg(feature = "azure_policy")]
pub fn register_azure_policy_builtins(engine: &mut Engine) {
    engine.register_builtin("azure.policy.compare", 2, azure_policy_compare);
    engine.register_builtin("azure.policy.contains", 2, azure_policy_contains);
    engine.register_builtin("azure.policy.in", 2, azure_policy_in);
    engine.register_builtin("azure.policy.like", 2, azure_policy_like);
    engine.register_builtin("azure.policy.match", 2, azure_policy_match);
    engine.register_builtin("azure.policy.match_insensitively", 2, azure_policy_match_insensitively);
}
```

These are additional to the standard Rego builtins. They appear in the
program's `builtin_info_table` and are referenced by `BuiltinCall`
instructions via their table index.

---

## Summary Table

| Builtin | Args | Returns | Case-insensitive | Covers |
|:--------|:-----|:--------|:-----------------|:-------|
| `azure.policy.compare` | 2 | i64 (-1/0/1) | strings only | equals, notEquals, greater, greaterOrEquals, less, lessOrEquals |
| `azure.policy.contains` | 2 | bool | strings only | contains, notContains |
| `azure.policy.in` | 2 | bool | strings only | in, notIn |
| `azure.policy.like` | 2 | bool | yes (literals) | like, notLike |
| `azure.policy.match` | 2 | bool | no | match, notMatch |
| `azure.policy.match_insensitively` | 2 | bool | yes (literals) | matchInsensitively, notMatchInsensitively |

---

## Open Questions

These are documented for resolution during implementation:

1. **String ↔ number coercion in `compare`**: Azure Policy may coerce
   `"80"` to `80` for numeric comparison. Need to verify the exact coercion
   rules against Azure Policy service behavior.
2. **Ordering on mismatched types**: What does `"abc" > 42` evaluate to?
   Current design returns `0` (equal / not comparable). Need to verify.
3. **Null semantics**: Is `null` different from undefined in Azure Policy?
   Undefined is handled before the builtin is called. Null as a *value*
   (field exists but is null) needs clarification.
4. **Unicode**: Current implementation uses ASCII lowering. If Azure Policy
   resources contain non-ASCII strings, should we use full Unicode case
   folding?

---

## See Also

- [comparison-strategy.md](comparison-strategy.md) — Evaluation of all
  approaches for case-insensitive comparison (lower, builtins, normalization,
  VM-level)
- [compiler.md](compiler.md) §6.2.1 — Undefined field behavior table
- [compiler.md](compiler.md) §6.2.2 — Builtin table and compilation strategy
- [compiler.md](compiler.md) §6.3 — Per-operator instruction mappings
