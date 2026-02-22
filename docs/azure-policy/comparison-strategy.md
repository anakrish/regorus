# Azure Policy Comparison Strategy — Case-Insensitivity

This document evaluates different approaches for handling Azure Policy's
case-insensitive string comparisons in the RVM compiler pipeline.

## Problem Statement

Azure Policy string comparisons are **case-insensitive** for:
`equals`, `notEquals`, `in`, `notIn`, `contains`, `notContains`, `like`,
`notLike`.

However, the same RVM is also used to execute policies written in **Rego**,
where comparisons are **case-sensitive** (standard Rego semantics). The chosen
approach must:

1. Produce correct case-insensitive behavior for Azure Policy JSON → RVM
2. Preserve correct case-sensitive behavior for Rego → RVM
3. Avoid modifying the VM's core comparison instructions (`Eq`, `Lt`, etc.)
4. Handle mixed-type comparisons (field could be string, number, or boolean)

---

## Approaches Evaluated

### Approach A: `lower()` both operands before comparison

The Azure Policy compiler emits `BuiltinCall("lower")` on both operands
before each comparison instruction (`Eq`, `Lt`, etc.).

```
// Azure Policy: "field": "name", "equals": "FooBar"
BuiltinCall("lower", r_field) → r_field_low
BuiltinCall("lower", r_value) → r_value_low
Eq { dest: r_cmp, left: r_field_low, right: r_value_low }
```

The Rego compiler continues to emit bare `Eq`/`Lt`/etc.

**Pros:**
- Simple to implement — reuses existing Rego `lower` builtin
- No new builtins needed
- VM comparison instructions remain unchanged
- Rego semantics preserved automatically (Rego compiler doesn't emit `lower`)
- Literal-side optimization: pre-lowercase string literals at compile time

**Cons:**
- **Type safety**: `lower()` on a number or boolean will fail in Rego's type
  system. Numbers and booleans should be compared without lowering.
- **Extra instructions**: 2 additional `BuiltinCall` instructions per
  comparison (or 1 with literal optimization)
- **Incorrect for non-string types**: The compiler would need runtime type
  guards (`IsString` check → branch) to avoid calling `lower()` on numbers,
  adding further instruction overhead
- **Ordering semantics**: `lower()` + `Lt` gives lexicographic ordering on
  lowered strings, but Azure Policy's `greater`/`less` may need type-aware
  comparison logic (e.g., `"80" < "9"` lexicographically but `80 > 9`
  numerically)
- **`in` operator**: Would need to lower every element of the set, not just
  the search value — expensive for large sets

### Approach B: Case-insensitive comparison builtins (✅ chosen)

Register custom `azure.policy.*` builtins that encapsulate case-insensitive
semantics:

| Builtin | Semantics | Covers |
|:--------|:----------|:-------|
| `azure.policy.compare(a, b)` | Returns -1/0/1; case-insensitive for strings; type-appropriate for numbers/bools | `equals`, `notEquals`, `greater`, `less`, `greaterOrEquals`, `lessOrEquals` |
| `azure.policy.contains(haystack, needle)` | Case-insensitive substring (string) or case-insensitive membership (array) | `contains`, `notContains` |
| `azure.policy.in(element, array)` | Case-insensitive element membership | `in`, `notIn` |
| `azure.policy.like(input, pattern)` | Case-insensitive glob match | `like`, `notLike` |
| `azure.policy.match(input, pattern)` | Case-sensitive `#`/`?` pattern | `match`, `notMatch` |
| `azure.policy.match_insensitively(input, pattern)` | Case-insensitive `#`/`?` pattern | `matchInsensitively`, `notMatchInsensitively` |

```
// Azure Policy: "field": "name", "equals": "FooBar"
BuiltinCall("azure.policy.compare", r_field, r_value) → r_cmp
Load { dest: r_zero, literal_idx: <0> }
Eq { dest: r_result, left: r_cmp, right: r_zero }
```

The Rego compiler continues to emit bare `Eq`/`Lt`/etc.

**Pros:**
- **Type-safe**: Builtins handle mixed types correctly (case-insensitive for
  strings, standard comparison for numbers/booleans) — no type guards needed
- **Fewer emitted instructions**: One `BuiltinCall` replaces two `lower()`
  calls + a comparison. For `in`/`contains`, one call replaces what would be
  a loop of per-element lowering.
- **Rego semantics preserved**: Standard comparison instructions remain
  case-sensitive. The custom builtins are only emitted by the Azure Policy
  JSON compiler.
- **Dual-mode `contains`**: String vs array dispatch encapsulated inside the
  builtin — no need for emitted `IsArray` + branch instructions
- **Extensible**: If Azure Policy adds new comparison semantics (e.g.,
  locale-aware ordering, date comparison), only the builtin implementation
  changes — no compiler changes
- **`in` is efficient**: The builtin can iterate the array internally with
  case-insensitive comparison, rather than the compiler lowering every element

**Cons:**
- New builtins to implement and maintain (6 builtins)
- Feature-gated behind `#[cfg(feature = "azure_policy")]` — small binary
  size cost when enabled
- `azure.policy.compare` returns -1/0/1, so `equals` still needs a follow-up
  `Eq` vs 0 instruction (though this could be optimized into a dedicated
  `azure.policy.equals` returning bool if the extra instruction is a concern)

### Approach C: Lowercase at normalization time (input preprocessing)

The input normalizer (alias-normalization.md §11) pre-lowercases all string
values in the resource before evaluation begins.

**Pros:**
- Zero per-comparison overhead — comparisons use standard `Eq`/`Lt`/etc.
- Simple compiler — no special handling needed
- One-pass preprocessing

**Cons:**
- **Destructive**: Original casing is lost. If the policy's effect needs to
  read the original field value (e.g., `modify` operations, `append`, or
  returning field values in compliance messages), it gets the lowered version.
- **Breaks Rego policies**: Rego policies authored against the same normalized
  input would see all-lowercase strings, which they don't expect.
- **Parameters too?**: Would also need to lowercase all parameter strings,
  including those used in non-comparison contexts (e.g., `concat`, template
  expressions that build resource names).
- **Incomplete**: Doesn't help with `like`/`match` patterns that contain
  uppercase literal characters — the patterns themselves would also need
  lowering, which changes their semantics (e.g., match `?` checks for
  letters; lowercase `?` pattern against lowered input would only match
  lowercase letters, which happens to work, but it's fragile).
- **Ordering broken**: Pre-lowering all strings means `greater`/`less`
  comparisons see only lowercase versions, which may differ from Azure
  Policy's intended ordering semantics.

### Approach D: VM-level case-insensitive comparison mode

Add a flag or variant to the VM's comparison instructions (e.g.,
`EqInsensitive`, or a mode register) that makes them case-insensitive.

**Pros:**
- Most efficient at runtime — no extra instructions or function call overhead
- Clean instruction stream

**Cons:**
- **Modifies the VM**: Changes core instruction semantics. Every comparison
  instruction needs a case-sensitivity variant or flag, doubling the
  instruction surface area.
- **RVM instruction size**: Adding a flag may not fit in the 32-bit
  instruction encoding without restructuring.
- **Rego correctness risk**: Must ensure the case-insensitive mode is never
  accidentally active during Rego evaluation.
- **Coupling**: The VM now carries Azure Policy–specific semantics, violating
  the principle that the RVM is a general-purpose Rego execution engine.

---

## Decision

**Approach B** (custom comparison builtins) was chosen because it:

1. **Cleanly separates concerns**: The RVM's core instructions remain
   standard Rego semantics. Case-insensitivity is an Azure Policy compiler
   concern, handled entirely in the builtin layer.
2. **Handles mixed types correctly**: No risk of calling `lower()` on a
   number. The builtins internally dispatch based on value type.
3. **Preserves Rego semantics**: Policies written in Rego use standard
   case-sensitive instructions. No modal flags, no pre-processing, no
   shared mutable state.
4. **Encapsulates dual-mode operators**: `contains` (string vs array) and
   `in` (case-insensitive membership) are single builtin calls rather than
   multi-instruction emitted sequences.
5. **Minimal instruction count**: Typically one `BuiltinCall` per comparison
   (plus one `Eq`/`Lt`/etc. vs 0 for the `compare` builtin's return value).

The builtins are registered under `#[cfg(feature = "azure_policy")]` and
documented in [compiler.md](compiler.md) §6.2.2 and §6.3.

---

## See Also

- [compiler.md](compiler.md) §6.2.2 — Builtin table and compilation strategy
- [compiler.md](compiler.md) §6.3 — Per-operator instruction mappings
- [compiler.md](compiler.md) §6.3.1 — `azure.policy.contains` dual-mode implementation
- [compiler.md](compiler.md) §6.3.2 — `azure.policy.match` pattern builtin implementation
