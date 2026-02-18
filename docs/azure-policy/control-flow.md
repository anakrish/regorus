# Control Flow for Azure Policy Compilation

This document analyzes why the Azure Policy compiler needs control-flow
constructs that the Rego compiler does not, examines four alternative
approaches, and documents the chosen design.

See also:
- [compiler.md §6.2.1](compiler.md) — undefined field handling
- [compiler.md §6.6](compiler.md) — template expression compilation
- [builtins.md](builtins.md) — azure.policy.* builtins
- [semantic-behaviors.md](semantic-behaviors.md) — null/undefined/empty-string
  distinctions

---

## Table of Contents

1. [The Problem](#1-the-problem)
2. [How Rego Handles the Same Logic](#2-how-rego-handles-the-same-logic)
3. [Why the Rego Patterns Don't Map Directly](#3-why-the-rego-patterns-dont-map-directly)
4. [Approach A: Raw Jumps (`Jump`, `JumpIf`, `IsUndefined`)](#4-approach-a-raw-jumps)
5. [Approach B: Helper Rules (Rego-Native Pattern)](#5-approach-b-helper-rules)
6. [Approach C: Structured `IfThenElse` + `IsDefined`](#6-approach-c-structured-ifthenelse--isdefined)
7. [Approach D: `soft_assert_mode` Reuse](#7-approach-d-soft_assert_mode-reuse)
8. [Comparison Matrix](#8-comparison-matrix)
9. [Chosen Approach](#9-chosen-approach)
10. [Open Questions](#10-open-questions)

---

## 1. The Problem

Azure Policy has two patterns that require conditional control flow, which the
existing RVM instruction set (designed for Rego) does not directly support.

### 1.1 Negative operators with undefined → succeed

Azure Policy's negative operators (`notEquals`, `notIn`, `notContains`,
`notContainsKey`, `notLike`, `notMatch`, `notMatchInsensitively`) must
**succeed** when the field is undefined.

```json
{ "field": "optionalTag", "notEquals": "badValue" }
```

Semantics:
- If `optionalTag` is undefined → **condition succeeds** (true)
- If `optionalTag` is `"badValue"` → condition fails (false)
- If `optionalTag` is `"goodValue"` → condition succeeds (true)

The challenge: the RVM's `AssertNotUndefined` **fails** when the field is
undefined. But for negative operators, undefined must *succeed*. We need to
detect undefined and take a different path.

### 1.2 `if()` template expressions

Azure Policy has ternary expressions in template syntax:

```json
"[if(equals(field('Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType'), 'Windows'), 'Microsoft.Compute/virtualMachines/extensions', 'Microsoft.Compute/virtualMachines/extensions')]"
```

This selects between two values based on a condition. The RVM has no ternary
instruction — Rego doesn't need one because it uses multi-body rules instead.

---

## 2. How Rego Handles the Same Logic

Understanding how Rego compiles equivalent logic is essential — the RVM was
designed for Rego, and any new instruction should feel natural alongside the
existing ones.

### 2.1 Rego's `not` — negation via soft-assert mode

Rego:
```rego
deny {
    not input.resource.tags.environment
}
```

How the Rego compiler handles this:

1. **Enter soft-assert mode** — the compiler sets `soft_assert_mode = true`
   for the inner expression. In this mode, `AssertNotUndefined` and
   `AssertCondition` instructions are **suppressed** — they are not emitted.
   This allows the inner expression to return `undefined` without aborting
   the rule body.

2. **Compile the inner expression** — `input.resource.tags.environment` is
   compiled as `ChainedIndex` lookups. Normally `AssertNotUndefined` would
   follow, but in soft-assert mode it's skipped. If the field is absent,
   the register holds `undefined`.

3. **Emit `Not`** — The `Not` instruction handles undefined specially:
   - `undefined` → `true` (negation of "no result" succeeds)
   - `true` → `false`
   - `false` → `true`

4. **Emit `AssertCondition`** — Asserts the negated result.

RVM instructions:
```
ChainedIndex → r_field          // may produce undefined (soft-assert: no AssertNotUndefined)
Not { dest: r_neg, operand: r_field }   // undefined→true, true→false, false→true
AssertCondition { condition: r_neg }
```

Key: **no branching is needed** because `Not` absorbs the undefined→true
conversion in a single instruction.

### 2.2 Rego's multi-body rules — if/else via try/fail

Rego:
```rego
default message = "unknown"

message = "windows" {
    input.resource.osType == "Windows"
}

message = "linux" {
    input.resource.osType == "Linux"
}
```

How this compiles:

1. Each body becomes a separate **entry point** in the program
2. The VM tries each body in order via `jump_to(entry_point)`
3. If a body succeeds (`Ok`) → that's the result, skip remaining bodies
4. If a body fails (assertion failure → `Err`) → try next body
5. If all bodies fail → use the `default` literal (pre-computed at compile time)

No branching instructions — the try/fail mechanism IS the control flow.

### 2.3 Rego's `not` with comparison — the closest analog

The closest Rego equivalent to Azure Policy's `notEquals` with undefined:

```rego
# Azure Policy: { "field": "location", "notEquals": "eastus" }
# Rego equivalent:

deny {
    not location_is_eastus
}

location_is_eastus {
    input.resource.location  # asserts defined
    azure.policy.compare(input.resource.location, "eastus") == 0
}
```

RVM compilation of `location_is_eastus` helper:
```
RuleInit { result_reg: r_helper, rule_index: N }
  LoadInput → r_input
  ChainedIndex { path: ["resource", "location"] } → r_field
  AssertNotUndefined { register: r_field }          // undefined → body fails
  BuiltinCall("azure.policy.compare") → r_cmp
  Load { dest: r_zero, literal: 0 }
  Eq { dest: r_eq, left: r_cmp, right: r_zero }
  AssertCondition { condition: r_eq }                // not equal → body fails
  LoadTrue { dest: r_helper }
RuleReturn
```

RVM compilation of `deny` body:
```
CallRule { dest: r_result, rule_index: N }
Not { dest: r_neg, operand: r_result }               // helper failed → true
AssertCondition { condition: r_neg }
```

This works perfectly via existing instructions.

---

## 3. Why the Rego Patterns Don't Map Directly

### 3.1 Soft-assert mode is a compiler concept, not an instruction

Soft-assert mode works by *suppressing instruction emission* at compile time.
The RVM doesn't know about it — there's no runtime cost or special instruction.

For Azure Policy's `notEquals`, we could use soft-assert mode during
compilation of the field access, then `Not` the result. But there's a subtlety:

```
// Compiling: { "field": "location", "notEquals": "eastus" }
// With soft-assert mode for the field access:

LoadInput → r_input
ChainedIndex → r_field                    // soft-assert: no AssertNotUndefined
BuiltinCall("azure.policy.compare", r_field, r_expected) → r_cmp
```

**Problem**: If `r_field` is undefined, calling `azure.policy.compare` with an
undefined argument is undefined behavior (builtins assume defined inputs — see
[builtins.md §design principles](builtins.md)). We need to either:
- Check for undefined *before* calling the builtin, or
- Make every builtin handle undefined inputs (violates the builtin contract)

In Rego's `not` pattern, this isn't a problem because `not` negates the
*entire* expression outcome (including undefined). But Azure Policy needs to
negate *just the comparison* while treating undefined as a special success case.

### 3.2 Multi-body rules are heavyweight for inline conditions

Azure Policy's `if()` expression appears **inline** within a field reference:

```json
"field": "[if(equals(field('type'), 'Microsoft.Compute'), 'runCommand', 'extensions')]"
```

Creating separate helper rules for every `if()` expression is structurally
correct but:
- Requires allocating a `rule_index` per `if()` occurrence
- Each body evaluates the condition separately (duplicated work)
- Flattens inline ternary logic into top-level program structure

For complex policies with many `if()` expressions (common in production Azure
policies), this becomes significant overhead both in program size and
execution time.

### 3.3 The fundamental gap

| Concept | Rego solution | Azure Policy need |
|:--------|:-------------|:-----------------|
| "succeed on undefined" | `not <helper>` — helper body fails on undefined → `not` flips to true | Same semantics, but inline — undefined field + negated comparison in one flow |
| "choose between values" | Multi-body rule: body 1 with condition, body 2 as else/default | Inline ternary — evaluate one condition, pick one of two values |

Both Rego solutions work, but both introduce structural overhead (extra
rules/bodies) for what are fundamentally inline operations in Azure Policy.

---

## 4. Approach A: Raw Jumps

**New instructions**: `IsUndefined`, `Jump`, `JumpIf`

```rust
IsUndefined { dest: u8, operand: u8 }    // dest = (operand == undefined)
Jump { target: u16 }                      // unconditional jump to offset
JumpIf { condition: u8, target: u16 }     // jump if condition is truthy
```

### Negative operator example

```
LoadInput → r_input
ChainedIndex → r_field
IsUndefined { dest: r_undef, operand: r_field }
JumpIf { condition: r_undef, target: SUCCEED }
// Field is defined — do comparison
BuiltinCall("azure.policy.compare") { args: [r_field, r_expected] } → r_cmp
Load { dest: r_zero, literal: 0 }
Eq { dest: r_eq, left: r_cmp, right: r_zero }
Not { dest: r_result, operand: r_eq }
AssertCondition { r_result }
Jump { target: END }
SUCCEED:
// Field is undefined — notEquals succeeds (no-op, fall through)
END:
```

### `if()` expression example

```
<evaluate condition> → r_cond
JumpIf { condition: r_cond, target: TRUE_BRANCH }
Load { dest: r_result, literal: "value-b" }
Jump { target: END }
TRUE_BRANCH:
Load { dest: r_result, literal: "value-a" }
END:
```

### Pros
- Maximum flexibility — any control-flow pattern possible
- Minimal instruction count (3 new)
- Low overhead per use (no rule calls)

### Cons
- **Breaks the RVM's design philosophy** — every other construct is structured
  (assertions, rule bodies, loops, comprehensions). Jumps are the one unstructured
  primitive in most VMs.
- **Hard to verify** — arbitrary jump targets could create non-terminating loops
  or jumps into the middle of structured blocks
- **Difficult to optimize** — a jump-based CFG is harder to analyze than
  structured constructs
- **Precedent risk** — once jumps exist, they tend to be used for everything,
  eroding the structured model over time

---

## 5. Approach B: Helper Rules

**New instructions**: none

Use the Rego compiler's existing `not` + helper rule pattern.

### Negative operator example

```
// Helper rule: "field is defined AND equals value"
RuleInit { result_reg: r_helper, rule_index: HELPER_N }
  LoadInput → r_input
  ChainedIndex → r_field
  AssertNotUndefined { register: r_field }
  BuiltinCall("azure.policy.compare") { args: [r_field, r_expected] } → r_cmp
  Load { dest: r_zero, literal: 0 }
  Eq { dest: r_eq, left: r_cmp, right: r_zero }
  AssertCondition { condition: r_eq }
  LoadTrue { dest: r_helper }
RuleReturn

// Main rule:
CallRule { dest: r_result, rule_index: HELPER_N }
Not { dest: r_neg, operand: r_result }
AssertCondition { condition: r_neg }
```

### `if()` expression example

```
// Body 1: condition true → "value-a"
RuleInit { result_reg: r_if, rule_index: IF_N }
  <evaluate condition>
  AssertCondition { condition: r_cond }
  Load { dest: r_if, literal: "value-a" }
RuleReturn

// Body 2: condition false → "value-b"
RuleInit { result_reg: r_if, rule_index: IF_N }
  <evaluate condition>
  Not { dest: r_neg, operand: r_cond }
  AssertCondition { condition: r_neg }
  Load { dest: r_if, literal: "value-b" }
RuleReturn

// Main rule:
CallRule { dest: r_result, rule_index: IF_N }
```

### Rego equivalent

This IS the Rego pattern. The compiled output is identical to what the Rego
compiler would produce for:

```rego
helper_N { input.resource.location; azure.policy.compare(input.resource.location, "eastus") == 0 }

deny { not helper_N }
```

### Pros
- **Zero new instructions** — fully within existing RVM capabilities
- **Battle-tested** — this is exactly what the Rego compiler does
- **Keeps RVM purely structured** — no new control-flow primitives
- **Easy to verify** — all patterns are well-understood

### Cons
- **CallRule overhead** — each negative operator requires a rule call (enter
  rule, set up registers, execute, return, restore). Not expensive individually,
  but policies with many negative operators (common) accumulate overhead.
- **Program size inflation** — each negative operator adds a `RuleInit` +
  body + `RuleReturn` to the program. Each `if()` adds two bodies.
- **Condition duplication** — `if()` evaluates the condition in *both* bodies
  (once to assert true, once to assert false)
- **Loss of locality** — the helper rule is defined elsewhere in the program,
  making the instruction stream harder to follow during debugging

---

## 6. Approach C: Structured `IfThenElse` + `IsDefined`

**New instructions**: `IsDefined`, `IfThenElse`

```rust
IsDefined { dest: u8, operand: u8 }
// dest = true if operand is not undefined, false otherwise
// Pure predicate — no control flow, like Not or Eq

IfThenElse { params_index: u16 }
// Side table:
IfThenElseParams {
    condition_reg: u8,    // register holding boolean
    else_start: u16,      // instruction offset where else-branch begins
    end: u16,             // instruction offset past the whole block
}
```

VM execution of `IfThenElse`:
1. Read `condition_reg`
2. If truthy → continue (then-block runs), when PC reaches `else_start` → jump
   to `end`
3. If falsy or undefined → set PC to `else_start` (else-block runs)

This mirrors how `LoopStart`/`LoopNext` work — block boundaries are in the
side table, the VM manages structured transition between blocks.

### Negative operator example

```
LoadInput → r_input
ChainedIndex → r_field
IsDefined { dest: r_def, operand: r_field }

IfThenElse { condition: r_def, else_start: ELSE, end: END }
  // Then: field is defined → compare and negate
  BuiltinCall("azure.policy.compare") { args: [r_field, r_expected] } → r_cmp
  Load { dest: r_zero, literal: 0 }
  Eq { dest: r_eq, left: r_cmp, right: r_zero }
  Not { dest: r_result, operand: r_eq }
ELSE:
  // Else: field is undefined → succeed
  LoadTrue { dest: r_result }
END:

AssertCondition { condition: r_result }
```

### `if()` expression example

```
<evaluate condition> → r_cond

IfThenElse { condition: r_cond, else_start: ELSE, end: END }
  Load { dest: r_result, literal: "value-a" }
ELSE:
  Load { dest: r_result, literal: "value-b" }
END:
```

### Rego equivalent

There's no direct Rego equivalent because Rego doesn't have if/else
expressions. The closest is:

```rego
# Negative operator — identical to Approach B's Rego translation:
deny { not field_equals_value }

# if() — Rego uses multi-body rule:
result = "value-a" { condition }
result = "value-b" { not condition }
```

The `IfThenElse` instruction essentially inlines what Rego spreads across
multiple rule bodies.

### Need for `ElseMarker`?

The `IfThenElse` params encode `else_start` and `end` offsets in the side table.
But the VM also needs to know when the then-block ends (to skip to `end`).
Two sub-options:

**Option C1: Implicit** — The then-block runs until PC reaches `else_start`,
then the VM auto-jumps to `end`. The VM tracks "inside then-block" state on a
stack (similar to how loops track nesting).

**Option C2: Explicit `Else` marker** — Add a lightweight `Else {}` instruction
at the then/else boundary:

```rust
Else {}
// When the VM hits Else while executing a then-block, it jumps to end.
// When the VM hits Else while executing an else-block (was jumped to), it's a no-op PC advance.
```

This makes the instruction stream self-describing:
```
IfThenElse { condition_reg, else_offset, end_offset }
  <then instructions>
Else {}
  <else instructions>
EndIf {}
```

Option C2 adds a marker instruction but keeps the VM simpler (no tracking
stack needed — the marker IS the control flow).

### Pros
- **Structured** — same philosophy as `LoopStart`/`LoopNext` and
  `ComprehensionBegin`/`End`
- **Block boundaries are explicit** — VM can verify nesting at load time
- **Inline** — no rule-call overhead, condition evaluated once
- **Optimizable** — VM knows the exact structure; could specialize for
  then-only (no else) cases
- **Natural fit for `if()`** — the ternary maps 1:1

### Cons
- **2–3 new instructions** — `IsDefined`, `IfThenElse`, and optionally
  `Else`/`EndIf` markers
- **Not needed by Rego** — these instructions exist solely for Azure Policy.
  But this is acceptable with feature-gating (`#[cfg(feature = "azure_policy")]`)
  and the instructions are general-purpose enough to potentially benefit other
  future languages.
- **Side table entry** — each `IfThenElse` requires a `IfThenElseParams`.
  Comparable to `LoopStartParams` and `ComprehensionBeginParams`.

---

## 7. Approach D: `soft_assert_mode` + `Not` Reuse

**New instructions**: `IsDefined` only (or none — see variant)

This approach adapts the Rego compiler's `soft_assert_mode` technique for
the Azure Policy compiler.

### The idea

For negative operators, the Azure Policy compiler can:

1. Compile the field access in soft-assert mode (suppress
   `AssertNotUndefined`)
2. Compile the comparison (which produces undefined if the field is undefined)
3. Emit `Not` on the result

If the field is undefined:
- `ChainedIndex` produces undefined (no assert to abort)
- `BuiltinCall("azure.policy.compare")` receives undefined → behavior?

**Problem**: The builtins assume defined inputs. Calling `azure.policy.compare`
with an undefined argument would need special handling.

### Variant D1: Builtins return undefined for undefined input

Change the builtin contract so that if *any* argument is undefined, the
builtin returns undefined:

```rust
fn azure_policy_compare(a: &Value, b: &Value) -> Value {
    if a == &Value::Undefined || b == &Value::Undefined {
        return Value::Undefined;
    }
    // ... normal comparison
}
```

Then:

```
LoadInput → r_input
ChainedIndex → r_field          // soft-assert: may be undefined
BuiltinCall("azure.policy.compare") { args: [r_field, r_expected] } → r_cmp
// r_cmp is undefined if r_field was undefined
Load { dest: r_zero, literal: 0 }
Eq { dest: r_eq, left: r_cmp, right: r_zero }
// r_eq is undefined if r_cmp was undefined (Eq propagates undefined)
Not { dest: r_result, operand: r_eq }
// Not: undefined → true ✓
AssertCondition { condition: r_result }
```

This works IF `Eq` propagates undefined (returns undefined when either operand
is undefined). Let's check what the RVM does:

Looking at the VM's `Eq` dispatch — it does standard comparison. If either
operand is `Value::Undefined`, the comparison `a == b` returns `false`
(undefined ≠ 0), so `r_eq` becomes `false`, and `Not` flips it to `true`.

Wait — that's accidentally correct for `notEquals` but for the wrong reason.
And it's wrong for other negative operators: `notIn` with undefined field
should succeed, but `azure.policy.in(undefined, array)` would produce
unpredictable results.

### Variant D2: `IsDefined` + `And` composition

```
ChainedIndex → r_field                    // soft-assert
IsDefined { dest: r_def, operand: r_field }
// Only meaningful when r_def is true:
BuiltinCall("azure.policy.compare") → r_cmp   // soft-assert
Eq { dest: r_eq, left: r_cmp, right: r_zero }
// Combine: "defined AND equal"
And { dest: r_both, left: r_def, right: r_eq }
// Negate for notEquals
Not { dest: r_result, operand: r_both }
AssertCondition { r_result }
```

**Problem**: Even with `And`, the comparison may produce garbage when the field
is undefined. The `And` result would be `false` (since `r_def` is false), so
the garbage `r_eq` is ignored — but this relies on short-circuit semantics that
the RVM's `And` may not implement (it likely evaluates both operands since
they're already in registers).

Actually this DOES work correctly because:
- If field is undefined: `r_def` = false, `And` = false, `Not` = true → succeeds ✓
- If field is defined and equals: `r_def` = true, `r_eq` = true, `And` = true, `Not` = false → fails ✓
- If field is defined and not equals: `r_def` = true, `r_eq` = false, `And` = false, `Not` = true → succeeds ✓

But the builtin still runs on undefined input, which violates its contract and
could panic. This is the fundamental issue.

### `if()` expressions

Approach D does not naturally handle `if()` expressions. It would still need
helper rules or `IfThenElse` for ternary value selection.

### Pros
- Only 1 new instruction (`IsDefined`)
- Leverages existing `Not`, `And` instructions
- Close to the Rego compiler's internal technique

### Cons
- **Violates builtin contract** — builtins receive undefined values
- **Fragile** — correctness depends on subtle interaction between undefined
  propagation, `And` evaluation, and `Not` semantics
- **Does not solve `if()`** — still needs another mechanism for ternary
- **Hard to reason about** — the undefined value flows through multiple
  instructions, each of which must handle it correctly

---

## 8. Comparison Matrix

| Criterion | A: Raw jumps | B: Helper rules | C: IfThenElse | D: Soft-assert |
|:----------|:-------------|:----------------|:--------------|:---------------|
| New instructions | 3 | 0 | 2–3 | 1 |
| Solves negative ops | ✓ | ✓ | ✓ | ✓ (fragile) |
| Solves `if()` | ✓ | ✓ | ✓ | ✗ |
| RVM design consistency | ✗ (unstructured) | ✓ (native Rego) | ✓ (structured block) | ~ (reuses patterns) |
| Runtime overhead | Low | Medium (CallRule per use) | Low | Low |
| Program size impact | Small | Large (extra rules) | Small | Small |
| Verification/safety | Hard (arbitrary targets) | Easy (existing model) | Easy (bounded blocks) | Medium (undefined flows) |
| Builtin contract | Preserved | Preserved | Preserved | Violated |
| Condition eval count | 1 | 1–2 (if: 2×) | 1 | 1 |
| Implementation effort | Low | Low | Medium | Low |
| Rego compiler impact | None (feature-gated) | None | None (feature-gated) | Subtle (shared builtins) |

---

## 9. Chosen Approach: C — Structured `IfThenElse` + `IsDefined`

**Approach C** is the clear winner:

- **Structured** — matches the RVM's block-based design (`LoopStart`/`LoopNext`,
  `ComprehensionBegin`/`End`). An `IfThenElse` is the same pattern: a block
  instruction with boundaries in a side table, no arbitrary jump targets.
- **Inline** — no helper rules, no `CallRule` overhead. The conditional executes
  in-place, which is both faster and easier to debug.
- **Solves both use cases** — negative operators and `if()` expressions use the
  same instruction, keeping the design unified.
- **Safe** — block boundaries are statically known (in the side table), so the
  VM can verify nesting at program load time. No possibility of jumping into
  the middle of another block.
- **Preserves builtin contract** — builtins never receive undefined values.
  `IsDefined` + `IfThenElse` guards the comparison path.
- **Minimal additions** — 2 new instructions, 1 new side-table type. Comparable
  to what loops and comprehensions already add.

### New instructions to add to the RVM

```rust
/// Check if a register holds a defined (non-undefined) value.
/// Pure predicate — no control flow.
IsDefined { dest: u8, operand: u8 }

/// Structured conditional block.
/// Then-block: instructions from PC+1 to else_start-1.
/// Else-block: instructions from else_start to end-1.
/// If condition_reg is truthy → execute then-block, skip to end.
/// If condition_reg is falsy/undefined → skip to else_start, execute else-block.
IfThenElse { params_index: u16 }
```

```rust
/// Side table entry for IfThenElse.
IfThenElseParams {
    condition_reg: u8,
    else_start: u16,
    end: u16,
}
```

Feature-gated under `#[cfg(feature = "azure_policy")]`.

---

## 10. Open Questions

| # | Question | Impact |
|:--|:---------|:-------|
| Q1 | How frequent are negative operators in production Azure policies? | If rare, Approach B's overhead is negligible. If common (likely — `notEquals` is very popular), Approach C's inline model saves non-trivial overhead. |
| Q2 | How frequent are `if()` expressions in production policies? | Affects whether the `if()` compilation approach matters much in practice. |
| Q3 | Should `IsDefined` be a standalone instruction or a builtin? | As an instruction it's a simple register-to-register operation (very fast). As a builtin it goes through the `BuiltinCallParams` side table (slightly more overhead). Instruction is better. |
| Q4 | If Approach C: should the else-branch be optional? | Some uses (negative ops) need both branches. Others might only need a then-branch. An optional else (where `else_start == end`) keeps the instruction general. |
| Q5 | Could Approach B + C be combined — use helper rules now, add `IfThenElse` later as an optimization? | Yes. Approach B works immediately. If profiling shows helper-rule overhead matters, `IfThenElse` can be added as a performance optimization without changing correctness. |
