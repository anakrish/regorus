# Azure Policy First-Class RVM Instructions — Design Analysis

## Executive Summary

The RVM (Rego Virtual Machine) is a register-based VM designed for OPA/Rego's
open-world, undefined-propagating, case-sensitive, strictly-typed semantics.
Azure Policy has **closed-world, null-coalescing, case-insensitive,
type-coercing** semantics. Today, the compiler bridges this gap by routing all
20 operators and all logical combinators through `BuiltinCall` instructions to
custom `azure.policy.op.*` / `azure.policy.logic_*` functions, plus inserting
`CoalesceUndefinedToNull` after every field access.

This means the hottest path in policy evaluation — comparing a field value to a
literal — goes through the **heaviest instruction** (`BuiltinCall`) instead of
the **lightest** (a native comparison). A single new `PolicyOp` instruction
with sub-operation dispatch can eliminate this overhead entirely while keeping
the `Instruction` enum clean (+1 variant instead of +20).

Additionally, `allOf`/`anyOf` can be compiled with **lazy short-circuit
evaluation** — skipping remaining children once the result is determined —
instead of the current eager approach that evaluates all children upfront.

---

## Current Compilation: How Azure Policy Maps to RVM

### A Simple Condition

```json
{ "field": "type", "equals": "Microsoft.Storage/storageAccounts" }
```

Compiles to **5 instructions**:

```
r0 = LoadInput
r1 = ChainedIndex(r0, ["resource", "type"])
     CoalesceUndefinedToNull(r1)
r2 = Load("Microsoft.Storage/storageAccounts")
r3 = BuiltinCall "azure.policy.op.equals" [r1, r2]
```

### An `allOf` with 2 Conditions (Current: Eager)

```json
{
  "allOf": [
    { "field": "type", "equals": "Microsoft.Storage/storageAccounts" },
    { "field": "location", "equals": "eastus" }
  ]
}
```

Compiles to **13 instructions, 3 BuiltinCalls**, evaluating **all children
eagerly** before combining:

```
; -- child 0 --
r0 = LoadInput
r1 = ChainedIndex(r0, ["resource", "type"])
     CoalesceUndefinedToNull(r1)
r2 = Load("Microsoft.Storage/storageAccounts")
r3 = BuiltinCall "azure.policy.op.equals" [r1, r2]
     CoalesceUndefinedToNull(r3)

; -- child 1 (always evaluated even if child 0 was false) --
r4 = LoadInput
r5 = ChainedIndex(r4, ["resource", "location"])
     CoalesceUndefinedToNull(r5)
r6 = Load("eastus")
r7 = BuiltinCall "azure.policy.op.equals" [r5, r6]
     CoalesceUndefinedToNull(r7)

; -- combine (checks both results) --
r8 = BuiltinCall "azure.policy.logic_all" [r3, r7]
```

### A Full Policy Rule (Deny If Non-HTTPS Storage)

```json
{
  "if": {
    "allOf": [
      { "field": "type", "equals": "Microsoft.Storage/storageAccounts" },
      { "field": "supportsHttpsTrafficOnly", "equals": false }
    ]
  },
  "then": { "effect": "deny" }
}
```

Compiles to **16 instructions, 10 registers, ~7 literals, 3 BuiltinCalls**:

```
 0: r0  = LoadInput
 1: r1  = ChainedIndex(r0, ["resource", "type"])
 2:        CoalesceUndefinedToNull(r1)
 3: r2  = Load("Microsoft.Storage/storageAccounts")
 4: r3  = BuiltinCall "azure.policy.op.equals" [r1, r2]
 5:        CoalesceUndefinedToNull(r3)
 6: r4  = LoadInput
 7: r5  = ChainedIndex(r4, ["resource", "supportsHttpsTrafficOnly"])
 8:        CoalesceUndefinedToNull(r5)
 9: r6  = LoadFalse
10: r7  = BuiltinCall "azure.policy.op.equals" [r5, r6]
11:        CoalesceUndefinedToNull(r7)
12: r8  = BuiltinCall "azure.policy.logic_all" [r3, r7]
13:        ReturnUndefinedIfNotTrue(r8)
14: r9  = Load("deny")
15:        Return(r9)
```

---

## The Impedance Mismatch

| Domain | Azure Policy Semantics | Generic Rego VM | Current Bridge |
|--------|----------------------|-----------------|----------------|
| **Missing fields** | `null` (closed world) | `undefined` (propagates, short-circuits) | `CoalesceUndefinedToNull` instruction |
| **String comparison** | Case-insensitive | Case-sensitive | Custom builtins (`case_insensitive_equals`) |
| **Type coercion** | `"42" == 42` | Strict types | `try_coerce_to_number` in helpers |
| **Logic combinators** | `false AND x = false` | `undefined AND x = undefined` | `logic_all`/`logic_any` builtins (eager) |
| **Negation on undefined** | `notEquals(undefined, x) = true` | `undefined` | Explicit checks in each `Not*` builtin |
| **Related resources** | External lookup | No concept | `HostAwait` instruction |
| **Conditional** | `if(c, t, f)` is eager | No ternary | Builtin that ignores unused branch |
| **Pattern matching** | `like` wildcards, `match` with `?`/`#` | Regex | Custom pattern matchers |
| **Short-circuit logic** | `allOf` should skip on first false | All children always evaluated | N/A — not implemented |

---

## The Cost of `BuiltinCall` for Trivial Operations

Every `BuiltinCall` pays this overhead at runtime:

| Step | Cost |
|------|------|
| Look up `BuiltinCallParams` from instruction data table | Vec index |
| Clone each arg `Value` into a new `Vec` | **heap alloc + N clones** |
| Create dummy `Source`, `Span`, `Vec<Ref<Expr>>` | **3 heap allocs (pure waste — legacy signature compat)** |
| Check `must_cache` for deterministic builtins | hash lookup |
| Indirect fn pointer call | ~1 branch |
| The actual logic (e.g., `args.iter().all(is_true)`) | trivial |

For `logic_all(cond1, cond2)`, whose body is literally
`args.iter().all(|v| matches!(v, Value::Bool(true)))`, the **call envelope is
~100× more expensive than the computation**.

### Cascade Dispatch Overhead

The instruction dispatch is a cascading chain of `match` statements:

```
execute_instruction()
  → execute_load_and_move()
    → execute_arithmetic_instruction()
      → execute_comparison_instruction()
        → execute_call_instruction()         ← BuiltinCall lands here (4 levels deep)
          → execute_collection_instruction()
            → execute_loop_instruction()
              → execute_virtual_instruction()
```

`BuiltinCall` falls through **4 match levels** before dispatching.
`CoalesceUndefinedToNull` falls through **3 match levels**.
Native comparisons like `Eq` land at level 3 — but Azure Policy never uses them.

---

## Design: Single `PolicyOp` Instruction with Sub-Dispatch

Instead of adding 20+ new variants to the `Instruction` enum, we add **one**:

```rust
/// A single instruction covering all Azure Policy–specific operations.
/// Sub-operation kind and operands are stored in the params table.
PolicyOp {
    params_index: u16,
}
```

The `params_index` indexes into a new `Vec<PolicyOpParams>` in the
`InstructionData` table. `PolicyOpParams` is an enum that carries the
sub-operation kind and its operands:

```rust
/// Azure Policy sub-operations dispatched by the single `PolicyOp` instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyOpParams {
    // ── Condition operators (all 20) ────────────────────────────
    Equals       { dest: u8, left: u8, right: u8 },
    NotEquals    { dest: u8, left: u8, right: u8 },
    Greater      { dest: u8, left: u8, right: u8 },
    GreaterOrEquals { dest: u8, left: u8, right: u8 },
    Less         { dest: u8, left: u8, right: u8 },
    LessOrEquals { dest: u8, left: u8, right: u8 },
    In           { dest: u8, value: u8, array: u8 },
    NotIn        { dest: u8, value: u8, array: u8 },
    Contains     { dest: u8, haystack: u8, needle: u8 },
    NotContains  { dest: u8, haystack: u8, needle: u8 },
    ContainsKey  { dest: u8, obj: u8, key: u8 },
    NotContainsKey { dest: u8, obj: u8, key: u8 },
    Like         { dest: u8, left: u8, right: u8 },
    NotLike      { dest: u8, left: u8, right: u8 },
    Match        { dest: u8, value: u8, pattern: u8 },
    NotMatch     { dest: u8, value: u8, pattern: u8 },
    MatchInsensitively    { dest: u8, value: u8, pattern: u8 },
    NotMatchInsensitively { dest: u8, value: u8, pattern: u8 },
    Exists       { dest: u8, field: u8, expected: u8 },

    // ── Logic with lazy evaluation (short-circuit guards) ───────
    /// Logic NOT: `dest = !is_true(operand)`
    Not { dest: u8, operand: u8 },

    /// allOf guard: if `check` is not true, set `result` to false and
    /// jump to `end_pc`. Otherwise fall through to the next child.
    AllOfGuard { check: u8, result: u8, end_pc: u16 },

    /// anyOf guard: if `check` is true, set `result` to true and
    /// jump to `end_pc`. Otherwise fall through to the next child.
    AnyOfGuard { check: u8, result: u8, end_pc: u16 },

    // ── Composite (field load with null coalescing) ─────────────
    /// Navigate `input.resource.<path>`, return Null if any component
    /// is missing. Collapses LoadInput + ChainedIndex + CoalesceUndefinedToNull.
    FieldLoad { dest: u8, path_components: Vec<u16> },
}
```

### Why One Instruction?

| Approach | Instruction enum variants | Params table types |
|----------|--------------------------|-------------------|
| 20+ new instructions | ~24 new variants (one per operator/logic) | 2–3 new params types |
| Single `PolicyOp` | **1 new variant** | 1 enum (`PolicyOpParams`) |

The single-instruction approach:
- Keeps the `Instruction` enum at 43 variants (currently 42 + 1) instead of 63+
- All Azure Policy semantics are behind a single dispatch point
- Easy to feature-gate (`#[cfg(feature = "azure_policy")]`) as one variant
- The sub-dispatch `match` on `PolicyOpParams` is a flat jump table — just as
  fast as if they were top-level instruction variants
- The `params_index: u16` representation (2 bytes) is the same size as existing
  complex instructions like `BuiltinCall`, `LoopStart`, `ChainedIndex`

---

## Lazy Evaluation for `allOf` / `anyOf`

### The Problem

Currently, `allOf` with N children compiles as:

```
eval child 0 → coalesce → eval child 1 → coalesce → ... → eval child N
→ BuiltinCall("logic_all", [r0, r1, ..., rN])
```

**All N children are always evaluated**, even if child 0 is `false`. For
policies like `allOf([type_check, expensive_count_loop])`, the expensive count
loop runs even when the type doesn't match — a common pattern since most
real-world policies check `type` first.

### The Solution: Guard Instructions with Branching

Instead of evaluating all children then combining, we **interleave evaluation
with short-circuit guards** that use direct PC manipulation (the same
`self.pc = target.saturating_sub(1)` pattern used by `LoopNext` and
`ComprehensionBegin` in the existing RVM).

#### `allOf` — Short-Circuit on First False

```
                                        ; ┌── short-circuit path
     r_result = LoadFalse               ; │   pessimistic default
                                        ; │
     ; child 0                          ; │
     r0 = <evaluate condition 0>        ; │
     CoalesceUndefinedToNull(r0)        ; │
     PolicyOp(AllOfGuard r0 → END)  ────┤   if !is_true(r0): result=false, jump END
                                        ; │
     ; child 1 (only reached if 0 was true)
     r1 = <evaluate condition 1>        ; │
     CoalesceUndefinedToNull(r1)        ; │
     PolicyOp(AllOfGuard r1 → END)  ────┤   if !is_true(r1): result=false, jump END
                                        ; │
     ; child 2 (only reached if 0,1 were true)
     r2 = <evaluate condition 2>        ; │
     CoalesceUndefinedToNull(r2)        ; │
     PolicyOp(AllOfGuard r2 → END)  ────┤   if !is_true(r2): result=false, jump END
                                        ; │
     r_result = LoadTrue                ; │   all children passed → true
 END:                                   ; ◄──┘
     ; r_result is the allOf result
```

`AllOfGuard { check, result, end_pc }` semantics:
- If `R[check]` is **not** `true`: set `R[result] = false`, PC ← `end_pc`
  (short-circuit)
- If `R[check]` **is** `true`: fall through (continue to next child)

#### `anyOf` — Short-Circuit on First True

```
                                        ; ┌── short-circuit path
     r_result = LoadFalse               ; │   pessimistic default
                                        ; │
     ; child 0                          ; │
     r0 = <evaluate condition 0>        ; │
     CoalesceUndefinedToNull(r0)        ; │
     PolicyOp(AnyOfGuard r0 → END)  ────┤   if is_true(r0): result=true, jump END
                                        ; │
     ; child 1                          ; │
     r1 = <evaluate condition 1>        ; │
     CoalesceUndefinedToNull(r1)        ; │
     PolicyOp(AnyOfGuard r1 → END)  ────┤   if is_true(r1): result=true, jump END
                                        ; │
     ; child 2                          ; │
     r2 = <evaluate condition 2>        ; │
     CoalesceUndefinedToNull(r2)        ; │
     PolicyOp(AnyOfGuard r2 → END)  ────┤   if is_true(r2): result=true, jump END
                                        ; │
     ; none passed → r_result stays false
 END:                                   ; ◄──┘
```

`AnyOfGuard { check, result, end_pc }` semantics:
- If `R[check]` **is** `true`: set `R[result] = true`, PC ← `end_pc`
  (short-circuit)
- If `R[check]` is **not** `true`: fall through (continue to next child)

#### Nested Logic

Nested `allOf`/`anyOf` works naturally — each level has its own result register
and its own `END` label:

```json
{
  "allOf": [
    { "field": "type", "equals": "Microsoft.Storage/..." },
    { "anyOf": [
        { "field": "location", "equals": "eastus" },
        { "field": "location", "equals": "westus" }
    ]}
  ]
}
```

Compiles to:

```
     r_allof = LoadFalse

     ; allOf child 0: type check
     r0 = <type condition>
     CoalesceUndefinedToNull(r0)
     PolicyOp(AllOfGuard r0, r_allof → ALLOF_END)

     ; allOf child 1: nested anyOf
     r_anyof = LoadFalse
     ; anyOf child 0
     r1 = <location == eastus>
     CoalesceUndefinedToNull(r1)
     PolicyOp(AnyOfGuard r1, r_anyof → ANYOF_END)
     ; anyOf child 1
     r2 = <location == westus>
     CoalesceUndefinedToNull(r2)
     PolicyOp(AnyOfGuard r2, r_anyof → ANYOF_END)
 ANYOF_END:
     CoalesceUndefinedToNull(r_anyof)
     PolicyOp(AllOfGuard r_anyof, r_allof → ALLOF_END)

     r_allof = LoadTrue
 ALLOF_END:
```

If `type != "Microsoft.Storage/..."`, we jump directly from the first
`AllOfGuard` to `ALLOF_END` — the entire `anyOf` block (with its two field
lookups + comparisons) is **never evaluated**.

### Why This Matters in Practice

Real Azure Policy patterns almost always start with a type check:

```json
{
  "allOf": [
    { "field": "type", "equals": "Microsoft.Storage/storageAccounts" },
    { "count": { "field": "ipRules[*]", "where": { ... } }, "greater": 0 }
  ]
}
```

With lazy evaluation, when the resource type doesn't match (the common case in
bulk evaluation), the expensive count loop is **never entered**. This is
especially impactful when evaluating many policies against many resources, where
most type checks fail.

---

## VM Dispatch

One new match arm handles everything. The `PolicyOp` handler is inserted early
in the dispatch chain for hot-path priority:

```rust
PolicyOp { params_index } => {
    let params = program.instruction_data
        .get_policy_op_params(params_index)
        .ok_or(VmError::InvalidParamsIndex { index: params_index })?;
    match params {
        // ── Condition operators ─────────────────────────────
        PolicyOpParams::Equals { dest, left, right } => {
            let lhs = self.get_register(*left)?;
            let rhs = self.get_register(*right)?;
            let result = case_insensitive_equals(lhs, rhs);
            self.set_register(*dest, Value::Bool(result))?;
        }
        PolicyOpParams::NotEquals { dest, left, right } => {
            let lhs = self.get_register(*left)?;
            let rhs = self.get_register(*right)?;
            let result = if is_undefined(lhs) { true }
                         else { !case_insensitive_equals(lhs, rhs) };
            self.set_register(*dest, Value::Bool(result))?;
        }
        PolicyOpParams::Exists { dest, field, expected } => {
            let field_val = self.get_register(*field)?;
            let expected_bool = matches!(
                self.get_register(*expected)?, Value::Bool(true));
            let is_defined = !matches!(
                field_val, Value::Undefined | Value::Null);
            self.set_register(*dest,
                Value::Bool(is_defined == expected_bool))?;
        }

        // ── Short-circuit logic ─────────────────────────────
        PolicyOpParams::AllOfGuard { check, result, end_pc } => {
            let val = self.get_register(*check)?;
            if !matches!(val, Value::Bool(true)) {
                self.set_register(*result, Value::Bool(false))?;
                // Jump: saturating_sub(1) because main loop does pc += 1
                self.pc = (*end_pc as usize).saturating_sub(1);
            }
        }
        PolicyOpParams::AnyOfGuard { check, result, end_pc } => {
            let val = self.get_register(*check)?;
            if matches!(val, Value::Bool(true)) {
                self.set_register(*result, Value::Bool(true))?;
                self.pc = (*end_pc as usize).saturating_sub(1);
            }
        }
        PolicyOpParams::Not { dest, operand } => {
            let val = self.get_register(*operand)?;
            self.set_register(*dest,
                Value::Bool(!matches!(val, Value::Bool(true))))?;
        }

        // ── Composite field load ────────────────────────────
        PolicyOpParams::FieldLoad { dest, path_components } => {
            let mut current = self.input.clone();
            current = current.index(&Value::from("resource"))
                .unwrap_or(Value::Undefined);
            for &lit_idx in path_components {
                if matches!(current, Value::Undefined) { break; }
                let key = program.get_literal(lit_idx)?;
                current = current.index(key).unwrap_or(Value::Undefined);
            }
            if matches!(current, Value::Undefined) {
                current = Value::Null;
            }
            self.set_register(*dest, current)?;
        }

        // ... remaining operators follow the same pattern
    }
    Ok(InstructionOutcome::Continue)
}
```

**Key points:**
- `get_register` returns `&Value` — **no cloning** for comparisons. Compare to
  `BuiltinCall` which clones every argument into a `Vec<Value>`.
- The `saturating_sub(1)` in branch targets accounts for the main loop's
  `self.pc += 1` after `Continue` — the same pattern used by `LoopNext`,
  `ComprehensionBegin`, and other existing control flow instructions.
- No `Vec` allocation, no dummy `Span`/`Source`/`Expr`, no indirect fn pointer
  call.

---

## Full Example: Deny Policy — Before and After

### Before (Current: Eager, BuiltinCalls)

```json
{
  "if": {
    "allOf": [
      { "field": "type", "equals": "Microsoft.Storage/storageAccounts" },
      { "field": "supportsHttpsTrafficOnly", "equals": false }
    ]
  },
  "then": { "effect": "deny" }
}
```

```
 0: r0  = LoadInput
 1: r1  = ChainedIndex(r0, ["resource", "type"])
 2:        CoalesceUndefinedToNull(r1)
 3: r2  = Load("Microsoft.Storage/storageAccounts")
 4: r3  = BuiltinCall "azure.policy.op.equals" [r1, r2]        ← HEAP ALLOCS
 5:        CoalesceUndefinedToNull(r3)
 6: r4  = LoadInput
 7: r5  = ChainedIndex(r4, ["resource", "supportsHttpsTrafficOnly"])
 8:        CoalesceUndefinedToNull(r5)
 9: r6  = LoadFalse
10: r7  = BuiltinCall "azure.policy.op.equals" [r5, r6]        ← HEAP ALLOCS
11:        CoalesceUndefinedToNull(r7)
12: r8  = BuiltinCall "azure.policy.logic_all" [r3, r7]        ← HEAP ALLOCS
13:        ReturnUndefinedIfNotTrue(r8)
14: r9  = Load("deny")
15:        Return(r9)

Total: 16 instructions, 3 BuiltinCalls, ~18 heap allocations
Both conditions ALWAYS evaluated (even if type doesn't match)
```

### After (PolicyOp + Lazy allOf)

```
 0: r_res = LoadFalse                                           ; allOf pessimistic
 1: r0  = LoadInput
 2: r1  = ChainedIndex(r0, ["resource", "type"])
 3:        CoalesceUndefinedToNull(r1)
 4: r2  = Load("Microsoft.Storage/storageAccounts")
 5: r3  = PolicyOp(Equals { dest: r3, left: r1, right: r2 })   ; INLINE, no alloc
 6:        CoalesceUndefinedToNull(r3)
 7:        PolicyOp(AllOfGuard { r3, r_res, end: 17 })          ; SHORT-CIRCUIT ──┐
 8: r4  = LoadInput                                             ;                 │
 9: r5  = ChainedIndex(r4, ["resource", "supportsHttpsOnly"])   ;                 │
10:        CoalesceUndefinedToNull(r5)                          ;                 │
11: r6  = LoadFalse                                             ;                 │
12: r7  = PolicyOp(Equals { dest: r7, left: r5, right: r6 })   ;                 │
13:        CoalesceUndefinedToNull(r7)                          ;                 │
14:        PolicyOp(AllOfGuard { r7, r_res, end: 17 })          ; ────────────────┤
15: r_res = LoadTrue                                            ; all passed      │
16:        /* fall through */                                   ;                 │
17:        ReturnUndefinedIfNotTrue(r_res)                      ; ◄───────────────┘
18: r9  = Load("deny")
19:        Return(r9)

Total: 20 instructions, 0 BuiltinCalls, 0 heap allocations
If type doesn't match → jumps from 7 to 17 (skips 9 instructions)
```

### After (PolicyOp + Lazy allOf + FieldLoad)

```
 0: r_res = LoadFalse
 1: r1  = PolicyOp(FieldLoad { dest: r1, path: ["type"] })     ; 1 instruction!
 2: r2  = Load("Microsoft.Storage/storageAccounts")
 3: r3  = PolicyOp(Equals { dest: r3, left: r1, right: r2 })
 4:        CoalesceUndefinedToNull(r3)
 5:        PolicyOp(AllOfGuard { r3, r_res, end: 13 })          ; ────────────────┐
 6: r5  = PolicyOp(FieldLoad { dest: r5,                        ;                 │
              path: ["supportsHttpsTrafficOnly"] })             ;                 │
 7: r6  = LoadFalse                                             ;                 │
 8: r7  = PolicyOp(Equals { dest: r7, left: r5, right: r6 })   ;                 │
 9:        CoalesceUndefinedToNull(r7)                          ;                 │
10:        PolicyOp(AllOfGuard { r7, r_res, end: 13 })          ; ────────────────┤
11: r_res = LoadTrue                                            ;                 │
12:        /* fall through */                                   ;                 │
13:        ReturnUndefinedIfNotTrue(r_res)                      ; ◄───────────────┘
14: r9  = Load("deny")
15:        Return(r9)

Total: 16 instructions, 0 BuiltinCalls, 0 heap allocations, 7 registers
If type doesn't match → jumps from 5 to 13 (skips 7 instructions)
```

---

## Compiler Changes

### Operator Emission (conditions.rs)

```rust
// BEFORE
let builtin = match op.kind {
    OperatorKind::Equals => "azure.policy.op.equals",
    OperatorKind::NotEquals => "azure.policy.op.not_equals",
    // ... 18 more
};
self.emit_builtin_call(builtin, &[lhs_reg, rhs_reg], &op.span)

// AFTER
let dest = self.alloc_register();
let params = match op.kind {
    OperatorKind::Equals =>
        PolicyOpParams::Equals { dest, left: lhs_reg, right: rhs_reg },
    OperatorKind::NotEquals =>
        PolicyOpParams::NotEquals { dest, left: lhs_reg, right: rhs_reg },
    // ... 18 more — one line each
};
self.emit_policy_op(params)
```

### Logic Combinator Emission (conditions.rs) — Lazy

```rust
// BEFORE (eager — evaluates all children, then combines)
for child in constraints {
    let reg = compile_constraint(child)?;
    emit(CoalesceUndefinedToNull { register: reg });
    regs.push(reg);
}
emit_builtin_call("azure.policy.logic_all", &regs)

// AFTER (lazy — short-circuits on first failure)
fn compile_allof(&mut self, constraints: &[Constraint]) -> Result<u8> {
    let result_reg = self.alloc_register();
    self.emit(Instruction::LoadFalse { dest: result_reg });

    // Emit each child with a guard; collect PCs for fixup
    let mut guard_fixup_pcs = Vec::new();
    for child in constraints {
        let child_reg = self.compile_constraint(child)?;
        self.emit(Instruction::CoalesceUndefinedToNull {
            register: child_reg,
        });
        // Emit guard with placeholder end_pc (patched below)
        let guard_pc = self.current_pc();
        self.emit_policy_op(PolicyOpParams::AllOfGuard {
            check: child_reg,
            result: result_reg,
            end_pc: 0,  // placeholder
        });
        guard_fixup_pcs.push(guard_pc);
    }

    // All children passed → set result to true
    self.emit(Instruction::LoadTrue { dest: result_reg });

    // Patch all guards to jump past the LoadTrue
    let end_pc = self.current_pc();
    for fixup_pc in guard_fixup_pcs {
        self.patch_policy_op_end_pc(fixup_pc, end_pc);
    }

    Ok(result_reg)
}
```

`anyOf` is symmetric: `LoadFalse` pessimistic default, `AnyOfGuard` jumps on
`true`, no `LoadTrue` at the end (result stays `false` if none matched).

### Field Access (fields.rs) — With FieldLoad

```rust
// BEFORE (3 instructions)
let input_reg = self.load_input(span)?;
let path_parts = ["resource"].iter()
    .chain(split_path(field_path).iter());
let reg = self.emit_chained_index_literal_path(
    input_reg, &path_parts, span)?;
self.emit(CoalesceUndefinedToNull { register: reg });

// AFTER (1 instruction)
let path_indices = split_path(field_path).iter()
    .map(|p| self.add_literal(Value::from(*p)))
    .collect();
let dest = self.alloc_register();
self.emit_policy_op(PolicyOpParams::FieldLoad {
    dest, path_components: path_indices
});
```

---

## Instruction Size & Representation

The `Instruction` enum is `#[repr(C)]` + `Copy` + `Serialize/Deserialize`.
Adding one variant:

```rust
PolicyOp {
    params_index: u16,  // index into InstructionData.policy_op_params
}
```

2 bytes of data — same as `BuiltinCall`, `LoopStart`, `ChainedIndex`.
No change to the enum's size characteristics.

The `PolicyOpParams` enum lives in the params table (`InstructionData`):

```rust
pub struct InstructionData {
    // ... existing fields ...
    pub policy_op_params: Vec<PolicyOpParams>,
}

impl InstructionData {
    pub fn add_policy_op_params(&mut self, params: PolicyOpParams) -> u16 {
        let idx = self.policy_op_params.len();
        self.policy_op_params.push(params);
        idx as u16
    }

    pub fn get_policy_op_params(&self, index: u16) -> Option<&PolicyOpParams> {
        self.policy_op_params.get(index as usize)
    }
}
```

---

## What Should Remain as Builtins

| Keep as Builtin | Reason |
|----------------|--------|
| `azure.policy.resolve_field` | Dynamic field resolution (`[concat(...)]`) — rare, complex |
| `azure.policy.get_parameter` | Parameter resolution with fallback — moderately complex |
| `azure.policy.fn.ip_range_contains` | IP range parsing — complex, uses `ipnet` crate |
| `azure.policy.fn.split`, `pad_left`, etc. | ARM template helper functions — rarely on hot path |

All 20 condition operators and logic combinators move into `PolicyOp`.
ARM template functions remain as builtins.

---

## Quantitative Impact Estimate

### Per-Evaluation Costs: 3-Condition `allOf` Policy

| Metric | Current (Eager) | PolicyOp + Lazy | + FieldLoad |
|--------|----------------|-----------------|-------------|
| Total instructions | ~22 | ~21 | ~16 |
| `BuiltinCall` invocations | **6** | **0** | **0** |
| Heap allocations per eval | ~18 | **0** | **0** |
| Dispatch depth | 4 match levels | 1 match + 1 sub | 1 match + 1 sub |
| Registers used | ~10 | ~9 | ~7 |
| **Short-circuit benefit** | None | **Skips remaining** | **Skips remaining** |

### Short-Circuit Impact: Type Check Fails (Common Case)

When evaluating `allOf([type_check, expensive_condition])` against a
resource whose type doesn't match:

| Metric | Current (Eager) | PolicyOp + Lazy |
|--------|----------------|-----------------|
| Conditions evaluated | **2** (both) | **1** (type only) |
| Instructions executed | ~16 | ~8 (stops at guard) |
| Count loops entered | 1 (if present) | **0** |

For bulk policy evaluation (thousands of resources × hundreds of policies),
this is a **multiplicative improvement** — most policy/resource pairs fail on
the type check.

---

## Implementation Plan

### Phase 1 — Core

1. Add `PolicyOpParams` enum with all 20 operators + `Not` + `AllOfGuard` +
   `AnyOfGuard`
2. Add `PolicyOp { params_index: u16 }` to `Instruction` enum
3. Add `policy_op_params: Vec<PolicyOpParams>` to `InstructionData`
4. Add VM dispatch handler (single `match` on `PolicyOpParams`)
5. Update compiler `conditions.rs`: operators → `PolicyOp` instead of
   `BuiltinCall`
6. Update compiler `conditions.rs`: `allOf`/`anyOf` use lazy guard pattern
   with `AllOfGuard`/`AnyOfGuard` and PC fixup
7. Move helper functions (`case_insensitive_equals`, `compare_values`, etc.)
   to a shared location accessible by both builtins and VM

**Scope**: 1 new instruction variant, 1 new params enum (24 sub-variants),
compiler changes in `conditions.rs`, one new VM dispatch function.

**Risk**: Low — purely additive. Existing builtins remain functional for
ARM template expression functions. All existing tests must still pass.

### Phase 2 — Composite FieldLoad

1. Add `FieldLoad` variant to `PolicyOpParams`
2. Update compiler `fields.rs`: simple field paths emit `FieldLoad`
3. Handle edge case: fields inside count bindings still use the old path
   (they reference loop iteration variables, not `input.resource`)

**Scope**: 1 new sub-variant, compiler changes in `fields.rs`.

### Phase 3 — Optimization

- Profile and benchmark against the builtin-based path
- Consider `PolicyCondition` super-variant (field path + operator + RHS in
  one params entry) if instruction count reduction matters further
- Consider `PolicyIf` sub-variant for lazy `if(cond, true_expr, false_expr)`
  evaluation (currently both branches are always evaluated)

---

## Appendix: Current Operator → Builtin Mapping (All 20)

| OperatorKind | Builtin Name | Core Semantic |
|-------------|-------------|---------------|
| `Equals` | `azure.policy.op.equals` | CI string compare, string↔number coercion |
| `NotEquals` | `azure.policy.op.not_equals` | Negation + undefined→true |
| `Greater` | `azure.policy.op.greater` | `compare_values > 0` |
| `GreaterOrEquals` | `azure.policy.op.greater_or_equals` | `compare_values >= 0` |
| `Less` | `azure.policy.op.less` | `compare_values < 0` |
| `LessOrEquals` | `azure.policy.op.less_or_equals` | `compare_values <= 0` |
| `In` | `azure.policy.op.in` | CI array membership |
| `NotIn` | `azure.policy.op.not_in` | Negation + undefined→true |
| `Contains` | `azure.policy.op.contains` | CI substring OR CI array element |
| `NotContains` | `azure.policy.op.not_contains` | Negation + undefined→true |
| `ContainsKey` | `azure.policy.op.contains_key` | CI object key lookup |
| `NotContainsKey` | `azure.policy.op.not_contains_key` | Negation + undefined→true |
| `Like` | `azure.policy.op.like` | Glob `*` pattern, CI |
| `NotLike` | `azure.policy.op.not_like` | Negation + undefined→true |
| `Match` | `azure.policy.op.match` | `?`=letter, `#`=digit, exact-length |
| `NotMatch` | `azure.policy.op.not_match` | Negation + undefined→true |
| `MatchInsensitively` | `azure.policy.op.match_insensitively` | CI match |
| `NotMatchInsensitively` | `azure.policy.op.not_match_insensitively` | Negation + undefined→true |
| `Exists` | `azure.policy.op.exists` | `(!undefined && !null) == expected_bool` |

## Appendix: Azure Policy Semantic Concepts

### Constraint Tree

```
Constraint ::= AllOf(Vec<Constraint>)     -- all children must be true
             | AnyOf(Vec<Constraint>)     -- at least one child must be true
             | Not(Constraint)            -- negate child
             | Condition(Condition)       -- leaf condition
```

### Condition Triple

```
Condition  ::= { lhs: Lhs, operator: OperatorKind, rhs: ValueOrExpr }

Lhs        ::= Field(FieldNode)          -- resource field reference
             | Value(ValueOrExpr)        -- literal or expression
             | Count(CountNode)          -- count expression
```

### Field Classification

| Kind | Example | Resolution |
|------|---------|------------|
| `Type` | `"type"` | `input.resource.type` |
| `Id` | `"id"` | `input.resource.id` |
| `Name` | `"name"` | `input.resource.name` |
| `Location` | `"location"` | `input.resource.location` |
| `Kind` | `"kind"` | `input.resource.kind` |
| `FullName` | `"fullName"` | `input.resource.fullName` |
| `Tags` | `"tags"` | `input.resource.tags` |
| `IdentityType` | `"identity.type"` | `input.resource.identity.type` |
| `ApiVersion` | `"apiVersion"` | `input.resource.apiVersion` |
| `Tag(name)` | `"tags.env"` | `input.resource.tags.env` |
| `Alias(path)` | `"Microsoft.Compute/..."` | Resolved via alias map → `input.resource.<shortName>` |
| `Expr(expr)` | `"[concat(...)]"` | Runtime resolution via `azure.policy.resolve_field` |

### Count Expression Semantics

**Field count**: `{ "count": { "field": "alias[*]", "where": {...} } }` — iterate
array field, filter with `where` constraint, return count of matching elements.

**Value count**: `{ "count": { "value": [...], "name": "x", "where": {...} } }` —
iterate inline array, bind to `current('x')`, filter, return count.

**Nested counts**: Inner `[*]` paths relative to outer loop's current element.

### Implicit `allOf` for `[*]` Outside Count

When `[*]` appears in a bare field condition (not inside `count`), Azure Policy
applies all-elements-must-match semantics. Empty/missing arrays → `true`
(vacuous truth). Compiled as `LoopMode::Every` loop.

### Effect Types

`Deny`, `Audit`, `Append`, `AuditIfNotExists`, `DeployIfNotExists`, `Disabled`,
`Modify`, `DenyAction`, `Manual`, `Other(String)` (parameterized).

### ARM Template Expressions

26 supported functions: `parameters`, `field`, `current`, `concat`, `if`,
`resourceGroup`, `subscription`, `tolower`, `toupper`, `replace`, `substring`,
`length`, `add`, `equals`, `greaterOrEquals`, `lessOrEquals`, `contains`,
`split`, `empty`, `first`, `last`, `createArray`, `startsWith`, `endsWith`,
`int`, `string`, `bool`, `padLeft`, `ipRangeContains`, `and`, `not`.
