# Causality Branch — Bug Report

## Bug 1 (CRITICAL): Post-loop AssertCondition kills outer loop iterations

**Affects:** ALL builds (not feature-gated)

### Description

The causality branch adds an **unconditional** `AssertCondition { result_reg }` instruction immediately after every loop's `LoopNext`. This instruction is emitted by all three loop compilation functions in `src/languages/rego/compiler/loops.rs`:
- `compile_every_quantifier` (line ~191)
- `compile_index_iteration_loop` (line ~308)
- `compile_some_in_loop_with_body` (line ~481)

The companion change sets `loop_end` to point **at** the `AssertCondition` (instead of past `LoopNext`), and adjusts `loop_next_idx` to `len() - 2` (instead of `len() - 1`).

### Root cause

When the VM finishes iterating a loop (all items exhausted, or early exit), the `LoopContext` is **popped** from `loop_stack` and `result_reg` is set to the loop's final boolean. The PC then advances to the `AssertCondition` instruction. The dispatch code:

```
AssertCondition { condition } =>
    let value = self.get_register(condition)?;
    ...
    self.handle_condition(condition_result)?;
```

calls `handle_condition(false)` whenever `result_reg == false`. Inside `handle_condition_run_to_completion`:

```rust
if !self.loop_stack.is_empty() {
    // routes to whatever loop is on top of loop_stack
} else if self.handle_comprehension_condition_failure_run_to_completion()? {
    // comprehension fallback
} else {
    return Err(VmError::AssertionFailed { pc: self.pc });
}
```

Because the **inner** loop's context was already popped by `LoopNext`, `loop_stack` now contains the **outer** loop. The false condition is attributed to the outer loop, causing the outer loop to:
- Mark `current_iteration_failed = true` (for `Any`/`ForEach`) and jump to the outer loop's `LoopNext`, or
- Pop and exit immediately (for `Every`).

This skips all instructions between the inner loop's `AssertCondition` and the outer loop's `LoopNext` — including `ComprehensionEnd`, `count()`, `sprintf()`, `SetAdd()`, etc.

### Scenarios that trigger the bug

| Inner loop result | Inner loop mode | Triggered? |
|---|---|---|
| `false` (zero matching iterations) | ForEach | **YES** |
| `false` (one body failure) | Every | **YES** (Every pops context in handle_condition, then hits AssertCondition again) |
| `true` (at least one success) | Any/ForEach | No (handle_condition(true) is a no-op) |
| `true` (all pass) | Every | No |

### Confirmed reproduction

Policy with nested `ForEach` loop inside a set comprehension:
```
RVM Result:  Set({"Subnet nsgY has no nsg"})    ← WRONG
Interpreter: Set({"Subnet subnetA has no nsg", "Subnet subnetB has no nsg"})  ← CORRECT
```

### Fix approaches

**Approach A — Skip AssertCondition when loop already completed (VM fix):**
After `LoopNext` pops the loop and sets the final result, **jump past** the `AssertCondition` instead of to it. Change `pc = loop_end_local.saturating_sub(1)` to `pc = loop_end_local` (landing one past AssertCondition after increment). This requires updating all exit paths in `execute_loop_next_run_to_completion` and `execute_loop_next_suspendable`, plus `handle_empty_collection`.

**Approach B — Feature-gate the AssertCondition emission (compiler fix):**
Wrap the `AssertCondition` emission in `#[cfg(feature = "explanations")]` and adjust `loop_end` / `loop_next_idx` accordingly. This keeps the bug-fix branch behavior for non-explanation builds. For explanation builds, the VM's `handle_condition` needs a refinement so that a post-loop assert failure doesn't propagate upward (see Approach C).

**Approach C — Make handle_condition aware of post-loop asserts (VM fix):**
In the compiler, tag the `AssertCondition` with metadata indicating it's a "post-loop summary assert." In the VM, when this assert fails and the loop context has already been popped, treat it as a **no-op** (the loop result is already final) rather than propagating to the parent. This could be done with a new instruction variant (`AssertLoopResult`) or a flag on `AssertCondition`.

**Approach D — Record explanation data in LoopNext itself:**
Instead of emitting a separate `AssertCondition`, fold the explanation recording into the `LoopNext` handler. The LoopNext already knows the loop result and has access to all the context. This eliminates the problematic instruction entirely.

**Recommended:** Approach D is the cleanest. Approach A is the simplest mechanical fix.

---

## Bug 2 (HIGH): handle_empty_collection hits AssertCondition

**Affects:** ALL builds (same root cause as Bug 1)

### Description

`handle_empty_collection` is called during `execute_loop_start` when the collection is empty (or not iterable). It sets `pc = loop_end.saturating_sub(1)`. After the dispatch loop increments PC, execution lands on the `AssertCondition` instruction.

For Any/ForEach modes, `result_reg = false` → `handle_condition(false)` fires. Since no `LoopContext` was pushed for the empty collection (the function returns early from `execute_loop_start`), `loop_stack` may contain an **outer** loop context, causing the same cascading failure as Bug 1.

If `loop_stack` is empty AND `comprehension_stack` is empty, the VM returns `VmError::AssertionFailed` — a hard error for what should be a normal "no results" case.

### Fix approaches

Same as Bug 1. Specifically:
- **Approach A:** Change `handle_empty_collection` to set `pc = loop_end` (past AssertCondition). After increment, this skips the AssertCondition entirely.
- **Approach B:** Feature-gate the instruction away.
- **Approach D:** Remove the instruction entirely by folding into LoopNext.

---

## Bug 3 (CRITICAL): ComprehensionEnd skipped — context leak on comprehension_stack

**Affects:** ALL builds (consequence of Bug 1)

### Description

When Bug 1 or Bug 2 causes `handle_condition(false)` to route to the outer loop, the PC jumps to the outer loop's `LoopNext`, skipping the `ComprehensionEnd` instruction for any active comprehension between the inner loop and the outer loop.

The `ComprehensionContext` that was pushed by `ComprehensionStart` is **never popped** from `comprehension_stack`. This has cascading effects:

1. **Future condition failures** that check `handle_comprehension_condition_failure_run_to_completion()` will find and operate on the **stale** comprehension context instead of the current one.
2. **Future `ComprehensionEnd` instructions** may pop the wrong context, corrupting execution state.
3. **Explanation witness recording** in `execute_comprehension_end_run_to_completion` is skipped entirely for the leaked comprehension.

### Fix approaches

Fixing Bug 1 inherently fixes Bug 3, since the PC will no longer skip `ComprehensionEnd`. Additionally:

**Defense-in-depth:** When `handle_condition(false)` routes to an outer loop, check whether any comprehension contexts on `comprehension_stack` have a `comprehension_end` PC that falls between the current PC and the target PC. If so, pop and finalize them before jumping.

---

## Bug 4 (MEDIUM): Allocations per builtin call — performance regression

**Affects:** ALL builds

### Description

`src/rvm/vm/functions.rs` `execute_builtin_call` was refactored. The old code cached:
- `dummy_span` (allocated once, reused)
- `dummy_exprs` (grown once to max arity, reused)  
- `cached_builtin_args` (Vec reused across calls)

The new code allocates all three **fresh on every call**:
```rust
let dummy_source = crate::lexer::Source::from_contents("arg".into(), String::new())?;
let dummy_span = crate::lexer::Span { ... };
let mut dummy_exprs: Vec<crate::ast::Ref<crate::ast::Expr>> = Vec::new();
for _ in 0..args.len() { ... }

let mut args = Vec::new();
for &arg_reg in params.arg_registers().iter() { ... }
```

For hot paths with many builtin calls (e.g., `sprintf`, `count` inside loops), this creates significant allocation pressure.

### Fix approaches

**Approach A:** Restore the cached fields on `RegoVM` (`dummy_span`, `dummy_exprs`, `cached_builtin_args`) and use `core::mem::take` + put-back pattern as before.

**Approach B:** If the caching was removed to avoid borrow conflicts with explanation recording, consider pre-allocating in a separate struct that can be borrowed independently.

---

## Bug 5 (MEDIUM): builtins_cache key forces arg clone on every lookup

**Affects:** ALL builds

### Description

The `builtins_cache` type was changed from:
```rust
BTreeMap<&'static str, Vec<(Vec<Value>, Value)>>  // old: two-level, linear scan
```
to:
```rust
BTreeMap<(&'static str, Vec<Value>), Value>  // new: composite key
```

The cache lookup requires:
```rust
self.builtins_cache.get(&(name, args.clone()))
```

This **clones the args Vec on every lookup**, even for cache hits. The old code did a cheap `&str` lookup followed by slice comparison (`entry.0.as_slice() == args.as_slice()`) with zero cloning.

### Fix approaches

**Approach A:** Revert to the two-level structure for zero-clone lookups.

**Approach B:** Keep single-level but implement `Borrow` trait on the key type to allow lookup with `(&str, &[Value])` without cloning.

---

## Bug 6 (MEDIUM): ComprehensionYield O(n²) regression — take_register removed

**Affects:** ALL builds

### Description

The `take_register` method was removed from `machine.rs`. The old `ComprehensionYield` code used `take_register(result_reg)` to get ownership of the collection value without incrementing the `Rc` refcount, allowing `Rc::make_mut` to mutate the inner collection **in-place** (O(1) amortized per yield).

The new code uses `get_register(result_reg)?.clone()`, which bumps the `Rc` refcount to 2, then constructs a new collection:
```rust
let current_result = self.get_register(result_reg)?.clone();
// ...
let mut new_set = set.as_ref().clone();  // always clones inner BTreeSet
new_set.insert(value_to_add);
Value::Set(crate::Rc::new(new_set))
```

For a comprehension yielding N items, the old approach was O(N log N) total. The new approach is O(N² log N) — each yield clones the entire set/object/array built so far.

### Fix approaches

**Approach A:** Restore `take_register` and the `Rc::make_mut` pattern in `ComprehensionYield`. The explanation provenance tracking can read the register value *before* take_register, then the yield can use the efficient path.

**Approach B:** Use `get_register_mut` to get `&mut Value` and mutate in-place without going through take/set.

---

## Bug 7 (LOW): Provenance not cleared in reset_execution_state

**Affects:** `explanations` feature only

### Description

`state.rs` `reset_execution_state()` clears `causality` but does **not** clear or reset `provenance`. The `provenance` tracker is only resized in `load_program()`. If the VM is reused across evaluations of the same program (same register count), stale provenance paths from the previous evaluation may persist.

### Fix approaches

Add `self.provenance.clear()` (or equivalent) to `reset_execution_state()` alongside the `causality.clear()` call:
```rust
#[cfg(feature = "explanations")]
{
    self.causality.clear();
    self.provenance.clear();  // ADD THIS
    if self.explanation_settings.enabled {
        self.causality.set_enabled(true);
    }
}
```

---

## Bug 8 (LOW): Loop emission scope leaked on early exit paths

**Affects:** `explanations` feature only

### Description

`push_loop_emission_scope()` is called at the start of `execute_loop_start` (both run-to-completion and suspendable paths). The corresponding `pop` happens in `insert_loop_summary_state`. However, when `handle_empty_collection` is called and `result_reg` is true (Every mode with empty collection), the flow goes:
1. `push_loop_emission_scope()`
2. `handle_empty_collection` → calls `insert_loop_summary_state` → pops scope ✓

But when Bug 1/2 triggers and PC jumps to an outer loop's LoopNext, the emission scope pushed for the inner loop is never popped. Over many iterations, emission scopes accumulate.

### Fix approaches

Ensure `insert_loop_summary_state` or equivalent is called on all loop exit paths, including abnormal ones forced by Bug 1. Fixing Bug 1 inherently fixes this for the normal case.

---

## Summary

| Bug | Severity | Feature-gated? | Root cause |
|-----|----------|----------------|------------|
| 1 | **CRITICAL** | No — all builds | Unconditional `AssertCondition` after `LoopNext`; false result propagates to outer loop |
| 2 | **HIGH** | No — all builds | `handle_empty_collection` PC lands on `AssertCondition` |
| 3 | **CRITICAL** | No — all builds | Consequence of Bug 1: `ComprehensionEnd` skipped, context leaks |
| 4 | MEDIUM | No — all builds | Per-call allocation of dummy_span/exprs/args in builtin calls |
| 5 | MEDIUM | No — all builds | `builtins_cache` key forces `args.clone()` on every lookup |
| 6 | MEDIUM | No — all builds | `take_register` removed; `Rc::make_mut` in-place mutation lost |
| 7 | LOW | `explanations` only | Provenance not cleared between evaluations |
| 8 | LOW | `explanations` only | Loop emission scope leaked on abnormal exit |

### Recommended fix priority

1. **Fix Bug 1** (which also fixes Bug 2, 3, and 8). Best approach: **Approach D** (fold explanation recording into `LoopNext`) or **Approach A** (adjust all PC calculations to skip past `AssertCondition`).
2. **Fix Bug 6** (ComprehensionYield O(n²)) — restore `take_register`.
3. **Fix Bug 4 & 5** (builtin call allocations) — restore caching.
4. **Fix Bug 7** (provenance clear) — one-line fix.
