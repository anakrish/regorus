# Verus Plan for RVM Verification

This document outlines a high-level plan to formally verify the RVM in this repository using Verus. It focuses on a staged approach that starts with core data structures and scales up to the interpreter loop, instruction semantics, builtins, and policy execution.

## Goals

- Define a precise, executable spec model for RVM behavior.
- Prove the Rust implementation refines the spec model.
- Maintain a small trusted base and expand coverage incrementally.
- Use Verus to validate invariants across state transitions and limits.
- Enable verified input generators (bounded) for policy examples and tests.

## Scope: Components to Verify

- Value model (including nested values, arrays, objects, and numeric types).
- Heap or allocation model (if references are used).
- Instruction decoder and bytecode encoding.
- Instruction semantics and interpreter loop.
- Builtin functions (core and optional/extended sets).
- Policy execution pipeline (input/data loading, rule evaluation, output).
- Error handling and execution limits.

## Stage 1: Spec Model

### 1.1 Spec Types

Define spec-only types that model the RVM state and values:

- SpecValue: abstract value representation.
- SpecHeap: map from addresses to SpecValue (if heap-like behavior exists).
- SpecState: registers/stack, heap, globals, input, data, policy info.
- SpecInstr: the instruction set or a subset for incremental verification.

### 1.2 Spec Semantics

Define a deterministic step function:

- spec_step(state, instr) -> state or error
- spec_exec(state, program, steps) -> state or error (small-step or fuel-based)

Prove:

- Determinism of spec_step.
- Basic safety invariants are preserved by spec_step.

## Stage 2: Value + Heap Invariants

### 2.1 Value Invariants

- Value shape invariants: arrays contain only valid values, objects have unique keys.
- Numeric invariants: no NaN if disallowed, integer bounds as needed.
- No cycles if the representation forbids them.

### 2.2 Heap/Allocation Invariants

- All references point to valid allocations.
- Allocation is unique and monotonic (if that matches implementation).
- Writes preserve value invariants.

Deliverables:

- Spec-level representation of value/heap.
- Proofs that constructors and mutators preserve invariants.

## Stage 3: Instruction Decoder

Define a spec decoder for bytecode and show it matches the implementation:

- decode(bytes) = instr sequence
- encode(instr sequence) = bytes

Prove:

- decode(encode(program)) = program
- decode failures align with implementation errors

## Stage 4: Instruction Semantics

For each instruction (start with a small subset):

- Define spec behavior (preconditions and postconditions).
- Prove Rust implementation matches spec_step for the same instruction.

Key invariants:

- Stack/register bounds preserved.
- Type/shape constraints satisfied by operands.
- No unexpected panics under valid preconditions.

## Stage 5: Interpreter Loop

Prove the loop refines the spec execution semantics.

- Define a loop invariant: pc bounds, heap/value invariants, limits tracking.
- Prove each iteration preserves invariants.
- Prove equivalence with spec_exec for a bounded number of steps (fuel).

## Stage 6: Builtins

Model builtins as pure spec functions and connect them to implementation.

- spec_builtin(name, args) -> value or error
- Prove each builtin implementation refines spec function.

Notes:

- For complex external behavior (hashing, regex), consider an abstract spec.
- Treat external dependencies as trusted or model them with axioms.

## Stage 7: Policy Execution

Define spec-level policy evaluation:

- spec_eval(policy, data, input) -> output
- Prove the interpreter produces the same output under matching conditions.

Focus on:

- Input/data loading and schema enforcement (if any).
- Rule evaluation semantics.
- Output shape invariants.

## Stage 8: Limits and Errors

Formalize error states and execution limits:

- Out-of-bounds, invalid instruction, type errors.
- Step limits, memory limits, depth limits.

Prove:

- Limits are enforced consistently.
- Errors correspond between spec and implementation.

## Verified Input Generation (Bounded)

Verus can verify input generators but does not solve arbitrary constraints.

Approach:

- Define a bounded domain of inputs (size/depth limited).
- Provide an enumerator that returns all possible inputs up to a bound.
- Prove: every generated input satisfies well-formedness constraints.
- Optional: filter by a spec predicate to produce valid examples.

This is useful for:

- Example generation for policies.
- Exhaustive testing for small domains.

## Suggested Milestones

1) SpecValue + value invariants
2) SpecHeap + allocation invariants
3) Decoder spec + encode/decode roundtrip
4) Small instruction subset + proofs
5) Interpreter loop proof with fuel
6) Expand instruction set
7) Builtins proof set
8) Policy execution end-to-end proof

## Expected Verification Artifacts

- Spec modules for values, state, instruction semantics.
- Proof modules for invariants and refinement.
- A minimal set of trusted axioms (if required).
- Verified test/input generators (bounded).

## Notes on Practical Integration

- Start with a small core and scale.
- Keep the spec executable for sanity checks.
- Use proof automation sparingly; keep proofs explicit and stable.
- Consider separate modules for spec vs implementation to avoid tangling.

---

# Detailed RVM Analysis for Verus Verification

This section records a deep analysis of the RVM internals and maps them to
concrete Verus verification targets.

## RVM Architecture Summary

The RVM is a register-based bytecode VM with these key layers:

| Layer | Files | Contents |
|-------|-------|----------|
| **Values** | `src/value.rs`, `src/number.rs` | `Value` enum (`Null`, `Bool`, `Number`, `String`, `Array`, `Set`, `Object`, `Undefined`) with `Rc`-based sharing; `Number` with `BigInt` support |
| **Instructions** | `src/rvm/instructions/mod.rs` | ~35 `Instruction` variants (load/move, arithmetic, comparison, logic, collections, loops, comprehensions, calls, host-await, halt) |
| **Param Tables** | `src/rvm/instructions/params.rs` | `InstructionData` with 9 parameter tables indexed by `u16`, holding complex operands for loops, calls, object/array/set creation |
| **Program** | `src/rvm/program/core.rs` | `Program` struct: instruction stream, literal pool, entry points, rule infos, builtin table, rule tree |
| **VM State** | `src/rvm/vm/machine.rs` | `RegoVM` struct: registers, pc, stacks (loop, call-rule, register, comprehension), rule cache, execution limits, execution state machine |
| **Execution** | `src/rvm/vm/execution.rs` | Two modes: `RunToCompletion` (`jump_to` loop), `Suspendable` (explicit `ExecutionStack` of frames) |
| **Dispatch** | `src/rvm/vm/dispatch.rs` | Layered dispatch chain: `execute_instruction` → load/move → arithmetic → comparison → logic → collections → control-flow |
| **Loops/Comprehensions** | `src/rvm/vm/loops.rs`, `src/rvm/vm/comprehension.rs` | `LoopContext`/`IterationState`, `ComprehensionContext` with three modes (`Any`/`Every`/`ForEach`, `Set`/`Array`/`Object`) |
| **Rules** | `src/rvm/vm/rules.rs`, `src/rvm/vm/functions.rs` | Rule execution with caching, register window swap, destructuring, multi-body evaluation, inconsistency detection |
| **Errors** | `src/rvm/vm/errors.rs` | `VmError` enum with ~40 variants covering bounds violations, type errors, limits, invalid state |

## Key Challenges for Verification

### 1. Rc-based Values

`Value` uses `Rc<Vec<Value>>`, `Rc<BTreeMap<Value,Value>>`, etc. Verus does not
currently support `Rc` or interior mutability well. The solution is to define
**spec-only ghost types** that model values as pure mathematical objects
(sequences, maps, sets of spec values), and prove a refinement relation between
concrete `Value` instances and their spec counterparts.

### 2. Dynamic Collections

The VM uses many growable vectors (register file, stacks, parameter tables).
Verus has `vstd::vec::Vec` and `vstd::map::Map` in spec mode, but bridging to
`alloc::collections` requires wrapper types or trusted boundary axioms.

### 3. Two Execution Modes

`RunToCompletion` uses the Rust call stack (via `jump_to`'s while-loop), while
`Suspendable` uses an explicit `ExecutionStack`. These need separate but related
proofs, or a unified abstract model they both refine.

### 4. State Machine Complexity

The VM state has ~20+ fields. Defining a tractable invariant is the core
challenge. However, the state decomposes naturally into subsystems:
- `(registers, pc)`
- `(loop_stack)`
- `(call_rule_stack, register_stack)`
- `(comprehension_stack)`
- `(rule_cache, evaluated)`

Each subsystem can be assigned its own local invariant and composed.

### 5. Builtins

The builtin table holds resolved function pointers (`BuiltinFcn`). These are
fundamentally opaque to Verus and must be axiomatized or modeled one-by-one.

## Concrete Verus Verification Targets

### Target 1: Spec Value Model (Foundation)

Create a `spec` module with pure ghost types:

```rust
// In verus proof mode (spec functions only)
use vstd::prelude::*;

pub enum SpecValue {
    Null,
    Bool(bool),
    Number(int),           // Abstract all numbers as mathematical ints (or rationals)
    String(Seq<char>),
    Array(Seq<SpecValue>),
    Set(Set<SpecValue>),
    Object(Map<SpecValue, SpecValue>),
    Undefined,
}
```

Key proofs at this level:
- Value well-formedness invariant (no `Undefined` inside arrays/objects/sets,
  objects have unique keys).
- Value ordering is total (needed because `BTreeMap`/`BTreeSet` require `Ord`).
- A refinement relation `value_matches(concrete: &Value, spec: SpecValue) -> bool`.

Why this is tractable: These are purely structural/inductive proofs. No mutation,
no control flow. Verus handles algebraic datatypes and inductive proofs well.

### Target 2: Register File & Bounds Checking

The register file is `Vec<Value>` and all register accesses go through
`get_register(u8)` / `set_register(u8, Value)` which return `Result`:

```rust
pub(super) fn get_register(&self, index: u8) -> Result<&Value> { ... }
pub(super) fn set_register(&mut self, index: u8, value: Value) -> Result<()> { ... }
```

What to prove:
- `ensures`: If `index < self.registers.len()`, get/set succeed. Otherwise,
  `VmError::RegisterIndexOutOfBounds`.
- **VM invariant**: At every instruction, the register window is large enough
  for all registers referenced by that instruction. This is a static property
  of well-formed programs (the compiler guarantees `num_registers` covers all
  register refs).
- `requires`: A well-formed `Program` satisfies: for every instruction at PC
  `i`, all register operands are `< rule_info.num_registers`.

Why this matters: Register bounds are the #1 source of potential runtime panics.
Proving them away gives high confidence.

### Target 3: Instruction Semantics (Per-Instruction Specs)

For each instruction, define a spec transition:

```rust
spec fn spec_step(state: SpecState, instr: SpecInstr) -> Result<SpecState, SpecError> {
    match instr {
        SpecInstr::LoadTrue { dest } => {
            Ok(SpecState {
                registers: state.registers.update(dest, SpecValue::Bool(true)),
                pc: state.pc + 1,
                ..state
            })
        }
        SpecInstr::Add { dest, left, right } => {
            let a = state.registers[left];
            let b = state.registers[right];
            match (a, b) {
                (SpecValue::Number(x), SpecValue::Number(y)) =>
                    Ok(SpecState {
                        registers: state.registers.update(dest, SpecValue::Number(x + y)),
                        pc: state.pc + 1,
                        ..state
                    }),
                _ => Err(SpecError::InvalidAddition),
            }
        }
        // ...
    }
}
```

Then for each instruction's implementation in `src/rvm/vm/dispatch.rs`, prove:

```rust
ensures |result|
    value_matches(result, spec_step(abstract_state(self), abstract_instr(instruction)))
```

Recommended first subset (~10 instructions): `Load`, `LoadTrue`, `LoadFalse`,
`Move`, `Add`, `Sub`, `Eq`, `AssertCondition`, `AssertNotUndefined`, `Return`.
These are self-contained (no stack effects) and cover the core
numeric/boolean logic.

### Target 4: The Main Execution Loop

The `jump_to` loop in `src/rvm/vm/execution.rs` is the heart of
run-to-completion mode:

```rust
while self.pc < program.instructions.len() {
    // 1. Check memory limit
    // 2. Check instruction limit
    // 3. Tick execution timer
    // 4. Fetch instruction
    // 5. execute_instruction → InstructionOutcome
    // 6. Continue / Return / Break / Suspend
}
```

Loop invariant (the central proof obligation):

```
invariant:
  0 <= self.pc <= program.instructions.len()
  && self.registers.len() >= current_rule_num_registers
  && self.executed_instructions <= self.max_instructions
  && forall |i| 0 <= i < self.registers.len() ==> well_formed(self.registers[i])
  && loop_stack_valid(&self.loop_stack, &self.registers)
  && call_rule_stack_valid(&self.call_rule_stack, ...)
```

Termination argument:
`fuel = self.max_instructions - self.executed_instructions` decreases each
iteration, bounded by `max_instructions`. This is clean — the VM already
enforces an instruction budget.

### Target 5: Loop & Comprehension Correctness

The loop system in `src/rvm/vm/loops.rs` is the most complex subsystem.
Key properties to verify:

1. **`LoopMode::Any`**: Result is `true` iff at least one iteration's body
   succeeded. Early-exit on first success.
2. **`LoopMode::Every`**: Result is `true` iff all iterations' bodies
   succeeded. Early-exit on first failure.
3. **`LoopMode::ForEach`**: All iterations execute; result accumulates.
4. **`IterationState` advances monotonically** (array index increases,
   object/set cursors move forward-only via `BTreeMap`/`BTreeSet` ordering).
5. **`body_start` / `loop_end` PCs** are within bounds and correctly bracket
   the loop body.

Spec model:

```rust
spec fn spec_loop(
    mode: LoopMode,
    collection: Seq<SpecValue>,
    body_fn: FnSpec(SpecValue) -> bool,
) -> bool {
    match mode {
        LoopMode::Any   => exists |i| 0 <= i < collection.len() && body_fn(collection[i]),
        LoopMode::Every => forall |i| 0 <= i < collection.len() ==> body_fn(collection[i]),
        LoopMode::ForEach => true, // always runs all iterations
    }
}
```

### Target 6: Rule Caching Correctness

The rule cache is `Vec<(bool, Value)>` indexed by `rule_index`. Key property:

```
invariant: forall |i| rule_cache[i].0 == true ==>
    rule_cache[i].1 == spec_eval_rule(program, data, input, i)
```

If a rule is marked computed, its cached value must equal what fresh evaluation
would produce. This is a functional correctness property — the hardest but most
valuable.

### Target 7: Limits & Error Handling

Properties from `src/rvm/vm/errors.rs`:
- **Instruction limit**: `executed_instructions` never exceeds
  `max_instructions + 1` (the check happens before dispatch).
- **Memory limit**: checked via `memory_check()` before each instruction.
- **All error paths produce valid `VmError` variants** (no panics via `unwrap`
  in the hot path).
- **No undefined behavior**: all `get()` calls on vectors return `Option` and
  are handled.

## Practical Recommendations

| Aspect | Recommendation |
|--------|---------------|
| **Verus boundary** | Create a `src/rvm/verified/` directory with `spec.rs`, `proof.rs` modules. Keep specs separate from implementation. |
| **Trusted base** | Trust: `Value`/`Number` construction, serde, `Rc`, `BTreeMap`/`BTreeSet` ordering, builtins. Everything else can be verified. |
| **First milestone** | Verify `get_register`, `set_register`, `validate_vm_state`, and the 10 simplest instruction handlers (Load*, Move, Add, Sub, Eq, Return). |
| **Second milestone** | Verify the `jump_to` loop invariant (bounds, limits, termination). |
| **Third milestone** | Verify loop semantics (`Any`/`Every`/`ForEach` correctness). |
| **Biggest bang for buck** | Register bounds + instruction limit enforcement. These are the invariants that prevent crashes and DoS in production. |
| **What to skip (for now)** | Suspendable mode (complex frame management, lower priority), serialization, and builtins (external dependencies). |

## Why the RVM is Amenable to Verus

1. **Fixed-width instructions** (`#[repr(C)]`, `Copy`) — easy to model as spec enum.
2. **Explicit error handling** — every fallible path returns `Result<_, VmError>`, no panics.
3. **Linear execution** with bounded fuel — `max_instructions` gives a natural termination measure.
4. **Register-based, not stack-based** — register indices are statically bounded per rule, making bounds proofs feasible.
5. **Layered dispatch** — each dispatch function handles a clean subset of instructions, allowing per-layer proofs.
6. **Clean state reset** — `reset_execution_state()` in `src/rvm/vm/state.rs` means every execution starts from a well-defined initial state, simplifying precondition establishment.

## Revised Milestone Ordering

The original milestones above follow a bottom-up approach (spec model first).
An alternative **safety-first** ordering offers quicker wins:

1. Register bounds + `get_register`/`set_register` proofs.
2. `jump_to` loop invariant (pc bounds, instruction limit, termination).
3. SpecValue + value well-formedness invariants.
4. Small instruction subset (Load*, Move, Add, Sub, Eq, Return) refinement proofs.
5. Loop semantics (`Any`/`Every`/`ForEach`).
6. Rule caching functional correctness.
7. Expand instruction coverage.
8. Builtins (axiomatized or per-function).
9. Policy execution end-to-end proof.

This ordering prioritizes the invariants that prevent crashes and denial-of-service
before tackling full functional correctness.
