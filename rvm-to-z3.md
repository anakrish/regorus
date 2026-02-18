# RVM-to-Z3: Symbolic Execution of Rego Bytecode

## Design Document

### 1. Overview

This document describes the design for a **symbolic executor** that translates compiled RVM
(Rego Virtual Machine) bytecode programs into Z3 SMT constraints. The goal is to enable
static analysis of Rego policies — including input generation, coverage targeting, policy
diff/equivalence checking, satisfiability analysis, and "why denied?" explanations — by
converting RVM's concrete execution semantics into symbolic constraints that Z3 can solve.

### 1.1 Why RVM Bytecode (Not Rego AST)?

- **Single canonical representation.** The compiler has already resolved imports, partial
  rules, comprehensions, and function calls. What remains is a flat instruction stream with
  explicit control flow.
- **Finite, enumerable instruction set.** ~35 instruction variants, all `#[repr(C)]` and
  `Copy`. Every instruction's semantics are spelled out in `dispatch.rs` — no ambiguity.
- **Register-based SSA-like form.** Each instruction names its operands and destination by
  register number. There is no expression tree to walk — just registers.
- **Explicit data flow for input/data.** `LoadInput`, `LoadData`, `IndexLiteral`,
  `ChainedIndex`, and `VirtualDataDocumentLookup` make it clear exactly which paths into
  `input` and `data` are accessed.
- **Instruction spans.** `SpanInfo { source_index, line, column, length }` maps every PC
  back to source, enabling coverage targeting at the source line level.

### 1.2 Requirements

| # | Requirement | Description |
|---|-------------|-------------|
| R1 | **Input generation** | Given a policy + data + desired output → generate an `input` that produces that output |
| R2 | **Line coverage** | Constrain the solver to exercise a specific source line (or set of lines) |
| R3 | **Policy diff** | Given two policies → find an input where they disagree |
| R4 | **Satisfiability** | Can any input make this rule true? (vacuity check) |
| R5 | **"Why denied?"** | Given a denied request → minimal set of conditions that failed |
| R6 | **Schema-constrained** | Restrict symbolic `input` to conform to a JSON Schema |
| R7 | **Easy input extraction** | Given a Z3 model, reconstruct concrete JSON trivially |

### 1.3 Design Principles

1. **Path encoding as the primary value representation.** Every symbolic value accessed from
   `input` or `data` is named by its access path (e.g., `input.user.role`). This makes
   model-to-JSON extraction trivial (R7) — each Z3 variable maps directly to a JSON path.

2. **Bounded, deterministic analysis.** Loops are unrolled to a configurable depth. The
   analysis is sound up to the bound (if Z3 says UNSAT, the property truly holds up to that
   depth; if SAT, the model is a genuine witness).

3. **One Z3 context per query.** Each analysis question (R1–R6) constructs a self-contained
   Z3 formula. No incremental state between queries.

4. **Fail-open for unsupported features.** When we encounter a builtin we cannot model, we
   emit an uninterpreted function symbol and log a warning. The analysis is still useful for
   the modeled subset.

---

## 2. Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌────────────┐
│  Compiled   │     │   Path       │     │  Symbolic    │     │   Z3       │
│  Program    │────▶│   Extractor  │────▶│  Translator  │────▶│   Solver   │
│  (bytecode) │     │              │     │              │     │            │
└─────────────┘     └──────────────┘     └──────────────┘     └────────────┘
                           │                    │                    │
                           ▼                    ▼                    ▼
                    ┌──────────────┐     ┌──────────────┐     ┌────────────┐
                    │  Path        │     │  Constraint  │     │   Model    │
                    │  Registry    │     │  Set (Z3     │     │   → JSON   │
                    │              │     │   formulas)  │     │   Extractor │
                    └──────────────┘     └──────────────┘     └────────────┘
```

### 2.1 Components

1. **Path Extractor** — Static analysis pass over bytecode. Walks instructions to discover
   all access paths into `input` and `data`. Produces a `PathRegistry`.

2. **Path Registry** — Maps each discovered path (e.g., `input.user.role`) to a Z3 symbolic
   variable. Also tracks type constraints observed from the bytecode.

3. **Symbolic Translator** — The core engine. Walks the instruction stream symbolically,
   maintaining a symbolic register file. Each instruction updates registers with Z3
   expressions and/or emits constraints.

4. **Z3 Solver** — Standard Z3 context. Receives the constraint set plus any query-specific
   assertions (desired output, coverage target, etc.) and produces SAT/UNSAT + model.

5. **Model-to-JSON Extractor** — Reads the Z3 model, looks up each path variable's concrete
   value, and reconstructs a JSON document.

---

## 3. Symbolic Value Encoding

### 3.1 The Problem

Regorus `Value` is a recursive enum:

```rust
pub enum Value {
    Null,
    Bool(bool),
    Number(Number),        // UInt(u64) | Int(i64) | Float(f64) | BigInt(Rc<BigInt>)
    String(Rc<str>),
    Array(Rc<Vec<Value>>),
    Set(Rc<BTreeSet<Value>>),
    Object(Rc<BTreeMap<Value, Value>>),
    Undefined,
}
```

Modeling this directly in Z3 as a recursive algebraic datatype is possible but makes model
extraction painful (nested constructors, heap pointers). We previously had significant
difficulty extracting usable inputs from such models.

### 3.2 Solution: Hybrid Path + Tagged Scalar Encoding

We use a **two-layer** encoding:

#### Layer 1: Path Encoding (Primary)

Every access path from `input` (or `data`) seen in the bytecode gets a flat Z3 variable.

```
input.user.role        →  Z3 String variable "input.user.role"
input.request.method   →  Z3 String variable "input.request.method"
input.user.age         →  Z3 Int variable "input.user.age"
```

The access path is discovered statically from `LoadInput` → `IndexLiteral` / `ChainedIndex`
chains. Since most Rego policies access `input` through known literal keys, the vast majority
of symbolic variables are captured this way.

**Advantages:**
- Model extraction = iterate path variables, slot each value into a JSON tree. Trivial.
- No recursive Z3 types needed for the common case.
- Z3 reasoning is efficient (flat variables, no datatype overhead).

#### Layer 2: Tagged Scalar (for Computed/Dynamic Access)

For paths that go through a **register** (not a literal) — e.g., `input[x]` where `x` is a
loop variable — we use a tagged scalar representation:

```
Z3 Datatype SymValue:
  | SNull
  | SBool(val: Bool)
  | SInt(val: Int)
  | SFloat(val: Real)
  | SString(val: String)
  | SUndefined
```

No recursive constructors. Collection-typed values that arise from dynamic access are
modeled conservatively (the solver may return Unknown for those constraints, or we fall back
to concrete evaluation).

#### Deciding Which Layer

At each `IndexLiteral` / `ChainedIndex`:
- If **all** path components are `LiteralOrRegister::Literal` → Layer 1 (path variable).
- If **any** component is `LiteralOrRegister::Register` → Layer 2 (tagged scalar), and the
  path becomes symbolic.

At `VirtualDataDocumentLookup`:
- Same logic: literal-only paths → Layer 1; register components → Layer 2.

### 3.3 Type Inference from Usage

We track how each path variable is used to refine its Z3 sort:

| Instruction context | Inferred type |
|---------------------|---------------|
| Operand of `Add`/`Sub`/`Mul`/`Div`/`Mod` | `Int` or `Real` |
| Operand of `Lt`/`Le`/`Gt`/`Ge` | `Int` or `Real` |
| Operand of `And`/`Or`/`Not` | `Bool` |
| Operand of `Eq`/`Ne` | Same type as the other operand |
| Used as `AssertCondition` operand | `Bool` |
| Compared to a literal `Bool` | `Bool` |
| Compared to a literal `String` | `String` |
| Compared to a literal `Number` | `Int` or `Real` |
| Used in `Contains` as value | Same type as collection elements |
| Used in string builtin | `String` |

When the type is ambiguous, we default to `String` (most general for Rego) and add a
tag discriminant constraint.

### 3.4 Undefined Semantics

`Undefined` is the central control flow mechanism in Rego. Our encoding:

- Every path variable gets a companion `Bool` variable: `defined_<path>`.
- `defined_<path> == false` means the path is absent from input.
- When `defined_<path> == false`, any constraint involving that path uses the `Undefined`
  propagation rules from the concrete VM.

The concrete VM's undefined rules:
- **Arithmetic/comparison with Undefined → Undefined.** (`Add`, `Sub`, `Eq`, `Lt`, etc.)
- **`Not` on Undefined → `true`.** (Rego negation succeeds when the expression has no value.)
- **`AssertCondition` on Undefined → condition fails** (body of rule aborts).
- **`AssertNotUndefined` on Undefined → condition fails.**

In Z3:

```python
# For Add { dest, left, right }:
dest_defined = And(left_defined, right_defined)
dest_value = If(dest_defined, left_value + right_value, UNDEFINED_SENTINEL)

# For Not { dest, operand }:
dest_defined = True  # Not always produces a defined value
dest_value = If(operand_defined, Not(operand_value), True)  # not-undefined = true

# For AssertCondition { condition }:
path_alive = And(path_alive_before, Or(
    And(cond_defined, cond_value == True),
    And(Not(cond_defined), False)  # undefined → fails
))
```

---

## 4. Symbolic Register File

The translator maintains a **symbolic register file**: an array of Z3 expressions indexed by
register number. This mirrors the concrete VM's `registers: Vec<Value>`.

```rust
struct SymbolicRegister {
    /// The Z3 expression for this register's value.
    /// Sort depends on usage context (Int, Bool, String, Real, SymValue).
    value: z3::ast::Dynamic,

    /// Whether this register holds a defined (non-Undefined) value.
    defined: z3::ast::Bool,

    /// If this register traces back to an input path, which one.
    source_path: Option<String>,

    /// Known type constraint (may be refined over execution).
    type_tag: Option<ValueType>,
}

enum ValueType {
    Bool,
    Int,
    Float,
    String,
    Null,
    Array,
    Set,
    Object,
    Unknown,
}

struct SymbolicState<'ctx> {
    /// Symbolic registers, indexed by register number.
    registers: Vec<SymbolicRegister>,

    /// Path condition: conjunction of all branch decisions taken on this path.
    path_condition: z3::ast::Bool<'ctx>,

    /// Current PC (for span lookups).
    pc: usize,

    /// Accumulated constraints emitted by instructions.
    constraints: Vec<z3::ast::Bool<'ctx>>,
}
```

### 4.1 Register Window Handling

When `CallRule` or `FunctionCall` executes, the concrete VM swaps register windows:

```rust
// Concrete VM (rules.rs):
let mut register_window = self.new_register_window();
mem::swap(&mut previous_registers, &mut self.registers);
self.registers = register_window;
// ... execute rule body ...
// restore:
self.registers = restored_registers;
```

The symbolic translator does the same: save/restore the symbolic register file on
`CallRule`/`FunctionCall`/`Return`. Arguments are copied from caller registers to callee
Window (using `FunctionCallParams.arg_registers()`), and the result is copied back to
`dest`.

---

## 5. Instruction Translation

Each RVM instruction maps to Z3 constraint(s). We walk the instruction stream sequentially,
updatng the symbolic register file.

### 5.1 Load Instructions

| Instruction | Translation |
|-------------|-------------|
| `Load { dest, literal_idx }` | `reg[dest] = concrete(program.literals[literal_idx])` |
| `LoadTrue { dest }` | `reg[dest] = z3.Bool(true)` |
| `LoadFalse { dest }` | `reg[dest] = z3.Bool(false)` |
| `LoadNull { dest }` | `reg[dest] = SNull` |
| `LoadBool { dest, value }` | `reg[dest] = z3.Bool(value)` |
| `LoadData { dest }` | `reg[dest] = symbolic_data_root` |
| `LoadInput { dest }` | `reg[dest] = symbolic_input_root` |
| `Move { dest, src }` | `reg[dest] = reg[src]` |

`LoadData` and `LoadInput` are the entry points into symbolic territory. When `data` is
provided concretely (common case), `LoadData` loads the concrete value. When `input` is
symbolic, `LoadInput` loads a symbolic root marker.

### 5.2 Arithmetic Instructions

For `Add { dest, left, right }` (and `Sub`, `Mul`, `Div`, `Mod`):

```python
# Undefined propagation
if not left.defined or not right.defined:
    reg[dest] = Undefined
else:
    reg[dest].value = left.value OP right.value   # Z3 arithmetic
    reg[dest].defined = True
```

Z3 translation:
```python
dest_defined = And(left_defined, right_defined)
dest_value = If(dest_defined, left_value + right_value, 0)  # sentinel
```

Division by zero: `Div` and `Mod` add a constraint that the divisor is non-zero when
defined, or mark the result as potentially error-valued.

### 5.3 Comparison Instructions

For `Eq { dest, left, right }` (and `Ne`, `Lt`, `Le`, `Gt`, `Ge`):

```python
dest_defined = And(left_defined, right_defined)
dest_value = If(dest_defined, left_value == right_value, UNDEFINED)
```

For `Lt`/`Le`/`Gt`/`Ge`, the concrete VM also checks that both operands have the same
discriminant when `strict_builtin_errors` is set. In the symbolic model, we assume
compatible types (since the path-extracted types usually are).

### 5.4 Logical Instructions

```python
# And { dest, left, right }
dest_defined = And(left_defined, right_defined)
dest_value = If(dest_defined, And(left_value, right_value), UNDEFINED)

# Or { dest, left, right }
dest_defined = And(left_defined, right_defined)
dest_value = If(dest_defined, Or(left_value, right_value), UNDEFINED)

# Not { dest, operand }
# Special: Not on Undefined → true (Rego negation semantics)
dest_defined = True
dest_value = If(operand_defined, Not(operand_value), True)
```

### 5.5 Assert Instructions

These are the primary control flow mechanism in Rego. They don't produce values — they
constrain the path condition.

```python
# AssertCondition { condition }
cond = reg[condition]
# Condition passes if: defined AND truthy
passed = If(cond.defined,
    If(is_bool(cond), cond.value,    # Bool → must be true
       True),                         # Non-bool → truthy
    False)                             # Undefined → fails
path_condition = And(path_condition, passed)

# AssertNotUndefined { register }
path_condition = And(path_condition, reg[register].defined)
```

When a path condition becomes UNSAT (the body cannot succeed), the symbolic executor can
prune that path early.

### 5.6 Index Instructions

These are the most important instructions for path extraction.

```python
# IndexLiteral { dest, container, literal_idx }
key = program.literals[literal_idx]      # concrete key
if reg[container].source_path is not None:
    # This is an access into input/data — create/lookup path variable
    new_path = f"{reg[container].source_path}.{key}"
    reg[dest] = path_registry.get_or_create(new_path)
else:
    # Container is a concrete or computed collection
    reg[dest] = symbolic_index(reg[container], key)

# Index { dest, container, key }
# key is a register — dynamic access → Layer 2
reg[dest] = symbolic_dynamic_index(reg[container], reg[key])

# ChainedIndex { params_index }
params = instruction_data.chained_index_params[params_index]
current = reg[params.root]
for component in params.path_components:
    match component:
        Literal(idx): current = symbolic_literal_index(current, program.literals[idx])
        Register(r):  current = symbolic_dynamic_index(current, reg[r])
reg[params.dest] = current
```

### 5.7 Collection Creation

```python
# ArrayCreate { params_index } — if any element is Undefined, result is Undefined
params = instruction_data.array_create_params[params_index]
all_defined = And(*(reg[r].defined for r in params.elements))
reg[params.dest].defined = all_defined
# Value: concrete array of the symbolic element values (for small known-size arrays)

# ObjectCreate { params_index } — same Undefined propagation
# SetCreate { params_index } — same pattern

# ArrayNew, ArrayPush, SetNew, SetAdd, ObjectSet — mutable builders
# These are harder to model symbolically. Common in comprehensions.
# Strategy: track as "builder expressions" that accumulate constraints.
```

### 5.8 Contains and Count

```python
# Contains { dest, collection, value }
# Z3 encoding depends on collection type:
# - Known set/array of concrete literals → Or(value == lit1, value == lit2, ...)
# - Symbolic collection → uninterpreted function contains(collection, value)

# Count { dest, collection }
# For concrete collections: concrete integer
# For symbolic collections: uninterpreted function size(collection)
```

---

## 6. Loop Handling

### 6.1 RVM Loop Structure

Loops in RVM are delimited by `LoopStart` / `LoopNext` pairs with explicit `LoopMode`:

```rust
pub enum LoopMode {
    Any,      // Existential: succeeds if any iteration's body succeeds
    Every,    // Universal: succeeds only if all iterations' body succeed
    ForEach,  // Iteration: execute body for each element, collect results
}
```

The loop iterates over a collection in a register (`params.collection`), binding
`key_reg` and `value_reg` per iteration.

### 6.2 Symbolic Translation Strategy

#### Case A: Concrete Collection (data-derived)

When the loop's collection register holds a **concrete** value (from `data` or a literal),
we know the exact elements. We unroll fully:

```python
# For loop over concrete array [a, b, c] with mode=Any:
body_a = translate_body(key=0, value=a)
body_b = translate_body(key=1, value=b)
body_c = translate_body(key=2, value=c)
result = Or(body_a.succeeded, body_b.succeeded, body_c.succeeded)

# For mode=Every:
result = And(body_a.succeeded, body_b.succeeded, body_c.succeeded)

# For mode=ForEach:
# Each body contributes to the accumulated result
```

#### Case B: Symbolic Collection (input-derived)

When the collection is symbolic, we use **bounded unrolling**:

```python
MAX_ITERATIONS = config.max_loop_depth  # default: 10

# Create N symbolic element variables
for i in range(MAX_ITERATIONS):
    elem_exists_i = z3.Bool(f"loop_{pc}_elem_{i}_exists")
    key_i = z3.fresh(f"loop_{pc}_key_{i}")
    val_i = z3.fresh(f"loop_{pc}_val_{i}")

    # Monotonicity: if elem_i doesn't exist, elem_{i+1} doesn't either
    if i > 0:
        solver.add(Implies(Not(elem_exists_{i-1}), Not(elem_exists_i)))

    # Translate body with key_i, val_i bound
    body_i = translate_body(key=key_i, value=val_i)

    # Gate body constraints by elem_exists_i
    body_i.constraints = [Implies(elem_exists_i, c) for c in body_i.constraints]

# For mode=Any:
result = Or(*(And(elem_exists_i, body_i.succeeded) for i in range(MAX_ITERATIONS)))

# For mode=Every:
result = And(*(Implies(elem_exists_i, body_i.succeeded) for i in range(MAX_ITERATIONS)))
```

### 6.3 Empty Collection Handling

The concrete VM calls `handle_empty_collection` which, for `LoopMode::Every`, sets
`result = true` (vacuous truth). We mirror this:

```python
collection_empty = And(*(Not(elem_exists_i) for i in range(MAX_ITERATIONS)))
every_result = If(collection_empty, True, all_iterations_succeeded)
```

### 6.4 LoopAction Semantics

The concrete VM has `LoopAction::ExitWithSuccess` (early exit on first match for `Any`)
and `ExitWithFailure` (early exit on first failure for `Every`). In the Z3 model, we don't
need early-exit logic since we encode all iterations symbolically — the `Or`/`And` naturally
captures the semantics.

---

## 7. Comprehension Handling

### 7.1 RVM Comprehension Structure

Comprehensions use `ComprehensionBegin` / `ComprehensionYield` / `ComprehensionEnd`:

```rust
pub enum ComprehensionMode {
    Set,     // { expr | ... }
    Array,   // [ expr | ... ]
    Object,  // { key: value | ... }
}
```

The concrete VM builds the result incrementally: each `ComprehensionYield` adds an element
to the result collection.

### 7.2 Symbolic Translation

Comprehensions are essentially loops that produce collections. We translate them similarly
to loops:

```python
# Set comprehension: {expr | x in collection, condition(x)}
# → For each unrolled iteration that succeeds, the yielded value is in the result set

result_elements = []
for i in range(MAX_ITERATIONS):
    if iteration_i.succeeded:
        result_elements.append(iteration_i.yield_value)

# Constraint: result = { e | e in result_elements and its iteration succeeded }
```

For **concrete** source collections, we unroll exactly.

For **symbolic** source collections, bounded unrolling produces a symbolic result
collection of bounded size.

When the comprehension result is subsequently used in a simple way (e.g., `count(result)`,
`x in result`), we map directly to constraints over the yielded elements without
materializing the collection.

---

## 8. Rule Calls

### 8.1 RVM Rule Call Semantics

`CallRule { dest, rule_index }` does:

1. Check rule cache — if already computed, return cached result.
2. Allocate a new register window.
3. For each definition in `rule_info.definitions`:
   a. For each body entry point in that definition:
      - Execute destructuring block (if any). If fails → skip to next definition.
      - Execute body. If succeeds → record result.
      - **First successful body in a definition → skip remaining bodies (else-branches).**
   b. For `Complete` rules: if this definition's result conflicts with a previous
      definition's result → `Undefined` (inconsistency).
4. If no body succeeded and rule has `default_literal_index` → use default.
5. Cache and return.

### 8.2 Symbolic Translation

```python
def translate_call_rule(dest, rule_index):
    rule_info = program.rule_infos[rule_index]

    if is_function_rule(rule_info):
        # Functions are not cached; inline the body
        return translate_function_call(dest, rule_index)

    # For non-function rules, inline symbolically:
    definition_results = []

    for def_idx, definition_bodies in enumerate(rule_info.definitions):
        body_results = []
        for body_entry in definition_bodies:
            # Save symbolic register file
            saved = snapshot_registers()

            # Translate destructuring (if any)
            if rule_info.destructuring_blocks[def_idx] is not None:
                destr_ok = translate_block(destructuring_entry)
                if destr_ok is UNSAT:
                    restore_registers(saved)
                    continue

            # Translate body
            body_state = translate_block(body_entry)
            body_results.append((body_state.path_condition, body_state.result))

            restore_registers(saved)

            # First successful body → skip remaining (else-branch semantics)
            break  # In Z3: use If-then-else chain for body priority

        definition_results.append(combine_body_results(body_results, rule_info.rule_type))

    # Combine across definitions
    final_result = combine_definitions(definition_results, rule_info)

    # Apply default if all definitions failed
    if rule_info.default_literal_index is not None:
        default_val = program.literals[rule_info.default_literal_index]
        final_result = If(all_defs_failed, default_val, final_result)

    reg[dest] = final_result
```

### 8.3 Rule Types

- **`Complete`**: All definitions must agree on the result value. If two definitions
  produce different results, the rule evaluates to `Undefined`. In Z3: assert that all
  successful definitions yield equal results.

- **`PartialSet`**: Each successful body contributes elements to a set. The result is the
  union. In Z3: result set contains an element iff some body succeeded with that element.

- **`PartialObject`**: Each successful body contributes key-value pairs. Result is the
  merged object. In Z3: similar to PartialSet but with key→value mappings.

### 8.4 Recursion

RVM tracks recursion via `call_rule_stack`. For symbolic execution, we handle recursion
by **inlining to a bounded depth** (configurable, default 3). Beyond the depth limit,
the rule returns `Undefined`.

### 8.5 Rule Caching

In the concrete VM, `rule_cache` ensures each non-function rule is evaluated at most once.
In the symbolic translator, we achieve the same by caching the symbolic result of the first
translation of each rule. Subsequent `CallRule` for the same `rule_index` reuses the cached
Z3 expression.

---

## 9. Virtual Data Document Lookup

### 9.1 RVM Semantics

`VirtualDataDocumentLookup` merges base `data` with rule-defined virtual documents. The
concrete VM:

1. Walks `program.rule_tree["data"]` following the path components.
2. If it hits a `Number` (rule index) → calls that rule.
3. If it hits an `Object` → recursively evaluates all rules in the subtree.
4. Merges rule results with base `data` values.

### 9.2 Symbolic Translation

Since `data` is typically concrete:

```python
def translate_vddl(params):
    # Resolve path components
    path = resolve_path(params.path_components)

    # Walk rule_tree to find what we're looking at
    node = program.rule_tree["data"]
    for component in path:
        node = node[component]

    if is_rule_index(node):
        # Inline the rule
        translate_call_rule(params.dest, node.as_rule_index())
    elif is_object(node):
        # Multiple rules: merge results
        result = translate_rule_tree_subtree(node, path)
        reg[params.dest] = result
    else:
        # Pure data access
        reg[params.dest] = concrete_data_lookup(path)
```

---

## 10. Builtin Functions

### 10.1 Strategy

RVM has a `BuiltinCallParams` with `builtin_index` referencing `program.builtin_info_table`.
The table provides `{ name, num_args }`.

We classify builtins into tiers:

#### Tier 1: Precisely Modeled

| Builtin | Z3 Encoding |
|---------|-------------|
| `count` | `If(is_array, array_length, If(is_object, object_size, ...))` |
| `to_number` | Z3 type cast |
| `abs` | `If(x >= 0, x, -x)` |
| `min`/`max` | `If(a < b, a, b)` / `If(a > b, a, b)` |
| `contains` (string) | `z3.Contains(haystack, needle)` |
| `startswith`/`endswith` | `z3.PrefixOf` / `z3.SuffixOf` |
| `lower`/`upper` | Uninterpreted (but axiomatized for idempotence) |
| `concat` | `z3.Concat` |
| `sprintf` | Partially: simple `%s`/`%d` patterns → `z3.Concat` |
| `split` | Partially: `z3.Contains` based constraints |
| `trim`/`trim_left`/`trim_right` | Partially: prefix/suffix constraints |
| `numbers.range` | Enumerate if bounds are concrete |
| `array.concat` | Concatenation constraint |
| `object.get` | Index with default |
| `is_null`/`is_boolean`/`is_number`/`is_string`/`is_array`/`is_object`/`is_set` | Tag check |

#### Tier 2: Axiomatized (Partially Modeled)

| Builtin | Strategy |
|---------|----------|
| `regex.match` | Uninterpreted with `z3.InRe` for simple patterns |
| `json.marshal`/`json.unmarshal` | Uninterpreted |
| `base64.encode`/`decode` | Uninterpreted with inverse axiom |
| `time.now_ns` | Fresh unconstrained integer |
| `crypto.*` | Uninterpreted |
| `http.send` | Uninterpreted (opaque external call) |
| `net.cidr_contains` | IP range containment (partial) |
| `glob.match` | Simple patterns → regex translation |

#### Tier 3: Uninterpreted

All remaining builtins get a fresh uninterpreted function symbol.
We track which builtins were modeled vs. uninterpreted and report this to the user,
so they understand the analysis scope.

### 10.2 Implementation

```rust
fn translate_builtin_call(&mut self, params: &BuiltinCallParams) -> Result<()> {
    let builtin_info = &self.program.builtin_info_table[params.builtin_index as usize];

    match builtin_info.name.as_str() {
        "count" => self.translate_builtin_count(params),
        "contains" => self.translate_builtin_contains_string(params),
        "startswith" => self.translate_builtin_startswith(params),
        // ... tier 1 builtins ...

        name if AXIOMATIZED_BUILTINS.contains(name) => {
            self.translate_axiomatized_builtin(name, params)
        }

        _ => {
            // Tier 3: uninterpreted
            self.warnings.push(format!(
                "Builtin '{}' modeled as uninterpreted function", builtin_info.name
            ));
            self.translate_uninterpreted_builtin(params)
        }
    }
}
```

---

## 11. Path Extraction

### 11.1 Static Path Discovery

Before symbolic execution, we perform a **static pass** over the bytecode to discover all
input access paths. This populates the `PathRegistry`.

Algorithm:

```python
def extract_paths(program: Program) -> PathRegistry:
    registry = PathRegistry()

    # Track which registers hold input-derived values
    # (forward dataflow analysis)
    reg_source: dict[u8, str] = {}

    for pc, instruction in enumerate(program.instructions):
        match instruction:
            LoadInput { dest }:
                reg_source[dest] = "input"

            LoadData { dest }:
                reg_source[dest] = "data"

            IndexLiteral { dest, container, literal_idx }:
                if container in reg_source:
                    key = program.literals[literal_idx].as_string()
                    path = f"{reg_source[container]}.{key}"
                    reg_source[dest] = path
                    registry.register(path)

            ChainedIndex { params_index }:
                params = program.instruction_data.chained_index_params[params_index]
                if params.root in reg_source:
                    path = reg_source[params.root]
                    all_literal = True
                    for component in params.path_components:
                        match component:
                            Literal(idx):
                                key = program.literals[idx].as_string()
                                path = f"{path}.{key}"
                            Register(r):
                                all_literal = False
                                path = f"{path}[*]"  # wildcard
                    reg_source[params.dest] = path
                    registry.register(path, all_literal=all_literal)

            Move { dest, src }:
                if src in reg_source:
                    reg_source[dest] = reg_source[src]

            # Clear on overwrite
            Load { dest, .. } | LoadTrue { dest } | ... :
                reg_source.pop(dest, None)

    return registry
```

### 11.2 PathRegistry

```rust
struct PathRegistry<'ctx> {
    /// Map from path string to Z3 variable info.
    paths: HashMap<String, PathEntry<'ctx>>,
}

struct PathEntry<'ctx> {
    /// The Z3 variable for this path's value.
    value: z3::ast::Dynamic<'ctx>,
    /// Whether this path is defined (not Undefined).
    defined: z3::ast::Bool<'ctx>,
    /// Inferred Z3 sort.
    sort: z3::Sort<'ctx>,
    /// Whether all access components were literal (fully static path).
    is_static: bool,
    /// Source instruction PCs that access this path.
    access_pcs: Vec<usize>,
}
```

### 11.3 Model-to-JSON Extraction

Given a Z3 model:

```python
def extract_json(model: z3.Model, registry: PathRegistry) -> dict:
    result = {}

    for path, entry in registry.paths.items():
        if not path.startswith("input."):
            continue

        # Check if the path is defined in the model
        defined_val = model.eval(entry.defined)
        if defined_val is False:
            continue  # Path absent from input

        # Get the concrete value
        concrete = model.eval(entry.value)
        json_value = z3_to_json(concrete, entry.sort)

        # Place into the JSON tree
        segments = path.removeprefix("input.").split(".")
        set_nested(result, segments, json_value)

    return result


def z3_to_json(z3_val, sort):
    match sort:
        BoolSort: return z3_val.as_bool()
        IntSort:  return z3_val.as_long()
        RealSort: return float(z3_val.as_fraction())
        StringSort: return z3_val.as_string()
        _:        return str(z3_val)


def set_nested(obj, segments, value):
    for seg in segments[:-1]:
        if seg not in obj:
            obj[seg] = {}
        obj = obj[seg]
    obj[segments[-1]] = value
```

This is the key payoff of path encoding: **input extraction is a simple iteration + JSON tree
construction.** No recursive datatype decoding, no heap reconstruction.

---

## 12. Coverage Targeting (R2)

### 12.1 SpanInfo Mapping

Every instruction has a `SpanInfo`:
```rust
pub struct SpanInfo {
    pub source_index: u16,  // index into program.sources
    pub line: u32,
    pub column: u32,
    pub length: u32,
}
```

We build a reverse map: `(source_index, line) → Vec<usize>` (PCs on that line).

### 12.2 Forcing Coverage

To generate an input that exercises source line L:

```python
# Find all PCs that map to line L
target_pcs = line_to_pcs[(source_index, L)]

# During symbolic execution, each PC accumulates a path condition.
# The path condition at PC p is the conjunction of all AssertCondition
# and AssertNotUndefined constraints on the path from entry to p.

# To cover line L, at least one of its PCs must be reachable:
coverage_constraint = Or(*(path_condition_at[pc] for pc in target_pcs))

solver.add(coverage_constraint)
```

### 12.3 Multi-Line Coverage

For covering multiple lines simultaneously:

```python
for line in target_lines:
    target_pcs = line_to_pcs[(source_index, line)]
    solver.add(Or(*(path_condition_at[pc] for pc in target_pcs)))
```

If UNSAT, the lines cannot all be covered simultaneously — try subsets or report infeasible.

---

## 13. Query Modes

### 13.1 Input Generation (R1)

```python
# Given: policy P, data D, desired output O
# Find: input I such that P(I, D) = O

constraints = translate_program(P, symbolic_input, concrete_data=D)
solver.add(constraints)
solver.add(result_register == encode(O))

if solver.check() == SAT:
    model = solver.model()
    input_json = extract_json(model, path_registry)
    return input_json
else:
    return "No input can produce this output"
```

### 13.2 Policy Diff (R3)

```python
# Given: policies P1, P2 with same data D
# Find: input I where P1(I, D) ≠ P2(I, D)

constraints_1 = translate_program(P1, symbolic_input, concrete_data=D)
constraints_2 = translate_program(P2, symbolic_input, concrete_data=D)

solver.add(constraints_1)
solver.add(constraints_2)
solver.add(result_1 != result_2)  # They must disagree

if solver.check() == SAT:
    model = solver.model()
    input_json = extract_json(model, path_registry)
    result_1_val = model.eval(result_1)
    result_2_val = model.eval(result_2)
    return DiffWitness(input_json, result_1_val, result_2_val)
else:
    return "Policies are equivalent (up to analysis bound)"
```

### 13.3 Satisfiability / Vacuity Check (R4)

```python
# Is there any input that makes rule R true?

constraints = translate_program(P, symbolic_input, concrete_data=D)
solver.add(constraints)
solver.add(rule_result == True)

if solver.check() == SAT:
    return "Rule is satisfiable", extract_json(solver.model(), path_registry)
else:
    return "Rule is vacuously false — no input can satisfy it"
```

### 13.4 "Why Denied?" (R5)

Using **MAX-SAT** to find the minimal set of failing conditions:

```python
# The request was denied. Which conditions failed?

# Collect all AssertCondition constraints with their source spans
assertions = [(pc, span, constraint) for each AssertCondition/AssertNotUndefined]

# Add the concrete input as constraints
for path, value in concrete_input.items():
    solver.add(path_var == value)

# Make each assertion a soft constraint
for pc, span, constraint in assertions:
    solver.add_soft(constraint, weight=1, group=f"assert_{pc}")

# The result must be the denied value
solver.add(result == denied_value)

# Solve with MAX-SAT
if solver.check() == SAT:
    # Assertions NOT in the MAX-SAT solution are the ones that failed
    failed = [a for a in assertions if not solver.model().eval(a.constraint)]
    # Map back to source lines via SpanInfo
    return [(span.source_index, span.line, span.column) for _, span, _ in failed]
```

### 13.5 Schema-Constrained Analysis (R6)

Given a JSON Schema for `input`, we add type constraints to path variables:

```python
def apply_schema(schema, prefix="input"):
    match schema.type:
        "object":
            for prop_name, prop_schema in schema.properties.items():
                path = f"{prefix}.{prop_name}"
                apply_schema(prop_schema, path)
            if schema.required:
                for prop_name in schema.required:
                    solver.add(path_defined(f"{prefix}.{prop_name}"))
        "string":
            solver.add(path_type(prefix) == STRING_TAG)
            if schema.enum:
                solver.add(Or(*(path_value(prefix) == e for e in schema.enum)))
            if schema.pattern:
                solver.add(z3.InRe(path_value(prefix), parse_regex(schema.pattern)))
        "integer":
            solver.add(path_type(prefix) == INT_TAG)
            if schema.minimum is not None:
                solver.add(path_value(prefix) >= schema.minimum)
            if schema.maximum is not None:
                solver.add(path_value(prefix) <= schema.maximum)
        "boolean":
            solver.add(path_type(prefix) == BOOL_TAG)
        "array":
            solver.add(path_type(prefix) == ARRAY_TAG)
            # Bounded element constraints if items schema provided
```

---

## 14. Execution Flow

### 14.1 Top-Level Pipeline

```
1. Load compiled Program (bytecode + literals + instruction_data + rule_infos + instruction_spans)
2. Build line → PC mapping from instruction_spans
3. Run Path Extractor → PathRegistry
4. Create Z3 Context and Solver
5. Initialize symbolic register file (size = program.max_rule_window_size)
6. Initialize symbolic input root (connected to PathRegistry)
7. Load concrete data (if provided)
8. For the target entry point (from program.entry_points):
   a. Symbolically translate instruction stream starting at entry PC
   b. Handle CallRule by inlining rule bodies (with caching)
   c. Handle loops by unrolling (bounded)
   d. Collect constraints
9. Add query-specific constraints (desired output, coverage target, etc.)
10. solver.check()
11. If SAT: extract model → JSON
12. Return result
```

### 14.2 Symbolic Execution Strategy

We use **single-path symbolic execution with path merging at joins**. Unlike a concrete
executor that backtracks on failure, we encode all paths symbolically and let Z3 handle
the search.

For `AssertCondition` failures, rather than aborting the path, we gate all subsequent
constraints by the path condition at that point. This means a single symbolic execution
pass covers all feasible paths.

```python
# Before an AssertCondition at PC p:
path_cond_before = current_path_condition

# After:
passed = assertion_expression
current_path_condition = And(path_cond_before, passed)

# All constraints after this point are gated:
# constraint_at_pc_q = Implies(current_path_condition, actual_constraint)
```

### 14.3 Handling Multiple Entry Points

RVM has `program.entry_points: IndexMap<String, usize>`. For whole-program analysis,
we translate the `main_entry_point`. For rule-specific analysis, we translate only the
relevant entry point.

---

## 15. Implementation Plan

### Phase 1: Foundation (Weeks 1-3)

**Goal:** Translate straight-line RVM code (no loops, no rule calls) into Z3.

- [ ] Z3 Rust bindings setup (use `z3` crate)
- [ ] `PathRegistry` implementation
- [ ] `SymbolicState` (register file + path condition)
- [ ] Path extractor (static analysis pass)
- [ ] Load instructions (`Load`, `LoadTrue`, `LoadFalse`, `LoadNull`, `LoadBool`,
      `LoadData`, `LoadInput`, `Move`)
- [ ] Arithmetic instructions (`Add`, `Sub`, `Mul`, `Div`, `Mod`)
- [ ] Comparison instructions (`Eq`, `Ne`, `Lt`, `Le`, `Gt`, `Ge`)
- [ ] Logical instructions (`And`, `Or`, `Not`)
- [ ] Assert instructions (`AssertCondition`, `AssertNotUndefined`)
- [ ] Index instructions (`Index`, `IndexLiteral`, `ChainedIndex`)
- [ ] Model-to-JSON extraction
- [ ] **Test:** Simple policies (allow if input.user == "admin")

### Phase 2: Collections + Builtins (Weeks 4-5)

- [ ] Collection creation (`ArrayNew`, `ArrayPush`, `ArrayCreate`, `SetNew`, `SetAdd`,
      `SetCreate`, `ObjectSet`, `ObjectCreate`)
- [ ] `Contains`, `Count`
- [ ] Tier 1 builtins (count, contains, startswith, endswith, concat, abs, etc.)
- [ ] Tier 2/3 builtin fallback (uninterpreted functions)
- [ ] **Test:** Policies with collection membership checks

### Phase 3: Loops + Comprehensions (Weeks 6-7)

- [ ] `LoopStart` / `LoopNext` translation with bounded unrolling
- [ ] `LoopMode::Any` / `Every` / `ForEach` semantics
- [ ] `ComprehensionBegin` / `ComprehensionYield` / `ComprehensionEnd`
- [ ] Concrete-collection optimization (exact unrolling)
- [ ] **Test:** Policies with `some x in collection; condition(x)`

### Phase 4: Rules + Virtual Documents (Weeks 8-9)

- [ ] `CallRule` translation (register window save/restore)
- [ ] `FunctionCall` translation
- [ ] `RuleInit` / `RuleReturn` / `DestructuringSuccess`
- [ ] Rule caching (symbolic)
- [ ] `VirtualDataDocumentLookup` translation
- [ ] Multiple definitions + else-branch semantics
- [ ] `PartialSet` / `PartialObject` / `Complete` rule types
- [ ] Default values
- [ ] **Test:** Multi-rule policies with rule dependencies

### Phase 5: Query Modes (Weeks 10-11)

- [ ] Input generation (R1)
- [ ] Coverage targeting (R2) using SpanInfo
- [ ] Policy diff (R3)
- [ ] Satisfiability check (R4)
- [ ] "Why denied?" via MAX-SAT (R5)
- [ ] Schema constraints (R6)
- [ ] **Test:** End-to-end on real-world policies

### Phase 6: Optimization + Polish (Week 12+)

- [ ] Constraint simplification
- [ ] Path condition pruning (early UNSAT detection)
- [ ] Incremental solving for batched queries
- [ ] Timeout handling and partial results
- [ ] CLI / API surface
- [ ] Documentation

---

## 16. Key Data Structures Reference

### 16.1 Program (from `src/rvm/program/core.rs`)

```rust
pub struct Program {
    pub instructions: Vec<Instruction>,        // max 65535
    pub literals: Vec<Value>,                  // max 65535
    pub instruction_data: InstructionData,     // 9 param tables
    pub builtin_info_table: Vec<BuiltinInfo>,  // { name, num_args }
    pub entry_points: IndexMap<String, usize>, // name → PC
    pub sources: Vec<SourceFile>,              // source files
    pub rule_infos: Vec<RuleInfo>,             // max 4000
    pub instruction_spans: Vec<SpanInfo>,      // 1:1 with instructions
    pub main_entry_point: usize,
    pub max_rule_window_size: usize,
    pub dispatch_window_size: usize,
    pub rule_tree: Value,                      // data namespace tree
    pub resolved_builtins: Vec<...>,
    // ...
}
```

### 16.2 RuleInfo (from `src/rvm/program/types.rs`)

```rust
pub struct RuleInfo {
    pub name: String,
    pub rule_type: RuleType,                         // Complete | PartialSet | PartialObject
    pub definitions: Rc<Vec<Vec<u32>>>,              // definitions → body entry PCs
    pub function_info: Option<FunctionInfo>,          // param_names, num_params
    pub default_literal_index: Option<u16>,
    pub result_reg: u8,
    pub num_registers: u8,
    pub destructuring_blocks: Vec<Option<u32>>,       // per-definition
}
```

### 16.3 InstructionData (from `src/rvm/instructions/params.rs`)

```rust
pub struct InstructionData {
    pub loop_params: Vec<LoopStartParams>,
    pub builtin_call_params: Vec<BuiltinCallParams>,
    pub function_call_params: Vec<FunctionCallParams>,
    pub object_create_params: Vec<ObjectCreateParams>,
    pub array_create_params: Vec<ArrayCreateParams>,
    pub set_create_params: Vec<SetCreateParams>,
    pub virtual_data_document_lookup_params: Vec<VirtualDataDocumentLookupParams>,
    pub chained_index_params: Vec<ChainedIndexParams>,
    pub comprehension_begin_params: Vec<ComprehensionBeginParams>,
}
```

### 16.4 SpanInfo

```rust
pub struct SpanInfo {
    pub source_index: u16,  // index into program.sources
    pub line: u32,
    pub column: u32,
    pub length: u32,
}
```

---

## 17. Comparison with Cedar / AWS Verified Permissions

| Capability | Cedar/AVP | RVM-to-Z3 |
|------------|-----------|-----------|
| Policy validation | ✅ | ✅ |
| Authorization simulation | ✅ | ✅ (via input generation) |
| Reachability analysis | ✅ (can any request reach Allow?) | ✅ (satisfiability check) |
| Policy diff | ❌ (not in AVP) | ✅ |
| Input generation | ❌ | ✅ |
| Line coverage targeting | ❌ | ✅ |
| "Why denied?" | Limited (via simulation) | ✅ (MAX-SAT) |
| Schema-constrained analysis | ✅ (entity schema) | ✅ (JSON Schema) |
| Loops | N/A (Cedar has no loops) | ✅ (bounded) |
| User-defined functions | N/A (Cedar has no functions) | ✅ (inlined) |
| Partial rules | N/A | ✅ |
| Dead rule detection | ❌ | ✅ (UNSAT path condition) |
| Redundancy detection | ❌ | ✅ (subset analysis) |
| Counterexample generation | Limited | ✅ (full model extraction) |

Cedar works on a restricted language (PARC model, no loops, no user-defined functions),
which makes its analysis decidable. RVM-to-Z3 works on the full Rego language (via bytecode),
which is more expressive but analysis is bounded (loops unrolled to a depth limit).

---

## 18. Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| **Z3 timeout on complex policies** | No result | Timeout budget + incremental simplification; report partial results |
| **Unbounded loops** | Incomplete analysis | Bounded unrolling with clear reporting of the bound used |
| **Dynamic object keys** | Loss of precision | Fall back to tagged scalar encoding; report reduced precision |
| **Complex builtins (regex, crypto)** | Uninterpreted functions reduce analysis power | Tier system with clear reporting; most security-relevant builtins (string matching) are modeled |
| **Large literal tables** | Memory pressure in Z3 | Lazy variable creation; only instantiate path variables that are actually used |
| **Recursive rules** | Infinite inlining | Bounded depth with configurable limit; detect and report recursion |
| **HostAwait** | External I/O cannot be modeled | Model as uninterpreted function returning symbolic value |
| **Path-based encoding misses aliasing** | When same object is accessed via different paths | Alias analysis pass; add equality constraints for known aliases |

---

## 19. Open Questions

1. **Should we support incremental analysis?** (Add/remove one rule and re-analyze without
   re-translating everything.) Would require Z3 incremental mode with push/pop.

2. **How to handle `with` keyword?** (Rego's value override mechanism.) The compiler may
   already lower this, but we need to verify.

3. **How deep should default loop unrolling be?** Trade-off between coverage and solver
   time. Configurable, but what's a good default? Start with 5.

4. **Should we support partial evaluation?** (Given concrete `data` but symbolic `input`,
   partially evaluate rules that depend only on `data` and fold them.) This is an
   optimization, not a requirement.

5. **External data sources.** Policies that call `http.send` or `opa.runtime` depend on
   external state. Model as unconstrained symbolic values.

---

## 20. Glossary

| Term | Definition |
|------|-----------|
| **RVM** | Rego Virtual Machine — the register-based bytecode VM in regorus |
| **PC** | Program Counter — index into `program.instructions` |
| **Path Variable** | A Z3 variable named by its access path (e.g., `input.user.role`) |
| **Path Condition** | Conjunction of all branch constraints leading to a program point |
| **Bounded Unrolling** | Expanding a loop a fixed number of times for symbolic analysis |
| **MAX-SAT** | Maximum Satisfiability — find the largest satisfiable subset of soft constraints |
| **Tagged Scalar** | Z3 algebraic datatype with tag discriminant for Value type |
| **SpanInfo** | Source location metadata attached to each instruction |
| **Rule Tree** | Hierarchical structure mapping data namespace paths to rule indices |
| **Register Window** | Per-rule register allocation; saved/restored on rule calls |
