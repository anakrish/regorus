# Deep Review Report — PR 718

> Note: the environment forbids `/tmp` writes, so this report is stored at `.copilot-pr718/deep-review-report.md` instead of `/tmp/deep-review-report.md`.

## Findings

### 1) High — Multi-level partial-object rules lose the outer key in RVM
- **Severity:** High
- **Confidence:** High
- **Source:** Agent B
- **Location:** `src/languages/rego/compiler/rules.rs:353-356`
- **Issue:** `p[a][b] if { ... }` is now classified as `PartialObject`, but compilation keeps only the innermost bracket key, so nested objects flatten and exact nested lookups fail.
- **Evidence:**
```rust
let key_expr = match refr.as_ref() {
    Expr::RefBrack { index, .. } => Some(index.clone()),
    _ => None,
};
```
  `queries.rs:190-198` then emits a single `ObjectSet`, so `a` is never materialized.
- **Trace:** `p[a][b] if { some a, obj in input.nested; some b, _ in obj }`, query `data.test.p.app.read` → expected `true`; actual outer key is dropped, so `.app` is undefined.
- **Verification:** **CONFIRMED** — verifier found no guard; only the last `index` is preserved.
- **Suggestion:** Preserve the full bracket chain and emit nested object construction, or keep multi-level keyed rules on the virtual-document path until supported.

### 2) Medium — Constant-key partial-object parity is still disabled in RVM
- **Severity:** Medium
- **Confidence:** High
- **Source:** Agent C
- **Location:** `tests/rvm/rego/cases/partial_object_rules.yaml:45-59`
- **Issue:** The PR changes compiler/RVM behavior for `p["fixed"] if`, but the only RVM regression for that shape is still skipped.
- **Evidence:**
```yaml
- note: partial_object_constant_key_still_works
  skip: true  # Existing constant-key rule path handling is tracked separately.
```
- **Trace:** N/A (test-gap finding).
- **Verification:** **CONFIRMED** — the case remains skipped.
- **Suggestion:** Implement/fix constant-key RVM handling and unskip this case before merging.

### 3) Medium — Multi-level partial-object parity is still disabled in RVM
- **Severity:** Medium
- **Confidence:** High
- **Source:** Agent C
- **Location:** `tests/rvm/rego/cases/partial_object_rules.yaml:105-129`
- **Issue:** The PR changes multi-level bracket classification, but the only end-to-end RVM regression for `p[a][b] if` is still skipped.
- **Evidence:**
```yaml
- note: partial_object_multilevel_key_collects_nested_bindings
  skip: true  # Existing multi-level bracket rule path handling is tracked separately.
```
- **Trace:** N/A (test-gap finding).
- **Verification:** **CONFIRMED** — no active RVM parity case exists for this path.
- **Suggestion:** Add the missing RVM support and unskip this case before merging.

### 4) Medium — RVM partial-object rules now admit undefined keys
- **Severity:** Medium
- **Confidence:** High
- **Source:** Adversarial
- **Location:** `src/languages/rego/compiler/queries.rs:190-198`, `src/rvm/vm/dispatch.rs:449-458`
- **Issue:** Reclassifying `p[k] if` into the RVM partial-object path exposes `ObjectSet` for keyed rules, but that path inserts keys unconditionally instead of dropping `Undefined` results like the interpreter does.
- **Evidence:**
```rust
Instruction::ObjectSet { obj: dest_register, key: key_register, value: value_register }
...
obj_mut.insert(key_value, value_value);
```
  By contrast, `src/interpreter.rs:1860` guards on `key != Value::Undefined && value != Value::Undefined`.
- **Trace:** `p[input.missing] if { true }`, input `{}`, query `data.test.p` → expected `{}`; actual RVM path attempts to insert an undefined key.
- **Verification:** **CONFIRMED** — verifier found no undefined guard on the emitted `ObjectSet` path.
- **Suggestion:** Skip `ObjectSet` when key or value is `Undefined`, or emit that guard during compilation.

### 5) Medium — RVM partial-object writes still overwrite conflicting duplicate keys
- **Severity:** Medium
- **Confidence:** High
- **Source:** Adversarial
- **Location:** `src/rvm/vm/rules.rs:127-135`, `src/rvm/vm/dispatch.rs:456-458`
- **Issue:** The RVM only checks rule-result inconsistency for `Complete` rules; once `p[k] if` routes through partial-object writes, conflicting duplicate keys silently overwrite instead of raising inconsistency like the interpreter.
- **Evidence:**
```rust
if matches!(rule_info.rule_type, RuleType::Complete) || is_function_call {
    ...
}
...
obj_mut.insert(key_value, value_value);
```
- **Trace:** `p["x"] := 1 if { true }` and `p["x"] := 2 if { true }` → expected inconsistency error; actual RVM keeps the later value.
- **Verification:** **CONFIRMED** — interpreter rejects divergent duplicate-object values at `src/interpreter.rs:1862-1877`; RVM does not.
- **Suggestion:** Detect occupied partial-object keys and raise inconsistency when a new value differs.

### 6) Low — Constant-key exact-path lookups remain untested
- **Severity:** Low
- **Confidence:** High
- **Source:** Test micro-pass
- **Location:** `tests/interpreter/cases/rule/partial_object_v1.yaml:17`, `tests/rvm/rego/cases/partial_object_rules.yaml:57`
- **Issue:** New constant-key tests only assert `data.test` / `data.test.p`; they do not assert `data.test.p.fixed` or `data.test.p["fixed"]`.
- **Evidence:** Current new tests stop at object materialization and never query the leaf path.
- **Trace:** N/A.
- **Verification:** **CONFIRMED** — repo search found no active exact-path assertion for this shape.
- **Suggestion:** Add interpreter and RVM cases that query the exact leaf path and assert scalar `true`.

### 7) Low — Active RVM coverage for constant-key partial objects is missing
- **Severity:** Low
- **Confidence:** High
- **Source:** Test micro-pass
- **Location:** `tests/rvm/rego/cases/partial_object_rules.yaml:45`
- **Issue:** The only compiler-backed RVM case for `p["fixed"]` is skipped, so the changed compiler path is not exercised end-to-end.
- **Evidence:** Same skipped case as finding 2; generic VM partial-object suites do not cover compiler lowering for this rule head.
- **Trace:** N/A.
- **Verification:** **CONFIRMED**.
- **Suggestion:** Keep a non-skipped compiler-backed RVM regression for `p["fixed"]`.

### 8) Low — No active compiler-backed RVM regression covers `p[a][b]`
- **Severity:** Low
- **Confidence:** High (likely)
- **Source:** Test micro-pass
- **Location:** `tests/rvm/vm/suites/call_rule.yaml:27`, `tests/rvm/vm/suites/else_rules.yaml:113`, `src/languages/rego/compiler/rules.rs:353`
- **Issue:** Existing VM `PartialObject` tests exercise hand-authored bytecode behavior, not compiler lowering from multi-level bracket rule heads, so they would not catch the flattening bug above.
- **Evidence:** The generic VM suites validate `PartialObject` mechanics only; the dedicated compiler-backed `p[a][b]` case remains skipped.
- **Trace:** N/A.
- **Verification:** **LIKELY** — verifier found no active end-to-end RVM regression for this path.
- **Suggestion:** Add/enable a compiler-backed RVM case asserting nested `app/read`, `app/write`, and `ops/deploy` lookups.

### 9) Low — Multi-level RVM parity remains disabled
- **Severity:** Low
- **Confidence:** High
- **Source:** Test micro-pass
- **Location:** `tests/rvm/rego/cases/partial_object_rules.yaml:105`
- **Issue:** The only direct RVM parity case for multi-level keyed partial objects is skipped.
- **Evidence:** Same skipped case as finding 3.
- **Trace:** N/A.
- **Verification:** **CONFIRMED**.
- **Suggestion:** Unskip once fixed; until then, keep a tracked failing regression rather than leaving the path unexercised.

## Test Gaps (confirmed findings only)
- **#1:** No active RVM end-to-end test catches this; the only `p[a][b]` case is skipped.
- **#2:** No existing RVM test catches this because the constant-key parity case is skipped.
- **#3:** No existing RVM test catches this because the multilevel parity case is skipped.
- **#4:** No test asserts that `p[input.missing] if { true }` leaves the object empty on the RVM path.
- **#5:** No test asserts conflicting duplicate keys fail for RVM partial objects.
- **#6:** By definition, no exact-path test exists today.
- **#7:** By definition, no active compiler-backed RVM constant-key case exists today.
- **#9:** By definition, no active multi-level RVM parity case exists today.

## Agent Performance
- **Agent A (broad, gpt-5.4):** found 0; covered items `[1-12]`.
- **Agent B (tracer, opus-4.6):** found 2; covered items `[1-12]`.
- **Agent C (safety/API, default):** found 2; covered items `[1-12]`.
- **Micro-passes launched:** 2 (`type-conversion`, `test-adequacy`) — found 4 low-severity test gaps; type-conversion found none.
- **Adversarial verifier:** confirmed 6, likely 1, dropped 1, found 2 new.

## Summary
9 findings (0 critical, 1 high, 4 medium, 4 low). 1 likely finding. 1 dropped finding: exact-path constant-key leaf access appears to work because the compiler emits `CallRule(data.test.p)` followed by indexed access into the returned object.

**Risk assessment:** High risk to merge as-is: the PR fixes one partial-object collection bug, but it still leaves a confirmed RVM correctness bug for multi-level keyed rules and exposes untested/incorrect partial-object semantics for undefined and conflicting keys.
