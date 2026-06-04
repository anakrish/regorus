# Number Semantics Test Plan

## Goals
- Lock down behavior of `Number` conversions (BigInt/Int/UInt/Float) across edge ranges (2^63, 2^64, 2^53) so refactors cannot regress silently.
- Ensure interpreter and VM stay bit-for-bit aligned on arithmetic, modulo, and bitwise operations, including large integer cases.
- Cover no-std-specific code paths (`FloatCore`, `thumbv7m-none-eabi`) so CI fails if floor/ceil/round regress.
- Capture serialization/formatting expectations for extreme values (scientific notation, lossy f64 fallback, ±Infinity, NaN).

## Existing Coverage Snapshot
- `tests/interpreter/cases/builtins/numbers/*.yaml` exercises basic operations on small ints/floats only.
- `tests/rvm/vm/suites/arithmetic_operations.yaml` and `interpreter_operator_compatibility.yaml` pin a few float rounding cases but not BigInts.
- `tests/value/mod.rs` checks serialization formatting for simple numbers.
- No tests currently target `Number::from_bigint_owned`, `float_to_small_bigint`, modulo with negative divisors, or bitwise ops beyond 64-bit.
- No test suite runs against the no-std build artifacts.

## Proposed Test Additions

### 1. Rust Unit Tests for `Number`
File: `src/number/tests.rs` (new, gated with `#[cfg(test)]`).
Scenarios:
1. **Conversion Boundaries**
   - `from_bigint_owned` returns `Int` for values in `[-2^63, 2^63-1]`, `UInt` for `[0, 2^64-1]`, `BigInt` otherwise.
   - `float_to_small_bigint` succeeds for `2^53` but fails for `2^53+1`.
   - `to_f64_lossy` returns ±∞ for values exceeding `F64_SAFE_INTEGER`.
2. **Arithmetic Promotion**
   - `add/sub/mul/div` covering UInt+Int → BigInt, Int overflow → BigInt, BigInt±Float → Float normalization.
   - `divide` returns exact integer when divisible and float otherwise.
3. **Modulo Semantics**
   - `(-5) % 2 == -1`, `5 % -2 == 1`, `(-5) % -2 == -1` to match Rego semantics.
4. **Bitwise/Shift**
   - Operations on >64-bit operands to ensure `ensure_integer` path works.
5. **Formatter/Serializer**
   - `format_decimal`, `format_scientific`, `format_decimal_with_width` on very large ints and floats.

### 2. Interpreter YAML Suites
Folder: `tests/interpreter/cases/builtins/numbers/`
Add/extend YAML cases for:
1. **Large Integer Literals**: expressions using numbers beyond 64-bit (parsed via string concatenation or `pow10`).
2. **Mixed Sign Arithmetic**: ensure modulo/division with negative operands matches expected result maps.
3. **Normalization**: `round/ceil/floor` on floats that should collapse to ints.
4. **Bitwise**: new YAML under `builtins/bitwise/` referencing >64-bit values via `to_number("1e40")` conversions.

### 3. VM Regression Suites
Files: `tests/rvm/vm/suites/*.yaml`
Add suites mirroring new interpreter cases to confirm bytecode parity:
1. **BigInt Arithmetic**: addition, subtraction, multiplication, division with results requiring `BigInt`.
2. **Modulo Matrix**: table-driven tests for positive/negative combinations.
3. **Bitwise / Shift**: operate on integers wider than 64 bits and assert results.
4. **Float Normalization**: operations producing `0.30000000000000004`-style outputs to pin rounding.

### 4. Parser & Literal Handling
Files: `tests/parser/cases/expressions/arithmetic.yaml`, new `tests/parser/cases/numbers/*`.
Tests:
- Numeric literal with underscores (`1_000_000_000_000_000_001`) parsed as BigInt.
- Scientific notation that should downcast to BigInt (`1e5`) vs stay float (`1e-2`).
- Invalid combinations (multiple dots, `+._1`) confirm `ParseNumberError`.

### 5. No-Std / Embedded Smoke Tests
Script:
- Extend `scripts/pre-push` or CI workflow to run `cargo test -p regorus --features opa-no-std --target thumbv7m-none-eabi` for the new `number` unit tests (mark them `#[cfg(all(test, not(feature = "std")))]` friendly).
Runtime tests:
- Add minimal integration test under `tests/ensure_no_std/` invoking `floor/ceil/round` to prove `FloatCore` imports resolve.

### 6. Property / Fuzz Hooks (Optional Stretch)
- Use `proptest` to randomly generate integers/floats and compare interpreter outputs with native Rust arithmetic for addition/multiplication modulo BigInt limits.
- Guard behind `cfg(feature = "fuzz" )` so it can run in nightly CI or local stress jobs.

### 7. Equivalence & Cross-Operation Tests
File: extend `src/number/tests.rs` or new `tests/number_equivalence.rs`
1. **Symmetry/Commutative**: `a + b == b + a`, `a * b == b * a` for random int/float/BigInt pairs.
2. **Inverse Operations**: `(a / b) * b ≈ a` (within epsilon for floats), `(a - b) + b == a` for ints.
3. **Serialization Roundtrip**: `Number::from_str(&n.format_decimal()) == n` for a sample of numbers.
4. **Format Consistency**: `format_scientific` → parse → `format_scientific` is stable; same for `format_bin`, `format_hex`, etc.
5. **Type Stability**: operations on small ints stay as Int/UInt until overflow forces BigInt promotion.

### 8. Error/Boundary Handling Tests
Files: `src/number/tests.rs`, interpreter YAML, VM YAML
1. **Division/Modulo by Zero**: ensure `divide(0)` and `modulo(0)` return errors, not panics.
2. **Fractional Modulo**: `(3.5 % 2)` should error per Rego semantics.
3. **Infinity/NaN Propagation**: arithmetic with `f64::INFINITY` or `NaN` → `Float(inf/NaN)`.
4. **Bitwise on Floats**: `and/or/xor/lsh/rsh` return `None` when operands aren't integers.
5. **ParseNumberError Cases**: `".."`, `"e"`, `"1e"`, `"++1"`, `"1_"`, empty strings all return `Err`.
6. **Overflow in `pow10`/`pow2`**: test `Number::two_pow(10000)` doesn't panic, allocates BigInt cleanly.

### 9. Integration with Builtins
Files: extend `tests/interpreter/cases/builtins/units/*.yaml`, `tests/interpreter/cases/builtins/numbers/*.yaml`
1. **units.parse / units.parse_bytes**: test suffixes producing very large BigInts (e.g., `"1P"`, `"1E"`), ensure they round-trip through serialization.
2. **numbers.range**: edge cases like `range(2^63, 2^63+10)` → BigInt iteration.
3. **Aggregate Functions**: `sum`/`product` over arrays containing mixed Int/BigInt/Float ensure promotion works.
4. **sprintf with Format Specifiers**: `%e`, `%g`, `%d` on BigInt/Float edge values.

### 10. Concurrency & Aliasing (Rc Safety)
File: `src/number/tests.rs`
1. **Rc Cloning**: ensure `Number::BigInt(Rc<BigInt>)` clones don't mutate shared state (Rust's `Rc` is immutable by default, but verify no `unsafe` escape hatches exist).
2. **Thread Send/Sync**: if `Number` is marked `Send`, add test spawning threads that share `Rc<BigInt>` values and assert no data races (note: `Rc` is !Send, so likely not applicable unless wrapped differently).

## Execution & Ownership
- **Unit tests**: `src/number/tests.rs` owned by core language team.
- **Interpreter YAML**: policy semantics team to add cases, validated via `cargo test -p regorus tests::interpreter`.
- **VM suites**: VM team ensures parity tests run with `cargo test -p regorus tests::rvm`.
- **No-std**: Build/test integrated into release CI, failure blocks merges touching numeric code.
- **Maintenance**: any future numeric change requires updating this plan and adding targeted cases before merging.

## Acceptance Criteria
- New tests reproducibly fail on current main if we reintroduce prior rounding/modulo bugs.
- CI matrix shows coverage for std + no-std builds.
- Reviewer checklist references this document when verifying numeric changes.
