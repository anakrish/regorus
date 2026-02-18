# Azure Policy Compiler — Future Work

Infrastructure and design topics to address during implementation phases.
These were identified during the design completeness audit but deferred because
they don't affect instruction design or compilation strategy.

---

## 1. Backward Compatibility / Versioning

Azure Policy evolves — new operators, effects, template functions, or condition
types may appear in policy JSON over time. The compiler needs a strategy for
handling unrecognized features:

- **Error behavior**: Hard-error on unknown operators? Warn and skip? Emit a
  host-callback fallback?
- **Bytecode versioning**: Should compiled programs carry a version tag
  indicating the policy language level they were compiled against?
- **Forward compatibility**: Can older RVM versions safely reject or ignore
  programs compiled with newer features? The existing serialization format
  (version 3, `REGO` magic) may need an extension or feature-flag field.
- **Feature detection**: Should the compiler report which features a policy
  uses, so the host can decide whether its RVM version supports them before
  attempting evaluation?

## 2. Alias Table Distribution Format

The compiler requires an alias table mapping Azure Policy alias short names
(e.g., `supportsHttpsTrafficOnly`) to ARM resource paths. This relates to
open question Q4 from [alias-normalization.md](alias-normalization.md) §13.

Key decisions:

- **Format**: JSON, binary (e.g., bincode/MessagePack), or compiled into Rust
  code via `build.rs`?
- **Bundling**: Embedded in the library binary? Shipped as a separate artifact?
  Loaded at runtime from a file or network endpoint?
- **Update cadence**: How often does the table change? Is it tied to Azure SDK
  releases, ARM API versions, or an independent schedule?
- **Per-resource-type tables**: The alias namespace is scoped by resource type.
  Should tables be monolithic or split by provider/resource type for efficiency?
- **Size budget**: How large can the table be without impacting startup time
  or binary size?

## 3. Performance Targets

No concrete benchmarks or latency/throughput goals are defined yet. Targets to
establish during implementation:

- **Compilation latency**: How fast should a single policy compile? (Likely
  sub-millisecond for typical policies.)
- **Evaluation latency**: What's the acceptable per-resource evaluation time?
  (Target: microsecond range for simple policies.)
- **Memory footprint**: How much memory can a compiled program consume? What
  about the alias table?
- **Throughput**: If evaluating millions of resources against hundreds of
  policies (initiative scenario), what aggregate throughput is needed?
- **Comparison baseline**: How does compiled-policy evaluation compare to the
  existing Rego-based engine on equivalent policies?

Benchmarks should be added to `benches/` alongside existing regorus benchmarks.

## 4. Policy Validation Details

The architecture diagram in compiler.md §2.1 has a "Validate" box in the
pipeline, but the design doesn't specify what validation checks beyond basic
JSON structure parsing.

Questions to resolve:

- **Semantic validation**: Should the compiler verify that `count.where` field
  references share the count's array prefix? That `current()` is only used
  inside a count scope? That template expressions reference valid function
  names?
- **Iteration limit enforcement**: Are the limits from §6.5.10 (5 field counts
  per array, 10 value counts per rule, 100 value-count iterations) checked at
  validation time, compile time, or runtime?
- **Phase boundary**: What's the dividing line between parse-time errors
  (structural JSON issues), validation-time errors (semantic issues), and
  compile-time errors (instruction generation failures)?
- **Reporting**: Should validation produce a list of all errors (like a linter)
  or fail-fast on the first issue? Machine-generated policy JSON should be
  correct, but tooling may benefit from multi-error reporting.
- **Unknown fields**: Should the validator warn about unrecognized JSON keys
  in the policy rule? This ties into backward compatibility (§1).
