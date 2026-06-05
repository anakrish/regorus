# Type Analysis Output Audit

_Date: 2025-10-30_

## Captured Artefacts

The current `TypeAnalyzer` (`src/type_analysis/propagation`) materialises the following datasets:

- **ExpressionFacts** (`TypeAnalysisResult::expressions`)
  - `LookupContext` (`facts`): per-expression `TypeFact` entries, rule reachability set, dynamic reference catalog, and tracked rule references.
  - `ConstantStore` (`constants`): optional literal values for expressions with known compile-time results.
- **RuleTable** (`TypeAnalysisResult::rules`)
  - Per-module `ModuleSummary` lists rule paths, source spans, arity and definition metadata.
  - Each `DefinitionSummary` includes `RuleAnalysis` clones (input deps, rule deps, constant evaluation state) plus aggregated head/parameter facts and specialization traces.
  - `RuleBodySummary` instances identify body-level value expressions, inferred facts, and constant-body detection.
- **DependencyGraph**: placeholder structure (currently empty) reserved for future inter-rule dependency modelling.
- **EntrypointSummary**: records requested entrypoints, reachable rules, defaults included via entrypoint filtering, and dynamic lookup patterns (static prefix + glob).
- **Diagnostics**: full list of `TypeDiagnostic` records emitted during analysis, with provenance and spans.

Within the pipeline we also observed internal state that could be surfaced with minimal effort:

- Loop hoisting tables (`HoistedLoopsLookup`) already cloned into the analyzer when available.
- Binding/destructuring plans retrieved from the hoister and executed via `apply_binding_plan`.
- Constant-evaluation engine seeded through `TypeAnalyzer::from_engine`, enabling rule constant folding and specialization traces.

## Identified Gaps for Compiler Consumption

To drive the RVM compiler exclusively from analyzer output we still need to expose additional metadata:

1. **Virtual Document Lookups**
   - No dedicated structure describes the slot IDs, schema associations, or initialization order for virtual documents. The analyzer should emit a table keyed by expression index with the resolved virtual document handle information.
2. **Literal Table Sketch**
   - While constants are stored per expression, there is no consolidated literal pool description (deduplicated values with deterministic ordering) for direct reuse in bytecode generation.
3. **Binding Plan Accessors**
   - Binding plans are applied internally but not exposed. We should surface a read-only map of `(module_idx, expr_idx) → BindingPlan` so the compiler can reuse destructuring outcomes without mirroring logic.
4. **Rule/Entry Metadata for Emission**
   - The compiler requires a fast lookup of entrypoint PC ordering and rule indices. The analyzer currently records reachability, but lacks a normalized structure that mirrors the VM rule table (e.g., stable rule IDs, ordering hints).
5. **Expression Descriptor Convenience API**
   - Accessing `TypeFact` currently requires module + expression indices via `LookupContext`. A thin accessor (e.g., `TypeAnalysisView`) that normalises module/rule/query indexing would simplify compiler integration.
6. **Scheduler Snapshot**
   - `TypeAnalyzer::from_engine` keeps the `Schedule` clone, but `TypeAnalysisResult` does not expose it. The compiler still needs scheduling data for loop ordering, so the result should optionally carry the `Schedule` (or an immutable view).

## Next Steps

- Design the public accessor surface (RFC) that exposes the data above without coupling the compiler to the analyzer internals.
- Extend the analyzer pipeline to record virtual document metadata and literal pool sketches.
- Add unit tests in `src/type_analysis` verifying that the new exports remain stable across representative policies.
