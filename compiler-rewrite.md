# RVM Compiler Rewrite Plan

## Goals
- Drive RVM bytecode generation from the type analysis pipeline to eliminate duplicated reasoning about bindings, loop structure, and constant expressions.
- Preserve existing compiler behaviour as a baseline while enabling future typed instructions and optimizer passes.
- Improve handling of virtual document lookups by moving structure discovery entirely into the analyzer.

## Phase 0 – Groundwork
1. **Stabilise Analyzer Output Contracts**
   - Audit `TypeAnalysisResult` to catalogue available per-expression artefacts (facts, constants, dynamic references, binding plans).
   - Enumerate missing data required by the compiler (virtual document slot mapping, literal-table hints, entrypoint reachability summaries).
   - Draft an RFC describing the public accessor surface that the compiler will consume.
2. **Regression Guardrails**
   - Add snapshot tests for current compiler output (assembly listings for representative policies) to guard rework.
   - Ensure `cargo test --test aci` and `cargo clippy` are part of the rewrite CI gate.

### Phase 0 Status (2025-10-30)
- Documented the current analyzer artefacts and outstanding gaps in `docs/type-analysis-audit.md`.
- Added `tests/compiler_snapshots.rs` with an assembly snapshot (`tests/compiler_snapshots/simple_allow_policy.asm`) to freeze the existing code generation shape.
- Pending: RFC for the public accessor surface and CI wiring (cargo clippy/aci gating) once additional phases begin.

## Phase 1 – Analyzer API Surface
1. **Public Accessors**
   - Expose read-only getters on `TypeAnalysisResult` that map `(module_idx, expr_idx)` to:
     - `TypeFact` descriptors and provenance metadata.
     - Inferred constant values.
     - Binding plans / destructuring plans used during analysis.
     - Dynamic reference patterns (for diagnostics and future caching).
2. **Virtual Document Metadata**
   - Extend analyzer loop/binding passes to record:
     - Static prefix and computed suffix for each virtual document lookup.
     - Associated literal table entries or schema tags.
     - Initialization ordering requirements for virtual document handles.
   - Add analyzer tests covering complex nested lookups and `with` modifiers.
3. **Literal Table Export**
   - Teach analyzer to emit a literal table sketch (string, number, object constants) so the compiler can adopt it directly.

## Phase 2 – Compiler Integration Scaffolding
1. **Compiler Entry Wiring**
   - Modify `Compiler::compile_from_policy` to request a `TypeAnalysisResult` via `Engine::get_type_analysis_context` and `TypeAnalyzer::from_engine`.
   - Cache `(modules, schedule, loop_lookup, type_result)` inside a new `CompilationInputs` struct.
2. **Context Plumbing**
   - Thread `type_result` through existing compile functions (rule compilation, expression lowering, comprehension builders).
   - Add helper utilities to fetch per-expression facts and constants with graceful fallbacks when data is absent (legacy mode).
3. **Binding Reuse**
   - Replace compiler-side destructuring walkers with shared helpers that consume analyzer binding plans (`apply_binding_plan` style), ensuring both systems stay aligned.

## Phase 3 – Constant-Driven Codegen
1. **Literal Fast-Path**
   - During expression lowering, check for `TypeFact::constant` and emit literal pool references instead of recomputing expressions.
   - Skip control-flow construction for branches proven dead by constant conditions (behind a feature flag for validation).
2. **Chained Reference Simplification**
   - Use analyzer-provided dynamic/static reference metadata to pre-build `ReferenceChain` objects, removing parser duplication.
3. **Virtual Document Emission**
   - Swap compiler heuristics for analyzer metadata when emitting `VirtualDataDocumentLookupParams`, ensuring slot indices and initialisation order come from a single source of truth.

## Phase 4 – Typed Instruction Enablement
1. **Descriptor Propagation**
   - Attach analyzer type descriptors to intermediate nodes so instruction builders know operand types.
   - Extend instruction definitions to accept optional type tags (without changing runtime behaviour yet).
2. **Typed Opcode Pilot**
   - Introduce a small set of specialised opcodes (e.g., `AddInt`, `SetBool`) gated by a `type-aware-rvm` feature.
   - Add differential tests confirming typed and generic opcodes yield identical results.

## Phase 5 – Validation & Cleanup
1. **Dual-Path Comparison**
   - Keep legacy compiler path behind a flag; add a test harness that compiles policies through both paths and compares assembly listings.
2. **Performance Measurement**
   - Benchmark compile time (`cargo bench -- benches/regorus_benchmark`) and VM runtime to ensure no regressions.
3. **Documentation & Rollout**
   - Update `docs/RegoVirtualMachine.md` to describe the analyzer-driven compilation flow.
   - Add migration notes for extension authors once typed opcodes stabilise.

## Phase 6 – Future Enhancements
- Integrate analyzer reachability data to elide unused rules from bytecode.
- Feed specialization hints into the scheduler for better loop ordering.
- Explore emitting intermediate IR (SSA-like) using analyzer facts for advanced optimisations before lowering to bytecode.
