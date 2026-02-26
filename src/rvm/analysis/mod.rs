// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RVM-to-Z3 symbolic analysis engine.
//!
//! Translates compiled RVM bytecode into Z3 SMT constraints to enable
//! static analysis of Rego policies: input generation, coverage targeting,
//! policy diff, satisfiability checking, and "why denied?" explanations.

mod model_extract;
mod path_registry;
mod schema_constraints;
mod translator;
mod types;

#[cfg(test)]
mod tests;

pub use model_extract::extract_input;
pub use path_registry::{PathEntry, PathRegistry};
pub use schema_constraints::apply_schema_constraints;
pub use translator::Translator;
pub use types::{Definedness, SymRegister, SymValue, ValueSort};

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use crate::rvm::program::Program;
use crate::value::Value;

/// Result of a symbolic analysis query.
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    /// Whether Z3 found the constraints satisfiable.
    pub satisfiable: bool,
    /// A concrete input that satisfies the constraints (if SAT).
    pub input: Option<Value>,
    /// Warnings about unmodeled features (uninterpreted builtins, etc.).
    pub warnings: Vec<String>,
    /// SMT-LIB2 dump of all solver assertions (populated when
    /// `AnalysisConfig::dump_smt` is true).
    pub solver_smt: Option<String>,
    /// String representation of the Z3 model (populated when SAT and
    /// `AnalysisConfig::dump_model` is true).
    pub model_string: Option<String>,
}

/// Configuration for the symbolic analysis engine.
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    /// Maximum loop unrolling depth for symbolic collections.
    pub max_loop_depth: usize,
    /// Maximum rule inlining depth (for recursion).
    pub max_rule_depth: usize,
    /// Z3 solver timeout in milliseconds (0 = no timeout).
    pub timeout_ms: u32,
    /// When true, capture the SMT-LIB2 representation of all solver
    /// assertions and include it in `AnalysisResult::solver_smt`.
    pub dump_smt: bool,
    /// When true and the result is SAT, capture the Z3 model (variable
    /// assignments) and include it in `AnalysisResult::model_string`.
    pub dump_model: bool,
    /// An optional example input value.  When provided, the registry is
    /// pre-seeded with sort information (Bool / Int / String / …) for
    /// every leaf path in the example.  This ensures that symbolic path
    /// registers are created with the correct Z3 sort instead of staying
    /// as Unknown placeholders.
    pub example_input: Option<Value>,
    /// An optional JSON Schema for the input.  When provided, Z3 constraints
    /// are generated to restrict symbolic input fields to well-typed,
    /// non-degenerate values (required fields, min-length strings,
    /// pairwise-distinct IDs, etc.).
    pub input_schema: Option<serde_json::Value>,
    /// Concrete values for specific input paths.  When provided, these
    /// paths are treated as concrete data rather than symbolic variables.
    /// Keys are top-level input field names (e.g., `"entities"`).
    /// Used by Cedar analysis to inject the entity hierarchy as concrete
    /// data while keeping principal/action/resource/context symbolic.
    pub concrete_input: std::collections::HashMap<String, Value>,
    /// When set, `fetch()` calls are modeled as returning the value at
    /// `input.<fetch_input_path>`.  For example, `Some("fetchResponse")`
    /// maps `fetch(...)` → `input/fetchResponse` in the registry, so
    /// Z3 reasons symbolically about all possible fetch outcomes.
    pub fetch_input_path: Option<String>,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_loop_depth: 5,
            max_rule_depth: 3,
            timeout_ms: 30_000,
            dump_smt: false,
            dump_model: false,
            example_input: None,
            input_schema: None,
            concrete_input: std::collections::HashMap::new(),
            fetch_input_path: None,
        }
    }
}

/// Generate an input that causes `entry_point` to produce `desired_output`.
///
/// # Arguments
/// * `program` - The compiled RVM program
/// * `data` - Concrete data object
/// * `desired_output` - The value the entry point should produce
/// * `entry_point` - Name of the entry point to analyze (e.g., "data.test.allow")
/// * `config` - Analysis configuration
pub fn generate_input(
    program: &Program,
    data: &Value,
    desired_output: &Value,
    entry_point: &str,
    config: &AnalysisConfig,
) -> anyhow::Result<AnalysisResult> {
    let z3_cfg = z3::Config::new();
    let ctx = z3::Context::new(&z3_cfg);
    let solver = z3::Solver::new(&ctx);

    if config.timeout_ms > 0 {
        let mut params = z3::Params::new(&ctx);
        params.set_u32("timeout", config.timeout_ms);
        solver.set_params(&params);
    }

    let mut registry = PathRegistry::new(&ctx);

    // Pre-seed sort information from example input (if provided).
    if let Some(ref example) = config.example_input {
        registry.seed_sorts_from_value("input", example, config.max_loop_depth);
    }

    // Apply JSON Schema constraints (if provided).
    let schema_constraints = if let Some(ref schema) = config.input_schema {
        apply_schema_constraints(&ctx, &mut registry, schema, "input", config.max_loop_depth)
    } else {
        vec![]
    };

    let (result, constraints, path_condition, warnings) = {
        let mut translator = Translator::new(&ctx, program, data, &mut registry, config);

        let entry_pc = program
            .get_entry_point(entry_point)
            .ok_or_else(|| anyhow::anyhow!("Entry point '{}' not found", entry_point))?;

        let result = translator.translate_entry_point(entry_pc)?;
        let constraints = core::mem::take(&mut translator.constraints);
        let path_condition = translator.path_condition.clone();
        let warnings = core::mem::take(&mut translator.warnings);
        (result, constraints, path_condition, warnings)
    };

    // Assert all collected constraints
    for c in &constraints {
        solver.assert(c);
    }
    for c in &schema_constraints {
        solver.assert(c);
    }

    // Assert the path condition (all assertions must hold)
    solver.assert(&path_condition);

    // Assert the desired output
    let output_constraint = result.equals_value(&ctx, desired_output)?;
    solver.assert(&output_constraint);

    let solver_smt = if config.dump_smt {
        Some(format!("{}", solver))
    } else {
        None
    };

    match solver.check() {
        z3::SatResult::Sat => {
            let model = solver.get_model().unwrap();
            let model_string = if config.dump_model {
                Some(format!("{}", model))
            } else {
                None
            };
            let input = extract_input(&model, &registry);
            Ok(AnalysisResult {
                satisfiable: true,
                input: Some(input),
                warnings,
                solver_smt,
                model_string,
            })
        }
        z3::SatResult::Unsat => Ok(AnalysisResult {
            satisfiable: false,
            input: None,
            warnings,
            solver_smt,
            model_string: None,
        }),
        z3::SatResult::Unknown => {
            let mut w = warnings;
            w.push(format!(
                "Z3 returned Unknown: {}",
                solver.get_reason_unknown().unwrap_or_default()
            ));
            Ok(AnalysisResult {
                satisfiable: false,
                input: None,
                warnings: w,
                solver_smt,
                model_string: None,
            })
        }
    }
}

/// Check whether any input can make `entry_point` produce a non-Undefined result.
pub fn is_satisfiable(
    program: &Program,
    data: &Value,
    entry_point: &str,
    config: &AnalysisConfig,
) -> anyhow::Result<AnalysisResult> {
    let z3_cfg = z3::Config::new();
    let ctx = z3::Context::new(&z3_cfg);
    let solver = z3::Solver::new(&ctx);

    if config.timeout_ms > 0 {
        let mut params = z3::Params::new(&ctx);
        params.set_u32("timeout", config.timeout_ms);
        solver.set_params(&params);
    }

    let mut registry = PathRegistry::new(&ctx);

    // Pre-seed sort information from example input (if provided).
    if let Some(ref example) = config.example_input {
        registry.seed_sorts_from_value("input", example, config.max_loop_depth);
    }

    // Apply JSON Schema constraints (if provided).
    let schema_constraints = if let Some(ref schema) = config.input_schema {
        apply_schema_constraints(&ctx, &mut registry, schema, "input", config.max_loop_depth)
    } else {
        vec![]
    };

    let (result, constraints, path_condition, warnings) = {
        let mut translator = Translator::new(&ctx, program, data, &mut registry, config);

        let entry_pc = program
            .get_entry_point(entry_point)
            .ok_or_else(|| anyhow::anyhow!("Entry point '{}' not found", entry_point))?;

        let result = translator.translate_entry_point(entry_pc)?;
        let constraints = core::mem::take(&mut translator.constraints);
        let path_condition = translator.path_condition.clone();
        let warnings = core::mem::take(&mut translator.warnings);
        (result, constraints, path_condition, warnings)
    };

    for c in &constraints {
        solver.assert(c);
    }
    for c in &schema_constraints {
        solver.assert(c);
    }
    solver.assert(&path_condition);

    // The result must be defined (not Undefined)
    let defined = result.is_defined(&ctx);
    solver.assert(&defined);

    let solver_smt = if config.dump_smt {
        Some(format!("{}", solver))
    } else {
        None
    };

    match solver.check() {
        z3::SatResult::Sat => {
            let model = solver.get_model().unwrap();
            let model_string = if config.dump_model {
                Some(format!("{}", model))
            } else {
                None
            };
            let input = extract_input(&model, &registry);
            Ok(AnalysisResult {
                satisfiable: true,
                input: Some(input),
                warnings,
                solver_smt,
                model_string,
            })
        }
        z3::SatResult::Unsat => Ok(AnalysisResult {
            satisfiable: false,
            input: None,
            warnings,
            solver_smt,
            model_string: None,
        }),
        z3::SatResult::Unknown => {
            let mut w = warnings;
            w.push(format!(
                "Z3 returned Unknown: {}",
                solver.get_reason_unknown().unwrap_or_default()
            ));
            Ok(AnalysisResult {
                satisfiable: false,
                input: None,
                warnings: w,
                solver_smt,
                model_string: None,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// AnalysisGoal — rich query specification
// ---------------------------------------------------------------------------

/// Specifies what the analysis should achieve.
///
/// Supports three modes:
/// 1. **ExpectedOutput** — find an input that makes the entry point produce a
///    specific value (generalises the existing `generate_input`).
/// 2. **CoverLines** — find an input that forces execution through a given set
///    of Rego source lines (and optionally avoids others).
/// 3. **Both** — satisfy an output constraint *and* cover/avoid specific lines.
#[derive(Debug, Clone)]
pub enum AnalysisGoal {
    /// The entry point must produce exactly this value.
    ExpectedOutput(Value),

    /// Execution must pass through *all* of the listed `cover` lines and
    /// must *not* pass through any of the listed `avoid` lines.
    /// Each entry is `(source_file_name, line_number)` where `line_number`
    /// is 1-based, matching the Rego source.
    CoverLines {
        cover: Vec<(String, usize)>,
        avoid: Vec<(String, usize)>,
    },

    /// Both: produce the expected output **and** cover/avoid specific lines.
    OutputAndCoverLines {
        expected: Value,
        cover: Vec<(String, usize)>,
        avoid: Vec<(String, usize)>,
    },
}

/// Generate an input that satisfies a rich [`AnalysisGoal`].
///
/// This is the most flexible entry point.  It subsumes both
/// [`generate_input`] (when the goal is `ExpectedOutput`) and line-coverage
/// targeting (when the goal is `CoverLines` or `OutputAndCoverLines`).
pub fn generate_input_for_goal(
    program: &Program,
    data: &Value,
    entry_point: &str,
    goal: &AnalysisGoal,
    config: &AnalysisConfig,
) -> anyhow::Result<AnalysisResult> {
    let z3_cfg = z3::Config::new();
    let ctx = z3::Context::new(&z3_cfg);
    let solver = z3::Solver::new(&ctx);

    if config.timeout_ms > 0 {
        let mut params = z3::Params::new(&ctx);
        params.set_u32("timeout", config.timeout_ms);
        solver.set_params(&params);
    }

    let mut registry = PathRegistry::new(&ctx);

    // Pre-seed sort information from example input (if provided).
    if let Some(ref example) = config.example_input {
        registry.seed_sorts_from_value("input", example, config.max_loop_depth);
    }

    // Apply JSON Schema constraints (if provided).
    let schema_constraints = if let Some(ref schema) = config.input_schema {
        apply_schema_constraints(&ctx, &mut registry, schema, "input", config.max_loop_depth)
    } else {
        vec![]
    };

    let (result, constraints, path_condition, pc_path_conditions, warnings) = {
        let mut translator = Translator::new(&ctx, program, data, &mut registry, config);

        let entry_pc = program
            .get_entry_point(entry_point)
            .ok_or_else(|| anyhow::anyhow!("Entry point '{}' not found", entry_point))?;

        let result = translator.translate_entry_point(entry_pc)?;
        let constraints = core::mem::take(&mut translator.constraints);
        let path_condition = translator.path_condition.clone();
        let pc_conds = translator.take_pc_path_conditions();
        let warnings = core::mem::take(&mut translator.warnings);
        (result, constraints, path_condition, pc_conds, warnings)
    };

    // Assert all collected constraints and the overall path condition.
    for c in &constraints {
        solver.assert(c);
    }
    for c in &schema_constraints {
        solver.assert(c);
    }
    solver.assert(&path_condition);

    // ---- Output constraint ----
    let expected_output = match goal {
        AnalysisGoal::ExpectedOutput(v) => Some(v),
        AnalysisGoal::OutputAndCoverLines { expected, .. } => Some(expected),
        AnalysisGoal::CoverLines { .. } => None,
    };
    if let Some(desired) = expected_output {
        let output_constraint = result.equals_value(&ctx, desired)?;
        solver.assert(&output_constraint);
    } else {
        // No explicit output requested — just require the result to be defined.
        let defined = result.is_defined(&ctx);
        solver.assert(&defined);
    }

    // ---- Line-coverage constraints ----
    let (cover_lines, avoid_lines) = match goal {
        AnalysisGoal::CoverLines { cover, avoid } => (Some(cover), Some(avoid)),
        AnalysisGoal::OutputAndCoverLines { cover, avoid, .. } => (Some(cover), Some(avoid)),
        AnalysisGoal::ExpectedOutput(_) => (None, None),
    };
    let mut extra_warnings = Vec::new();
    if let Some(lines) = cover_lines {
        if !lines.is_empty() {
            let line_constraints = lines_to_constraints(
                program,
                lines,
                &pc_path_conditions,
                &ctx,
                &mut extra_warnings,
            );
            for lc in &line_constraints {
                solver.assert(lc);
            }
        }
    }
    if let Some(lines) = avoid_lines {
        if !lines.is_empty() {
            let line_constraints = lines_to_constraints(
                program,
                lines,
                &pc_path_conditions,
                &ctx,
                &mut extra_warnings,
            );
            for lc in &line_constraints {
                solver.assert(&lc.not());
            }
        }
    }

    let mut all_warnings = {
        let mut w = warnings;
        w.extend(extra_warnings);
        w
    };

    // Capture SMT dump before solving if requested.
    let solver_smt = if config.dump_smt {
        Some(format!("{}", solver))
    } else {
        None
    };

    match solver.check() {
        z3::SatResult::Sat => {
            let model = solver.get_model().unwrap();
            let model_string = if config.dump_model {
                Some(format!("{}", model))
            } else {
                None
            };
            let input = extract_input(&model, &registry);
            Ok(AnalysisResult {
                satisfiable: true,
                input: Some(input),
                warnings: all_warnings,
                solver_smt,
                model_string,
            })
        }
        z3::SatResult::Unsat => Ok(AnalysisResult {
            satisfiable: false,
            input: None,
            warnings: all_warnings,
            solver_smt,
            model_string: None,
        }),
        z3::SatResult::Unknown => {
            all_warnings.push(format!(
                "Z3 returned Unknown: {}",
                solver.get_reason_unknown().unwrap_or_default()
            ));
            Ok(AnalysisResult {
                satisfiable: false,
                input: None,
                warnings: all_warnings,
                solver_smt,
                model_string: None,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map `(source_file, line_number)` pairs to Z3 constraints that force those
/// PCs to be reachable.
///
/// For each requested line we find all PCs whose `SpanInfo` matches, collect
/// their path conditions, and OR them together (any one of those PCs being
/// reached counts as covering the line).  The resulting per-line constraints
/// are all returned so the caller can AND them into the solver.
fn lines_to_constraints<'ctx>(
    program: &Program,
    lines: &[(String, usize)],
    pc_path_conditions: &std::collections::HashMap<usize, z3::ast::Bool<'ctx>>,
    _ctx: &'ctx z3::Context,
    warnings: &mut Vec<String>,
) -> Vec<z3::ast::Bool<'ctx>> {
    use z3::ast::Bool as Z3Bool;

    let mut constraints = Vec::new();

    for (file, line) in lines {
        // Find the source index for this file name.
        let source_idx = program.sources.iter().position(|s| {
            s.name == *file || s.name.ends_with(file.as_str()) || file.ends_with(s.name.as_str())
        });

        let source_idx = match source_idx {
            Some(idx) => idx,
            None => {
                warnings.push(format!(
                    "CoverLines: source file '{}' not found in program",
                    file
                ));
                continue;
            }
        };

        // Find the LAST PC that maps to this source line. The last
        // instruction on a line captures the accumulated effect of all
        // earlier instructions (e.g., LoadInput followed by AssertCondition).
        // Using the last PC's path condition means "the entire line was
        // executed successfully."
        let mut last_pc_cond: Option<&Z3Bool<'ctx>> = None;
        for (pc, span) in program.instruction_spans.iter().enumerate() {
            if let Some(span) = span {
                if span.source_index == source_idx && span.line == *line {
                    if let Some(cond) = pc_path_conditions.get(&pc) {
                        last_pc_cond = Some(cond);
                    }
                }
            }
        }

        match last_pc_cond {
            Some(cond) => constraints.push(cond.clone()),
            None => {
                warnings.push(format!(
                    "CoverLines: no instructions found for {}:{} (line may not produce bytecode)",
                    file, line,
                ));
            }
        }
    }

    constraints
}

// ===========================================================================
// Policy Diff
// ===========================================================================

/// Result of a policy-diff analysis.
#[derive(Debug, Clone)]
pub struct DiffResult {
    /// True when Z3 proved no distinguishing input exists.
    pub equivalent: bool,
    /// A concrete input where the two policies disagree (when not equivalent).
    pub distinguishing_input: Option<Value>,
    /// Human-readable description of policy 1's output on the distinguishing
    /// input (e.g. `"matches"` / `"does not match"`).
    pub output_policy1: Option<String>,
    /// Human-readable description of policy 2's output.
    pub output_policy2: Option<String>,
    pub warnings: Vec<String>,
    pub solver_smt: Option<String>,
    pub model_string: Option<String>,
}

/// Find an input on which two policies disagree.
///
/// Both programs are translated against the **same** symbolic input space
/// (shared `PathRegistry`).  The solver is asked for an input where:
///
/// * `result₁ ≠ result₂` (with respect to `desired_output`, this becomes
///   `(result₁ == desired) XOR (result₂ == desired)`).
///
/// If SAT, the model is a concrete **distinguishing input**.  If UNSAT, the
/// two policies are equivalent for all inputs (within the analysis scope).
pub fn policy_diff(
    program1: &Program,
    program2: &Program,
    data: &Value,
    entry_point: &str,
    desired_output: Option<&Value>,
    config: &AnalysisConfig,
) -> anyhow::Result<DiffResult> {
    let z3_cfg = z3::Config::new();
    let ctx = z3::Context::new(&z3_cfg);
    let solver = z3::Solver::new(&ctx);

    if config.timeout_ms > 0 {
        let mut params = z3::Params::new(&ctx);
        params.set_u32("timeout", config.timeout_ms);
        solver.set_params(&params);
    }

    let mut registry = PathRegistry::new(&ctx);

    if let Some(ref example) = config.example_input {
        registry.seed_sorts_from_value("input", example, config.max_loop_depth);
    }

    let schema_constraints = if let Some(ref schema) = config.input_schema {
        apply_schema_constraints(&ctx, &mut registry, schema, "input", config.max_loop_depth)
    } else {
        vec![]
    };

    // --- Translate program 1 ---
    let (result1, constraints1, path_cond1, warnings1) = {
        let mut translator = Translator::new(&ctx, program1, data, &mut registry, config);
        translator.set_prefix("p1_");
        let entry_pc = program1.get_entry_point(entry_point).ok_or_else(|| {
            anyhow::anyhow!("Entry point '{}' not found in policy 1", entry_point)
        })?;
        let result = translator.translate_entry_point(entry_pc)?;
        let constraints = core::mem::take(&mut translator.constraints);
        let path_condition = translator.path_condition.clone();
        let warnings = core::mem::take(&mut translator.warnings);
        (result, constraints, path_condition, warnings)
    };

    // --- Translate program 2 (shares the same symbolic input variables) ---
    let (result2, constraints2, path_cond2, warnings2) = {
        let mut translator = Translator::new(&ctx, program2, data, &mut registry, config);
        translator.set_prefix("p2_");
        let entry_pc = program2.get_entry_point(entry_point).ok_or_else(|| {
            anyhow::anyhow!("Entry point '{}' not found in policy 2", entry_point)
        })?;
        let result = translator.translate_entry_point(entry_pc)?;
        let constraints = core::mem::take(&mut translator.constraints);
        let path_condition = translator.path_condition.clone();
        let warnings = core::mem::take(&mut translator.warnings);
        (result, constraints, path_condition, warnings)
    };

    // Assert all constraints from both translations.
    for c in &constraints1 {
        solver.assert(c);
    }
    for c in &constraints2 {
        solver.assert(c);
    }
    for c in &schema_constraints {
        solver.assert(c);
    }

    // Build the XOR constraint.
    // Each policy "fires" when its path condition holds AND the result equals
    // the desired output.  We look for an input where exactly one fires.
    // NOTE: We do NOT assert path_cond1 / path_cond2 as hard constraints;
    // instead, they become part of the goal so that the solver can explore
    // inputs where one path condition holds but not the other.
    let desired = desired_output.cloned().unwrap_or(Value::Bool(true));
    let r1_result_matches = result1.equals_value(&ctx, &desired)?;
    let r2_result_matches = result2.equals_value(&ctx, &desired)?;
    let r1_matches = z3::ast::Bool::and(&ctx, &[&path_cond1, &r1_result_matches]);
    let r2_matches = z3::ast::Bool::and(&ctx, &[&path_cond2, &r2_result_matches]);
    let xor = z3::ast::Bool::xor(&r1_matches, &r2_matches);
    solver.assert(&xor);

    let solver_smt = if config.dump_smt {
        Some(format!("{}", solver))
    } else {
        None
    };

    let mut all_warnings = warnings1;
    all_warnings.extend(warnings2);

    match solver.check() {
        z3::SatResult::Sat => {
            let model = solver.get_model().unwrap();
            let model_string = if config.dump_model {
                Some(format!("{}", model))
            } else {
                None
            };
            let input = extract_input(&model, &registry);

            // Determine which policy matched the desired output.
            let p1_match = model
                .eval(&r1_matches, true)
                .map(|b| format!("{}", b))
                .unwrap_or_else(|| "unknown".to_string());
            let p2_match = model
                .eval(&r2_matches, true)
                .map(|b| format!("{}", b))
                .unwrap_or_else(|| "unknown".to_string());

            Ok(DiffResult {
                equivalent: false,
                distinguishing_input: Some(input),
                output_policy1: Some(p1_match),
                output_policy2: Some(p2_match),
                warnings: all_warnings,
                solver_smt,
                model_string,
            })
        }
        z3::SatResult::Unsat => Ok(DiffResult {
            equivalent: true,
            distinguishing_input: None,
            output_policy1: None,
            output_policy2: None,
            warnings: all_warnings,
            solver_smt,
            model_string: None,
        }),
        z3::SatResult::Unknown => {
            all_warnings.push(format!(
                "Z3 returned Unknown: {}",
                solver.get_reason_unknown().unwrap_or_default()
            ));
            Ok(DiffResult {
                equivalent: false,
                distinguishing_input: None,
                output_policy1: None,
                output_policy2: None,
                warnings: all_warnings,
                solver_smt,
                model_string: None,
            })
        }
    }
}

// ===========================================================================
// Policy Subsumption
// ===========================================================================

/// Result of a policy-subsumption check.
#[derive(Debug, Clone)]
pub struct SubsumptionResult {
    /// True when new_policy subsumes old_policy: every input that old_policy
    /// accepts is also accepted by new_policy.
    pub subsumes: bool,
    /// A counterexample where old_policy permits but new_policy does not.
    pub counterexample: Option<Value>,
    pub warnings: Vec<String>,
    pub solver_smt: Option<String>,
    pub model_string: Option<String>,
}

/// Check whether `new_program` subsumes `old_program`.
///
/// Subsumption means: for all inputs, if `old_program` produces
/// `desired_output` then `new_program` also produces `desired_output`.
///
/// To check this, we negate the statement and ask Z3:
///   ∃ input: old(input) == desired ∧ new(input) ≠ desired
///
/// If SAT → counterexample found → new does NOT subsume old.
/// If UNSAT → new subsumes old.
pub fn policy_subsumes(
    old_program: &Program,
    new_program: &Program,
    data: &Value,
    entry_point: &str,
    desired_output: &Value,
    config: &AnalysisConfig,
) -> anyhow::Result<SubsumptionResult> {
    let z3_cfg = z3::Config::new();
    let ctx = z3::Context::new(&z3_cfg);
    let solver = z3::Solver::new(&ctx);

    if config.timeout_ms > 0 {
        let mut params = z3::Params::new(&ctx);
        params.set_u32("timeout", config.timeout_ms);
        solver.set_params(&params);
    }

    let mut registry = PathRegistry::new(&ctx);

    if let Some(ref example) = config.example_input {
        registry.seed_sorts_from_value("input", example, config.max_loop_depth);
    }

    let schema_constraints = if let Some(ref schema) = config.input_schema {
        apply_schema_constraints(&ctx, &mut registry, schema, "input", config.max_loop_depth)
    } else {
        vec![]
    };

    // --- Translate old policy ---
    let (old_result, old_constraints, old_path_cond, old_warnings) = {
        let mut translator = Translator::new(&ctx, old_program, data, &mut registry, config);
        translator.set_prefix("old_");
        let entry_pc = old_program.get_entry_point(entry_point).ok_or_else(|| {
            anyhow::anyhow!("Entry point '{}' not found in old policy", entry_point)
        })?;
        let result = translator.translate_entry_point(entry_pc)?;
        let constraints = core::mem::take(&mut translator.constraints);
        let path_condition = translator.path_condition.clone();
        let warnings = core::mem::take(&mut translator.warnings);
        (result, constraints, path_condition, warnings)
    };

    // --- Translate new policy ---
    let (new_result, new_constraints, new_path_cond, new_warnings) = {
        let mut translator = Translator::new(&ctx, new_program, data, &mut registry, config);
        translator.set_prefix("new_");
        let entry_pc = new_program.get_entry_point(entry_point).ok_or_else(|| {
            anyhow::anyhow!("Entry point '{}' not found in new policy", entry_point)
        })?;
        let result = translator.translate_entry_point(entry_pc)?;
        let constraints = core::mem::take(&mut translator.constraints);
        let path_condition = translator.path_condition.clone();
        let warnings = core::mem::take(&mut translator.warnings);
        (result, constraints, path_condition, warnings)
    };

    for c in &old_constraints {
        solver.assert(c);
    }
    for c in &new_constraints {
        solver.assert(c);
    }
    for c in &schema_constraints {
        solver.assert(c);
    }

    // ∃ input: old(input) fires  ∧  new(input) does NOT fire
    // A policy "fires" when its path condition holds AND the result equals
    // the desired output.  We do NOT hard-assert the path conditions; they
    // are folded into the subsumption query so the solver can explore inputs
    // where one path condition holds but not the other.
    let old_result_matches = old_result.equals_value(&ctx, desired_output)?;
    let new_result_matches = new_result.equals_value(&ctx, desired_output)?;
    let old_fires = z3::ast::Bool::and(&ctx, &[&old_path_cond, &old_result_matches]);
    let new_fires = z3::ast::Bool::and(&ctx, &[&new_path_cond, &new_result_matches]);
    solver.assert(&old_fires);
    solver.assert(&new_fires.not());

    let solver_smt = if config.dump_smt {
        Some(format!("{}", solver))
    } else {
        None
    };

    let mut all_warnings = old_warnings;
    all_warnings.extend(new_warnings);

    match solver.check() {
        z3::SatResult::Sat => {
            let model = solver.get_model().unwrap();
            let model_string = if config.dump_model {
                Some(format!("{}", model))
            } else {
                None
            };
            let input = extract_input(&model, &registry);
            Ok(SubsumptionResult {
                subsumes: false,
                counterexample: Some(input),
                warnings: all_warnings,
                solver_smt,
                model_string,
            })
        }
        z3::SatResult::Unsat => Ok(SubsumptionResult {
            subsumes: true,
            counterexample: None,
            warnings: all_warnings,
            solver_smt,
            model_string: None,
        }),
        z3::SatResult::Unknown => {
            all_warnings.push(format!(
                "Z3 returned Unknown: {}",
                solver.get_reason_unknown().unwrap_or_default()
            ));
            Ok(SubsumptionResult {
                subsumes: false,
                counterexample: None,
                warnings: all_warnings,
                solver_smt,
                model_string: None,
            })
        }
    }
}

// ===========================================================================
// Test Suite Generation
// ===========================================================================

/// A single generated test case.
#[derive(Debug, Clone)]
pub struct TestCase {
    /// Concrete input for this test.
    pub input: Value,
    /// Lines covered by this test (as `("file.rego", line_number)` pairs).
    pub covered_lines: Vec<(String, usize)>,
    /// Condition-coverage goals satisfied by this test case.
    /// Each entry is `("file.rego:line", true/false)` indicating whether
    /// the condition on that line was tested as true or false.
    pub condition_coverage: Vec<(String, bool)>,
}

/// Result of test-suite generation.
#[derive(Debug, Clone)]
pub struct TestSuiteResult {
    /// Generated test cases, one per unique reachability path.
    pub test_cases: Vec<TestCase>,
    /// How many source lines were coverable (had bytecode with path conditions).
    pub coverable_lines: usize,
    /// How many source lines were covered across all test cases.
    pub covered_lines: usize,
    /// Total condition-coverage goals (each assert × {true, false}).
    pub condition_goals: usize,
    /// How many condition-coverage goals were covered.
    pub condition_goals_covered: usize,
    pub warnings: Vec<String>,
    pub solver_smt: Option<String>,
}

/// Generate a test suite by iteratively covering all reachable source lines.
///
/// The algorithm:
/// 1. Translate the program once, collecting per-PC path conditions.
/// 2. Group PCs by source line → set of coverable lines.
/// 3. For each uncovered line, push/pop a constraint requiring that line
///    to be covered and solve.
/// 4. When SAT, record the test case and all lines it covers.
/// 5. Repeat until all lines are covered or proved uncoverable.
/// 6. If `condition_coverage` is true, also generate inputs where each
///    assertion condition is false (reaching the assert point but failing it).
pub fn generate_test_suite(
    program: &Program,
    data: &Value,
    entry_point: &str,
    desired_output: Option<&Value>,
    config: &AnalysisConfig,
    max_tests: usize,
    condition_coverage: bool,
) -> anyhow::Result<TestSuiteResult> {
    let z3_cfg = z3::Config::new();
    let ctx = z3::Context::new(&z3_cfg);
    let solver = z3::Solver::new(&ctx);

    if config.timeout_ms > 0 {
        let mut params = z3::Params::new(&ctx);
        params.set_u32("timeout", config.timeout_ms);
        solver.set_params(&params);
    }

    let mut registry = PathRegistry::new(&ctx);

    if let Some(ref example) = config.example_input {
        registry.seed_sorts_from_value("input", example, config.max_loop_depth);
    }

    let schema_constraints = if let Some(ref schema) = config.input_schema {
        apply_schema_constraints(&ctx, &mut registry, schema, "input", config.max_loop_depth)
    } else {
        vec![]
    };

    let (result, constraints, path_condition, pc_path_conditions, pc_conditions, warnings) = {
        let mut translator = Translator::new(&ctx, program, data, &mut registry, config);
        let entry_pc = program
            .get_entry_point(entry_point)
            .ok_or_else(|| anyhow::anyhow!("Entry point '{}' not found", entry_point))?;
        let result = translator.translate_entry_point(entry_pc)?;
        let constraints = core::mem::take(&mut translator.constraints);
        let path_condition = translator.path_condition.clone();
        let pc_conds = translator.take_pc_path_conditions();
        let cond_records = translator.take_pc_conditions();
        let warnings = core::mem::take(&mut translator.warnings);
        (result, constraints, path_condition, pc_conds, cond_records, warnings)
    };

    // Assert base constraints and path condition.
    for c in &constraints {
        solver.assert(c);
    }
    for c in &schema_constraints {
        solver.assert(c);
    }
    solver.assert(&path_condition);

    // Assert output constraint (if given).
    if let Some(desired) = desired_output {
        let output_constraint = result.equals_value(&ctx, desired)?;
        solver.assert(&output_constraint);
    } else {
        let defined = result.is_defined(&ctx);
        solver.assert(&defined);
    }

    // Build a map: (source_file, line) → Z3 condition (OR of all PCs on that line).
    // We use the LAST PC per line (same logic as lines_to_constraints).
    let mut line_conditions: std::collections::BTreeMap<(String, usize), z3::ast::Bool<'_>> =
        std::collections::BTreeMap::new();

    for (pc, span) in program.instruction_spans.iter().enumerate() {
        if let Some(span) = span {
            if let Some(cond) = pc_path_conditions.get(&pc) {
                let source_name = if span.source_index < program.sources.len() {
                    program.sources[span.source_index].name.clone()
                } else {
                    continue;
                };
                // Always replace: last PC on a line wins.
                line_conditions.insert((source_name, span.line), cond.clone());
            }
        }
    }

    let coverable_lines = line_conditions.len();
    let mut globally_covered: std::collections::BTreeSet<(String, usize)> =
        std::collections::BTreeSet::new();
    let mut test_cases: Vec<TestCase> = Vec::new();
    let mut all_warnings = warnings;

    // Capture the base SMT for reporting.
    let solver_smt = if config.dump_smt {
        Some(format!("{}", solver))
    } else {
        None
    };

    // Collect the lines to iterate over.
    let all_lines: Vec<(String, usize)> = line_conditions.keys().cloned().collect();

    for target_line in &all_lines {
        if test_cases.len() >= max_tests {
            break;
        }
        if globally_covered.contains(target_line) {
            continue;
        }

        let cond = match line_conditions.get(target_line) {
            Some(c) => c.clone(),
            None => continue,
        };

        // Push a scope, assert the target line must be covered, solve.
        solver.push();
        solver.assert(&cond);

        match solver.check() {
            z3::SatResult::Sat => {
                let model = solver.get_model().unwrap();
                let input = extract_input(&model, &registry);

                // Determine all lines covered by this model.
                let mut covered = Vec::new();
                for (line_key, line_cond) in &line_conditions {
                    if let Some(val) = model.eval(line_cond, true) {
                        // Check if the evaluated condition is `true`.
                        if format!("{}", val) == "true" {
                            covered.push(line_key.clone());
                        }
                    }
                }

                for l in &covered {
                    globally_covered.insert(l.clone());
                }

                test_cases.push(TestCase {
                    input,
                    covered_lines: covered,
                    condition_coverage: Vec::new(),
                });
            }
            z3::SatResult::Unsat => {
                // This line is uncoverable with the current output constraint.
                globally_covered.insert(target_line.clone());
                all_warnings.push(format!(
                    "Line {}:{} is unreachable (UNSAT)",
                    target_line.0, target_line.1
                ));
            }
            z3::SatResult::Unknown => {
                all_warnings.push(format!(
                    "Z3 returned Unknown for line {}:{}",
                    target_line.0, target_line.1
                ));
            }
        }

        solver.pop(1);
    }

    let covered_count = globally_covered.len();

    // ── Phase 2: Condition coverage ──────────────────────────────────────────
    // For each recorded assertion condition, we already have a "condition=true"
    // test case from line coverage. Now generate a "condition=false" test case
    // where the pre-path is reachable but the condition evaluates to false.
    let mut condition_goals: usize = 0;
    let mut condition_goals_covered: usize = 0;

    if condition_coverage && !pc_conditions.is_empty() {
        // Build a second solver that only has base constraints + schema
        // (no output constraint, no full path_condition) so we can ask
        // "reach this point but fail the condition".
        let solver_cond = z3::Solver::new(&ctx);
        if config.timeout_ms > 0 {
            let mut params = z3::Params::new(&ctx);
            params.set_u32("timeout", config.timeout_ms);
            solver_cond.set_params(&params);
        }
        for c in &constraints {
            solver_cond.assert(c);
        }
        for c in &schema_constraints {
            solver_cond.assert(c);
        }

        // Deduplicate conditions by source line.
        // Map: (source_file, line) → Vec<&ConditionRecord>
        let mut cond_by_line: std::collections::BTreeMap<
            (String, usize),
            Vec<&translator::ConditionRecord<'_>>,
        > = std::collections::BTreeMap::new();

        for rec in &pc_conditions {
            if let Some(span) = program.instruction_spans.get(rec.pc).and_then(|s| s.as_ref()) {
                if span.source_index < program.sources.len() {
                    let source_name = program.sources[span.source_index].name.clone();
                    cond_by_line
                        .entry((source_name, span.line))
                        .or_default()
                        .push(rec);
                }
            }
        }

        // Each line with a condition generates 2 goals: true and false.
        // The "true" goal is considered covered if the line was covered
        // by line-coverage phase. The "false" goal requires a new solve.
        condition_goals = cond_by_line.len() * 2;

        // Count "true" goals already covered by line coverage.
        for line_key in cond_by_line.keys() {
            if globally_covered.contains(line_key) {
                condition_goals_covered += 1;
            }
        }

        // Now solve "false" goals.
        for (line_key, recs) in &cond_by_line {
            if test_cases.len() >= max_tests {
                break;
            }

            // Use the last record for this line (consistent with line-coverage).
            let rec = recs.last().unwrap();

            solver_cond.push();
            solver_cond.assert(&rec.pre_path_condition);
            solver_cond.assert(&rec.condition.not());

            match solver_cond.check() {
                z3::SatResult::Sat => {
                    let model = solver_cond.get_model().unwrap();
                    let input = extract_input(&model, &registry);

                    // Determine which lines this model covers.
                    let mut covered_lines_for_tc = Vec::new();
                    for (lk, line_cond) in &line_conditions {
                        if let Some(val) = model.eval(line_cond, true) {
                            if format!("{}", val) == "true" {
                                covered_lines_for_tc.push(lk.clone());
                            }
                        }
                    }
                    for l in &covered_lines_for_tc {
                        globally_covered.insert(l.clone());
                    }

                    // Record which condition-coverage goals this test satisfies.
                    let mut cond_cov = Vec::new();
                    cond_cov.push((
                        format!("{}:{}", line_key.0, line_key.1),
                        false, // this was the "false" goal
                    ));

                    // Also check if any "true" condition goals are satisfied.
                    for (other_key, other_recs) in &cond_by_line {
                        let other_rec = other_recs.last().unwrap();
                        if let Some(val) = model.eval(&other_rec.condition, true) {
                            if format!("{}", val) == "true" {
                                cond_cov.push((
                                    format!("{}:{}", other_key.0, other_key.1),
                                    true,
                                ));
                            }
                        }
                    }

                    condition_goals_covered += 1; // the false goal
                    test_cases.push(TestCase {
                        input,
                        covered_lines: covered_lines_for_tc,
                        condition_coverage: cond_cov,
                    });
                }
                z3::SatResult::Unsat => {
                    // Condition can never be false at this point – tautological.
                    condition_goals_covered += 1; // vacuously covered
                    all_warnings.push(format!(
                        "Condition at {}:{} can never be false (tautological, UNSAT)",
                        line_key.0, line_key.1
                    ));
                }
                z3::SatResult::Unknown => {
                    all_warnings.push(format!(
                        "Z3 returned Unknown for condition-false at {}:{}",
                        line_key.0, line_key.1
                    ));
                }
            }

            solver_cond.pop(1);
        }
    }

    Ok(TestSuiteResult {
        test_cases,
        coverable_lines,
        covered_lines: covered_count,
        condition_goals,
        condition_goals_covered,
        warnings: all_warnings,
        solver_smt,
    })
}
