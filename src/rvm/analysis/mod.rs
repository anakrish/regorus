// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RVM symbolic analysis engine.
//!
//! Translates compiled RVM bytecode into SMT constraints to enable
//! static analysis of Rego policies: input generation, coverage targeting,
//! policy diff, satisfiability checking, and "why denied?" explanations.

mod model_extract;
mod path_registry;
mod schema_constraints;
mod translator;
mod types;

#[cfg(feature = "z3-analysis")]
#[allow(unsafe_code)]
pub(crate) mod z3_solver;

#[cfg(all(test, feature = "z3-analysis"))]
mod tests;

pub use model_extract::{extract_input, register_extractions, PathExtraction};
pub use path_registry::{PathEntry, PathRegistry};
pub use schema_constraints::apply_schema_constraints;
pub use translator::Translator;
pub use types::{Definedness, SymRegister, SymValue, ValueSort};

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use crate::rvm::program::Program;
use crate::value::Value;

use regorus_smt::SmtExpr;
use regorus_smt::SmtProblem;
#[cfg(feature = "z3-analysis")]
use regorus_smt::SmtStatus;

/// Result of a symbolic analysis query.
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    /// Whether the solver found the constraints satisfiable.
    pub satisfiable: bool,
    /// A concrete input that satisfies the constraints (if SAT).
    pub input: Option<Value>,
    /// Warnings about unmodeled features (uninterpreted builtins, etc.).
    pub warnings: Vec<String>,
    /// SMT-LIB2 dump of all solver assertions (populated when
    /// `AnalysisConfig::dump_smt` is true).
    pub solver_smt: Option<String>,
    /// String representation of the SMT model (populated when SAT and
    /// `AnalysisConfig::dump_model` is true).
    pub model_string: Option<String>,
}

/// Configuration for the symbolic analysis engine.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub struct AnalysisConfig {
    /// Maximum loop unrolling depth for symbolic collections.
    pub max_loop_depth: usize,
    /// Maximum rule inlining depth (for recursion).
    pub max_rule_depth: usize,
    /// SMT solver timeout in milliseconds (0 = no timeout).
    pub timeout_ms: u32,
    /// When true, capture the SMT-LIB2 representation of all solver
    /// assertions and include it in `AnalysisResult::solver_smt`.
    pub dump_smt: bool,
    /// When true and the result is SAT, capture the SMT model (variable
    /// assignments) and include it in `AnalysisResult::model_string`.
    pub dump_model: bool,
    /// An optional example input value.  When provided, the registry is
    /// pre-seeded with sort information (Bool / Int / String / …) for
    /// every leaf path in the example.  This ensures that symbolic path
    /// registers are created with the correct SMT sort instead of staying
    /// as Unknown placeholders.
    pub example_input: Option<Value>,
    /// An optional JSON Schema for the input.  When provided, SMT constraints
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
    /// the solver reasons symbolically about all possible fetch outcomes.
    pub fetch_input_path: Option<String>,
    /// Lines that execution *must* pass through.
    /// Each entry is `"source_file:line_number"` (1-based), e.g.
    /// `"allowed_server.rego:11"`.
    pub cover_lines: Vec<String>,
    /// Lines that execution must *not* pass through.
    /// Same format as `cover_lines`.
    pub avoid_lines: Vec<String>,
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
            cover_lines: Vec::new(),
            avoid_lines: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Look up the trimmed source text for a `(filename, line)` pair.
///
/// Returns the trimmed line content, or an empty string if not found.
fn get_source_line(program: &Program, line_key: &(String, usize)) -> String {
    for src in &program.sources {
        if src.name == line_key.0 {
            if let Some(line_text) = src.content.lines().nth(line_key.1.saturating_sub(1)) {
                return line_text.trim().to_string();
            }
        }
    }
    String::new()
}

/// Assemble an [`SmtProblem`] from the common pieces produced by translation.
///
/// Collects:
///  - all declarations from the registry
///  - translator constraints
///  - schema constraints
///  - any extra goal-specific assertions
///
/// Also registers extraction entries for every input path so the solver
/// knows what values to pull from the model.
fn build_problem(
    registry: &PathRegistry,
    constraints: &[SmtExpr],
    schema_constraints: &[SmtExpr],
    extra_assertions: &[SmtExpr],
    config: &AnalysisConfig,
) -> (SmtProblem, Vec<PathExtraction>) {
    let mut problem = SmtProblem::new();

    // Declarations from the registry.
    for decl in registry.declarations() {
        problem.declarations.push(decl.clone());
    }

    // Translator constraints.
    for c in constraints {
        problem.assert(c.clone());
    }

    // Schema constraints.
    for c in schema_constraints {
        problem.assert(c.clone());
    }

    // Goal-specific assertions.
    for c in extra_assertions {
        problem.assert(c.clone());
    }

    // Solver timeout.
    if config.timeout_ms > 0 {
        problem.config.timeout_ms = Some(config.timeout_ms);
    }

    // Register extractions for input reconstruction.
    let plan = register_extractions(&mut problem, registry);

    (problem, plan)
}

/// Render the problem to SMT-LIB2 if `dump_smt` is requested.
fn maybe_render_smt(problem: &SmtProblem, config: &AnalysisConfig) -> Option<String> {
    if config.dump_smt {
        Some(regorus_smt::render_problem(problem))
    } else {
        None
    }
}

/// Interpret a solver result into an [`AnalysisResult`].
pub fn interpret_result(
    check: &regorus_smt::SmtCheckResult,
    plan: &[PathExtraction],
    warnings: Vec<String>,
    solver_smt: Option<String>,
    config: &AnalysisConfig,
) -> AnalysisResult {
    match check.status {
        regorus_smt::SmtStatus::Sat => {
            let input = extract_input(check, plan);
            let model_string = if config.dump_model {
                Some(format!("{:?}", check.values))
            } else {
                None
            };
            AnalysisResult {
                satisfiable: true,
                input: Some(input),
                warnings,
                solver_smt,
                model_string,
            }
        }
        regorus_smt::SmtStatus::Unsat => AnalysisResult {
            satisfiable: false,
            input: None,
            warnings,
            solver_smt,
            model_string: None,
        },
        regorus_smt::SmtStatus::Unknown => {
            let mut w = warnings;
            w.push(format!(
                "Solver returned Unknown: {}",
                check.reason_unknown.as_deref().unwrap_or("")
            ));
            AnalysisResult {
                satisfiable: false,
                input: None,
                warnings: w,
                solver_smt,
                model_string: None,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Prepared analysis problems (for WASM / external solver flows)
// ---------------------------------------------------------------------------

/// A prepared analysis problem, ready to be sent to an external solver.
///
/// Contains the [`SmtProblem`] (serializable to JSON or renderable to
/// SMT-LIB2) and the extraction plan needed to reconstruct a concrete
/// input from a solver model.
///
/// Typical WASM workflow:
/// 1. Call `prepare_generate_input` (or another `prepare_*` function).
/// 2. Serialize `problem` to JSON or call `render_smt_lib2()` to get
///    SMT-LIB2 text.
/// 3. Send to the JavaScript Z3 WASM solver.
/// 4. Receive a solver result as JSON (`SmtCheckResult`).
/// 5. Call `interpret()` with the check result to get an `AnalysisResult`.
#[derive(Debug)]
pub struct PreparedProblem {
    /// The SMT problem to solve.
    pub problem: SmtProblem,
    /// Extraction plan for reconstructing input from solver model.
    pub plan: Vec<PathExtraction>,
    /// Warnings from translation.
    pub warnings: Vec<String>,
    /// Analysis config (used for `dump_model` flag).
    pub config: AnalysisConfig,
}

impl PreparedProblem {
    /// Render the problem to SMT-LIB2 text.
    pub fn render_smt_lib2(&self) -> String {
        regorus_smt::render_problem(&self.problem)
    }

    /// Serialize the problem to JSON.
    pub fn problem_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.problem)
    }

    /// Interpret a solver result into an [`AnalysisResult`].
    pub fn interpret(&self, check: &regorus_smt::SmtCheckResult) -> AnalysisResult {
        let solver_smt = if self.config.dump_smt {
            Some(regorus_smt::render_problem(&self.problem))
        } else {
            None
        };
        interpret_result(check, &self.plan, self.warnings.clone(), solver_smt, &self.config)
    }
}

/// Prepare an input-generation problem (without solving).
///
/// Returns a [`PreparedProblem`] that can be serialized and sent to an
/// external solver (e.g., Z3 WASM in a browser).
///
/// When `config.cover_lines` or `config.avoid_lines` are non-empty the
/// problem includes line-coverage constraints (same as `OutputAndCoverLines`
/// goal in the direct solver path).
pub fn prepare_generate_input(
    program: &Program,
    data: &Value,
    desired_output: &Value,
    entry_point: &str,
    config: &AnalysisConfig,
) -> anyhow::Result<PreparedProblem> {
    let has_lines = !config.cover_lines.is_empty() || !config.avoid_lines.is_empty();

    let mut registry = PathRegistry::new();

    if let Some(ref example) = config.example_input {
        registry.seed_sorts_from_value("input", example, config.max_loop_depth);
    }

    let schema_constraints = if let Some(ref schema) = config.input_schema {
        apply_schema_constraints(&mut registry, schema, "input", config.max_loop_depth)
    } else {
        vec![]
    };

    let (result, constraints, path_condition, pc_path_conditions, warnings) = {
        let mut translator = Translator::new(program, data, &mut registry, config);
        let entry_pc = program
            .get_entry_point(entry_point)
            .ok_or_else(|| anyhow::anyhow!("Entry point '{}' not found", entry_point))?;
        let result = translator.translate_entry_point(entry_pc)?;
        let constraints = core::mem::take(&mut translator.constraints);
        let path_condition = translator.path_condition.clone();
        let pc_conds = if has_lines {
            translator.take_pc_path_conditions()
        } else {
            std::collections::HashMap::new()
        };
        let warnings = core::mem::take(&mut translator.warnings);
        (result, constraints, path_condition, pc_conds, warnings)
    };

    let mut goal_assertions = vec![path_condition];
    goal_assertions.push(result.equals_value(desired_output)?);

    // ---- Line-coverage constraints from config ----
    let mut extra_warnings = Vec::new();
    if has_lines {
        let cover = parse_line_specs(&config.cover_lines)?;
        let avoid = parse_line_specs(&config.avoid_lines)?;

        if !cover.is_empty() {
            let lc = lines_to_constraints(program, &cover, &pc_path_conditions, &mut extra_warnings);
            goal_assertions.extend(lc);
        }
        if !avoid.is_empty() {
            let lc = lines_to_constraints(program, &avoid, &pc_path_conditions, &mut extra_warnings);
            for c in lc {
                goal_assertions.push(SmtExpr::not(c));
            }
        }
    }

    let all_warnings = {
        let mut w = warnings;
        w.extend(extra_warnings);
        w
    };

    let (problem, plan) = build_problem(
        &registry,
        &constraints,
        &schema_constraints,
        &goal_assertions,
        config,
    );

    Ok(PreparedProblem { problem, plan, warnings: all_warnings, config: config.clone() })
}

/// Prepare a satisfiability-check problem (without solving).
pub fn prepare_is_satisfiable(
    program: &Program,
    data: &Value,
    entry_point: &str,
    config: &AnalysisConfig,
) -> anyhow::Result<PreparedProblem> {
    let mut registry = PathRegistry::new();

    if let Some(ref example) = config.example_input {
        registry.seed_sorts_from_value("input", example, config.max_loop_depth);
    }

    let schema_constraints = if let Some(ref schema) = config.input_schema {
        apply_schema_constraints(&mut registry, schema, "input", config.max_loop_depth)
    } else {
        vec![]
    };

    let (result, constraints, path_condition, warnings) = {
        let mut translator = Translator::new(program, data, &mut registry, config);
        let entry_pc = program
            .get_entry_point(entry_point)
            .ok_or_else(|| anyhow::anyhow!("Entry point '{}' not found", entry_point))?;
        let result = translator.translate_entry_point(entry_pc)?;
        let constraints = core::mem::take(&mut translator.constraints);
        let path_condition = translator.path_condition.clone();
        let warnings = core::mem::take(&mut translator.warnings);
        (result, constraints, path_condition, warnings)
    };

    let defined = result.is_defined();

    let (problem, plan) = build_problem(
        &registry,
        &constraints,
        &schema_constraints,
        &[path_condition, defined],
        config,
    );

    Ok(PreparedProblem { problem, plan, warnings, config: config.clone() })
}

/// Prepare a policy-diff problem (without solving).
///
/// The returned [`PreparedProblem`] contains the XOR constraint that
/// distinguishes the two policies.
pub fn prepare_policy_diff(
    program1: &Program,
    program2: &Program,
    data: &Value,
    entry_point: &str,
    desired_output: Option<&Value>,
    config: &AnalysisConfig,
) -> anyhow::Result<PreparedProblem> {
    let mut registry = PathRegistry::new();

    if let Some(ref example) = config.example_input {
        registry.seed_sorts_from_value("input", example, config.max_loop_depth);
    }

    let schema_constraints = if let Some(ref schema) = config.input_schema {
        apply_schema_constraints(&mut registry, schema, "input", config.max_loop_depth)
    } else {
        vec![]
    };

    let (result1, constraints1, path_cond1, warnings1) = {
        let mut translator = Translator::new(program1, data, &mut registry, config);
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

    let (result2, constraints2, path_cond2, warnings2) = {
        let mut translator = Translator::new(program2, data, &mut registry, config);
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

    let desired = desired_output.cloned().unwrap_or(Value::Bool(true));
    let r1_result_matches = result1.equals_value(&desired)?;
    let r2_result_matches = result2.equals_value(&desired)?;
    let r1_matches = SmtExpr::and2(path_cond1, r1_result_matches);
    let r2_matches = SmtExpr::and2(path_cond2, r2_result_matches);
    let xor = SmtExpr::Xor(Box::new(r1_matches), Box::new(r2_matches));

    let all_constraints: Vec<SmtExpr> = constraints1
        .into_iter()
        .chain(constraints2.into_iter())
        .collect();

    let (problem, plan) = build_problem(
        &registry,
        &all_constraints,
        &schema_constraints,
        &[xor],
        config,
    );

    let mut all_warnings = warnings1;
    all_warnings.extend(warnings2);

    Ok(PreparedProblem { problem, plan, warnings: all_warnings, config: config.clone() })
}

/// Prepare a policy-subsumption check (without solving).
///
/// Subsumption means: for all inputs, if `old_program` produces
/// `desired_output` then `new_program` also produces `desired_output`.
///
/// We negate and ask:
///   ∃ input: old(input) == desired ∧ new(input) ≠ desired
///
/// If SAT → counterexample found → new does NOT subsume old.
/// If UNSAT → new subsumes old.
///
/// Returns a [`PreparedProblem`] whose `interpret()` result `satisfiable`
/// field means "counterexample found" (i.e., subsumption does NOT hold).
pub fn prepare_policy_subsumes(
    old_program: &Program,
    new_program: &Program,
    data: &Value,
    entry_point: &str,
    desired_output: &Value,
    config: &AnalysisConfig,
) -> anyhow::Result<PreparedProblem> {
    let mut registry = PathRegistry::new();

    if let Some(ref example) = config.example_input {
        registry.seed_sorts_from_value("input", example, config.max_loop_depth);
    }

    let schema_constraints = if let Some(ref schema) = config.input_schema {
        apply_schema_constraints(&mut registry, schema, "input", config.max_loop_depth)
    } else {
        vec![]
    };

    // --- Translate old policy ---
    let (old_result, old_constraints, old_path_cond, old_warnings) = {
        let mut translator = Translator::new(old_program, data, &mut registry, config);
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
        let mut translator = Translator::new(new_program, data, &mut registry, config);
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

    // ∃ input: old fires ∧ new does NOT fire
    let old_result_matches = old_result.equals_value(desired_output)?;
    let new_result_matches = new_result.equals_value(desired_output)?;
    let old_fires = SmtExpr::and2(old_path_cond, old_result_matches);
    let new_fires = SmtExpr::and2(new_path_cond, new_result_matches);

    let all_constraints: Vec<SmtExpr> = old_constraints
        .into_iter()
        .chain(new_constraints.into_iter())
        .collect();

    let (problem, plan) = build_problem(
        &registry,
        &all_constraints,
        &schema_constraints,
        &[old_fires, SmtExpr::not(new_fires)],
        config,
    );

    let mut all_warnings = old_warnings;
    all_warnings.extend(new_warnings);

    Ok(PreparedProblem { problem, plan, warnings: all_warnings, config: config.clone() })
}

// ---------------------------------------------------------------------------
// Public API — simple queries
// ---------------------------------------------------------------------------

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
    let mut registry = PathRegistry::new();

    if let Some(ref example) = config.example_input {
        registry.seed_sorts_from_value("input", example, config.max_loop_depth);
    }

    let schema_constraints = if let Some(ref schema) = config.input_schema {
        apply_schema_constraints(&mut registry, schema, "input", config.max_loop_depth)
    } else {
        vec![]
    };

    let (result, constraints, path_condition, warnings) = {
        let mut translator = Translator::new(program, data, &mut registry, config);
        let entry_pc = program
            .get_entry_point(entry_point)
            .ok_or_else(|| anyhow::anyhow!("Entry point '{}' not found", entry_point))?;
        let result = translator.translate_entry_point(entry_pc)?;
        let constraints = core::mem::take(&mut translator.constraints);
        let path_condition = translator.path_condition.clone();
        let warnings = core::mem::take(&mut translator.warnings);
        (result, constraints, path_condition, warnings)
    };

    let output_constraint = result.equals_value(desired_output)?;

    let (problem, plan) = build_problem(
        &registry,
        &constraints,
        &schema_constraints,
        &[path_condition, output_constraint],
        config,
    );

    let solver_smt = maybe_render_smt(&problem, config);

    #[cfg(feature = "z3-analysis")]
    {
        let solution = z3_solver::solve(&problem)?;
        let check = solution.first().unwrap();
        return Ok(interpret_result(check, &plan, warnings, solver_smt, config));
    }

    #[cfg(not(feature = "z3-analysis"))]
    {
        let _ = plan;
        Ok(AnalysisResult {
            satisfiable: false,
            input: None,
            warnings,
            solver_smt,
            model_string: None,
        })
    }
}

/// Check whether any input can make `entry_point` produce a non-Undefined result.
pub fn is_satisfiable(
    program: &Program,
    data: &Value,
    entry_point: &str,
    config: &AnalysisConfig,
) -> anyhow::Result<AnalysisResult> {
    let mut registry = PathRegistry::new();

    if let Some(ref example) = config.example_input {
        registry.seed_sorts_from_value("input", example, config.max_loop_depth);
    }

    let schema_constraints = if let Some(ref schema) = config.input_schema {
        apply_schema_constraints(&mut registry, schema, "input", config.max_loop_depth)
    } else {
        vec![]
    };

    let (result, constraints, path_condition, warnings) = {
        let mut translator = Translator::new(program, data, &mut registry, config);
        let entry_pc = program
            .get_entry_point(entry_point)
            .ok_or_else(|| anyhow::anyhow!("Entry point '{}' not found", entry_point))?;
        let result = translator.translate_entry_point(entry_pc)?;
        let constraints = core::mem::take(&mut translator.constraints);
        let path_condition = translator.path_condition.clone();
        let warnings = core::mem::take(&mut translator.warnings);
        (result, constraints, path_condition, warnings)
    };

    let defined = result.is_defined();

    let (problem, plan) = build_problem(
        &registry,
        &constraints,
        &schema_constraints,
        &[path_condition, defined],
        config,
    );

    let solver_smt = maybe_render_smt(&problem, config);

    #[cfg(feature = "z3-analysis")]
    {
        let solution = z3_solver::solve(&problem)?;
        let check = solution.first().unwrap();
        return Ok(interpret_result(check, &plan, warnings, solver_smt, config));
    }

    #[cfg(not(feature = "z3-analysis"))]
    {
        let _ = plan;
        Ok(AnalysisResult {
            satisfiable: false,
            input: None,
            warnings,
            solver_smt,
            model_string: None,
        })
    }
}

// ---------------------------------------------------------------------------
// AnalysisGoal — rich query specification
// ---------------------------------------------------------------------------

/// Specifies what the analysis should achieve.
///
/// Supports four modes:
/// 1. **ExpectedOutput** — find an input that makes the entry point produce a
///    specific value (generalises the existing `generate_input`).
/// 2. **NonDefault** — find an input that makes the entry point produce any
///    value other than its default / fallback.  Useful for rules whose
///    output is a complex object rather than a simple boolean.
/// 3. **CoverLines** — find an input that forces execution through a given set
///    of Rego source lines (and optionally avoids others).
/// 4. **Both** — satisfy an output constraint *and* cover/avoid specific lines.
#[derive(Debug, Clone)]
pub enum AnalysisGoal {
    /// The entry point must produce exactly this value.
    ExpectedOutput(Value),

    /// The entry point must produce any value that differs from its
    /// default / fallback.  For `ConditionalConcrete` results this means
    /// at least one non-fallback branch is active.
    NonDefault,

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
pub fn prepare_for_goal(
    program: &Program,
    data: &Value,
    entry_point: &str,
    goal: &AnalysisGoal,
    config: &AnalysisConfig,
) -> anyhow::Result<PreparedProblem> {
    let mut registry = PathRegistry::new();

    if let Some(ref example) = config.example_input {
        registry.seed_sorts_from_value("input", example, config.max_loop_depth);
    }

    let schema_constraints = if let Some(ref schema) = config.input_schema {
        apply_schema_constraints(&mut registry, schema, "input", config.max_loop_depth)
    } else {
        vec![]
    };

    let (result, constraints, path_condition, pc_path_conditions, warnings) = {
        let mut translator = Translator::new(program, data, &mut registry, config);
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

    let mut goal_assertions = vec![path_condition];

    let expected_output = match goal {
        AnalysisGoal::ExpectedOutput(v) => Some(v),
        AnalysisGoal::OutputAndCoverLines { expected, .. } => Some(expected),
        AnalysisGoal::CoverLines { .. } | AnalysisGoal::NonDefault => None,
    };
    if let Some(desired) = expected_output {
        goal_assertions.push(result.equals_value(desired)?);
    } else if matches!(goal, AnalysisGoal::NonDefault) {
        goal_assertions.push(result.is_non_default());
    } else {
        goal_assertions.push(result.is_defined());
    }

    let (cover_lines, avoid_lines) = match goal {
        AnalysisGoal::CoverLines { cover, avoid } => (Some(cover), Some(avoid)),
        AnalysisGoal::OutputAndCoverLines { cover, avoid, .. } => (Some(cover), Some(avoid)),
        AnalysisGoal::ExpectedOutput(_) | AnalysisGoal::NonDefault => (None, None),
    };
    let mut extra_warnings = Vec::new();
    if let Some(lines) = cover_lines {
        if !lines.is_empty() {
            let line_constraints = lines_to_constraints(
                program, lines, &pc_path_conditions, &mut extra_warnings,
            );
            goal_assertions.extend(line_constraints);
        }
    }
    if let Some(lines) = avoid_lines {
        if !lines.is_empty() {
            let line_constraints = lines_to_constraints(
                program, lines, &pc_path_conditions, &mut extra_warnings,
            );
            for lc in line_constraints {
                goal_assertions.push(SmtExpr::not(lc));
            }
        }
    }

    let all_warnings = {
        let mut w = warnings;
        w.extend(extra_warnings);
        w
    };

    let (problem, plan) = build_problem(
        &registry,
        &constraints,
        &schema_constraints,
        &goal_assertions,
        config,
    );

    Ok(PreparedProblem { problem, plan, warnings: all_warnings, config: config.clone() })
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
    let mut registry = PathRegistry::new();

    if let Some(ref example) = config.example_input {
        registry.seed_sorts_from_value("input", example, config.max_loop_depth);
    }

    let schema_constraints = if let Some(ref schema) = config.input_schema {
        apply_schema_constraints(&mut registry, schema, "input", config.max_loop_depth)
    } else {
        vec![]
    };

    let (result, constraints, path_condition, pc_path_conditions, warnings) = {
        let mut translator = Translator::new(program, data, &mut registry, config);
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

    // Collect all goal-specific assertions.
    let mut goal_assertions = vec![path_condition];

    // ---- Output constraint ----
    let expected_output = match goal {
        AnalysisGoal::ExpectedOutput(v) => Some(v),
        AnalysisGoal::OutputAndCoverLines { expected, .. } => Some(expected),
        AnalysisGoal::CoverLines { .. } | AnalysisGoal::NonDefault => None,
    };
    if let Some(desired) = expected_output {
        goal_assertions.push(result.equals_value(desired)?);
    } else if matches!(goal, AnalysisGoal::NonDefault) {
        goal_assertions.push(result.is_non_default());
    } else {
        goal_assertions.push(result.is_defined());
    }

    // ---- Line-coverage constraints ----
    let (cover_lines, avoid_lines) = match goal {
        AnalysisGoal::CoverLines { cover, avoid } => (Some(cover), Some(avoid)),
        AnalysisGoal::OutputAndCoverLines { cover, avoid, .. } => (Some(cover), Some(avoid)),
        AnalysisGoal::ExpectedOutput(_) | AnalysisGoal::NonDefault => (None, None),
    };
    let mut extra_warnings = Vec::new();
    if let Some(lines) = cover_lines {
        if !lines.is_empty() {
            let line_constraints = lines_to_constraints(
                program,
                lines,
                &pc_path_conditions,
                &mut extra_warnings,
            );
            goal_assertions.extend(line_constraints);
        }
    }
    if let Some(lines) = avoid_lines {
        if !lines.is_empty() {
            let line_constraints = lines_to_constraints(
                program,
                lines,
                &pc_path_conditions,
                &mut extra_warnings,
            );
            for lc in line_constraints {
                goal_assertions.push(SmtExpr::not(lc));
            }
        }
    }

    let all_warnings = {
        let mut w = warnings;
        w.extend(extra_warnings);
        w
    };

    let (problem, plan) = build_problem(
        &registry,
        &constraints,
        &schema_constraints,
        &goal_assertions,
        config,
    );

    let solver_smt = maybe_render_smt(&problem, config);

    #[cfg(feature = "z3-analysis")]
    {
        let solution = z3_solver::solve(&problem)?;
        let check = solution.first().unwrap();
        return Ok(interpret_result(check, &plan, all_warnings, solver_smt, config));
    }

    #[cfg(not(feature = "z3-analysis"))]
    {
        let _ = plan;
        Ok(AnalysisResult {
            satisfiable: false,
            input: None,
            warnings: all_warnings,
            solver_smt,
            model_string: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse `"file:line"` strings (e.g. `"allowed_server.rego:11"`) into
/// `(file_name, line_number)` tuples.
fn parse_line_specs(specs: &[String]) -> anyhow::Result<Vec<(String, usize)>> {
    let mut out = Vec::with_capacity(specs.len());
    for spec in specs {
        let parts: Vec<&str> = spec.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid line spec: '{spec}'. Expected FILE:LINE");
        }
        let line: usize = parts[0]
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid line number in '{spec}'"))?;
        out.push((parts[1].to_string(), line));
    }
    Ok(out)
}

/// Map `(source_file, line_number)` pairs to SMT constraints that force those
/// PCs to be reachable.
///
/// For each requested line we find all PCs whose `SpanInfo` matches, collect
/// their path conditions, and OR them together (any one of those PCs being
/// reached counts as covering the line).  The resulting per-line constraints
/// are all returned so the caller can AND them into the solver.
fn lines_to_constraints(
    program: &Program,
    lines: &[(String, usize)],
    pc_path_conditions: &std::collections::HashMap<usize, SmtExpr>,
    warnings: &mut Vec<String>,
) -> Vec<SmtExpr> {
    let mut constraints = Vec::new();

    for (file, line) in lines {
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

        let mut last_pc_cond: Option<&SmtExpr> = None;
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
    /// True when the solver proved no distinguishing input exists.
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
    let mut registry = PathRegistry::new();

    if let Some(ref example) = config.example_input {
        registry.seed_sorts_from_value("input", example, config.max_loop_depth);
    }

    let schema_constraints = if let Some(ref schema) = config.input_schema {
        apply_schema_constraints(&mut registry, schema, "input", config.max_loop_depth)
    } else {
        vec![]
    };

    // --- Translate program 1 ---
    let (result1, constraints1, path_cond1, warnings1) = {
        let mut translator = Translator::new(program1, data, &mut registry, config);
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
        let mut translator = Translator::new(program2, data, &mut registry, config);
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

    // Build the XOR constraint.
    let desired = desired_output.cloned().unwrap_or(Value::Bool(true));
    let r1_result_matches = result1.equals_value(&desired)?;
    let r2_result_matches = result2.equals_value(&desired)?;
    let r1_matches = SmtExpr::and2(path_cond1, r1_result_matches);
    let r2_matches = SmtExpr::and2(path_cond2, r2_result_matches);
    let xor = SmtExpr::Xor(Box::new(r1_matches.clone()), Box::new(r2_matches.clone()));

    // Merge constraints from both translations.
    let all_constraints: Vec<SmtExpr> = constraints1
        .into_iter()
        .chain(constraints2.into_iter())
        .collect();

    let (mut problem, plan) = build_problem(
        &registry,
        &all_constraints,
        &schema_constraints,
        &[xor],
        config,
    );

    // Register extra extractions for r1/r2 match status.
    let r1_match_idx = problem.extractions.len();
    problem.add_extraction("r1_matches", r1_matches, regorus_smt::SmtSort::Bool, true);
    let r2_match_idx = problem.extractions.len();
    problem.add_extraction("r2_matches", r2_matches, regorus_smt::SmtSort::Bool, true);

    let solver_smt = maybe_render_smt(&problem, config);

    let mut all_warnings = warnings1;
    all_warnings.extend(warnings2);

    #[cfg(feature = "z3-analysis")]
    {
        let solution = z3_solver::solve(&problem)?;
        let check = solution.first().unwrap();
        match check.status {
            SmtStatus::Sat => {
                let input = extract_input(check, &plan);
                let model_string = if config.dump_model {
                    Some(format!("{:?}", check.values))
                } else {
                    None
                };
                let p1_match = check
                    .get_bool(r1_match_idx)
                    .map(|b| format!("{}", b))
                    .unwrap_or_else(|| "unknown".to_string());
                let p2_match = check
                    .get_bool(r2_match_idx)
                    .map(|b| format!("{}", b))
                    .unwrap_or_else(|| "unknown".to_string());
                return Ok(DiffResult {
                    equivalent: false,
                    distinguishing_input: Some(input),
                    output_policy1: Some(p1_match),
                    output_policy2: Some(p2_match),
                    warnings: all_warnings,
                    solver_smt,
                    model_string,
                });
            }
            SmtStatus::Unsat => {
                return Ok(DiffResult {
                    equivalent: true,
                    distinguishing_input: None,
                    output_policy1: None,
                    output_policy2: None,
                    warnings: all_warnings,
                    solver_smt,
                    model_string: None,
                });
            }
            SmtStatus::Unknown => {
                all_warnings.push(format!(
                    "Solver returned Unknown: {}",
                    check.reason_unknown.as_deref().unwrap_or("")
                ));
                return Ok(DiffResult {
                    equivalent: false,
                    distinguishing_input: None,
                    output_policy1: None,
                    output_policy2: None,
                    warnings: all_warnings,
                    solver_smt,
                    model_string: None,
                });
            }
        }
    }

    #[cfg(not(feature = "z3-analysis"))]
    {
        let _ = (plan, r1_match_idx, r2_match_idx);
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
/// To check this, we negate the statement and ask the solver:
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
    let mut registry = PathRegistry::new();

    if let Some(ref example) = config.example_input {
        registry.seed_sorts_from_value("input", example, config.max_loop_depth);
    }

    let schema_constraints = if let Some(ref schema) = config.input_schema {
        apply_schema_constraints(&mut registry, schema, "input", config.max_loop_depth)
    } else {
        vec![]
    };

    // --- Translate old policy ---
    let (old_result, old_constraints, old_path_cond, old_warnings) = {
        let mut translator = Translator::new(old_program, data, &mut registry, config);
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
        let mut translator = Translator::new(new_program, data, &mut registry, config);
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

    // ∃ input: old fires ∧ new does NOT fire
    let old_result_matches = old_result.equals_value(desired_output)?;
    let new_result_matches = new_result.equals_value(desired_output)?;
    let old_fires = SmtExpr::and2(old_path_cond, old_result_matches);
    let new_fires = SmtExpr::and2(new_path_cond, new_result_matches);

    let all_constraints: Vec<SmtExpr> = old_constraints
        .into_iter()
        .chain(new_constraints.into_iter())
        .collect();

    let (problem, plan) = build_problem(
        &registry,
        &all_constraints,
        &schema_constraints,
        &[old_fires, SmtExpr::not(new_fires)],
        config,
    );

    let solver_smt = maybe_render_smt(&problem, config);

    let mut all_warnings = old_warnings;
    all_warnings.extend(new_warnings);

    #[cfg(feature = "z3-analysis")]
    {
        let solution = z3_solver::solve(&problem)?;
        let check = solution.first().unwrap();
        match check.status {
            SmtStatus::Sat => {
                let input = extract_input(check, &plan);
                let model_string = if config.dump_model {
                    Some(format!("{:?}", check.values))
                } else {
                    None
                };
                return Ok(SubsumptionResult {
                    subsumes: false,
                    counterexample: Some(input),
                    warnings: all_warnings,
                    solver_smt,
                    model_string,
                });
            }
            SmtStatus::Unsat => {
                return Ok(SubsumptionResult {
                    subsumes: true,
                    counterexample: None,
                    warnings: all_warnings,
                    solver_smt,
                    model_string: None,
                });
            }
            SmtStatus::Unknown => {
                all_warnings.push(format!(
                    "Solver returned Unknown: {}",
                    check.reason_unknown.as_deref().unwrap_or("")
                ));
                return Ok(SubsumptionResult {
                    subsumes: false,
                    counterexample: None,
                    warnings: all_warnings,
                    solver_smt,
                    model_string: None,
                });
            }
        }
    }

    #[cfg(not(feature = "z3-analysis"))]
    {
        let _ = plan;
        Ok(SubsumptionResult {
            subsumes: false,
            counterexample: None,
            warnings: all_warnings,
            solver_smt,
            model_string: None,
        })
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
    /// Each entry is `("file.rego:line", true/false, "expression text")` indicating
    /// whether the condition on that line was tested as true or false,
    /// with the trimmed source line for display.
    pub condition_coverage: Vec<(String, bool, String)>,
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

// ---------------------------------------------------------------------------
// Prepared Test Suite (external-solver / WASM path)
// ---------------------------------------------------------------------------

/// A condition-coverage target for Phase 2 of test-suite generation.
#[derive(Debug, Clone)]
struct ConditionTarget {
    /// Source line this condition belongs to.
    line_key: (String, usize),
    /// Path condition required to reach this assertion point.
    pre_path_condition: SmtExpr,
    /// Negated assertion condition (testing the false-branch).
    negated_condition: SmtExpr,
    /// Trimmed source line text for display.
    expression_text: String,
}

/// A stateful test-suite generator for use with an external solver.
///
/// Created by [`prepare_test_suite`].  The caller drives the loop:
///
/// ```text
/// let mut suite = prepare_test_suite(...)?;
/// while let Some(problem) = suite.next_problem() {
///     let smt = problem.render_smt_lib2();
///     let solution = external_solve(smt);          // e.g. Z3 WASM
///     suite.record_solution(&solution)?;
/// }
/// let result = suite.result();
/// ```
#[derive(Debug)]
pub struct PreparedTestSuite {
    // --- Phase 1: Line Coverage ---

    /// Base SMT problem with declarations, constraints, schema, path_condition,
    /// output constraint, and line-condition extractions — but *without* any
    /// line-targeting assertion.
    base_problem: SmtProblem,
    /// Extraction plan for reconstructing `input` from solver model values.
    plan: Vec<PathExtraction>,
    /// All coverable `(source_file, line)` keys, in iteration order.
    all_lines: Vec<(String, usize)>,
    /// SMT condition for each coverable line (parallel to `all_lines`).
    line_exprs: Vec<SmtExpr>,
    /// Index into `base_problem.extractions` where line-coverage booleans
    /// start.  Extractions `[line_extraction_start .. +all_lines.len()]`
    /// correspond 1-to-1 with `all_lines`.
    line_extraction_start: usize,
    /// Lines already proved covered (or unreachable).
    covered: std::collections::BTreeSet<usize>,
    /// Test cases generated so far.
    test_cases: Vec<TestCase>,
    /// Accumulated warnings.
    warnings: Vec<String>,
    /// Config snapshot.
    config: AnalysisConfig,
    /// Maximum number of test cases to generate.
    max_tests: usize,
    /// Index of the line currently being targeted (set by `next_problem`).
    current_target: Option<usize>,

    // --- Phase tracking ---

    /// Whether we have transitioned to the condition-coverage phase.
    in_condition_phase: bool,

    // --- Phase 2: Condition Coverage ---

    /// Base SMT problem for condition coverage (constraints + schema only,
    /// no path_condition or output constraint).
    cond_base_problem: SmtProblem,
    /// Extraction plan for reconstructing `input` from cond solver model.
    cond_plan: Vec<PathExtraction>,
    /// Ordered condition targets (one per unique assertion line).
    cond_targets: Vec<ConditionTarget>,
    /// Ordered condition-line keys (parallel to cond_targets and cond_record
    /// extractions).
    cond_lines_ordered: Vec<(String, usize)>,
    /// Where line-condition extractions start in `cond_base_problem`.
    cond_line_extraction_start: usize,
    /// Where condition-record value extractions start in `cond_base_problem`.
    cond_record_extraction_start: usize,
    /// Condition targets already resolved.
    cond_done: std::collections::BTreeSet<usize>,
    /// Currently targeted condition index (Phase 2).
    current_cond_target: Option<usize>,
    /// Total condition-coverage goals (2 × number of conditions).
    condition_goals: usize,
    /// Condition-coverage goals satisfied so far.
    condition_goals_covered: usize,
}

impl PreparedTestSuite {
    /// Return the next SMT problem to solve, or `None` if done.
    ///
    /// Phase 1 returns line-coverage problems; Phase 2 returns
    /// condition-coverage problems.
    pub fn next_problem(&mut self) -> Option<PreparedProblem> {
        if self.test_cases.len() >= self.max_tests {
            return None;
        }

        if !self.in_condition_phase {
            // Phase 1: Line Coverage
            for idx in 0..self.all_lines.len() {
                if self.covered.contains(&idx) {
                    continue;
                }
                self.current_target = Some(idx);
                let mut problem = self.base_problem.clone();
                problem.assert(self.line_exprs[idx].clone());
                return Some(PreparedProblem {
                    problem,
                    plan: self.plan.clone(),
                    warnings: self.warnings.clone(),
                    config: self.config.clone(),
                });
            }

            // Phase 1 exhausted → transition to Phase 2
            self.in_condition_phase = true;

            // Compute initial condition_goals_covered from Phase 1 results.
            // Lines covered in Phase 1 satisfy the "true-goal" for each
            // corresponding condition.
            let globally_covered: std::collections::BTreeSet<(String, usize)> = self
                .covered
                .iter()
                .filter_map(|&idx| self.all_lines.get(idx).cloned())
                .collect();
            for ct in &self.cond_targets {
                if globally_covered.contains(&ct.line_key) {
                    self.condition_goals_covered += 1;
                }
            }
        }

        // Phase 2: Condition Coverage
        if self.test_cases.len() >= self.max_tests {
            return None;
        }
        for idx in 0..self.cond_targets.len() {
            if self.cond_done.contains(&idx) {
                continue;
            }
            self.current_cond_target = Some(idx);
            let ct = &self.cond_targets[idx];
            let mut problem = self.cond_base_problem.clone();
            problem.assert(ct.pre_path_condition.clone());
            problem.assert(ct.negated_condition.clone());
            return Some(PreparedProblem {
                problem,
                plan: self.cond_plan.clone(),
                warnings: self.warnings.clone(),
                config: self.config.clone(),
            });
        }

        None
    }

    /// Record the solver's answer for the current target.
    ///
    /// In Phase 1, records line coverage.  In Phase 2, records condition
    /// coverage.  Returns the test case on SAT, or `None` on UNSAT/Unknown.
    pub fn record_solution(
        &mut self,
        check: &regorus_smt::SmtCheckResult,
    ) -> Option<TestCase> {
        if !self.in_condition_phase {
            self.record_line_solution(check)
        } else {
            self.record_condition_solution(check)
        }
    }

    /// Phase 1: record a line-coverage solver result.
    fn record_line_solution(
        &mut self,
        check: &regorus_smt::SmtCheckResult,
    ) -> Option<TestCase> {
        let idx = self.current_target.take()?;

        match check.status {
            regorus_smt::SmtStatus::Sat => {
                let input = extract_input(check, &self.plan);

                let mut covered = Vec::new();
                for (i, lk) in self.all_lines.iter().enumerate() {
                    let ext_idx = self.line_extraction_start + i;
                    if let Some(regorus_smt::SmtValue::Bool(true)) =
                        check.values.get(ext_idx)
                    {
                        covered.push(lk.clone());
                        self.covered.insert(i);
                    }
                }

                let tc = TestCase {
                    input,
                    covered_lines: covered,
                    condition_coverage: Vec::new(),
                };
                self.test_cases.push(tc.clone());
                Some(tc)
            }
            regorus_smt::SmtStatus::Unsat => {
                self.covered.insert(idx);
                self.warnings.push(format!(
                    "Line {}:{} is unreachable (UNSAT)",
                    self.all_lines[idx].0, self.all_lines[idx].1,
                ));
                None
            }
            regorus_smt::SmtStatus::Unknown => {
                self.warnings.push(format!(
                    "Solver returned Unknown for line {}:{}",
                    self.all_lines[idx].0, self.all_lines[idx].1,
                ));
                None
            }
        }
    }

    /// Phase 2: record a condition-coverage solver result.
    fn record_condition_solution(
        &mut self,
        check: &regorus_smt::SmtCheckResult,
    ) -> Option<TestCase> {
        let idx = self.current_cond_target.take()?;
        self.cond_done.insert(idx);

        match check.status {
            regorus_smt::SmtStatus::Sat => {
                let input = extract_input(check, &self.cond_plan);

                // Which source lines does this model cover?
                let mut covered_lines = Vec::new();
                for (i, lk) in self.all_lines.iter().enumerate() {
                    let ext_idx = self.cond_line_extraction_start + i;
                    if let Some(regorus_smt::SmtValue::Bool(true)) =
                        check.values.get(ext_idx)
                    {
                        covered_lines.push(lk.clone());
                        self.covered.insert(i);
                    }
                }

                // Build condition_coverage:
                // The targeted condition was tested as false.
                let ct = &self.cond_targets[idx];
                let mut cond_cov = Vec::new();
                cond_cov.push((
                    format!("{}:{}", ct.line_key.0, ct.line_key.1),
                    false,
                    ct.expression_text.clone(),
                ));
                // Check which other conditions evaluate to true in this model.
                for (oi, other_key) in self.cond_lines_ordered.iter().enumerate() {
                    let ext_idx = self.cond_record_extraction_start + oi;
                    if let Some(regorus_smt::SmtValue::Bool(true)) =
                        check.values.get(ext_idx)
                    {
                        let expr_text = self.cond_targets.get(oi)
                            .map(|t| t.expression_text.clone())
                            .unwrap_or_default();
                        cond_cov.push((
                            format!("{}:{}", other_key.0, other_key.1),
                            true,
                            expr_text,
                        ));
                    }
                }

                self.condition_goals_covered += 1;

                let tc = TestCase {
                    input,
                    covered_lines,
                    condition_coverage: cond_cov,
                };
                self.test_cases.push(tc.clone());
                Some(tc)
            }
            regorus_smt::SmtStatus::Unsat => {
                // Condition can never be false → tautological, counts as covered.
                self.condition_goals_covered += 1;
                let ct = &self.cond_targets[idx];
                self.warnings.push(format!(
                    "Condition at {}:{} can never be false (tautological, UNSAT)",
                    ct.line_key.0, ct.line_key.1,
                ));
                None
            }
            regorus_smt::SmtStatus::Unknown => {
                let ct = &self.cond_targets[idx];
                self.warnings.push(format!(
                    "Solver returned Unknown for condition-false at {}:{}",
                    ct.line_key.0, ct.line_key.1,
                ));
                None
            }
        }
    }

    /// Consume the suite and return the final result.
    pub fn result(self) -> TestSuiteResult {
        let coverable = self.all_lines.len();
        let covered = self.covered.len();
        let solver_smt = if self.config.dump_smt {
            Some(regorus_smt::render_problem(&self.base_problem))
        } else {
            None
        };
        TestSuiteResult {
            test_cases: self.test_cases,
            coverable_lines: coverable,
            covered_lines: covered,
            condition_goals: self.condition_goals,
            condition_goals_covered: self.condition_goals_covered,
            warnings: self.warnings,
            solver_smt,
        }
    }

    /// Number of coverable source lines.
    pub fn coverable_lines(&self) -> usize {
        self.all_lines.len()
    }

    /// Number of lines covered so far.
    pub fn covered_count(&self) -> usize {
        self.covered.len()
    }

    /// Total condition-coverage goals.
    pub fn condition_goals(&self) -> usize {
        self.condition_goals
    }

    /// Condition-coverage goals covered so far.
    pub fn condition_goals_covered(&self) -> usize {
        self.condition_goals_covered
    }

    /// Current accumulated warnings.
    pub fn current_warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Test cases generated so far.
    pub fn test_cases(&self) -> &[TestCase] {
        &self.test_cases
    }
}

/// Prepare a test-suite generator for use with an external solver.
///
/// This is the external-solver counterpart of [`generate_test_suite`].
/// It performs translation once and returns a [`PreparedTestSuite`]
/// whose `next_problem()` / `record_solution()` methods drive the
/// iterative coverage loop from the caller side (e.g. JavaScript).
pub fn prepare_test_suite(
    program: &Program,
    data: &Value,
    entry_point: &str,
    desired_output: Option<&Value>,
    config: &AnalysisConfig,
    max_tests: usize,
    condition_coverage: bool,
) -> anyhow::Result<PreparedTestSuite> {
    let mut registry = PathRegistry::new();

    if let Some(ref example) = config.example_input {
        registry.seed_sorts_from_value("input", example, config.max_loop_depth);
    }

    let schema_constraints = if let Some(ref schema) = config.input_schema {
        apply_schema_constraints(&mut registry, schema, "input", config.max_loop_depth)
    } else {
        vec![]
    };

    let (result, constraints, path_condition, pc_path_conditions, pc_conditions, warnings) = {
        let mut translator = Translator::new(program, data, &mut registry, config);
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

    // Build the base problem.
    let mut problem = SmtProblem::new();
    for decl in registry.declarations() {
        problem.declarations.push(decl.clone());
    }
    for c in &constraints {
        problem.assert(c.clone());
    }
    for c in &schema_constraints {
        problem.assert(c.clone());
    }
    problem.assert(path_condition);

    if let Some(desired) = desired_output {
        problem.assert(result.equals_value(desired)?);
    } else {
        problem.assert(result.is_defined());
    }

    if config.timeout_ms > 0 {
        problem.config.timeout_ms = Some(config.timeout_ms);
    }

    let plan = register_extractions(&mut problem, &registry);

    // Build line-condition map.
    let mut line_conditions: std::collections::BTreeMap<(String, usize), SmtExpr> =
        std::collections::BTreeMap::new();
    for (pc, span) in program.instruction_spans.iter().enumerate() {
        if let Some(span) = span {
            if let Some(cond) = pc_path_conditions.get(&pc) {
                let source_name = if span.source_index < program.sources.len() {
                    program.sources[span.source_index].name.clone()
                } else {
                    continue;
                };
                line_conditions.insert((source_name, span.line), cond.clone());
            }
        }
    }

    let all_lines: Vec<(String, usize)> = line_conditions.keys().cloned().collect();
    let line_exprs: Vec<SmtExpr> = all_lines
        .iter()
        .map(|lk| line_conditions[lk].clone())
        .collect();

    // Register line-coverage extractions.
    let line_extraction_start = problem.extractions.len();
    for (lk, cond) in &line_conditions {
        problem.add_extraction(
            format!("line_{}_{}", lk.0, lk.1),
            cond.clone(),
            regorus_smt::SmtSort::Bool,
            true,
        );
    }

    // --- Phase 2: Condition Coverage setup ---

    let mut cond_base_problem = SmtProblem::new();
    let mut cond_plan = Vec::new();
    let mut cond_line_extraction_start = 0;
    let mut cond_record_extraction_start = 0;
    let mut cond_lines_ordered = Vec::new();
    let mut cond_targets = Vec::new();
    let mut condition_goals = 0;

    if condition_coverage && !pc_conditions.is_empty() {
        // Build condition-coverage base problem:
        // same declarations & constraints/schema, but NO path_condition or output.
        for decl in registry.declarations() {
            cond_base_problem.declarations.push(decl.clone());
        }
        for c in constraints.iter().chain(schema_constraints.iter()) {
            cond_base_problem.assert(c.clone());
        }
        if config.timeout_ms > 0 {
            cond_base_problem.config.timeout_ms = Some(config.timeout_ms);
        }
        cond_plan = register_extractions(&mut cond_base_problem, &registry);

        // Register line-condition extractions in cond_base_problem (for tracking
        // which lines each condition-coverage model additionally covers).
        cond_line_extraction_start = cond_base_problem.extractions.len();
        for (_lk, cond) in &line_conditions {
            cond_base_problem.add_extraction(
                "line_cond",
                cond.clone(),
                regorus_smt::SmtSort::Bool,
                true,
            );
        }

        // Group condition records by source line.
        let mut cond_by_line: std::collections::BTreeMap<
            (String, usize),
            Vec<&translator::ConditionRecord>,
        > = std::collections::BTreeMap::new();
        for rec in &pc_conditions {
            if let Some(span) = program
                .instruction_spans
                .get(rec.pc)
                .and_then(|s| s.as_ref())
            {
                if span.source_index < program.sources.len() {
                    let source_name = program.sources[span.source_index].name.clone();
                    cond_by_line
                        .entry((source_name, span.line))
                        .or_default()
                        .push(rec);
                }
            }
        }

        cond_lines_ordered = cond_by_line.keys().cloned().collect();
        condition_goals = cond_by_line.len() * 2;

        // Register condition-value extractions.
        cond_record_extraction_start = cond_base_problem.extractions.len();
        for (_lk, recs) in &cond_by_line {
            let rec = recs.last().unwrap();
            cond_base_problem.add_extraction(
                "cond_val",
                rec.condition.clone(),
                regorus_smt::SmtSort::Bool,
                true,
            );
        }

        // Build condition targets.
        cond_targets = cond_by_line
            .iter()
            .map(|(line_key, recs)| {
                let rec = recs.last().unwrap();
                let expr_text = get_source_line(program, line_key);
                ConditionTarget {
                    line_key: line_key.clone(),
                    pre_path_condition: rec.pre_path_condition.clone(),
                    negated_condition: SmtExpr::not(rec.condition.clone()),
                    expression_text: expr_text,
                }
            })
            .collect();
    }

    Ok(PreparedTestSuite {
        base_problem: problem,
        plan,
        all_lines,
        line_exprs,
        line_extraction_start,
        covered: std::collections::BTreeSet::new(),
        test_cases: Vec::new(),
        warnings,
        config: config.clone(),
        max_tests,
        current_target: None,
        in_condition_phase: false,
        cond_base_problem,
        cond_plan,
        cond_targets,
        cond_lines_ordered,
        cond_line_extraction_start,
        cond_record_extraction_start,
        cond_done: std::collections::BTreeSet::new(),
        current_cond_target: None,
        condition_goals,
        condition_goals_covered: 0,
    })
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
#[cfg(feature = "z3-analysis")]
pub fn generate_test_suite(
    program: &Program,
    data: &Value,
    entry_point: &str,
    desired_output: Option<&Value>,
    config: &AnalysisConfig,
    max_tests: usize,
    condition_coverage: bool,
) -> anyhow::Result<TestSuiteResult> {
    let mut registry = PathRegistry::new();

    if let Some(ref example) = config.example_input {
        registry.seed_sorts_from_value("input", example, config.max_loop_depth);
    }

    let schema_constraints = if let Some(ref schema) = config.input_schema {
        apply_schema_constraints(&mut registry, schema, "input", config.max_loop_depth)
    } else {
        vec![]
    };

    let (result, constraints, path_condition, pc_path_conditions, pc_conditions, warnings) = {
        let mut translator = Translator::new(program, data, &mut registry, config);
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

    // Build base assertions (constraints + schema + path_condition + output).
    let mut base_assertions: Vec<SmtExpr> = Vec::new();
    base_assertions.extend(constraints.iter().cloned());
    base_assertions.extend(schema_constraints.iter().cloned());
    base_assertions.push(path_condition);

    if let Some(desired) = desired_output {
        base_assertions.push(result.equals_value(desired)?);
    } else {
        base_assertions.push(result.is_defined());
    }

    // Build a map: (source_file, line) → SmtExpr condition.
    let mut line_conditions: std::collections::BTreeMap<(String, usize), SmtExpr> =
        std::collections::BTreeMap::new();

    for (pc, span) in program.instruction_spans.iter().enumerate() {
        if let Some(span) = span {
            if let Some(cond) = pc_path_conditions.get(&pc) {
                let source_name = if span.source_index < program.sources.len() {
                    program.sources[span.source_index].name.clone()
                } else {
                    continue;
                };
                line_conditions.insert((source_name, span.line), cond.clone());
            }
        }
    }

    let coverable_lines = line_conditions.len();
    let mut globally_covered: std::collections::BTreeSet<(String, usize)> =
        std::collections::BTreeSet::new();
    let mut test_cases: Vec<TestCase> = Vec::new();
    let mut all_warnings = warnings;

    // Build the base problem (without line-specific assertions).
    let mut problem = SmtProblem::new();
    for decl in registry.declarations() {
        problem.declarations.push(decl.clone());
    }
    for a in &base_assertions {
        problem.assert(a.clone());
    }
    if config.timeout_ms > 0 {
        problem.config.timeout_ms = Some(config.timeout_ms);
    }
    let plan = register_extractions(&mut problem, &registry);

    // Register line condition extractions so we can check which lines
    // are covered by each model.
    let line_extraction_start = problem.extractions.len();
    let all_lines: Vec<(String, usize)> = line_conditions.keys().cloned().collect();
    for (line_key, cond) in &line_conditions {
        problem.add_extraction(
            format!("line_{}_{}", line_key.0, line_key.1),
            cond.clone(),
            regorus_smt::SmtSort::Bool,
            true,
        );
    }

    let solver_smt = maybe_render_smt(&problem, config);

    // Use the incremental solver for push/pop per target line.
    let mut solver = z3_solver::IncrementalSolver::new(&problem)?;

    for (line_idx, target_line) in all_lines.iter().enumerate() {
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

        solver.push();
        solver.assert_expr(&cond);

        let check = solver.check_and_extract(&problem)?;
        match check.status {
            SmtStatus::Sat => {
                let input = extract_input(&check, &plan);

                // Determine all lines covered by this model.
                let mut covered = Vec::new();
                for (i, lk) in all_lines.iter().enumerate() {
                    let ext_idx = line_extraction_start + i;
                    if let Some(regorus_smt::SmtValue::Bool(true)) =
                        check.values.get(ext_idx)
                    {
                        covered.push(lk.clone());
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
            SmtStatus::Unsat => {
                globally_covered.insert(target_line.clone());
                all_warnings.push(format!(
                    "Line {}:{} is unreachable (UNSAT)",
                    target_line.0, target_line.1
                ));
            }
            SmtStatus::Unknown => {
                all_warnings.push(format!(
                    "Solver returned Unknown for line {}:{}",
                    target_line.0, target_line.1
                ));
            }
        }

        solver.pop(1);
    }

    let covered_count = globally_covered.len();

    // ── Phase 2: Condition coverage ──────────────────────────────────────
    let mut condition_goals: usize = 0;
    let mut condition_goals_covered: usize = 0;

    if condition_coverage && !pc_conditions.is_empty() {
        // Build a second solver with base constraints + schema (no output/path_condition).
        let mut cond_problem = SmtProblem::new();
        for decl in registry.declarations() {
            cond_problem.declarations.push(decl.clone());
        }
        for c in constraints.iter().chain(schema_constraints.iter()) {
            cond_problem.assert(c.clone());
        }
        if config.timeout_ms > 0 {
            cond_problem.config.timeout_ms = Some(config.timeout_ms);
        }
        let _cond_plan = register_extractions(&mut cond_problem, &registry);

        // Register line condition extractions for coverage tracking.
        let cond_line_ext_start = cond_problem.extractions.len();
        for (_lk, cond) in &line_conditions {
            cond_problem.add_extraction("line_cond", cond.clone(), regorus_smt::SmtSort::Bool, true);
        }

        // Register condition record extractions.
        let mut cond_by_line: std::collections::BTreeMap<
            (String, usize),
            Vec<&translator::ConditionRecord>,
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

        condition_goals = cond_by_line.len() * 2;

        for line_key in cond_by_line.keys() {
            if globally_covered.contains(line_key) {
                condition_goals_covered += 1;
            }
        }

        // Register condition extractions so we can check true-goal satisfaction.
        let cond_rec_ext_start = cond_problem.extractions.len();
        let cond_lines_ordered: Vec<(String, usize)> = cond_by_line.keys().cloned().collect();
        for (_lk, recs) in &cond_by_line {
            let rec = recs.last().unwrap();
            cond_problem.add_extraction("cond_val", rec.condition.clone(), regorus_smt::SmtSort::Bool, true);
        }

        let mut cond_solver = z3_solver::IncrementalSolver::new(&cond_problem)?;

        for (ci, (line_key, recs)) in cond_by_line.iter().enumerate() {
            if test_cases.len() >= max_tests {
                break;
            }

            let rec = recs.last().unwrap();

            cond_solver.push();
            cond_solver.assert_expr(&rec.pre_path_condition);
            cond_solver.assert_expr(&SmtExpr::not(rec.condition.clone()));

            let check = cond_solver.check_and_extract(&cond_problem)?;
            match check.status {
                SmtStatus::Sat => {
                    let input = extract_input(&check, &_cond_plan);

                    let mut covered_lines_for_tc = Vec::new();
                    for (i, lk) in all_lines.iter().enumerate() {
                        let ext_idx = cond_line_ext_start + i;
                        if let Some(regorus_smt::SmtValue::Bool(true)) =
                            check.values.get(ext_idx)
                        {
                            covered_lines_for_tc.push(lk.clone());
                        }
                    }
                    for l in &covered_lines_for_tc {
                        globally_covered.insert(l.clone());
                    }

                    let mut cond_cov = Vec::new();
                    cond_cov.push((
                        format!("{}:{}", line_key.0, line_key.1),
                        false,
                        get_source_line(program, line_key),
                    ));

                    for (oi, (other_key, _)) in cond_by_line.iter().enumerate() {
                        let ext_idx = cond_rec_ext_start + oi;
                        if let Some(regorus_smt::SmtValue::Bool(true)) =
                            check.values.get(ext_idx)
                        {
                            cond_cov.push((
                                format!("{}:{}", other_key.0, other_key.1),
                                true,
                                get_source_line(program, other_key),
                            ));
                        }
                    }

                    condition_goals_covered += 1;
                    test_cases.push(TestCase {
                        input,
                        covered_lines: covered_lines_for_tc,
                        condition_coverage: cond_cov,
                    });
                }
                SmtStatus::Unsat => {
                    condition_goals_covered += 1;
                    all_warnings.push(format!(
                        "Condition at {}:{} can never be false (tautological, UNSAT)",
                        line_key.0, line_key.1
                    ));
                }
                SmtStatus::Unknown => {
                    all_warnings.push(format!(
                        "Solver returned Unknown for condition-false at {}:{}",
                        line_key.0, line_key.1
                    ));
                }
            }

            cond_solver.pop(1);
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
