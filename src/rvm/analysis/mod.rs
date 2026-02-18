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
            let line_constraints =
                lines_to_constraints(program, lines, &pc_path_conditions, &ctx, &mut extra_warnings);
            for lc in &line_constraints {
                solver.assert(lc);
            }
        }
    }
    if let Some(lines) = avoid_lines {
        if !lines.is_empty() {
            let line_constraints =
                lines_to_constraints(program, lines, &pc_path_conditions, &ctx, &mut extra_warnings);
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
        let source_idx = program
            .sources
            .iter()
            .position(|s| {
                s.name == *file
                    || s.name.ends_with(file.as_str())
                    || file.ends_with(s.name.as_str())
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
