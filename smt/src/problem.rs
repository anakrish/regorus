// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Problem and solution types for shipping analysis queries across boundaries.
//!
//! An [`SmtProblem`] is a self-contained description of an SMT query:
//! declarations, assertions, and a specification of what values to extract
//! from the model.  It can be serialized to JSON and sent to any solver
//! (native Z3, `z3-solver` npm in JS, or rendered to SMT-LIB2 text).
//!
//! An [`SmtSolution`] is the typed result returned by the solver.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::expr::{SmtDecl, SmtExpr, SmtSort};

// ---------------------------------------------------------------------------
// Problem
// ---------------------------------------------------------------------------

/// A complete SMT analysis problem, ready to be solved.
///
/// This is the unit of work that crosses the WASM→JS boundary (as JSON)
/// or stays in-process for the native Z3 backend.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmtProblem {
    /// All constant and function declarations.
    ///
    /// Indices into this vec are referenced by [`SmtExpr::Const`] and
    /// [`SmtExpr::App`].
    pub declarations: Vec<SmtDecl>,

    /// Top-level assertions.
    ///
    /// Each assertion is an [`SmtExpr`] of sort Bool.  The solver is asked
    /// to find a model satisfying the conjunction of all assertions.
    pub assertions: Vec<SmtExpr>,

    /// Solver-level push/pop structure.
    ///
    /// Commands are executed in order: `Assert(idx)` asserts the expression
    /// at `assertions[idx]`, `Push` / `Pop(n)` control the solver stack,
    /// `CheckSat` triggers a satisfiability check, and so on.
    ///
    /// If empty, the default behavior is: assert all assertions, then
    /// check-sat once.
    pub commands: Vec<SmtCommand>,

    /// What values to extract from the model when the result is SAT.
    ///
    /// Each entry specifies an expression to evaluate in the model
    /// (typically a declared constant) and the expected sort.
    pub extractions: Vec<SmtExtraction>,

    /// Solver configuration.
    pub config: SmtConfig,

    /// Path registry metadata — maps declared variable ids to their
    /// semantic meaning (e.g., `"input.user.role"`).
    ///
    /// This is not used by the solver itself but is needed by the host
    /// to reconstruct structured JSON from flat model values.
    pub path_info: Vec<SmtPathInfo>,
}

/// A solver command in a structured command sequence.
///
/// When [`SmtProblem::commands`] is non-empty, the solver executes these
/// in order instead of the default "assert all + check-sat" behavior.
/// This supports incremental solving (push/pop) needed for test-suite
/// generation and coverage iteration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SmtCommand {
    /// Assert the expression at `assertions[index]`.
    Assert(usize),
    /// Assert an inline expression (not pre-registered in `assertions`).
    AssertExpr(SmtExpr),
    /// `(push)` — create a backtracking point.
    Push,
    /// `(pop n)` — backtrack `n` levels.
    Pop(u32),
    /// `(check-sat)` — check satisfiability.
    CheckSat,
    /// `(check-sat-assuming (lits...))` — check with assumptions.
    CheckSatAssuming(Vec<SmtExpr>),
    /// `(get-model)` — extract model values per the `extractions` spec.
    GetModel,
}

/// Specification of a value to extract from a satisfying model.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmtExtraction {
    /// A human-readable id for this extraction (e.g., `"input.user.role"`,
    /// `"line_42_hit"`).
    pub id: String,
    /// The expression to evaluate in the model.
    ///
    /// Typically this is `SmtExpr::Const(var_id)`, but it can be any
    /// expression (e.g., a complex formula whose truth value we want to
    /// check in the model for coverage analysis).
    pub expr: SmtExpr,
    /// The expected sort of the result (controls typed extraction).
    pub sort: SmtSort,
    /// Whether to enable model completion.
    ///
    /// When `true`, Z3 assigns a default value to variables not constrained
    /// by the model.  When `false`, such variables return `Undefined`.
    /// Corresponds to the `model_completion` parameter of `Z3_model_eval`.
    pub model_completion: bool,
}

/// Solver configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SmtConfig {
    /// Solver timeout in milliseconds.  `None` means no timeout.
    pub timeout_ms: Option<u32>,
    /// Whether to produce unsat cores on UNSAT results.
    pub produce_unsat_core: bool,
    /// Whether to produce proofs on UNSAT results.
    pub produce_proofs: bool,
}

/// Metadata mapping a declared variable to its semantic path.
///
/// Used by the host to reconstruct structured JSON from flat model values.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmtPathInfo {
    /// The declaration id (index into `SmtProblem::declarations`).
    pub decl_id: u32,
    /// The semantic path (e.g., `"input.user.role"`, `"input.servers[0].port"`).
    pub path: String,
    /// The sort of the value at this path.
    pub sort: SmtSort,
}

// ---------------------------------------------------------------------------
// Solution
// ---------------------------------------------------------------------------

/// The result of solving an SMT problem.
///
/// For simple (single check-sat) problems, `results` has one entry.
/// For incremental problems (multiple check-sat commands), it has one
/// entry per `CheckSat` / `CheckSatAssuming` command.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmtSolution {
    /// Results for each check-sat command, in order.
    pub results: Vec<SmtCheckResult>,
}

/// The result of a single check-sat invocation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmtCheckResult {
    /// The satisfiability result.
    pub status: SmtStatus,

    /// Extracted values (populated only when `status == Sat` and a
    /// `GetModel` command follows the `CheckSat`).
    ///
    /// Indexed in the same order as [`SmtProblem::extractions`].
    pub values: Vec<SmtValue>,

    /// Unsat core — indices into [`SmtProblem::assertions`].
    ///
    /// Populated only when `status == Unsat` and
    /// `SmtConfig::produce_unsat_core` is `true`.
    pub unsat_core: Vec<usize>,

    /// Reason string when `status == Unknown`.
    pub reason_unknown: Option<String>,

    /// Solver statistics (optional).
    pub stats: Option<SmtStats>,
}

/// Satisfiability result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmtStatus {
    /// The assertions are satisfiable.
    Sat,
    /// The assertions are unsatisfiable.
    Unsat,
    /// The solver could not determine satisfiability.
    Unknown,
}

/// A concrete value extracted from a Z3 model.
///
/// Each variant corresponds to the typed extraction methods on Z3 model
/// values: `as_bool`, `as_i64`, `as_real`, `get_string`, etc.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SmtValue {
    /// A boolean value.
    Bool(bool),
    /// An integer value.
    Int(i64),
    /// A rational value (numerator, denominator).
    Real(i64, i64),
    /// A string value.
    String(String),
    /// A bitvector value (value, bit-width).
    BitVec(i64, u32),
    /// The expression was not assigned a value by the model
    /// (model completion was off, or the variable was unconstrained).
    Undefined,
}

/// Solver statistics.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SmtStats {
    /// Wall-clock solve time in milliseconds.
    pub solve_time_ms: Option<u64>,
    /// Number of conflicts during search.
    pub num_conflicts: Option<u64>,
    /// Number of decisions during search.
    pub num_decisions: Option<u64>,
}

// ---------------------------------------------------------------------------
// Convenience impls
// ---------------------------------------------------------------------------

impl SmtProblem {
    /// Create a new empty problem.
    pub fn new() -> Self {
        Self {
            declarations: Vec::new(),
            assertions: Vec::new(),
            commands: Vec::new(),
            extractions: Vec::new(),
            config: SmtConfig::default(),
            path_info: Vec::new(),
        }
    }

    /// Declare a constant and return its id.
    pub fn declare_const(&mut self, name: impl Into<String>, sort: SmtSort) -> u32 {
        let id = self.declarations.len() as u32;
        self.declarations.push(SmtDecl::Const {
            id,
            name: name.into(),
            sort,
        });
        id
    }

    /// Declare a function and return its id.
    pub fn declare_fun(
        &mut self,
        name: impl Into<String>,
        arg_sorts: Vec<SmtSort>,
        ret_sort: SmtSort,
    ) -> u32 {
        let id = self.declarations.len() as u32;
        self.declarations.push(SmtDecl::Fun {
            id,
            name: name.into(),
            arg_sorts,
            ret_sort,
        });
        id
    }

    /// Add an assertion and return its index.
    pub fn assert(&mut self, expr: SmtExpr) -> usize {
        let idx = self.assertions.len();
        self.assertions.push(expr);
        idx
    }

    /// Add an extraction request.
    pub fn add_extraction(
        &mut self,
        id: impl Into<String>,
        expr: SmtExpr,
        sort: SmtSort,
        model_completion: bool,
    ) {
        self.extractions.push(SmtExtraction {
            id: id.into(),
            expr,
            sort,
            model_completion,
        });
    }

    /// Add path info for a declaration.
    pub fn add_path_info(&mut self, decl_id: u32, path: impl Into<String>, sort: SmtSort) {
        self.path_info.push(SmtPathInfo {
            decl_id,
            path: path.into(),
            sort,
        });
    }
}

impl Default for SmtProblem {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtSolution {
    /// Create a simple solution with one result.
    pub fn single(result: SmtCheckResult) -> Self {
        Self {
            results: alloc::vec![result],
        }
    }

    /// Get the first (and often only) result.
    pub fn first(&self) -> Option<&SmtCheckResult> {
        self.results.first()
    }

    /// Is the first result SAT?
    pub fn is_sat(&self) -> bool {
        self.first().map_or(false, |r| r.status == SmtStatus::Sat)
    }

    /// Is the first result UNSAT?
    pub fn is_unsat(&self) -> bool {
        self.first()
            .map_or(false, |r| r.status == SmtStatus::Unsat)
    }
}

impl SmtCheckResult {
    /// Create a SAT result with extracted values.
    pub fn sat(values: Vec<SmtValue>) -> Self {
        Self {
            status: SmtStatus::Sat,
            values,
            unsat_core: Vec::new(),
            reason_unknown: None,
            stats: None,
        }
    }

    /// Create an UNSAT result.
    pub fn unsat() -> Self {
        Self {
            status: SmtStatus::Unsat,
            values: Vec::new(),
            unsat_core: Vec::new(),
            reason_unknown: None,
            stats: None,
        }
    }

    /// Create an UNSAT result with a core.
    pub fn unsat_with_core(core: Vec<usize>) -> Self {
        Self {
            status: SmtStatus::Unsat,
            values: Vec::new(),
            unsat_core: core,
            reason_unknown: None,
            stats: None,
        }
    }

    /// Create an Unknown result.
    pub fn unknown(reason: impl Into<String>) -> Self {
        Self {
            status: SmtStatus::Unknown,
            values: Vec::new(),
            unsat_core: Vec::new(),
            reason_unknown: Some(reason.into()),
            stats: None,
        }
    }

    /// Get a value by index.
    pub fn get_value(&self, idx: usize) -> Option<&SmtValue> {
        self.values.get(idx)
    }

    /// Get a bool value by index.
    pub fn get_bool(&self, idx: usize) -> Option<bool> {
        match self.values.get(idx) {
            Some(SmtValue::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    /// Get an int value by index.
    pub fn get_int(&self, idx: usize) -> Option<i64> {
        match self.values.get(idx) {
            Some(SmtValue::Int(i)) => Some(*i),
            _ => None,
        }
    }

    /// Get a string value by index.
    pub fn get_string(&self, idx: usize) -> Option<&str> {
        match self.values.get(idx) {
            Some(SmtValue::String(s)) => Some(s),
            _ => None,
        }
    }
}
