// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Trait-based abstraction over SMT solvers.
//!
//! [`SmtContext`] defines the expression-builder interface and
//! [`SmtSolver`] defines the solving interface.  Together they allow
//! the analysis engine to be parametric over:
//!
//! - **Native Z3** (via the `z3` crate) — fast, in-process, not WASM-safe.
//! - **AST backend** ([`crate::backend::AstBackend`]) — builds a
//!   serializable [`SmtExpr`] tree, portable to any target including WASM.
//!
//! # Design principles
//!
//! 1. Every method maps 1:1 to a `Z3_mk_*` C API function.
//! 2. The associated type `Expr` is opaque to the caller — it could be a
//!    live `z3::ast::Dynamic<'ctx>` or a boxed `SmtExpr`.
//! 3. Default implementations are provided for operations that can be
//!    derived from primitive ones, so backends only *need* to implement
//!    the core subset.

use alloc::string::String;
use alloc::vec::Vec;

use crate::expr::SmtSort;
use crate::problem::{SmtCheckResult, SmtConfig, SmtStatus, SmtValue};

// ---------------------------------------------------------------------------
// SmtContext — expression builder
// ---------------------------------------------------------------------------

/// Expression-builder interface, parametric over the expression type.
///
/// The lifetime `'ctx` allows Z3-backed implementations where expressions
/// borrow from a context.  For the AST backend it is `'static`.
pub trait SmtContext<'ctx> {
    /// The expression type produced by this context.
    type Expr: Clone;

    // ── Sorts (for backends that need sort objects) ──────────────────
    // Most methods accept SmtSort directly; backends that need native sort
    // objects can cache them internally.

    // ── Literals ─────────────────────────────────────────────────────

    fn mk_true(&self) -> Self::Expr;
    fn mk_false(&self) -> Self::Expr;
    fn mk_bool(&self, b: bool) -> Self::Expr;
    fn mk_int(&self, n: i64) -> Self::Expr;
    fn mk_real(&self, num: i64, den: i64) -> Self::Expr;
    fn mk_string(&self, s: &str) -> Self::Expr;
    fn mk_bv(&self, val: i64, width: u32) -> Self::Expr;

    // ── Declarations ─────────────────────────────────────────────────

    /// Declare a constant of the given sort and return its expression.
    fn declare_const(&mut self, name: &str, sort: SmtSort) -> Self::Expr;

    /// Declare a function and return a callable handle.
    ///
    /// Returns a function id that can be passed to [`mk_app`].
    fn declare_fun(
        &mut self,
        name: &str,
        arg_sorts: &[SmtSort],
        ret_sort: SmtSort,
    ) -> u32;

    /// Apply a declared function to arguments.
    fn mk_app(&self, func_id: u32, args: &[Self::Expr]) -> Self::Expr;

    // ── Propositional ────────────────────────────────────────────────

    fn mk_not(&self, a: &Self::Expr) -> Self::Expr;
    fn mk_and(&self, args: &[Self::Expr]) -> Self::Expr;
    fn mk_or(&self, args: &[Self::Expr]) -> Self::Expr;
    fn mk_xor(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_implies(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_iff(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_ite(&self, c: &Self::Expr, t: &Self::Expr, e: &Self::Expr) -> Self::Expr;

    // ── Equality ─────────────────────────────────────────────────────

    fn mk_eq(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_distinct(&self, args: &[Self::Expr]) -> Self::Expr;

    // ── Arithmetic ───────────────────────────────────────────────────

    fn mk_add(&self, args: &[Self::Expr]) -> Self::Expr;
    fn mk_sub(&self, args: &[Self::Expr]) -> Self::Expr;
    fn mk_mul(&self, args: &[Self::Expr]) -> Self::Expr;
    fn mk_div(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_mod(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_rem(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_neg(&self, a: &Self::Expr) -> Self::Expr;

    /// Default implementation calls `mk_ite(mk_ge(a, mk_int(0)), a, mk_neg(a))`.
    fn mk_abs(&self, a: &Self::Expr) -> Self::Expr {
        let zero = self.mk_int(0);
        let ge = self.mk_ge(a, &zero);
        let neg = self.mk_neg(a);
        self.mk_ite(&ge, a, &neg)
    }

    fn mk_power(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;

    // ── Comparison ───────────────────────────────────────────────────

    fn mk_lt(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_le(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_gt(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_ge(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;

    // ── Coercion ─────────────────────────────────────────────────────

    fn mk_int2real(&self, a: &Self::Expr) -> Self::Expr;
    fn mk_real2int(&self, a: &Self::Expr) -> Self::Expr;
    fn mk_int2bv(&self, a: &Self::Expr, n: u32) -> Self::Expr;
    fn mk_bv2int(&self, a: &Self::Expr, signed: bool) -> Self::Expr;

    // ── Bitvector ────────────────────────────────────────────────────

    fn mk_bvand(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_bvor(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_bvxor(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_bvnot(&self, a: &Self::Expr) -> Self::Expr;
    fn mk_bvneg(&self, a: &Self::Expr) -> Self::Expr;
    fn mk_bvadd(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_bvsub(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_bvmul(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_bvudiv(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_bvshl(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_bvlshr(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_bvashr(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;

    // ── Sequences / Strings ──────────────────────────────────────────

    fn mk_seq_length(&self, a: &Self::Expr) -> Self::Expr;
    fn mk_seq_concat(&self, args: &[Self::Expr]) -> Self::Expr;
    fn mk_seq_contains(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_seq_prefix(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_seq_suffix(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_seq_at(&self, a: &Self::Expr, i: &Self::Expr) -> Self::Expr;
    fn mk_seq_index(&self, a: &Self::Expr, b: &Self::Expr, offset: &Self::Expr) -> Self::Expr;
    fn mk_seq_replace(
        &self,
        a: &Self::Expr,
        src: &Self::Expr,
        dst: &Self::Expr,
    ) -> Self::Expr;
    fn mk_seq_extract(
        &self,
        a: &Self::Expr,
        offset: &Self::Expr,
        length: &Self::Expr,
    ) -> Self::Expr;
    fn mk_str_lt(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_str_le(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;

    // ── String ↔ numeric ─────────────────────────────────────────────

    fn mk_int_to_str(&self, a: &Self::Expr) -> Self::Expr;
    fn mk_str_to_int(&self, a: &Self::Expr) -> Self::Expr;

    // ── Regular expressions ──────────────────────────────────────────

    fn mk_seq_to_re(&self, a: &Self::Expr) -> Self::Expr;
    fn mk_seq_in_re(&self, a: &Self::Expr, re: &Self::Expr) -> Self::Expr;
    fn mk_re_star(&self, a: &Self::Expr) -> Self::Expr;
    fn mk_re_plus(&self, a: &Self::Expr) -> Self::Expr;
    fn mk_re_option(&self, a: &Self::Expr) -> Self::Expr;
    fn mk_re_union(&self, args: &[Self::Expr]) -> Self::Expr;
    fn mk_re_intersect(&self, args: &[Self::Expr]) -> Self::Expr;
    fn mk_re_concat(&self, args: &[Self::Expr]) -> Self::Expr;
    fn mk_re_range(&self, lo: &Self::Expr, hi: &Self::Expr) -> Self::Expr;
    fn mk_re_complement(&self, a: &Self::Expr) -> Self::Expr;
    fn mk_re_diff(&self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;
    fn mk_re_loop(&self, a: &Self::Expr, lo: u32, hi: u32) -> Self::Expr;
    fn mk_re_full(&self, sort: SmtSort) -> Self::Expr;
    fn mk_re_empty(&self, sort: SmtSort) -> Self::Expr;
    fn mk_re_allchar(&self, sort: SmtSort) -> Self::Expr;

    // ── Quantifiers ──────────────────────────────────────────────────

    fn mk_forall(&self, vars: &[(String, SmtSort)], body: &Self::Expr) -> Self::Expr;
    fn mk_exists(&self, vars: &[(String, SmtSort)], body: &Self::Expr) -> Self::Expr;
    fn mk_bound(&self, idx: u32, sort: SmtSort) -> Self::Expr;
}

// ---------------------------------------------------------------------------
// SmtSolver — solving interface
// ---------------------------------------------------------------------------

/// Solving interface.
pub trait SmtSolver<'ctx>: SmtContext<'ctx> {
    /// Configure the solver.
    fn configure(&mut self, config: &SmtConfig);

    /// Assert an expression.
    fn assert(&mut self, expr: &Self::Expr);

    /// Push a backtracking point.
    fn push(&mut self);

    /// Pop `n` backtracking points.
    fn pop(&mut self, n: u32);

    /// Check satisfiability.
    fn check_sat(&mut self) -> SmtStatus;

    /// Check satisfiability under assumptions.
    fn check_sat_assuming(&mut self, assumptions: &[Self::Expr]) -> SmtStatus;

    /// Extract a value from the current model.
    ///
    /// Only valid after `check_sat()` returned `Sat`.
    fn eval(&self, expr: &Self::Expr, model_completion: bool) -> SmtValue;

    /// Get unsat core (assertion indices or labels).
    ///
    /// Only valid after `check_sat()` returned `Unsat` and
    /// `produce_unsat_core` was enabled.
    fn get_unsat_core(&self) -> Vec<usize>;

    /// Get the reason for an `Unknown` result.
    fn get_reason_unknown(&self) -> Option<String>;

    /// Run a full problem and return the solution.
    ///
    /// Default implementation interprets the command sequence (or uses
    /// the simple assert-all-and-check if commands is empty).
    fn solve(&mut self, problem: &crate::problem::SmtProblem) -> crate::problem::SmtSolution {
        use crate::problem::{SmtCommand, SmtSolution};

        self.configure(&problem.config);

        // Build expression cache from declarations.
        let mut decl_exprs: Vec<Self::Expr> = Vec::new();
        for decl in &problem.declarations {
            match decl {
                crate::expr::SmtDecl::Const { name, sort, .. } => {
                    decl_exprs.push(self.declare_const(name, *sort));
                }
                crate::expr::SmtDecl::Fun {
                    name,
                    arg_sorts,
                    ret_sort,
                    ..
                } => {
                    let _fid = self.declare_fun(name, arg_sorts, *ret_sort);
                    // Push a placeholder — function exprs are created via mk_app.
                    decl_exprs.push(self.mk_true());
                }
            }
        }

        // Convert SmtExpr assertions to backend expressions.
        let assertion_exprs: Vec<Self::Expr> = problem
            .assertions
            .iter()
            .map(|e| self.convert_expr(e, &decl_exprs))
            .collect();

        let mut results = Vec::new();

        if problem.commands.is_empty() {
            // Simple mode.
            for expr in &assertion_exprs {
                self.assert(expr);
            }
            let status = self.check_sat();
            let values = if status == SmtStatus::Sat {
                self.extract_values(problem, &decl_exprs)
            } else {
                Vec::new()
            };
            let unsat_core = if status == SmtStatus::Unsat && problem.config.produce_unsat_core {
                self.get_unsat_core()
            } else {
                Vec::new()
            };
            let reason_unknown = if status == SmtStatus::Unknown {
                self.get_reason_unknown()
            } else {
                None
            };
            results.push(SmtCheckResult {
                status,
                values,
                unsat_core,
                reason_unknown,
                stats: None,
            });
        } else {
            // Command mode.
            for cmd in &problem.commands {
                match cmd {
                    SmtCommand::Assert(idx) => {
                        if let Some(expr) = assertion_exprs.get(*idx) {
                            self.assert(expr);
                        }
                    }
                    SmtCommand::AssertExpr(smt_expr) => {
                        let expr = self.convert_expr(smt_expr, &decl_exprs);
                        self.assert(&expr);
                    }
                    SmtCommand::Push => self.push(),
                    SmtCommand::Pop(n) => self.pop(*n),
                    SmtCommand::CheckSat => {
                        let status = self.check_sat();
                        results.push(SmtCheckResult {
                            status,
                            values: Vec::new(),
                            unsat_core: Vec::new(),
                            reason_unknown: if status == SmtStatus::Unknown {
                                self.get_reason_unknown()
                            } else {
                                None
                            },
                            stats: None,
                        });
                    }
                    SmtCommand::CheckSatAssuming(lits) => {
                        let lit_exprs: Vec<Self::Expr> = lits
                            .iter()
                            .map(|e| self.convert_expr(e, &decl_exprs))
                            .collect();
                        let status = self.check_sat_assuming(&lit_exprs);
                        results.push(SmtCheckResult {
                            status,
                            values: Vec::new(),
                            unsat_core: Vec::new(),
                            reason_unknown: if status == SmtStatus::Unknown {
                                self.get_reason_unknown()
                            } else {
                                None
                            },
                            stats: None,
                        });
                    }
                    SmtCommand::GetModel => {
                        if let Some(last) = results.last_mut() {
                            if last.status == SmtStatus::Sat {
                                last.values = self.extract_values(problem, &decl_exprs);
                            }
                            if last.status == SmtStatus::Unsat
                                && problem.config.produce_unsat_core
                            {
                                last.unsat_core = self.get_unsat_core();
                            }
                        }
                    }
                }
            }
        }

        SmtSolution { results }
    }

    /// Convert an [`SmtExpr`] into this backend's expression type.
    ///
    /// `decl_exprs` maps declaration ids to already-created backend exprs.
    fn convert_expr(
        &self,
        expr: &crate::expr::SmtExpr,
        decl_exprs: &[Self::Expr],
    ) -> Self::Expr {
        use crate::expr::SmtExpr as E;
        match expr {
            E::True => self.mk_true(),
            E::False => self.mk_false(),
            E::IntLit(n) => self.mk_int(*n),
            E::RealLit(n, d) => self.mk_real(*n, *d),
            E::StringLit(s) => self.mk_string(s),
            E::BvLit(v, w) => self.mk_bv(*v, *w),

            E::Const(id) => decl_exprs
                .get(*id as usize)
                .cloned()
                .unwrap_or_else(|| self.mk_true()),

            E::App(id, args) => {
                let converted: Vec<Self::Expr> =
                    args.iter().map(|a| self.convert_expr(a, decl_exprs)).collect();
                self.mk_app(*id, &converted)
            }

            E::Not(a) => {
                let a = self.convert_expr(a, decl_exprs);
                self.mk_not(&a)
            }
            E::And(args) => {
                let args: Vec<_> = args.iter().map(|a| self.convert_expr(a, decl_exprs)).collect();
                self.mk_and(&args)
            }
            E::Or(args) => {
                let args: Vec<_> = args.iter().map(|a| self.convert_expr(a, decl_exprs)).collect();
                self.mk_or(&args)
            }
            E::Xor(a, b) => {
                let a = self.convert_expr(a, decl_exprs);
                let b = self.convert_expr(b, decl_exprs);
                self.mk_xor(&a, &b)
            }
            E::Implies(a, b) => {
                let a = self.convert_expr(a, decl_exprs);
                let b = self.convert_expr(b, decl_exprs);
                self.mk_implies(&a, &b)
            }
            E::Iff(a, b) => {
                let a = self.convert_expr(a, decl_exprs);
                let b = self.convert_expr(b, decl_exprs);
                self.mk_iff(&a, &b)
            }
            E::Ite(c, t, e) => {
                let c = self.convert_expr(c, decl_exprs);
                let t = self.convert_expr(t, decl_exprs);
                let e = self.convert_expr(e, decl_exprs);
                self.mk_ite(&c, &t, &e)
            }
            E::Eq(a, b) => {
                let a = self.convert_expr(a, decl_exprs);
                let b = self.convert_expr(b, decl_exprs);
                self.mk_eq(&a, &b)
            }
            E::Distinct(args) => {
                let args: Vec<_> = args.iter().map(|a| self.convert_expr(a, decl_exprs)).collect();
                self.mk_distinct(&args)
            }

            E::Add(args) => {
                let args: Vec<_> = args.iter().map(|a| self.convert_expr(a, decl_exprs)).collect();
                self.mk_add(&args)
            }
            E::Sub(args) => {
                let args: Vec<_> = args.iter().map(|a| self.convert_expr(a, decl_exprs)).collect();
                self.mk_sub(&args)
            }
            E::Mul(args) => {
                let args: Vec<_> = args.iter().map(|a| self.convert_expr(a, decl_exprs)).collect();
                self.mk_mul(&args)
            }
            E::Div(a, b) => {
                let a = self.convert_expr(a, decl_exprs);
                let b = self.convert_expr(b, decl_exprs);
                self.mk_div(&a, &b)
            }
            E::Mod(a, b) => {
                let a = self.convert_expr(a, decl_exprs);
                let b = self.convert_expr(b, decl_exprs);
                self.mk_mod(&a, &b)
            }
            E::Rem(a, b) => {
                let a = self.convert_expr(a, decl_exprs);
                let b = self.convert_expr(b, decl_exprs);
                self.mk_rem(&a, &b)
            }
            E::Neg(a) => {
                let a = self.convert_expr(a, decl_exprs);
                self.mk_neg(&a)
            }
            E::Abs(a) => {
                let a = self.convert_expr(a, decl_exprs);
                self.mk_abs(&a)
            }
            E::Power(a, b) => {
                let a = self.convert_expr(a, decl_exprs);
                let b = self.convert_expr(b, decl_exprs);
                self.mk_power(&a, &b)
            }

            E::Lt(a, b) => {
                let a = self.convert_expr(a, decl_exprs);
                let b = self.convert_expr(b, decl_exprs);
                self.mk_lt(&a, &b)
            }
            E::Le(a, b) => {
                let a = self.convert_expr(a, decl_exprs);
                let b = self.convert_expr(b, decl_exprs);
                self.mk_le(&a, &b)
            }
            E::Gt(a, b) => {
                let a = self.convert_expr(a, decl_exprs);
                let b = self.convert_expr(b, decl_exprs);
                self.mk_gt(&a, &b)
            }
            E::Ge(a, b) => {
                let a = self.convert_expr(a, decl_exprs);
                let b = self.convert_expr(b, decl_exprs);
                self.mk_ge(&a, &b)
            }

            E::Int2Real(a) => {
                let a = self.convert_expr(a, decl_exprs);
                self.mk_int2real(&a)
            }
            E::Real2Int(a) => {
                let a = self.convert_expr(a, decl_exprs);
                self.mk_real2int(&a)
            }
            E::Int2Bv(a, n) => {
                let a = self.convert_expr(a, decl_exprs);
                self.mk_int2bv(&a, *n)
            }
            E::Bv2Int(a, signed) => {
                let a = self.convert_expr(a, decl_exprs);
                self.mk_bv2int(&a, *signed)
            }

            E::BvAnd(a, b) => { let a = self.convert_expr(a, decl_exprs); let b = self.convert_expr(b, decl_exprs); self.mk_bvand(&a, &b) }
            E::BvOr(a, b) => { let a = self.convert_expr(a, decl_exprs); let b = self.convert_expr(b, decl_exprs); self.mk_bvor(&a, &b) }
            E::BvXor(a, b) => { let a = self.convert_expr(a, decl_exprs); let b = self.convert_expr(b, decl_exprs); self.mk_bvxor(&a, &b) }
            E::BvNot(a) => { let a = self.convert_expr(a, decl_exprs); self.mk_bvnot(&a) }
            E::BvNeg(a) => { let a = self.convert_expr(a, decl_exprs); self.mk_bvneg(&a) }
            E::BvAdd(a, b) => { let a = self.convert_expr(a, decl_exprs); let b = self.convert_expr(b, decl_exprs); self.mk_bvadd(&a, &b) }
            E::BvSub(a, b) => { let a = self.convert_expr(a, decl_exprs); let b = self.convert_expr(b, decl_exprs); self.mk_bvsub(&a, &b) }
            E::BvMul(a, b) => { let a = self.convert_expr(a, decl_exprs); let b = self.convert_expr(b, decl_exprs); self.mk_bvmul(&a, &b) }
            E::BvUDiv(a, b) => { let a = self.convert_expr(a, decl_exprs); let b = self.convert_expr(b, decl_exprs); self.mk_bvudiv(&a, &b) }
            E::BvShl(a, b) => { let a = self.convert_expr(a, decl_exprs); let b = self.convert_expr(b, decl_exprs); self.mk_bvshl(&a, &b) }
            E::BvLShr(a, b) => { let a = self.convert_expr(a, decl_exprs); let b = self.convert_expr(b, decl_exprs); self.mk_bvlshr(&a, &b) }
            E::BvAShr(a, b) => { let a = self.convert_expr(a, decl_exprs); let b = self.convert_expr(b, decl_exprs); self.mk_bvashr(&a, &b) }

            E::SeqLength(a) => { let a = self.convert_expr(a, decl_exprs); self.mk_seq_length(&a) }
            E::SeqConcat(args) => {
                let args: Vec<_> = args.iter().map(|a| self.convert_expr(a, decl_exprs)).collect();
                self.mk_seq_concat(&args)
            }
            E::SeqContains(a, b) => { let a = self.convert_expr(a, decl_exprs); let b = self.convert_expr(b, decl_exprs); self.mk_seq_contains(&a, &b) }
            E::SeqPrefix(a, b) => { let a = self.convert_expr(a, decl_exprs); let b = self.convert_expr(b, decl_exprs); self.mk_seq_prefix(&a, &b) }
            E::SeqSuffix(a, b) => { let a = self.convert_expr(a, decl_exprs); let b = self.convert_expr(b, decl_exprs); self.mk_seq_suffix(&a, &b) }
            E::SeqAt(a, b) => { let a = self.convert_expr(a, decl_exprs); let b = self.convert_expr(b, decl_exprs); self.mk_seq_at(&a, &b) }
            E::SeqIndex(a, b, c) => {
                let a = self.convert_expr(a, decl_exprs);
                let b = self.convert_expr(b, decl_exprs);
                let c = self.convert_expr(c, decl_exprs);
                self.mk_seq_index(&a, &b, &c)
            }
            E::SeqReplace(a, b, c) => {
                let a = self.convert_expr(a, decl_exprs);
                let b = self.convert_expr(b, decl_exprs);
                let c = self.convert_expr(c, decl_exprs);
                self.mk_seq_replace(&a, &b, &c)
            }
            E::SeqExtract(a, b, c) => {
                let a = self.convert_expr(a, decl_exprs);
                let b = self.convert_expr(b, decl_exprs);
                let c = self.convert_expr(c, decl_exprs);
                self.mk_seq_extract(&a, &b, &c)
            }
            E::StrLt(a, b) => { let a = self.convert_expr(a, decl_exprs); let b = self.convert_expr(b, decl_exprs); self.mk_str_lt(&a, &b) }
            E::StrLe(a, b) => { let a = self.convert_expr(a, decl_exprs); let b = self.convert_expr(b, decl_exprs); self.mk_str_le(&a, &b) }

            E::IntToStr(a) => { let a = self.convert_expr(a, decl_exprs); self.mk_int_to_str(&a) }
            E::StrToInt(a) => { let a = self.convert_expr(a, decl_exprs); self.mk_str_to_int(&a) }

            E::SeqToRe(a) => { let a = self.convert_expr(a, decl_exprs); self.mk_seq_to_re(&a) }
            E::SeqInRe(a, b) => { let a = self.convert_expr(a, decl_exprs); let b = self.convert_expr(b, decl_exprs); self.mk_seq_in_re(&a, &b) }
            E::ReStar(a) => { let a = self.convert_expr(a, decl_exprs); self.mk_re_star(&a) }
            E::RePlus(a) => { let a = self.convert_expr(a, decl_exprs); self.mk_re_plus(&a) }
            E::ReOption(a) => { let a = self.convert_expr(a, decl_exprs); self.mk_re_option(&a) }
            E::ReUnion(args) => {
                let args: Vec<_> = args.iter().map(|a| self.convert_expr(a, decl_exprs)).collect();
                self.mk_re_union(&args)
            }
            E::ReIntersect(args) => {
                let args: Vec<_> = args.iter().map(|a| self.convert_expr(a, decl_exprs)).collect();
                self.mk_re_intersect(&args)
            }
            E::ReConcat(args) => {
                let args: Vec<_> = args.iter().map(|a| self.convert_expr(a, decl_exprs)).collect();
                self.mk_re_concat(&args)
            }
            E::ReRange(a, b) => { let a = self.convert_expr(a, decl_exprs); let b = self.convert_expr(b, decl_exprs); self.mk_re_range(&a, &b) }
            E::ReComplement(a) => { let a = self.convert_expr(a, decl_exprs); self.mk_re_complement(&a) }
            E::ReDiff(a, b) => { let a = self.convert_expr(a, decl_exprs); let b = self.convert_expr(b, decl_exprs); self.mk_re_diff(&a, &b) }
            E::ReLoop(a, lo, hi) => { let a = self.convert_expr(a, decl_exprs); self.mk_re_loop(&a, *lo, *hi) }
            E::ReFull(s) => self.mk_re_full(*s),
            E::ReEmpty(s) => self.mk_re_empty(*s),
            E::ReAllChar(s) => self.mk_re_allchar(*s),

            E::ForAll { vars, body } => {
                let body = self.convert_expr(body, decl_exprs);
                self.mk_forall(vars, &body)
            }
            E::Exists { vars, body } => {
                let body = self.convert_expr(body, decl_exprs);
                self.mk_exists(vars, &body)
            }
            E::Bound(idx, sort) => self.mk_bound(*idx, *sort),
        }
    }

    /// Extract values from the current model per the problem's extractions.
    fn extract_values(
        &self,
        problem: &crate::problem::SmtProblem,
        decl_exprs: &[Self::Expr],
    ) -> Vec<SmtValue> {
        problem
            .extractions
            .iter()
            .map(|ext| {
                let expr = self.convert_expr(&ext.expr, decl_exprs);
                self.eval(&expr, ext.model_completion)
            })
            .collect()
    }
}
