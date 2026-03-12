// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AST backend — the portable, WASM-safe implementation of [`SmtContext`].
//!
//! [`AstBackend`] implements [`SmtContext`] where `Expr = SmtExpr`.
//! Instead of calling a solver, it builds a serializable [`SmtExpr`] AST
//! that can be:
//!
//! 1. Serialized to JSON and sent to a JS runtime where the `z3-solver`
//!    npm package reconstructs live Z3 objects.
//! 2. Rendered to SMT-LIB2 text via [`crate::render`].
//! 3. Fed to any [`SmtSolver`] implementation via [`SmtSolver::solve`].

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::context::SmtContext;
use crate::expr::{SmtDecl, SmtExpr, SmtSort};
use crate::problem::{SmtConfig, SmtProblem};

/// The portable AST backend.
///
/// Builds [`SmtExpr`] trees and collects them into an [`SmtProblem`].
/// Does not perform any solving — the resulting problem is meant to be
/// sent to an actual solver (native Z3 or JS-side z3-solver).
pub struct AstBackend {
    /// Accumulated declarations.
    declarations: Vec<SmtDecl>,
    /// Accumulated assertions.
    assertions: Vec<SmtExpr>,
    /// Next declaration id.
    next_id: u32,
}

impl AstBackend {
    /// Create a new AST backend.
    pub fn new() -> Self {
        Self {
            declarations: Vec::new(),
            assertions: Vec::new(),
            next_id: 0,
        }
    }

    /// Assert an expression.
    pub fn assert(&mut self, expr: SmtExpr) {
        self.assertions.push(expr);
    }

    /// Get the declarations collected so far.
    pub fn declarations(&self) -> &[SmtDecl] {
        &self.declarations
    }

    /// Get the assertions collected so far.
    pub fn assertions(&self) -> &[SmtExpr] {
        &self.assertions
    }

    /// Consume this backend and produce an [`SmtProblem`].
    pub fn into_problem(self) -> SmtProblem {
        SmtProblem {
            declarations: self.declarations,
            assertions: self.assertions,
            commands: Vec::new(),
            extractions: Vec::new(),
            config: SmtConfig::default(),
            path_info: Vec::new(),
        }
    }

    /// Consume this backend and produce an [`SmtProblem`] with config.
    pub fn into_problem_with_config(self, config: SmtConfig) -> SmtProblem {
        SmtProblem {
            declarations: self.declarations,
            assertions: self.assertions,
            commands: Vec::new(),
            extractions: Vec::new(),
            config,
            path_info: Vec::new(),
        }
    }

    /// Allocate a declaration id.
    fn alloc_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

impl Default for AstBackend {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SmtContext implementation
// ---------------------------------------------------------------------------

impl<'ctx> SmtContext<'ctx> for AstBackend {
    type Expr = SmtExpr;

    // ── Literals ─────────────────────────────────────────────────────

    fn mk_true(&self) -> SmtExpr {
        SmtExpr::True
    }
    fn mk_false(&self) -> SmtExpr {
        SmtExpr::False
    }
    fn mk_bool(&self, b: bool) -> SmtExpr {
        SmtExpr::bool_lit(b)
    }
    fn mk_int(&self, n: i64) -> SmtExpr {
        SmtExpr::IntLit(n)
    }
    fn mk_real(&self, num: i64, den: i64) -> SmtExpr {
        SmtExpr::RealLit(num, den)
    }
    fn mk_string(&self, s: &str) -> SmtExpr {
        SmtExpr::StringLit(s.into())
    }
    fn mk_bv(&self, val: i64, width: u32) -> SmtExpr {
        SmtExpr::BvLit(val, width)
    }

    // ── Declarations ─────────────────────────────────────────────────

    fn declare_const(&mut self, name: &str, sort: SmtSort) -> SmtExpr {
        let id = self.alloc_id();
        self.declarations.push(SmtDecl::Const {
            id,
            name: name.into(),
            sort,
        });
        SmtExpr::Const(id)
    }

    fn declare_fun(
        &mut self,
        name: &str,
        arg_sorts: &[SmtSort],
        ret_sort: SmtSort,
    ) -> u32 {
        let id = self.alloc_id();
        self.declarations.push(SmtDecl::Fun {
            id,
            name: name.into(),
            arg_sorts: arg_sorts.to_vec(),
            ret_sort,
        });
        id
    }

    fn mk_app(&self, func_id: u32, args: &[SmtExpr]) -> SmtExpr {
        SmtExpr::App(func_id, args.to_vec())
    }

    // ── Propositional ────────────────────────────────────────────────

    fn mk_not(&self, a: &SmtExpr) -> SmtExpr {
        SmtExpr::Not(Box::new(a.clone()))
    }
    fn mk_and(&self, args: &[SmtExpr]) -> SmtExpr {
        SmtExpr::And(args.to_vec())
    }
    fn mk_or(&self, args: &[SmtExpr]) -> SmtExpr {
        SmtExpr::Or(args.to_vec())
    }
    fn mk_xor(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::Xor(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_implies(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::Implies(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_iff(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::Iff(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_ite(&self, c: &SmtExpr, t: &SmtExpr, e: &SmtExpr) -> SmtExpr {
        SmtExpr::Ite(
            Box::new(c.clone()),
            Box::new(t.clone()),
            Box::new(e.clone()),
        )
    }

    // ── Equality ─────────────────────────────────────────────────────

    fn mk_eq(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::Eq(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_distinct(&self, args: &[SmtExpr]) -> SmtExpr {
        SmtExpr::Distinct(args.to_vec())
    }

    // ── Arithmetic ───────────────────────────────────────────────────

    fn mk_add(&self, args: &[SmtExpr]) -> SmtExpr {
        SmtExpr::Add(args.to_vec())
    }
    fn mk_sub(&self, args: &[SmtExpr]) -> SmtExpr {
        SmtExpr::Sub(args.to_vec())
    }
    fn mk_mul(&self, args: &[SmtExpr]) -> SmtExpr {
        SmtExpr::Mul(args.to_vec())
    }
    fn mk_div(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::Div(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_mod(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::Mod(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_rem(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::Rem(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_neg(&self, a: &SmtExpr) -> SmtExpr {
        SmtExpr::Neg(Box::new(a.clone()))
    }
    fn mk_abs(&self, a: &SmtExpr) -> SmtExpr {
        SmtExpr::Abs(Box::new(a.clone()))
    }
    fn mk_power(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::Power(Box::new(a.clone()), Box::new(b.clone()))
    }

    // ── Comparison ───────────────────────────────────────────────────

    fn mk_lt(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::Lt(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_le(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::Le(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_gt(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::Gt(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_ge(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::Ge(Box::new(a.clone()), Box::new(b.clone()))
    }

    // ── Coercion ─────────────────────────────────────────────────────

    fn mk_int2real(&self, a: &SmtExpr) -> SmtExpr {
        SmtExpr::Int2Real(Box::new(a.clone()))
    }
    fn mk_real2int(&self, a: &SmtExpr) -> SmtExpr {
        SmtExpr::Real2Int(Box::new(a.clone()))
    }
    fn mk_int2bv(&self, a: &SmtExpr, n: u32) -> SmtExpr {
        SmtExpr::Int2Bv(Box::new(a.clone()), n)
    }
    fn mk_bv2int(&self, a: &SmtExpr, signed: bool) -> SmtExpr {
        SmtExpr::Bv2Int(Box::new(a.clone()), signed)
    }

    // ── Bitvector ────────────────────────────────────────────────────

    fn mk_bvand(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::BvAnd(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_bvor(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::BvOr(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_bvxor(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::BvXor(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_bvnot(&self, a: &SmtExpr) -> SmtExpr {
        SmtExpr::BvNot(Box::new(a.clone()))
    }
    fn mk_bvneg(&self, a: &SmtExpr) -> SmtExpr {
        SmtExpr::BvNeg(Box::new(a.clone()))
    }
    fn mk_bvadd(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::BvAdd(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_bvsub(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::BvSub(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_bvmul(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::BvMul(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_bvudiv(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::BvUDiv(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_bvshl(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::BvShl(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_bvlshr(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::BvLShr(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_bvashr(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::BvAShr(Box::new(a.clone()), Box::new(b.clone()))
    }

    // ── Sequences / Strings ──────────────────────────────────────────

    fn mk_seq_length(&self, a: &SmtExpr) -> SmtExpr {
        SmtExpr::SeqLength(Box::new(a.clone()))
    }
    fn mk_seq_concat(&self, args: &[SmtExpr]) -> SmtExpr {
        SmtExpr::SeqConcat(args.to_vec())
    }
    fn mk_seq_contains(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::SeqContains(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_seq_prefix(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::SeqPrefix(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_seq_suffix(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::SeqSuffix(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_seq_at(&self, a: &SmtExpr, i: &SmtExpr) -> SmtExpr {
        SmtExpr::SeqAt(Box::new(a.clone()), Box::new(i.clone()))
    }
    fn mk_seq_index(&self, a: &SmtExpr, b: &SmtExpr, offset: &SmtExpr) -> SmtExpr {
        SmtExpr::SeqIndex(
            Box::new(a.clone()),
            Box::new(b.clone()),
            Box::new(offset.clone()),
        )
    }
    fn mk_seq_replace(&self, a: &SmtExpr, src: &SmtExpr, dst: &SmtExpr) -> SmtExpr {
        SmtExpr::SeqReplace(
            Box::new(a.clone()),
            Box::new(src.clone()),
            Box::new(dst.clone()),
        )
    }
    fn mk_seq_extract(&self, a: &SmtExpr, offset: &SmtExpr, length: &SmtExpr) -> SmtExpr {
        SmtExpr::SeqExtract(
            Box::new(a.clone()),
            Box::new(offset.clone()),
            Box::new(length.clone()),
        )
    }
    fn mk_str_lt(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::StrLt(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_str_le(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::StrLe(Box::new(a.clone()), Box::new(b.clone()))
    }

    // ── String ↔ numeric ─────────────────────────────────────────────

    fn mk_int_to_str(&self, a: &SmtExpr) -> SmtExpr {
        SmtExpr::IntToStr(Box::new(a.clone()))
    }
    fn mk_str_to_int(&self, a: &SmtExpr) -> SmtExpr {
        SmtExpr::StrToInt(Box::new(a.clone()))
    }

    // ── Regular expressions ──────────────────────────────────────────

    fn mk_seq_to_re(&self, a: &SmtExpr) -> SmtExpr {
        SmtExpr::SeqToRe(Box::new(a.clone()))
    }
    fn mk_seq_in_re(&self, a: &SmtExpr, re: &SmtExpr) -> SmtExpr {
        SmtExpr::SeqInRe(Box::new(a.clone()), Box::new(re.clone()))
    }
    fn mk_re_star(&self, a: &SmtExpr) -> SmtExpr {
        SmtExpr::ReStar(Box::new(a.clone()))
    }
    fn mk_re_plus(&self, a: &SmtExpr) -> SmtExpr {
        SmtExpr::RePlus(Box::new(a.clone()))
    }
    fn mk_re_option(&self, a: &SmtExpr) -> SmtExpr {
        SmtExpr::ReOption(Box::new(a.clone()))
    }
    fn mk_re_union(&self, args: &[SmtExpr]) -> SmtExpr {
        SmtExpr::ReUnion(args.to_vec())
    }
    fn mk_re_intersect(&self, args: &[SmtExpr]) -> SmtExpr {
        SmtExpr::ReIntersect(args.to_vec())
    }
    fn mk_re_concat(&self, args: &[SmtExpr]) -> SmtExpr {
        SmtExpr::ReConcat(args.to_vec())
    }
    fn mk_re_range(&self, lo: &SmtExpr, hi: &SmtExpr) -> SmtExpr {
        SmtExpr::ReRange(Box::new(lo.clone()), Box::new(hi.clone()))
    }
    fn mk_re_complement(&self, a: &SmtExpr) -> SmtExpr {
        SmtExpr::ReComplement(Box::new(a.clone()))
    }
    fn mk_re_diff(&self, a: &SmtExpr, b: &SmtExpr) -> SmtExpr {
        SmtExpr::ReDiff(Box::new(a.clone()), Box::new(b.clone()))
    }
    fn mk_re_loop(&self, a: &SmtExpr, lo: u32, hi: u32) -> SmtExpr {
        SmtExpr::ReLoop(Box::new(a.clone()), lo, hi)
    }
    fn mk_re_full(&self, sort: SmtSort) -> SmtExpr {
        SmtExpr::ReFull(sort)
    }
    fn mk_re_empty(&self, sort: SmtSort) -> SmtExpr {
        SmtExpr::ReEmpty(sort)
    }
    fn mk_re_allchar(&self, sort: SmtSort) -> SmtExpr {
        SmtExpr::ReAllChar(sort)
    }

    // ── Quantifiers ──────────────────────────────────────────────────

    fn mk_forall(&self, vars: &[(String, SmtSort)], body: &SmtExpr) -> SmtExpr {
        SmtExpr::ForAll {
            vars: vars.to_vec(),
            body: Box::new(body.clone()),
        }
    }
    fn mk_exists(&self, vars: &[(String, SmtSort)], body: &SmtExpr) -> SmtExpr {
        SmtExpr::Exists {
            vars: vars.to_vec(),
            body: Box::new(body.clone()),
        }
    }
    fn mk_bound(&self, idx: u32, sort: SmtSort) -> SmtExpr {
        SmtExpr::Bound(idx, sort)
    }
}
