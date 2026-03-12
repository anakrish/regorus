// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Z3 solver backend — converts [`SmtProblem`] / [`SmtExpr`] to Z3 API calls.
//!
//! This module is only compiled when the `z3-analysis` feature is active.
//! It provides:
//! - [`solve`]: one-shot problem solving (assert-all + check-sat + extract).
//! - [`IncrementalSolver`]: push/pop solver for iterative workflows
//!   like test-suite generation.

// Note: unsafe is allowed on this module in mod.rs via #[allow(unsafe_code)].

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use std::collections::HashMap;

use z3::ast::Ast;

use regorus_smt::{SmtDecl, SmtExpr, SmtSort};
use regorus_smt::{SmtCheckResult, SmtProblem, SmtSolution, SmtStatus, SmtValue};

// ---------------------------------------------------------------------------
// Raw Z3 pointer extraction
// ---------------------------------------------------------------------------

/// Extract the raw `Z3_context` pointer from a [`z3::Context`].
///
/// # Safety
///
/// This relies on `z3::Context` being a single-field struct
/// (`z3_ctx: Z3_context`).  Verified for z3 crate v0.12.1.
/// A `debug_assert` checks the struct size at runtime.
unsafe fn raw_ctx(ctx: &z3::Context) -> z3_sys::Z3_context {
    debug_assert_eq!(
        std::mem::size_of::<z3::Context>(),
        std::mem::size_of::<z3_sys::Z3_context>(),
        "z3::Context layout changed — raw_ctx is no longer safe"
    );
    let ptr: *const z3::Context = ctx;
    *(ptr as *const z3_sys::Z3_context)
}

// Functions not present in z3-sys 0.8 but available in the Z3 C library.
extern "C" {
    fn Z3_mk_str_lt(
        c: z3_sys::Z3_context,
        lhs: z3_sys::Z3_ast,
        rhs: z3_sys::Z3_ast,
    ) -> z3_sys::Z3_ast;
    fn Z3_mk_str_le(
        c: z3_sys::Z3_context,
        lhs: z3_sys::Z3_ast,
        rhs: z3_sys::Z3_ast,
    ) -> z3_sys::Z3_ast;
    fn Z3_mk_re_diff(
        c: z3_sys::Z3_context,
        re1: z3_sys::Z3_ast,
        re2: z3_sys::Z3_ast,
    ) -> z3_sys::Z3_ast;
    fn Z3_mk_re_allchar(
        c: z3_sys::Z3_context,
        regex_sort: z3_sys::Z3_sort,
    ) -> z3_sys::Z3_ast;
}

// ---------------------------------------------------------------------------
// One-shot solver
// ---------------------------------------------------------------------------

/// Solve an [`SmtProblem`] with Z3 and return an [`SmtSolution`].
///
/// For simple problems (no incremental commands), this asserts all
/// assertions, runs check-sat, and extracts model values per the
/// problem's extraction spec.
pub fn solve(problem: &SmtProblem) -> anyhow::Result<SmtSolution> {
    let cfg = z3::Config::new();
    let ctx = z3::Context::new(&cfg);
    let solver = z3::Solver::new(&ctx);

    if let Some(ms) = problem.config.timeout_ms {
        let mut params = z3::Params::new(&ctx);
        params.set_u32("timeout", ms);
        solver.set_params(&params);
    }

    let mut converter = ExprConverter::new(&ctx, &problem.declarations);

    // Assert all assertions.
    for assertion in &problem.assertions {
        let z3_expr = converter.convert(assertion);
        let z3_bool = z3_expr.as_bool().unwrap_or_else(|| {
            panic!("Assertion is not a Bool expression: {:?}", assertion);
        });
        solver.assert(&z3_bool);
    }

    let status = match solver.check() {
        z3::SatResult::Sat => SmtStatus::Sat,
        z3::SatResult::Unsat => SmtStatus::Unsat,
        z3::SatResult::Unknown => SmtStatus::Unknown,
    };

    let mut values = Vec::new();
    let reason_unknown = if status == SmtStatus::Unknown {
        solver.get_reason_unknown().map(|s| s.to_string())
    } else {
        None
    };

    if status == SmtStatus::Sat {
        let model = solver.get_model().unwrap();
        for extraction in &problem.extractions {
            let z3_expr = converter.convert(&extraction.expr);
            let val = eval_z3_dynamic(&model, &z3_expr, extraction.model_completion);
            values.push(val);
        }
    }

    Ok(SmtSolution::single(SmtCheckResult {
        status,
        values,
        unsat_core: Vec::new(),
        reason_unknown,
        stats: None,
    }))
}

// ---------------------------------------------------------------------------
// Incremental solver
// ---------------------------------------------------------------------------

/// An incremental Z3 solver that supports push/pop and repeated check-sat.
///
/// # Usage
/// ```ignore
/// let mut solver = IncrementalSolver::new(&problem)?;
/// solver.push();
/// solver.assert_expr(&extra_constraint);
/// let result = solver.check_and_extract(&problem)?;
/// solver.pop(1);
/// ```
pub struct IncrementalSolver {
    /// Boxed context — stable address, dropped last.
    /// This field is never read directly, but must be kept alive so that
    /// the solver and converter raw pointers remain valid.
    #[allow(dead_code)]
    ctx_box: std::boxed::Box<z3::Context>,
    /// Raw pointer to the solver (owns it).
    solver_ptr: *mut u8,
    /// Raw pointer to the converter (owns it).
    converter_ptr: *mut u8,
}

// SAFETY: Z3 Context/Solver are thread-safe (Z3 uses internal locking).
unsafe impl Send for IncrementalSolver {}

impl IncrementalSolver {
    /// Create an incremental solver from an [`SmtProblem`].
    ///
    /// All declarations are registered and all assertions are loaded.
    pub fn new(problem: &SmtProblem) -> anyhow::Result<Self> {
        let cfg = z3::Config::new();
        let ctx_box = std::boxed::Box::new(z3::Context::new(&cfg));

        // SAFETY: ctx_box is heap-allocated and will not move. We create
        // references to it that are valid for the lifetime of this struct.
        // We must ensure the solver and converter are dropped *before*
        // ctx_box.
        let ctx_ref: &z3::Context = unsafe { &*std::ptr::from_ref(ctx_box.as_ref()) };

        let solver = z3::Solver::new(ctx_ref);

        if let Some(ms) = problem.config.timeout_ms {
            let mut params = z3::Params::new(ctx_ref);
            params.set_u32("timeout", ms);
            solver.set_params(&params);
        }

        let mut converter = ExprConverter::new(ctx_ref, &problem.declarations);

        // Assert all base assertions.
        for assertion in &problem.assertions {
            let z3_expr = converter.convert(assertion);
            let z3_bool = z3_expr
                .as_bool()
                .expect("Assertion must be Bool");
            solver.assert(&z3_bool);
        }

        // Heap-allocate solver and converter, store as raw pointers.
        let solver_ptr = std::boxed::Box::into_raw(std::boxed::Box::new(solver)) as *mut u8;
        let converter_ptr = std::boxed::Box::into_raw(std::boxed::Box::new(converter)) as *mut u8;

        Ok(IncrementalSolver {
            ctx_box,
            solver_ptr,
            converter_ptr,
        })
    }

    fn solver(&self) -> &z3::Solver<'_> {
        unsafe { &*(self.solver_ptr as *const z3::Solver<'_>) }
    }

    #[allow(dead_code)]
    fn converter(&mut self) -> &mut ExprConverter<'_> {
        unsafe { &mut *(self.converter_ptr as *mut ExprConverter<'_>) }
    }

    /// Assert an additional expression.
    pub fn assert_expr(&mut self, expr: &SmtExpr) {
        // Access converter and solver via raw pointers to avoid borrow conflicts.
        let converter: &mut ExprConverter<'_> =
            unsafe { &mut *(self.converter_ptr as *mut ExprConverter<'_>) };
        let solver: &z3::Solver<'_> =
            unsafe { &*(self.solver_ptr as *const z3::Solver<'_>) };
        let z3_expr = converter.convert(expr);
        let z3_bool = z3_expr.as_bool().expect("assert_expr: not a Bool");
        solver.assert(&z3_bool);
    }

    /// Push a solver scope.
    pub fn push(&mut self) {
        self.solver().push();
    }

    /// Pop `n` solver scopes.
    pub fn pop(&mut self, n: u32) {
        self.solver().pop(n);
    }

    /// Check satisfiability and extract values per the problem's extractions.
    pub fn check_and_extract(&mut self, problem: &SmtProblem) -> anyhow::Result<SmtCheckResult> {
        let solver: &z3::Solver<'_> =
            unsafe { &*(self.solver_ptr as *const z3::Solver<'_>) };
        let converter: &mut ExprConverter<'_> =
            unsafe { &mut *(self.converter_ptr as *mut ExprConverter<'_>) };

        let status = match solver.check() {
            z3::SatResult::Sat => SmtStatus::Sat,
            z3::SatResult::Unsat => SmtStatus::Unsat,
            z3::SatResult::Unknown => SmtStatus::Unknown,
        };

        let reason_unknown = if status == SmtStatus::Unknown {
            solver.get_reason_unknown().map(|s| s.to_string())
        } else {
            None
        };

        let mut values = Vec::new();
        if status == SmtStatus::Sat {
            let model = solver.get_model().unwrap();
            for extraction in &problem.extractions {
                let z3_expr = converter.convert(&extraction.expr);
                let val = eval_z3_dynamic(&model, &z3_expr, extraction.model_completion);
                values.push(val);
            }
        }

        Ok(SmtCheckResult {
            status,
            values,
            unsat_core: Vec::new(),
            reason_unknown,
            stats: None,
        })
    }
}

impl Drop for IncrementalSolver {
    fn drop(&mut self) {
        // Drop solver and converter BEFORE ctx_box (which is dropped
        // automatically after this block).
        unsafe {
            // Drop converter first (it may reference the context).
            drop(std::boxed::Box::from_raw(
                self.converter_ptr as *mut ExprConverter<'_>,
            ));
            // Drop solver.
            drop(std::boxed::Box::from_raw(
                self.solver_ptr as *mut z3::Solver<'_>,
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// SmtExpr → Z3 AST converter
// ---------------------------------------------------------------------------

/// Converts [`SmtExpr`] trees into Z3 AST objects.
///
/// Maintains a map from declaration ids to Z3 constants/functions so that
/// `SmtExpr::Const(id)` references are resolved consistently.
struct ExprConverter<'ctx> {
    ctx: &'ctx z3::Context,
    /// Maps declaration id → Z3 AST (for constants).
    consts: HashMap<u32, z3::ast::Dynamic<'ctx>>,
}

impl<'ctx> ExprConverter<'ctx> {
    fn new(ctx: &'ctx z3::Context, declarations: &[SmtDecl]) -> Self {
        let mut consts = HashMap::new();

        for decl in declarations {
            match decl {
                SmtDecl::Const { id, name, sort } => {
                    let z3_const = make_const(ctx, name.as_str(), sort);
                    consts.insert(*id, z3_const);
                }
                SmtDecl::Fun { .. } => {
                    // Function declarations are more complex; handle as needed.
                    // For now, the analysis code doesn't use declared functions.
                }
            }
        }

        ExprConverter { ctx, consts }
    }

    /// Helper: get the raw Z3_context.
    fn z3_ctx(&self) -> z3_sys::Z3_context {
        unsafe { raw_ctx(self.ctx) }
    }

    /// Convert an [`SmtExpr`] to a Z3 `Dynamic` AST node.
    fn convert(&mut self, expr: &SmtExpr) -> z3::ast::Dynamic<'ctx> {
        use z3::ast::{Bool, Dynamic, Int, Real, String as Z3String};

        match expr {
            // === Literals ===
            SmtExpr::True => Bool::from_bool(self.ctx, true).into(),
            SmtExpr::False => Bool::from_bool(self.ctx, false).into(),
            SmtExpr::IntLit(i) => Int::from_i64(self.ctx, *i).into(),
            SmtExpr::RealLit(num, den) => Real::from_real(self.ctx, *num as i32, *den as i32).into(),
            SmtExpr::StringLit(s) => Z3String::from_str(self.ctx, s).unwrap().into(),
            SmtExpr::BvLit(val, width) => {
                z3::ast::BV::from_i64(self.ctx, *val, *width).into()
            }

            // === Variable references ===
            SmtExpr::Const(id) => {
                self.consts
                    .get(id)
                    .unwrap_or_else(|| panic!("Unknown constant id: {}", id))
                    .clone()
            }
            SmtExpr::App(_func_id, _args) => {
                // TODO: implement function application when needed
                unimplemented!("SmtExpr::App not yet implemented in z3_solver")
            }

            // === Propositional logic ===
            SmtExpr::Not(a) => {
                let a = self.convert_bool(a);
                a.not().into()
            }
            SmtExpr::And(args) => {
                let bools: Vec<Bool<'ctx>> = args.iter().map(|a| self.convert_bool(a)).collect();
                let refs: Vec<&Bool<'ctx>> = bools.iter().collect();
                Bool::and(self.ctx, &refs).into()
            }
            SmtExpr::Or(args) => {
                let bools: Vec<Bool<'ctx>> = args.iter().map(|a| self.convert_bool(a)).collect();
                let refs: Vec<&Bool<'ctx>> = bools.iter().collect();
                Bool::or(self.ctx, &refs).into()
            }
            SmtExpr::Xor(a, b) => {
                let a = self.convert_bool(a);
                let b = self.convert_bool(b);
                Bool::xor(&a, &b).into()
            }
            SmtExpr::Implies(a, b) => {
                let a = self.convert_bool(a);
                let b = self.convert_bool(b);
                a.implies(&b).into()
            }
            SmtExpr::Iff(a, b) => {
                let a = self.convert_bool(a);
                let b = self.convert_bool(b);
                Bool::and(self.ctx, &[&a.implies(&b), &b.implies(&a)]).into()
            }
            SmtExpr::Ite(c, t, e) => {
                let c = self.convert_bool(c);
                let t = self.convert(t);
                let e = self.convert(e);
                c.ite(&t, &e)
            }

            // === Equality ===
            SmtExpr::Eq(a, b) => {
                let a = self.convert(a);
                let b = self.convert(b);
                a._eq(&b).into()
            }
            SmtExpr::Distinct(args) => {
                let dyns: Vec<Dynamic<'ctx>> = args.iter().map(|a| self.convert(a)).collect();
                let refs: Vec<&Dynamic<'ctx>> = dyns.iter().collect();
                Dynamic::distinct(self.ctx, &refs).into()
            }

            // === Arithmetic ===
            SmtExpr::Add(args) => {
                let ints: Vec<Int<'ctx>> = args.iter().map(|a| self.convert_int(a)).collect();
                let refs: Vec<&Int<'ctx>> = ints.iter().collect();
                Int::add(self.ctx, &refs).into()
            }
            SmtExpr::Sub(args) => {
                let ints: Vec<Int<'ctx>> = args.iter().map(|a| self.convert_int(a)).collect();
                let refs: Vec<&Int<'ctx>> = ints.iter().collect();
                Int::sub(self.ctx, &refs).into()
            }
            SmtExpr::Mul(args) => {
                let ints: Vec<Int<'ctx>> = args.iter().map(|a| self.convert_int(a)).collect();
                let refs: Vec<&Int<'ctx>> = ints.iter().collect();
                Int::mul(self.ctx, &refs).into()
            }
            SmtExpr::Div(a, b) => {
                let a = self.convert_int(a);
                let b = self.convert_int(b);
                a.div(&b).into()
            }
            SmtExpr::Mod(a, b) => {
                let a = self.convert_int(a);
                let b = self.convert_int(b);
                a.modulo(&b).into()
            }
            SmtExpr::Rem(a, b) => {
                let a = self.convert_int(a);
                let b = self.convert_int(b);
                a.rem(&b).into()
            }
            SmtExpr::Neg(a) => {
                let a = self.convert_int(a);
                a.unary_minus().into()
            }
            SmtExpr::Abs(a) => {
                // |a| = ite(a >= 0, a, -a)
                let a = self.convert_int(a);
                let zero = Int::from_i64(self.ctx, 0);
                a.ge(&zero).ite(&a, &a.unary_minus()).into()
            }
            SmtExpr::Power(a, b) => {
                let a = self.convert_int(a);
                let b = self.convert_int(b);
                a.power(&b).into()
            }

            // === Comparison ===
            SmtExpr::Lt(a, b) => {
                let a = self.convert(a);
                let b = self.convert(b);
                if let (Some(ai), Some(bi)) = (a.as_int(), b.as_int()) {
                    ai.lt(&bi).into()
                } else if let (Some(ar), Some(br)) = (a.as_real(), b.as_real()) {
                    ar.lt(&br).into()
                } else {
                    let ai = a.as_int().expect("Lt: expected int or real");
                    let bi = b.as_int().expect("Lt: expected int or real");
                    ai.lt(&bi).into()
                }
            }
            SmtExpr::Le(a, b) => {
                let a = self.convert(a);
                let b = self.convert(b);
                if let (Some(ai), Some(bi)) = (a.as_int(), b.as_int()) {
                    ai.le(&bi).into()
                } else if let (Some(ar), Some(br)) = (a.as_real(), b.as_real()) {
                    ar.le(&br).into()
                } else {
                    let ai = a.as_int().expect("Le: expected int or real");
                    let bi = b.as_int().expect("Le: expected int or real");
                    ai.le(&bi).into()
                }
            }
            SmtExpr::Gt(a, b) => {
                let a = self.convert(a);
                let b = self.convert(b);
                if let (Some(ai), Some(bi)) = (a.as_int(), b.as_int()) {
                    ai.gt(&bi).into()
                } else if let (Some(ar), Some(br)) = (a.as_real(), b.as_real()) {
                    ar.gt(&br).into()
                } else {
                    let ai = a.as_int().expect("Gt: expected int or real");
                    let bi = b.as_int().expect("Gt: expected int or real");
                    ai.gt(&bi).into()
                }
            }
            SmtExpr::Ge(a, b) => {
                let a = self.convert(a);
                let b = self.convert(b);
                if let (Some(ai), Some(bi)) = (a.as_int(), b.as_int()) {
                    ai.ge(&bi).into()
                } else if let (Some(ar), Some(br)) = (a.as_real(), b.as_real()) {
                    ar.ge(&br).into()
                } else {
                    let ai = a.as_int().expect("Ge: expected int or real");
                    let bi = b.as_int().expect("Ge: expected int or real");
                    ai.ge(&bi).into()
                }
            }

            // === Coercion ===
            SmtExpr::Int2Real(a) => {
                let a = self.convert_int(a);
                Int::to_real(&a).into()
            }
            SmtExpr::Real2Int(a) => {
                let a = self.convert_real(a);
                Real::to_int(&a).into()
            }
            SmtExpr::Int2Bv(a, width) => {
                let a = self.convert_int(a);
                z3::ast::BV::from_int(&a, *width).into()
            }
            SmtExpr::Bv2Int(a, signed) => {
                let a = self.convert(a);
                let bv = a.as_bv().expect("Bv2Int: expected BV");
                bv.to_int(*signed).into()
            }

            // === Bitvector ===
            SmtExpr::BvAnd(a, b) => {
                let a = self.convert_bv(a);
                let b = self.convert_bv(b);
                a.bvand(&b).into()
            }
            SmtExpr::BvOr(a, b) => {
                let a = self.convert_bv(a);
                let b = self.convert_bv(b);
                a.bvor(&b).into()
            }
            SmtExpr::BvXor(a, b) => {
                let a = self.convert_bv(a);
                let b = self.convert_bv(b);
                a.bvxor(&b).into()
            }
            SmtExpr::BvNot(a) => {
                let a = self.convert_bv(a);
                a.bvnot().into()
            }
            SmtExpr::BvNeg(a) => {
                let a = self.convert_bv(a);
                a.bvneg().into()
            }
            SmtExpr::BvAdd(a, b) => {
                let a = self.convert_bv(a);
                let b = self.convert_bv(b);
                a.bvadd(&b).into()
            }
            SmtExpr::BvSub(a, b) => {
                let a = self.convert_bv(a);
                let b = self.convert_bv(b);
                a.bvsub(&b).into()
            }
            SmtExpr::BvMul(a, b) => {
                let a = self.convert_bv(a);
                let b = self.convert_bv(b);
                a.bvmul(&b).into()
            }
            SmtExpr::BvUDiv(a, b) => {
                let a = self.convert_bv(a);
                let b = self.convert_bv(b);
                a.bvudiv(&b).into()
            }
            SmtExpr::BvShl(a, b) => {
                let a = self.convert_bv(a);
                let b = self.convert_bv(b);
                a.bvshl(&b).into()
            }
            SmtExpr::BvLShr(a, b) => {
                let a = self.convert_bv(a);
                let b = self.convert_bv(b);
                a.bvlshr(&b).into()
            }
            SmtExpr::BvAShr(a, b) => {
                let a = self.convert_bv(a);
                let b = self.convert_bv(b);
                a.bvashr(&b).into()
            }

            // === Sequences / Strings ===
            SmtExpr::SeqLength(s) => {
                let s = self.convert(s);
                unsafe {
                    let raw = z3_sys::Z3_mk_seq_length(self.z3_ctx(), s.get_z3_ast());
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::SeqConcat(args) => {
                let strs: Vec<Dynamic<'ctx>> = args.iter().map(|a| self.convert(a)).collect();
                let ptrs: Vec<z3_sys::Z3_ast> =
                    strs.iter().map(|s| s.get_z3_ast()).collect();
                unsafe {
                    let raw = z3_sys::Z3_mk_seq_concat(
                        self.z3_ctx(),
                        ptrs.len() as u32,
                        ptrs.as_ptr(),
                    );
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::SeqContains(s, t) => {
                let s = self.convert(s);
                let t = self.convert(t);
                unsafe {
                    let raw = z3_sys::Z3_mk_seq_contains(
                        self.z3_ctx(),
                        s.get_z3_ast(),
                        t.get_z3_ast(),
                    );
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::SeqPrefix(pre, s) => {
                let pre = self.convert(pre);
                let s = self.convert(s);
                unsafe {
                    let raw = z3_sys::Z3_mk_seq_prefix(
                        self.z3_ctx(),
                        pre.get_z3_ast(),
                        s.get_z3_ast(),
                    );
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::SeqSuffix(suf, s) => {
                let suf = self.convert(suf);
                let s = self.convert(s);
                unsafe {
                    let raw = z3_sys::Z3_mk_seq_suffix(
                        self.z3_ctx(),
                        suf.get_z3_ast(),
                        s.get_z3_ast(),
                    );
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::SeqAt(s, i) => {
                let s = self.convert(s);
                let i = self.convert(i);
                unsafe {
                    let raw = z3_sys::Z3_mk_seq_at(
                        self.z3_ctx(),
                        s.get_z3_ast(),
                        i.get_z3_ast(),
                    );
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::SeqIndex(s, t, offset) => {
                let s = self.convert(s);
                let t = self.convert(t);
                let offset = self.convert(offset);
                unsafe {
                    let raw = z3_sys::Z3_mk_seq_index(
                        self.z3_ctx(),
                        s.get_z3_ast(),
                        t.get_z3_ast(),
                        offset.get_z3_ast(),
                    );
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::SeqReplace(s, src, dst) => {
                let s = self.convert(s);
                let src = self.convert(src);
                let dst = self.convert(dst);
                unsafe {
                    let raw = z3_sys::Z3_mk_seq_replace(
                        self.z3_ctx(),
                        s.get_z3_ast(),
                        src.get_z3_ast(),
                        dst.get_z3_ast(),
                    );
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::SeqExtract(s, offset, length) => {
                let s = self.convert(s);
                let offset = self.convert(offset);
                let length = self.convert(length);
                unsafe {
                    let raw = z3_sys::Z3_mk_seq_extract(
                        self.z3_ctx(),
                        s.get_z3_ast(),
                        offset.get_z3_ast(),
                        length.get_z3_ast(),
                    );
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::StrLt(a, b) => {
                let a = self.convert(a);
                let b = self.convert(b);
                unsafe {
                    let raw = Z3_mk_str_lt(
                        self.z3_ctx(),
                        a.get_z3_ast(),
                        b.get_z3_ast(),
                    );
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::StrLe(a, b) => {
                let a = self.convert(a);
                let b = self.convert(b);
                unsafe {
                    let raw = Z3_mk_str_le(
                        self.z3_ctx(),
                        a.get_z3_ast(),
                        b.get_z3_ast(),
                    );
                    Dynamic::wrap(self.ctx, raw)
                }
            }

            // === String ↔ numeric ===
            SmtExpr::IntToStr(a) => {
                let a = self.convert(a);
                unsafe {
                    let raw = z3_sys::Z3_mk_int_to_str(self.z3_ctx(), a.get_z3_ast());
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::StrToInt(a) => {
                let a = self.convert(a);
                unsafe {
                    let raw = z3_sys::Z3_mk_str_to_int(self.z3_ctx(), a.get_z3_ast());
                    Dynamic::wrap(self.ctx, raw)
                }
            }

            // === Regular expressions ===
            SmtExpr::SeqToRe(s) => {
                let s = self.convert(s);
                unsafe {
                    let raw = z3_sys::Z3_mk_seq_to_re(self.z3_ctx(), s.get_z3_ast());
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::SeqInRe(s, re) => {
                let s = self.convert(s);
                let re = self.convert(re);
                unsafe {
                    let raw = z3_sys::Z3_mk_seq_in_re(
                        self.z3_ctx(),
                        s.get_z3_ast(),
                        re.get_z3_ast(),
                    );
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::ReStar(re) => {
                let re = self.convert(re);
                unsafe {
                    let raw = z3_sys::Z3_mk_re_star(self.z3_ctx(), re.get_z3_ast());
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::RePlus(re) => {
                let re = self.convert(re);
                unsafe {
                    let raw = z3_sys::Z3_mk_re_plus(self.z3_ctx(), re.get_z3_ast());
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::ReOption(re) => {
                let re = self.convert(re);
                unsafe {
                    let raw = z3_sys::Z3_mk_re_option(self.z3_ctx(), re.get_z3_ast());
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::ReUnion(args) => {
                let res: Vec<Dynamic<'ctx>> = args.iter().map(|a| self.convert(a)).collect();
                let ptrs: Vec<z3_sys::Z3_ast> =
                    res.iter().map(|r| r.get_z3_ast()).collect();
                unsafe {
                    let raw = z3_sys::Z3_mk_re_union(
                        self.z3_ctx(),
                        ptrs.len() as u32,
                        ptrs.as_ptr(),
                    );
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::ReIntersect(args) => {
                let res: Vec<Dynamic<'ctx>> = args.iter().map(|a| self.convert(a)).collect();
                let ptrs: Vec<z3_sys::Z3_ast> =
                    res.iter().map(|r| r.get_z3_ast()).collect();
                unsafe {
                    let raw = z3_sys::Z3_mk_re_intersect(
                        self.z3_ctx(),
                        ptrs.len() as u32,
                        ptrs.as_ptr(),
                    );
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::ReConcat(args) => {
                let res: Vec<Dynamic<'ctx>> = args.iter().map(|a| self.convert(a)).collect();
                let ptrs: Vec<z3_sys::Z3_ast> =
                    res.iter().map(|r| r.get_z3_ast()).collect();
                unsafe {
                    let raw = z3_sys::Z3_mk_re_concat(
                        self.z3_ctx(),
                        ptrs.len() as u32,
                        ptrs.as_ptr(),
                    );
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::ReRange(lo, hi) => {
                let lo = self.convert(lo);
                let hi = self.convert(hi);
                unsafe {
                    let raw = z3_sys::Z3_mk_re_range(
                        self.z3_ctx(),
                        lo.get_z3_ast(),
                        hi.get_z3_ast(),
                    );
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::ReComplement(re) => {
                let re = self.convert(re);
                unsafe {
                    let raw = z3_sys::Z3_mk_re_complement(self.z3_ctx(), re.get_z3_ast());
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::ReDiff(a, b) => {
                let a = self.convert(a);
                let b = self.convert(b);
                unsafe {
                    let raw = Z3_mk_re_diff(
                        self.z3_ctx(),
                        a.get_z3_ast(),
                        b.get_z3_ast(),
                    );
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::ReLoop(re, lo, hi) => {
                let re = self.convert(re);
                unsafe {
                    let raw = z3_sys::Z3_mk_re_loop(
                        self.z3_ctx(),
                        re.get_z3_ast(),
                        *lo,
                        *hi,
                    );
                    Dynamic::wrap(self.ctx, raw)
                }
            }
            SmtExpr::ReFull(_sort) => {
                // ReFull over string sort — use high-level API
                Dynamic::from_ast(&z3::ast::Regexp::full(self.ctx))
            }
            SmtExpr::ReEmpty(_sort) => {
                // ReEmpty over string sort — use high-level API
                Dynamic::from_ast(&z3::ast::Regexp::empty(self.ctx))
            }
            SmtExpr::ReAllChar(_sort) => {
                // re.allchar — matches any single character
                unsafe {
                    let str_sort =
                        z3_sys::Z3_mk_string_sort(self.z3_ctx());
                    let re_sort =
                        z3_sys::Z3_mk_re_sort(self.z3_ctx(), str_sort);
                    let raw = Z3_mk_re_allchar(self.z3_ctx(), re_sort);
                    Dynamic::wrap(self.ctx, raw)
                }
            }

            // === Quantifiers ===
            SmtExpr::ForAll { .. } | SmtExpr::Exists { .. } | SmtExpr::Bound(_, _) => {
                unimplemented!("Quantifiers not yet implemented in z3_solver")
            }
        }
    }

    /// Convert an expression expected to be Bool.
    fn convert_bool(&mut self, expr: &SmtExpr) -> z3::ast::Bool<'ctx> {
        self.convert(expr)
            .as_bool()
            .unwrap_or_else(|| panic!("Expected Bool expression, got: {:?}", expr))
    }

    /// Convert an expression expected to be Int.
    fn convert_int(&mut self, expr: &SmtExpr) -> z3::ast::Int<'ctx> {
        self.convert(expr)
            .as_int()
            .unwrap_or_else(|| panic!("Expected Int expression, got: {:?}", expr))
    }

    /// Convert an expression expected to be Real.
    fn convert_real(&mut self, expr: &SmtExpr) -> z3::ast::Real<'ctx> {
        self.convert(expr)
            .as_real()
            .unwrap_or_else(|| panic!("Expected Real expression, got: {:?}", expr))
    }

    /// Convert an expression expected to be BV.
    fn convert_bv(&mut self, expr: &SmtExpr) -> z3::ast::BV<'ctx> {
        self.convert(expr)
            .as_bv()
            .unwrap_or_else(|| panic!("Expected BV expression, got: {:?}", expr))
    }
}

// ---------------------------------------------------------------------------
// Typed constant creation
// ---------------------------------------------------------------------------

/// Create a Z3 constant from an [`SmtSort`], using the typed constructors
/// so we never need the raw `Z3_sort` pointer.
fn make_const<'ctx>(
    ctx: &'ctx z3::Context,
    name: &str,
    sort: &SmtSort,
) -> z3::ast::Dynamic<'ctx> {
    match sort {
        SmtSort::Bool => z3::ast::Bool::new_const(ctx, name).into(),
        SmtSort::Int => z3::ast::Int::new_const(ctx, name).into(),
        SmtSort::Real => z3::ast::Real::new_const(ctx, name).into(),
        SmtSort::String => z3::ast::String::new_const(ctx, name).into(),
        SmtSort::BitVec(width) => z3::ast::BV::new_const(ctx, name, *width).into(),
        SmtSort::Regex => {
            // Regex constants are unusual; create via uninterpreted sort
            // if ever needed. For now, panic as analysis doesn't declare
            // regex-sorted constants.
            unimplemented!("Regex-sorted constants are not supported")
        }
    }
}

// ---------------------------------------------------------------------------
// Model evaluation
// ---------------------------------------------------------------------------

/// Evaluate a Z3 expression in a model and return an [`SmtValue`].
fn eval_z3_dynamic(
    model: &z3::Model<'_>,
    expr: &z3::ast::Dynamic<'_>,
    model_completion: bool,
) -> SmtValue {
    match model.eval(expr, model_completion) {
        None => SmtValue::Undefined,
        Some(val) => {
            // Try each typed extraction.
            if let Some(b) = val.as_bool() {
                if let Some(bv) = b.as_bool() {
                    return SmtValue::Bool(bv);
                }
            }
            if let Some(i) = val.as_int() {
                if let Some(iv) = i.as_i64() {
                    return SmtValue::Int(iv);
                }
            }
            if let Some(r) = val.as_real() {
                if let Some((num, den)) = r.as_real() {
                    return SmtValue::Real(num, den);
                }
            }
            // For strings and other types, use the display representation.
            let s = format!("{}", val);
            // Strip outer quotes if present.
            let s = if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
                s[1..s.len() - 1].to_string()
            } else {
                s
            };
            SmtValue::String(s)
        }
    }
}
