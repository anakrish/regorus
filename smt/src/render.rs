// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SMT-LIB2 text renderer for [`SmtExpr`], [`SmtSort`], and [`SmtProblem`].
//!
//! This module produces standards-compliant SMT-LIB2 text that can be piped
//! directly to any SMT solver (Z3, CVC5, etc.).  It also serves as a
//! human-readable debug dump of analysis queries.

use alloc::string::String;

use crate::expr::{SmtDecl, SmtExpr, SmtSort};
use crate::problem::{SmtCommand, SmtProblem};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Render a complete [`SmtProblem`] as an SMT-LIB2 script.
pub fn render_problem(problem: &SmtProblem) -> String {
    let mut out = String::with_capacity(4096);

    // Preamble: logic and options.
    out.push_str("(set-logic ALL)\n");

    if let Some(ms) = problem.config.timeout_ms {
        out.push_str("(set-option :timeout ");
        push_u32(&mut out, ms);
        out.push_str(")\n");
    }

    if problem.config.produce_unsat_core {
        out.push_str("(set-option :produce-unsat-cores true)\n");
    }

    if problem.config.produce_proofs {
        out.push_str("(set-option :produce-proofs true)\n");
    }

    out.push('\n');

    // Declarations.
    for decl in &problem.declarations {
        render_decl(&mut out, decl);
        out.push('\n');
    }

    if !problem.declarations.is_empty() {
        out.push('\n');
    }

    if problem.commands.is_empty() {
        // Simple mode: assert all, check-sat, extract.
        for (i, assertion) in problem.assertions.iter().enumerate() {
            // Named assertions for unsat-core support.
            if problem.config.produce_unsat_core {
                out.push_str("(assert (! ");
                render_expr(&mut out, assertion, &problem.declarations);
                out.push_str(" :named a");
                push_usize(&mut out, i);
                out.push_str("))\n");
            } else {
                out.push_str("(assert ");
                render_expr(&mut out, assertion, &problem.declarations);
                out.push_str(")\n");
            }
        }

        out.push_str("\n(check-sat)\n");

        if !problem.extractions.is_empty() {
            out.push_str("(get-value (");
            for (i, ext) in problem.extractions.iter().enumerate() {
                if i > 0 {
                    out.push(' ');
                }
                render_expr(&mut out, &ext.expr, &problem.declarations);
            }
            out.push_str("))\n");
        }
    } else {
        // Command mode: execute commands in sequence.
        for cmd in &problem.commands {
            render_command(&mut out, cmd, problem);
            out.push('\n');
        }
    }

    out.push_str("\n(exit)\n");
    out
}

/// Render a single [`SmtExpr`] to SMT-LIB2 text.
///
/// `decls` is needed to resolve `Const(id)` references to their names.
pub fn render_expr_string(expr: &SmtExpr, decls: &[SmtDecl]) -> String {
    let mut out = String::with_capacity(256);
    render_expr(&mut out, expr, decls);
    out
}

/// Render an [`SmtSort`] to SMT-LIB2 text.
pub fn render_sort_string(sort: &SmtSort) -> String {
    let mut out = String::with_capacity(16);
    render_sort(&mut out, sort);
    out
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn render_command(out: &mut String, cmd: &SmtCommand, problem: &SmtProblem) {
    match cmd {
        SmtCommand::Assert(idx) => {
            if let Some(assertion) = problem.assertions.get(*idx) {
                if problem.config.produce_unsat_core {
                    out.push_str("(assert (! ");
                    render_expr(out, assertion, &problem.declarations);
                    out.push_str(" :named a");
                    push_usize(out, *idx);
                    out.push_str("))");
                } else {
                    out.push_str("(assert ");
                    render_expr(out, assertion, &problem.declarations);
                    out.push(')');
                }
            }
        }
        SmtCommand::AssertExpr(expr) => {
            out.push_str("(assert ");
            render_expr(out, expr, &problem.declarations);
            out.push(')');
        }
        SmtCommand::Push => {
            out.push_str("(push 1)");
        }
        SmtCommand::Pop(n) => {
            out.push_str("(pop ");
            push_u32(out, *n);
            out.push(')');
        }
        SmtCommand::CheckSat => {
            out.push_str("(check-sat)");
        }
        SmtCommand::CheckSatAssuming(lits) => {
            out.push_str("(check-sat-assuming (");
            for (i, lit) in lits.iter().enumerate() {
                if i > 0 {
                    out.push(' ');
                }
                render_expr(out, lit, &problem.declarations);
            }
            out.push_str("))");
        }
        SmtCommand::GetModel => {
            if !problem.extractions.is_empty() {
                out.push_str("(get-value (");
                for (i, ext) in problem.extractions.iter().enumerate() {
                    if i > 0 {
                        out.push(' ');
                    }
                    render_expr(out, &ext.expr, &problem.declarations);
                }
                out.push_str("))");
            } else {
                out.push_str("(get-model)");
            }
        }
    }
}

fn render_decl(out: &mut String, decl: &SmtDecl) {
    match decl {
        SmtDecl::Const { name, sort, .. } => {
            out.push_str("(declare-const ");
            render_symbol(out, name);
            out.push(' ');
            render_sort(out, sort);
            out.push(')');
        }
        SmtDecl::Fun {
            name,
            arg_sorts,
            ret_sort,
            ..
        } => {
            out.push_str("(declare-fun ");
            render_symbol(out, name);
            out.push_str(" (");
            for (i, s) in arg_sorts.iter().enumerate() {
                if i > 0 {
                    out.push(' ');
                }
                render_sort(out, s);
            }
            out.push_str(") ");
            render_sort(out, ret_sort);
            out.push(')');
        }
    }
}

fn render_sort(out: &mut String, sort: &SmtSort) {
    match sort {
        SmtSort::Bool => out.push_str("Bool"),
        SmtSort::Int => out.push_str("Int"),
        SmtSort::Real => out.push_str("Real"),
        SmtSort::String => out.push_str("String"),
        SmtSort::BitVec(sz) => {
            out.push_str("(_ BitVec ");
            push_u32(out, *sz);
            out.push(')');
        }
        SmtSort::Regex => out.push_str("(RegEx String)"),
    }
}

fn render_symbol(out: &mut String, name: &str) {
    // SMT-LIB2 simple symbols: [a-zA-Z~!@$%^&*_\-+=<>\.?/][a-zA-Z0-9~!@$%^&*_\-+=<>\.?/]*
    // If the name contains spaces or other special chars, quote it.
    let needs_quoting = name.is_empty()
        || name.contains(|c: char| {
            !c.is_ascii_alphanumeric()
                && !matches!(
                    c,
                    '~' | '!'
                        | '@'
                        | '$'
                        | '%'
                        | '^'
                        | '&'
                        | '*'
                        | '_'
                        | '-'
                        | '+'
                        | '='
                        | '<'
                        | '>'
                        | '.'
                        | '?'
                        | '/'
                )
        });

    if needs_quoting {
        out.push('|');
        out.push_str(name);
        out.push('|');
    } else {
        out.push_str(name);
    }
}

fn render_string_literal(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\"\""), // SMT-LIB2 escaping
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
}

/// Get the name of a declaration by id, falling back to `?<id>`.
fn decl_name(decls: &[SmtDecl], id: u32) -> &str {
    if let Some(decl) = decls.get(id as usize) {
        decl.name()
    } else {
        // This shouldn't happen in well-formed problems; we'll render
        // something parseable.
        "?unknown"
    }
}

fn render_expr(out: &mut String, expr: &SmtExpr, decls: &[SmtDecl]) {
    match expr {
        // Literals
        SmtExpr::True => out.push_str("true"),
        SmtExpr::False => out.push_str("false"),
        SmtExpr::IntLit(n) => {
            if *n < 0 {
                out.push_str("(- ");
                push_i64_abs(out, *n);
                out.push(')');
            } else {
                push_i64(out, *n);
            }
        }
        SmtExpr::RealLit(num, den) => {
            out.push_str("(/ ");
            if *num < 0 {
                out.push_str("(- ");
                push_i64_abs(out, *num);
                out.push(')');
            } else {
                push_i64(out, *num);
            }
            out.push(' ');
            push_i64(out, *den);
            out.push_str(".0)");
        }
        SmtExpr::StringLit(s) => render_string_literal(out, s),
        SmtExpr::BvLit(val, width) => {
            // Use hex if width is a multiple of 4, else binary.
            if *width > 0 && *width % 4 == 0 {
                out.push_str("#x");
                let hex_digits = (*width / 4) as usize;
                let mask = if *width >= 64 {
                    u64::MAX
                } else {
                    (1u64 << *width) - 1
                };
                let v = (*val as u64) & mask;
                for i in (0..hex_digits).rev() {
                    let nibble = (v >> (i * 4)) & 0xF;
                    out.push(core::char::from_digit(nibble as u32, 16).unwrap_or('0'));
                }
            } else {
                out.push_str("#b");
                for i in (0..*width).rev() {
                    if (*val >> i) & 1 == 1 {
                        out.push('1');
                    } else {
                        out.push('0');
                    }
                }
            }
        }

        // Variables
        SmtExpr::Const(id) => {
            render_symbol(out, decl_name(decls, *id));
        }
        SmtExpr::App(id, args) => {
            out.push('(');
            render_symbol(out, decl_name(decls, *id));
            for arg in args {
                out.push(' ');
                render_expr(out, arg, decls);
            }
            out.push(')');
        }

        // Propositional
        SmtExpr::Not(a) => render_unary(out, "not", a, decls),
        SmtExpr::And(args) => render_nary(out, "and", args, decls),
        SmtExpr::Or(args) => render_nary(out, "or", args, decls),
        SmtExpr::Xor(a, b) => render_binary(out, "xor", a, b, decls),
        SmtExpr::Implies(a, b) => render_binary(out, "=>", a, b, decls),
        SmtExpr::Iff(a, b) => render_binary(out, "=", a, b, decls), // iff is = in SMT-LIB2
        SmtExpr::Ite(c, t, e) => render_ternary(out, "ite", c, t, e, decls),

        // Equality
        SmtExpr::Eq(a, b) => render_binary(out, "=", a, b, decls),
        SmtExpr::Distinct(args) => render_nary(out, "distinct", args, decls),

        // Arithmetic
        SmtExpr::Add(args) => render_nary(out, "+", args, decls),
        SmtExpr::Sub(args) => render_nary(out, "-", args, decls),
        SmtExpr::Mul(args) => render_nary(out, "*", args, decls),
        SmtExpr::Div(a, b) => render_binary(out, "div", a, b, decls),
        SmtExpr::Mod(a, b) => render_binary(out, "mod", a, b, decls),
        SmtExpr::Rem(a, b) => render_binary(out, "rem", a, b, decls),
        SmtExpr::Neg(a) => render_unary(out, "-", a, decls),
        SmtExpr::Abs(a) => render_unary(out, "abs", a, decls),
        SmtExpr::Power(a, b) => render_binary(out, "^", a, b, decls),

        // Comparison
        SmtExpr::Lt(a, b) => render_binary(out, "<", a, b, decls),
        SmtExpr::Le(a, b) => render_binary(out, "<=", a, b, decls),
        SmtExpr::Gt(a, b) => render_binary(out, ">", a, b, decls),
        SmtExpr::Ge(a, b) => render_binary(out, ">=", a, b, decls),

        // Coercion
        SmtExpr::Int2Real(a) => render_unary(out, "to_real", a, decls),
        SmtExpr::Real2Int(a) => render_unary(out, "to_int", a, decls),
        SmtExpr::Int2Bv(a, n) => {
            out.push_str("((_ int2bv ");
            push_u32(out, *n);
            out.push_str(") ");
            render_expr(out, a, decls);
            out.push(')');
        }
        SmtExpr::Bv2Int(a, signed) => {
            // Z3 bv2int takes a bool for signedness, but SMT-LIB2 uses
            // bv2nat (unsigned).  We render signed conversion as a
            // comment-annotated form.
            if *signed {
                // There's no standard SMT-LIB2 for signed bv2int.
                // We use Z3 extension syntax.
                out.push_str("(bv2int ");
                render_expr(out, a, decls);
                out.push_str(" true)");
            } else {
                out.push_str("(bv2nat ");
                render_expr(out, a, decls);
                out.push(')');
            }
        }

        // Bitvector
        SmtExpr::BvAnd(a, b) => render_binary(out, "bvand", a, b, decls),
        SmtExpr::BvOr(a, b) => render_binary(out, "bvor", a, b, decls),
        SmtExpr::BvXor(a, b) => render_binary(out, "bvxor", a, b, decls),
        SmtExpr::BvNot(a) => render_unary(out, "bvnot", a, decls),
        SmtExpr::BvNeg(a) => render_unary(out, "bvneg", a, decls),
        SmtExpr::BvAdd(a, b) => render_binary(out, "bvadd", a, b, decls),
        SmtExpr::BvSub(a, b) => render_binary(out, "bvsub", a, b, decls),
        SmtExpr::BvMul(a, b) => render_binary(out, "bvmul", a, b, decls),
        SmtExpr::BvUDiv(a, b) => render_binary(out, "bvudiv", a, b, decls),
        SmtExpr::BvShl(a, b) => render_binary(out, "bvshl", a, b, decls),
        SmtExpr::BvLShr(a, b) => render_binary(out, "bvlshr", a, b, decls),
        SmtExpr::BvAShr(a, b) => render_binary(out, "bvashr", a, b, decls),

        // Sequences / Strings
        SmtExpr::SeqLength(a) => render_unary(out, "str.len", a, decls),
        SmtExpr::SeqConcat(args) => render_nary(out, "str.++", args, decls),
        SmtExpr::SeqContains(a, b) => render_binary(out, "str.contains", a, b, decls),
        SmtExpr::SeqPrefix(a, b) => render_binary(out, "str.prefixof", a, b, decls),
        SmtExpr::SeqSuffix(a, b) => render_binary(out, "str.suffixof", a, b, decls),
        SmtExpr::SeqAt(a, b) => render_binary(out, "str.at", a, b, decls),
        SmtExpr::SeqIndex(a, b, c) => render_ternary(out, "str.indexof", a, b, c, decls),
        SmtExpr::SeqReplace(a, b, c) => render_ternary(out, "str.replace", a, b, c, decls),
        SmtExpr::SeqExtract(a, b, c) => render_ternary(out, "str.substr", a, b, c, decls),
        SmtExpr::StrLt(a, b) => render_binary(out, "str.<", a, b, decls),
        SmtExpr::StrLe(a, b) => render_binary(out, "str.<=", a, b, decls),

        // String<->numeric
        SmtExpr::IntToStr(a) => render_unary(out, "str.from_int", a, decls),
        SmtExpr::StrToInt(a) => render_unary(out, "str.to_int", a, decls),

        // Regular expressions
        SmtExpr::SeqToRe(a) => render_unary(out, "str.to_re", a, decls),
        SmtExpr::SeqInRe(a, b) => render_binary(out, "str.in_re", a, b, decls),
        SmtExpr::ReStar(a) => render_unary(out, "re.*", a, decls),
        SmtExpr::RePlus(a) => render_unary(out, "re.+", a, decls),
        SmtExpr::ReOption(a) => render_unary(out, "re.opt", a, decls),
        SmtExpr::ReUnion(args) => render_nary(out, "re.union", args, decls),
        SmtExpr::ReIntersect(args) => render_nary(out, "re.inter", args, decls),
        SmtExpr::ReConcat(args) => render_nary(out, "re.++", args, decls),
        SmtExpr::ReRange(a, b) => render_binary(out, "re.range", a, b, decls),
        SmtExpr::ReComplement(a) => render_unary(out, "re.comp", a, decls),
        SmtExpr::ReDiff(a, b) => render_binary(out, "re.diff", a, b, decls),
        SmtExpr::ReLoop(a, lo, hi) => {
            out.push_str("((_ re.loop ");
            push_u32(out, *lo);
            out.push(' ');
            push_u32(out, *hi);
            out.push_str(") ");
            render_expr(out, a, decls);
            out.push(')');
        }
        SmtExpr::ReFull(_) => out.push_str("re.all"),
        SmtExpr::ReEmpty(_) => out.push_str("re.none"),
        SmtExpr::ReAllChar(_) => out.push_str("re.allchar"),

        // Quantifiers
        SmtExpr::ForAll { vars, body } => render_quantifier(out, "forall", vars, body, decls),
        SmtExpr::Exists { vars, body } => render_quantifier(out, "exists", vars, body, decls),
        SmtExpr::Bound(idx, _sort) => {
            // de-Bruijn index — rendered as `_bN` for readability.
            out.push_str("_b");
            push_u32(out, *idx);
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

fn render_unary(out: &mut String, op: &str, a: &SmtExpr, decls: &[SmtDecl]) {
    out.push('(');
    out.push_str(op);
    out.push(' ');
    render_expr(out, a, decls);
    out.push(')');
}

fn render_binary(out: &mut String, op: &str, a: &SmtExpr, b: &SmtExpr, decls: &[SmtDecl]) {
    out.push('(');
    out.push_str(op);
    out.push(' ');
    render_expr(out, a, decls);
    out.push(' ');
    render_expr(out, b, decls);
    out.push(')');
}

fn render_ternary(
    out: &mut String,
    op: &str,
    a: &SmtExpr,
    b: &SmtExpr,
    c: &SmtExpr,
    decls: &[SmtDecl],
) {
    out.push('(');
    out.push_str(op);
    out.push(' ');
    render_expr(out, a, decls);
    out.push(' ');
    render_expr(out, b, decls);
    out.push(' ');
    render_expr(out, c, decls);
    out.push(')');
}

fn render_nary(out: &mut String, op: &str, args: &[SmtExpr], decls: &[SmtDecl]) {
    out.push('(');
    out.push_str(op);
    for arg in args {
        out.push(' ');
        render_expr(out, arg, decls);
    }
    out.push(')');
}

fn render_quantifier(
    out: &mut String,
    kind: &str,
    vars: &[(String, SmtSort)],
    body: &SmtExpr,
    decls: &[SmtDecl],
) {
    out.push('(');
    out.push_str(kind);
    out.push_str(" (");
    for (i, (name, sort)) in vars.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push('(');
        render_symbol(out, name);
        out.push(' ');
        render_sort(out, sort);
        out.push(')');
    }
    out.push_str(") ");
    render_expr(out, body, decls);
    out.push(')');
}

// ---------------------------------------------------------------------------
// Number rendering (no alloc::format! needed)
// ---------------------------------------------------------------------------

fn push_u32(out: &mut String, n: u32) {
    let mut buf = itoa::Buffer::new();
    out.push_str(buf.format(n));
}

fn push_i64(out: &mut String, n: i64) {
    let mut buf = itoa::Buffer::new();
    out.push_str(buf.format(n));
}

fn push_i64_abs(out: &mut String, n: i64) {
    let mut buf = itoa::Buffer::new();
    let abs = if n == i64::MIN {
        // i64::MIN.abs() overflows; handle specially.
        out.push_str(buf.format(i64::MAX));
        return;
    } else {
        n.abs()
    };
    out.push_str(buf.format(abs));
}

fn push_usize(out: &mut String, n: usize) {
    let mut buf = itoa::Buffer::new();
    out.push_str(buf.format(n));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn no_decls() -> Vec<SmtDecl> {
        vec![]
    }

    #[test]
    fn test_sort_rendering() {
        assert_eq!(render_sort_string(&SmtSort::Bool), "Bool");
        assert_eq!(render_sort_string(&SmtSort::Int), "Int");
        assert_eq!(render_sort_string(&SmtSort::Real), "Real");
        assert_eq!(render_sort_string(&SmtSort::String), "String");
        assert_eq!(render_sort_string(&SmtSort::BitVec(32)), "(_ BitVec 32)");
        assert_eq!(render_sort_string(&SmtSort::Regex), "(RegEx String)");
    }

    #[test]
    fn test_literal_rendering() {
        let d = no_decls();
        assert_eq!(render_expr_string(&SmtExpr::True, &d), "true");
        assert_eq!(render_expr_string(&SmtExpr::False, &d), "false");
        assert_eq!(render_expr_string(&SmtExpr::IntLit(42), &d), "42");
        assert_eq!(render_expr_string(&SmtExpr::IntLit(-5), &d), "(- 5)");
        assert_eq!(
            render_expr_string(&SmtExpr::StringLit("hello".into()), &d),
            "\"hello\""
        );
        assert_eq!(
            render_expr_string(&SmtExpr::StringLit("say \"hi\"".into()), &d),
            "\"say \"\"hi\"\"\""
        );
        assert_eq!(
            render_expr_string(&SmtExpr::BvLit(0xFF, 8), &d),
            "#xff"
        );
        assert_eq!(
            render_expr_string(&SmtExpr::BvLit(5, 3), &d),
            "#b101"
        );
    }

    #[test]
    fn test_binary_ops() {
        let d = no_decls();
        let expr = SmtExpr::and2(SmtExpr::True, SmtExpr::False);
        assert_eq!(render_expr_string(&expr, &d), "(and true false)");

        let expr = SmtExpr::implies(SmtExpr::True, SmtExpr::False);
        assert_eq!(render_expr_string(&expr, &d), "(=> true false)");

        let expr = SmtExpr::eq(SmtExpr::IntLit(1), SmtExpr::IntLit(2));
        assert_eq!(render_expr_string(&expr, &d), "(= 1 2)");
    }

    #[test]
    fn test_const_rendering() {
        let decls = vec![SmtDecl::Const {
            id: 0,
            name: "x".into(),
            sort: SmtSort::Int,
        }];
        assert_eq!(render_expr_string(&SmtExpr::Const(0), &decls), "x");
    }

    #[test]
    fn test_problem_rendering() {
        let mut p = SmtProblem::new();
        let x = p.declare_const("x", SmtSort::Int);
        p.assert(SmtExpr::gt(SmtExpr::Const(x), SmtExpr::IntLit(0)));
        p.assert(SmtExpr::lt(SmtExpr::Const(x), SmtExpr::IntLit(10)));
        p.add_extraction("x_val", SmtExpr::Const(x), SmtSort::Int, true);

        let text = render_problem(&p);
        assert!(text.contains("(declare-const x Int)"));
        assert!(text.contains("(assert (> x 0))"));
        assert!(text.contains("(assert (< x 10))"));
        assert!(text.contains("(check-sat)"));
        assert!(text.contains("(get-value (x))"));
    }

    #[test]
    fn test_string_ops() {
        let decls = vec![SmtDecl::Const {
            id: 0,
            name: "s".into(),
            sort: SmtSort::String,
        }];
        let s = SmtExpr::Const(0);
        let expr = SmtExpr::SeqLength(Box::new(s.clone()));
        assert_eq!(render_expr_string(&expr, &decls), "(str.len s)");

        let expr = SmtExpr::SeqContains(
            Box::new(s.clone()),
            Box::new(SmtExpr::StringLit("abc".into())),
        );
        assert_eq!(
            render_expr_string(&expr, &decls),
            "(str.contains s \"abc\")"
        );
    }

    #[test]
    fn test_quantifier_rendering() {
        let d = no_decls();
        let expr = SmtExpr::ForAll {
            vars: vec![("x".into(), SmtSort::Int)],
            body: Box::new(SmtExpr::ge(
                SmtExpr::Bound(0, SmtSort::Int),
                SmtExpr::IntLit(0),
            )),
        };
        assert_eq!(
            render_expr_string(&expr, &d),
            "(forall ((x Int)) (>= _b0 0))"
        );
    }

    #[test]
    fn test_regex_rendering() {
        let d = no_decls();
        let re = SmtExpr::ReStar(Box::new(SmtExpr::SeqToRe(Box::new(SmtExpr::StringLit(
            "a".into(),
        )))));
        assert_eq!(
            render_expr_string(&re, &d),
            "(re.* (str.to_re \"a\"))"
        );

        let re_loop = SmtExpr::ReLoop(Box::new(SmtExpr::ReAllChar(SmtSort::String)), 2, 5);
        assert_eq!(
            render_expr_string(&re_loop, &d),
            "((_ re.loop 2 5) re.allchar)"
        );
    }
}
