// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the regorus-smt crate.

use regorus_smt::*;

/// Test: build a problem with AstBackend, render to SMT-LIB2, serialize to JSON.
#[test]
fn test_ast_backend_roundtrip() {
    let mut ctx = AstBackend::new();

    // Declare variables.
    let x = ctx.declare_const("x", SmtSort::Int);
    let y = ctx.declare_const("y", SmtSort::Int);
    let s = ctx.declare_const("s", SmtSort::String);

    // Build constraints:  x > 0, y > 0, x + y < 100, str.len(s) > 0
    let zero = ctx.mk_int(0);
    let hundred = ctx.mk_int(100);

    let x_pos = ctx.mk_gt(&x, &zero);
    let y_pos = ctx.mk_gt(&y, &zero);
    let sum = ctx.mk_add(&[x.clone(), y.clone()]);
    let sum_bound = ctx.mk_lt(&sum, &hundred);
    let s_nonempty = ctx.mk_gt(&ctx.mk_seq_length(&s), &zero);

    ctx.assert(x_pos);
    ctx.assert(y_pos);
    ctx.assert(sum_bound);
    ctx.assert(s_nonempty);

    // Build problem.
    let mut problem = ctx.into_problem();
    problem.add_extraction("x_val", SmtExpr::Const(0), SmtSort::Int, true);
    problem.add_extraction("y_val", SmtExpr::Const(1), SmtSort::Int, true);
    problem.add_extraction("s_val", SmtExpr::Const(2), SmtSort::String, true);
    problem.add_path_info(0, "input.x", SmtSort::Int);
    problem.add_path_info(1, "input.y", SmtSort::Int);
    problem.add_path_info(2, "input.s", SmtSort::String);

    // Render to SMT-LIB2.
    let smt2 = render_problem(&problem);
    assert!(smt2.contains("(declare-const x Int)"));
    assert!(smt2.contains("(declare-const y Int)"));
    assert!(smt2.contains("(declare-const s String)"));
    assert!(smt2.contains("(> x 0)"));
    assert!(smt2.contains("(> y 0)"));
    assert!(smt2.contains("(< (+ x y) 100)"));
    assert!(smt2.contains("(> (str.len s) 0)"));
    assert!(smt2.contains("(check-sat)"));
    assert!(smt2.contains("(get-value (x y s))"));

    // Serialize to JSON and back.
    let json = serde_json::to_string_pretty(&problem).unwrap();
    let roundtripped: SmtProblem = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtripped.declarations.len(), 3);
    assert_eq!(roundtripped.assertions.len(), 4);
    assert_eq!(roundtripped.extractions.len(), 3);
    assert_eq!(roundtripped.path_info.len(), 3);

    // Re-render should produce identical output.
    let smt2_rt = render_problem(&roundtripped);
    assert_eq!(smt2, smt2_rt);
}

/// Test: SmtSolution and SmtCheckResult construction and query.
#[test]
fn test_solution_types() {
    let sat_result = SmtCheckResult::sat(vec![
        SmtValue::Int(42),
        SmtValue::String("hello".into()),
        SmtValue::Bool(true),
    ]);
    assert_eq!(sat_result.status, SmtStatus::Sat);
    assert_eq!(sat_result.get_int(0), Some(42));
    assert_eq!(sat_result.get_string(1), Some("hello"));
    assert_eq!(sat_result.get_bool(2), Some(true));
    assert_eq!(sat_result.get_int(3), None); // out of bounds

    let sol = SmtSolution::single(sat_result);
    assert!(sol.is_sat());
    assert!(!sol.is_unsat());

    let unsat = SmtSolution::single(SmtCheckResult::unsat());
    assert!(!unsat.is_sat());
    assert!(unsat.is_unsat());

    let unsat_core = SmtSolution::single(SmtCheckResult::unsat_with_core(vec![0, 2, 5]));
    assert!(unsat_core.is_unsat());
    assert_eq!(unsat_core.first().unwrap().unsat_core, vec![0, 2, 5]);

    let unknown = SmtSolution::single(SmtCheckResult::unknown("timeout"));
    assert!(!unknown.is_sat());
    assert!(!unknown.is_unsat());
    assert_eq!(
        unknown.first().unwrap().reason_unknown.as_deref(),
        Some("timeout")
    );
}

/// Test: SmtProblem builder API.
#[test]
fn test_problem_builder() {
    let mut p = SmtProblem::new();
    let x = p.declare_const("x", SmtSort::Int);
    let f = p.declare_fun("f", vec![SmtSort::Int], SmtSort::Bool);
    assert_eq!(x, 0);
    assert_eq!(f, 1);
    assert_eq!(p.declarations.len(), 2);

    let idx = p.assert(SmtExpr::gt(SmtExpr::Const(x), SmtExpr::IntLit(0)));
    assert_eq!(idx, 0);

    p.add_extraction("result", SmtExpr::Const(x), SmtSort::Int, false);
    assert_eq!(p.extractions.len(), 1);
    assert!(!p.extractions[0].model_completion);
}

/// Test: incremental solving command sequence renders correctly.
#[test]
fn test_command_mode_render() {
    let mut p = SmtProblem::new();
    let x = p.declare_const("x", SmtSort::Int);
    p.assert(SmtExpr::gt(SmtExpr::Const(x), SmtExpr::IntLit(0)));
    p.assert(SmtExpr::lt(SmtExpr::Const(x), SmtExpr::IntLit(10)));

    p.commands = vec![
        SmtCommand::Assert(0),
        SmtCommand::Push,
        SmtCommand::Assert(1),
        SmtCommand::CheckSat,
        SmtCommand::GetModel,
        SmtCommand::Pop(1),
        SmtCommand::CheckSat,
    ];

    let smt2 = render_problem(&p);
    assert!(smt2.contains("(assert (> x 0))"));
    assert!(smt2.contains("(push 1)"));
    assert!(smt2.contains("(assert (< x 10))"));
    assert!(smt2.contains("(check-sat)"));
    assert!(smt2.contains("(pop 1)"));
}

/// Test: all SmtExpr convenience constructors.
#[test]
fn test_expr_convenience() {
    let e = SmtExpr::bool_lit(true);
    assert!(matches!(e, SmtExpr::True));

    let e = SmtExpr::bool_lit(false);
    assert!(matches!(e, SmtExpr::False));

    let e = SmtExpr::var(7);
    assert!(matches!(e, SmtExpr::Const(7)));

    let e = SmtExpr::and2(SmtExpr::True, SmtExpr::False);
    assert!(matches!(e, SmtExpr::And(ref v) if v.len() == 2));

    let e = SmtExpr::or2(SmtExpr::True, SmtExpr::False);
    assert!(matches!(e, SmtExpr::Or(ref v) if v.len() == 2));

    let e = SmtExpr::not(SmtExpr::True);
    assert!(matches!(e, SmtExpr::Not(_)));

    let e = SmtExpr::implies(SmtExpr::True, SmtExpr::False);
    assert!(matches!(e, SmtExpr::Implies(_, _)));
}

/// Test: bitvector literal rendering edge cases.
#[test]
fn test_bv_rendering() {
    let d: Vec<SmtDecl> = vec![];
    // 16-bit hex
    assert_eq!(
        render_expr_string(&SmtExpr::BvLit(0xABCD, 16), &d),
        "#xabcd"
    );
    // 32-bit hex
    assert_eq!(
        render_expr_string(&SmtExpr::BvLit(0, 32), &d),
        "#x00000000"
    );
    // 1-bit binary
    assert_eq!(
        render_expr_string(&SmtExpr::BvLit(1, 1), &d),
        "#b1"
    );
    // 5-bit binary (non-multiple of 4)
    assert_eq!(
        render_expr_string(&SmtExpr::BvLit(0b10101, 5), &d),
        "#b10101"
    );
}

/// Test: JSON serialization of SmtExpr variants.
#[test]
fn test_expr_serde() {
    let exprs = vec![
        SmtExpr::True,
        SmtExpr::IntLit(42),
        SmtExpr::StringLit("test".into()),
        SmtExpr::And(vec![SmtExpr::True, SmtExpr::False]),
        SmtExpr::SeqLength(Box::new(SmtExpr::StringLit("hello".into()))),
        SmtExpr::ReLoop(Box::new(SmtExpr::ReAllChar(SmtSort::String)), 1, 5),
        SmtExpr::ForAll {
            vars: vec![("x".into(), SmtSort::Int)],
            body: Box::new(SmtExpr::Bound(0, SmtSort::Int)),
        },
    ];

    for expr in &exprs {
        let json = serde_json::to_string(expr).unwrap();
        let rt: SmtExpr = serde_json::from_str(&json).unwrap();
        let json_rt = serde_json::to_string(&rt).unwrap();
        assert_eq!(json, json_rt, "round-trip failed for {:?}", expr);
    }
}

/// Test: AstBackend used through SmtContext trait.
#[test]
fn test_context_trait_usage() {
    fn build_constraint<'a, C: SmtContext<'a>>(ctx: &mut C) -> (C::Expr, C::Expr) {
        let x = ctx.declare_const("x", SmtSort::Int);
        let y = ctx.declare_const("y", SmtSort::Int);
        let sum = ctx.mk_add(&[x.clone(), y.clone()]);
        let zero = ctx.mk_int(0);
        let constraint = ctx.mk_gt(&sum, &zero);
        (x, constraint)
    }

    let mut ctx = AstBackend::new();
    let (_x, constraint) = build_constraint(&mut ctx);

    let decls = ctx.declarations();
    let text = render_expr_string(&constraint, decls);
    assert_eq!(text, "(> (+ x y) 0)");
}
