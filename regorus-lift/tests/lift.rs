//! Unit tests for the lift admission gate, driving [`lift`] with hand-built
//! [`PartialEvalResult`] values so each accept/reject path is covered in
//! isolation (no engine required).

use regorus::causality_report::{
    Lowerability, PartialEvalResult, ResidualCondition, ResidualDisjunctOutcome, Soundness,
};
use regorus::Value;

use regorus_lift::sim::simulate;
use regorus_lift::{lift, ContextSchema, FieldType, RejectReason, Verdict};

/// A schema observing the egress-style fields used throughout these tests.
fn egress_schema() -> ContextSchema {
    ContextSchema::new()
        .with("input.dest_ip", FieldType::Str)
        .with("input.proto", FieldType::Str)
        .with("input.port", FieldType::Uint)
        .with("input.host", FieldType::Str)
        .with("input.user.name", FieldType::Str)
}

/// Build a sound `==` atom condition over `input_path == value`.
fn eq_atom(input_path: &str, value: Value) -> ResidualCondition {
    ResidualCondition {
        condition: format!("{input_path} == ..."),
        operator: Some("==".to_string()),
        input_path: Some(input_path.to_string()),
        value: Some(value),
        value_encoding: None,
        kind: "input_eq".to_string(),
        lowerable: Lowerability::Atom,
        soundness: Soundness::Sound,
        negated_conditions: Vec::new(),
        source_rule: Some("data.egress.allow".to_string()),
        source_file: None,
        source_row: None,
        source_col: None,
    }
}

fn sound_allow_outcome() -> ResidualDisjunctOutcome {
    ResidualDisjunctOutcome {
        result: Value::Bool(true),
        soundness: Soundness::Sound,
    }
}

fn atom(
    input_path: &str,
    operator: Option<&str>,
    value: Option<Value>,
    kind: &str,
) -> ResidualCondition {
    ResidualCondition {
        condition: format!("{input_path} atom"),
        operator: operator.map(str::to_string),
        input_path: Some(input_path.to_string()),
        value,
        value_encoding: None,
        kind: kind.to_string(),
        lowerable: Lowerability::Atom,
        soundness: Soundness::Sound,
        negated_conditions: Vec::new(),
        source_rule: Some("data.egress.allow".to_string()),
        source_file: None,
        source_row: None,
        source_col: None,
    }
}

/// Assemble a sound PE result from aligned (disjunct, outcome) pairs.
fn pe_with(disjuncts: Vec<(Vec<ResidualCondition>, ResidualDisjunctOutcome)>) -> PartialEvalResult {
    let (residual_queries, residual_outcomes): (Vec<_>, Vec<_>) = disjuncts.into_iter().unzip();
    PartialEvalResult {
        result: Value::Undefined,
        residual_queries,
        residual_outcomes,
        depends_on_unknown: Vec::new(),
        soundness: Soundness::Sound,
        unsound_reasons: Vec::new(),
        warnings: Vec::new(),
    }
}

#[test]
fn lifts_single_conjunction_disjunct() {
    let disjunct = vec![
        eq_atom("input.dest_ip", Value::from("10.0.0.1")),
        eq_atom("input.proto", Value::from("tcp")),
    ];
    let pe = pe_with(vec![(disjunct, sound_allow_outcome())]);

    let res = lift(&pe, &egress_schema());

    assert!(
        res.is_complete(),
        "unexpected rejections: {:?}",
        res.rejections
    );
    let config = res.config.expect("expected a config");
    assert_eq!(config.allow_clauses.len(), 1);
    assert_eq!(config.allow_clauses[0].atoms.len(), 2);
    assert!(config.static_verdict.is_none());
    assert_eq!(config.fields.get("input.dest_ip"), Some(&FieldType::Str));
}

#[test]
fn lifts_multiple_disjuncts_as_or() {
    let pe = pe_with(vec![
        (
            vec![eq_atom("input.dest_ip", Value::from("10.0.0.1"))],
            sound_allow_outcome(),
        ),
        (
            vec![eq_atom("input.dest_ip", Value::from("10.0.0.2"))],
            sound_allow_outcome(),
        ),
    ]);

    let res = lift(&pe, &egress_schema());

    assert!(res.is_complete(), "rejections: {:?}", res.rejections);
    assert_eq!(res.config.unwrap().allow_clauses.len(), 2);
}

#[test]
fn fully_determined_true_is_static_allow() {
    let pe = PartialEvalResult {
        result: Value::Bool(true),
        residual_queries: Vec::new(),
        residual_outcomes: Vec::new(),
        depends_on_unknown: Vec::new(),
        soundness: Soundness::Sound,
        unsound_reasons: Vec::new(),
        warnings: Vec::new(),
    };

    let config = lift(&pe, &egress_schema()).config.unwrap();
    assert_eq!(config.static_verdict, Some(Verdict::Allow));
}

#[test]
fn fully_determined_false_is_static_deny() {
    let pe = PartialEvalResult {
        result: Value::Bool(false),
        residual_queries: Vec::new(),
        residual_outcomes: Vec::new(),
        depends_on_unknown: Vec::new(),
        soundness: Soundness::Sound,
        unsound_reasons: Vec::new(),
        warnings: Vec::new(),
    };

    let config = lift(&pe, &egress_schema()).config.unwrap();
    assert_eq!(config.static_verdict, Some(Verdict::Deny));
}

#[test]
fn rejects_when_result_unsound() {
    let mut pe = pe_with(vec![(
        vec![eq_atom("input.dest_ip", Value::from("10.0.0.1"))],
        sound_allow_outcome(),
    )]);
    pe.soundness = Soundness::Unsound {
        reason: regorus::evaluation_trace::PeUnsoundReason::UnknownInputDependency,
    };

    let res = lift(&pe, &egress_schema());
    assert!(res.config.is_none());
    assert_eq!(res.rejections.len(), 1);
    assert_eq!(
        res.rejections[0].reason,
        RejectReason::ResultUnsound(
            regorus::evaluation_trace::PeUnsoundReason::UnknownInputDependency
        )
    );
}

#[test]
fn rejects_non_atom_condition() {
    let mut cond = eq_atom("input.dest_ip", Value::from("10.0.0.1"));
    cond.lowerable = Lowerability::Builtin;
    let pe = pe_with(vec![(vec![cond], sound_allow_outcome())]);

    let res = lift(&pe, &egress_schema());
    assert!(res.config.is_none());
    assert_eq!(res.rejections[0].reason, RejectReason::ConditionNotAtom);
}

#[test]
fn rejects_unsound_condition() {
    let mut cond = eq_atom("input.dest_ip", Value::from("10.0.0.1"));
    cond.soundness = Soundness::Unsound {
        reason: regorus::evaluation_trace::PeUnsoundReason::NonScalarValue,
    };
    let pe = pe_with(vec![(vec![cond], sound_allow_outcome())]);

    let res = lift(&pe, &egress_schema());
    assert_eq!(res.rejections[0].reason, RejectReason::ConditionUnsound);
}

#[test]
fn lifts_numeric_comparison_operator() {
    let mut cond = eq_atom("input.port", Value::from(443u64));
    cond.operator = Some(">".to_string());
    let pe = pe_with(vec![(vec![cond], sound_allow_outcome())]);

    let res = lift(&pe, &egress_schema());
    assert!(res.is_complete(), "rejections: {:?}", res.rejections);
    assert_eq!(res.config.unwrap().allow_clauses[0].atoms.len(), 1);
}

#[test]
fn lifts_and_simulates_cidr_prefix_and_exists_atoms() {
    let pe = pe_with(vec![(
        vec![
            atom(
                "input.dest_ip",
                Some("cidr_contains"),
                Some(Value::from("10.0.0.0/24")),
                "condition_holds",
            ),
            atom(
                "input.host",
                Some("startswith"),
                Some(Value::from("trusted-")),
                "condition_holds",
            ),
            atom("input.user.name", None, None, "exists"),
        ],
        sound_allow_outcome(),
    )]);

    let res = lift(&pe, &egress_schema());
    assert!(res.is_complete(), "rejections: {:?}", res.rejections);
    let config = res.config.unwrap();
    let good: serde_json::Value = serde_json::from_str(
        r#"{"dest_ip":"10.0.0.7","host":"trusted-api","user":{"name":"ana"}}"#,
    )
    .unwrap();
    assert_eq!(simulate(&config, &good), Verdict::Allow);

    let bad: serde_json::Value = serde_json::from_str(
        r#"{"dest_ip":"10.0.1.7","host":"trusted-api","user":{"name":"ana"}}"#,
    )
    .unwrap();
    assert_eq!(simulate(&config, &bad), Verdict::Deny);
}

#[test]
fn lifts_negated_prefix_with_rego_undefined_semantics() {
    let pe = pe_with(vec![(
        vec![atom(
            "input.host",
            Some("not_startswith"),
            Some(Value::from("admin-")),
            "condition_holds",
        )],
        sound_allow_outcome(),
    )]);
    let config = lift(&pe, &egress_schema()).config.unwrap();
    let viewer: serde_json::Value = serde_json::from_str(r#"{"host":"user-api"}"#).unwrap();
    assert_eq!(simulate(&config, &viewer), Verdict::Allow);
    let non_string: serde_json::Value = serde_json::from_str(r#"{"host":7}"#).unwrap();
    assert_eq!(simulate(&config, &non_string), Verdict::Allow);
}

#[test]
fn rejects_unbound_field() {
    let cond = eq_atom("input.unobserved", Value::from("x"));
    let pe = pe_with(vec![(vec![cond], sound_allow_outcome())]);

    let res = lift(&pe, &egress_schema());
    assert_eq!(
        res.rejections[0].reason,
        RejectReason::UnboundField("input.unobserved".to_string())
    );
}

#[test]
fn rejects_type_mismatch_against_schema() {
    // dest_ip is Str in the schema; supply a numeric value.
    let cond = eq_atom("input.dest_ip", Value::from(5u64));
    let pe = pe_with(vec![(vec![cond], sound_allow_outcome())]);

    let res = lift(&pe, &egress_schema());
    assert_eq!(
        res.rejections[0].reason,
        RejectReason::UnboundField("input.dest_ip".to_string())
    );
}

#[test]
fn rejects_disjunct_not_allow() {
    let outcome = ResidualDisjunctOutcome {
        result: Value::Bool(false),
        soundness: Soundness::Sound,
    };
    let pe = pe_with(vec![(
        vec![eq_atom("input.dest_ip", Value::from("10.0.0.1"))],
        outcome,
    )]);

    let res = lift(&pe, &egress_schema());
    assert!(res.config.is_none());
    assert_eq!(res.rejections[0].reason, RejectReason::DisjunctNotAllow);
}

#[test]
fn rejects_unsound_disjunct() {
    let outcome = ResidualDisjunctOutcome {
        result: Value::Bool(true),
        soundness: Soundness::Unsound {
            reason: regorus::evaluation_trace::PeUnsoundReason::UnsupportedOperator,
        },
    };
    let pe = pe_with(vec![(
        vec![eq_atom("input.dest_ip", Value::from("10.0.0.1"))],
        outcome,
    )]);

    let res = lift(&pe, &egress_schema());
    assert_eq!(res.rejections[0].reason, RejectReason::DisjunctUnsound);
}

#[test]
fn unlifted_unknown_dependency_blocks_lifting() {
    let mut pe = pe_with(vec![(
        vec![eq_atom("input.dest_ip", Value::from("10.0.0.1"))],
        sound_allow_outcome(),
    )]);
    pe.depends_on_unknown = vec!["input.hidden".to_string()];

    let res = lift(&pe, &egress_schema());
    // A possibly-incomplete DNF must not be partially enforced (fail closed).
    assert!(res.config.is_none());
    assert!(res.rejections.iter().any(|r| matches!(
        &r.reason,
        RejectReason::UnliftedDependency(p) if p == "input.hidden"
    )));
}

#[test]
fn local_lowering_failure_does_not_block_sound_disjuncts() {
    // Disjunct 2 is unsound for a *local* reason (also tagged on its condition);
    // it must be dropped while disjunct 1 still lifts.
    let mut bad_cond = eq_atom("input.dest_ip", Value::from("10.0.0.9"));
    bad_cond.lowerable = Lowerability::Builtin;
    bad_cond.soundness = Soundness::Unsound {
        reason: regorus::evaluation_trace::PeUnsoundReason::BuiltinUnsupported,
    };
    let bad_outcome = ResidualDisjunctOutcome {
        result: Value::Bool(true),
        soundness: Soundness::Unsound {
            reason: regorus::evaluation_trace::PeUnsoundReason::BuiltinUnsupported,
        },
    };
    let mut pe = pe_with(vec![
        (
            vec![eq_atom("input.dest_ip", Value::from("10.0.0.1"))],
            sound_allow_outcome(),
        ),
        (vec![bad_cond], bad_outcome),
    ]);
    // The result is unsound, but only for the local builtin reason present on a
    // dropped disjunct.
    pe.soundness = Soundness::Unsound {
        reason: regorus::evaluation_trace::PeUnsoundReason::BuiltinUnsupported,
    };
    pe.unsound_reasons = vec![regorus::evaluation_trace::PeUnsoundReason::BuiltinUnsupported];

    let res = lift(&pe, &egress_schema());
    assert_eq!(res.config.as_ref().unwrap().allow_clauses.len(), 1);
    assert_eq!(res.rejections[0].reason, RejectReason::DisjunctUnsound);
}

#[test]
fn one_bad_disjunct_does_not_sink_good_ones() {
    let mut bad = eq_atom("input.dest_ip", Value::from("10.0.0.9"));
    bad.lowerable = Lowerability::Builtin;
    let pe = pe_with(vec![
        (
            vec![eq_atom("input.dest_ip", Value::from("10.0.0.1"))],
            sound_allow_outcome(),
        ),
        (vec![bad], sound_allow_outcome()),
    ]);

    let res = lift(&pe, &egress_schema());
    assert_eq!(res.config.as_ref().unwrap().allow_clauses.len(), 1);
    assert_eq!(res.rejections.len(), 1);
    assert_eq!(res.rejections[0].reason, RejectReason::ConditionNotAtom);
    assert!(!res.is_complete());
}
