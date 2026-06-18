//! Differential conformance: drive partial evaluation through the real engine,
//! lift the result, simulate the lifted enforcer, and assert the **soundness
//! property** against full RVM evaluation:
//!
//! ```text
//!   sim(lift(PE), input) == Allow   ⟹   full_eval(policy, input) == allow
//! ```
//!
//! i.e. the kernel-enforceable subset never over-permits. When the lift is
//! *complete* (no rejections) we additionally require exact agreement, so a
//! fully kernel-observable policy is reproduced faithfully.

use regorus::*;

use regorus_lift::sim::simulate;
use regorus_lift::{lift, ContextSchema, FieldType, Verdict};

/// Drive PE for `policy`/`entrypoint` with `input` unknown, returning the typed
/// partial-evaluation result.
fn run_pe_typed(
    policy: &str,
    entrypoint_str: &str,
) -> regorus::causality_report::PartialEvalResult {
    let mut engine = Engine::new();
    engine
        .add_policy("test.rego".into(), policy.into())
        .unwrap();

    let entrypoint: Rc<str> = entrypoint_str.into();
    let compiled = engine.compile_with_entrypoint(&entrypoint).unwrap();
    let program =
        languages::rego::compiler::Compiler::compile_from_policy(&compiled, &[entrypoint.as_ref()])
            .unwrap();

    let mut vm = rvm::RegoVM::new_with_policy(compiled);
    vm.load_program(program);
    vm.set_explanation_settings(evaluation_trace::ExplanationSettings {
        enabled: true,
        value_mode: evaluation_trace::ValueMode::Full,
        condition_mode: evaluation_trace::ConditionMode::AllContributing,
        scope: evaluation_trace::ExplanationScope::AllEmissions,
        detail: evaluation_trace::ExplanationDetail::Full,
        emission_index: None,
        emission_value: None,
        assume_unknown_input: true,
        eval_mode: evaluation_trace::EvaluationMode::PartialEval,
        unknowns: vec!["input".into()],
    });
    vm.set_input(Value::new_object());

    let value = vm.execute_entry_point_by_name(entrypoint_str).unwrap();
    vm.take_partial_eval_result_typed(value)
}

/// Full (concrete) evaluation of `entrypoint` under `input`, as a bool.
fn full_eval(policy: &str, entrypoint_rule: &str, input_json: &str) -> bool {
    let mut engine = Engine::new();
    engine
        .add_policy("test.rego".into(), policy.into())
        .unwrap();
    engine.set_input(serde_json::from_str::<Value>(input_json).unwrap());
    let v = engine.eval_rule(entrypoint_rule.to_string()).unwrap();
    matches!(serde_json::to_value(&v), Ok(serde_json::Value::Bool(true)))
}

const EGRESS_POLICY: &str = r#"
package egress

default allow = false

allow if {
    input.dest_ip == "10.0.0.1"
    input.proto == "tcp"
}

allow if {
    input.dest_ip == "10.0.0.2"
}
"#;

fn egress_schema() -> ContextSchema {
    ContextSchema::new()
        .with("input.dest_ip", FieldType::Str)
        .with("input.proto", FieldType::Str)
}

/// Inputs spanning matches, partial matches, and non-matches.
fn egress_inputs() -> Vec<String> {
    let ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"];
    let protos = ["tcp", "udp"];
    let mut out = Vec::new();
    for ip in ips {
        for proto in protos {
            out.push(format!(r#"{{"dest_ip":"{ip}","proto":"{proto}"}}"#));
        }
    }
    out
}

#[test]
fn egress_lift_is_complete_and_exact() {
    let pe = run_pe_typed(EGRESS_POLICY, "data.egress.allow");
    let res = lift(&pe, &egress_schema());

    assert!(
        res.is_complete(),
        "egress policy should fully lift; rejections: {:?}",
        res.rejections
    );
    let config = res.config.expect("expected config");

    for input_json in egress_inputs() {
        let want_allow = full_eval(EGRESS_POLICY, "data.egress.allow", &input_json);
        let input: serde_json::Value = serde_json::from_str(&input_json).unwrap();
        let got = simulate(&config, &input);

        // Soundness: simulator must never over-permit.
        if got == Verdict::Allow {
            assert!(
                want_allow,
                "OVER-PERMISSION: sim allowed but full eval denied for {input_json}"
            );
        }
        // Completeness: a fully-lifted policy must agree exactly.
        let got_allow = got == Verdict::Allow;
        assert_eq!(
            got_allow, want_allow,
            "verdict mismatch for {input_json}: sim={got:?} full={want_allow}"
        );
    }
}

const MIXED_POLICY: &str = r#"
package mixed

default allow = false

# Kernel-observable disjunct.
allow if {
    input.dest_ip == "10.0.0.1"
}

# Not kernel-observable: depends on a builtin over an unknown.
allow if {
    startswith(input.host, "trusted-")
}
"#;

#[test]
fn mixed_policy_lifts_observable_subset_without_over_permission() {
    let pe = run_pe_typed(MIXED_POLICY, "data.mixed.allow");
    // Only dest_ip is observable; host/startswith is not.
    let schema = ContextSchema::new().with("input.dest_ip", FieldType::Str);
    let res = lift(&pe, &schema);

    // The builtin disjunct must be rejected -> not complete.
    assert!(
        !res.is_complete(),
        "mixed policy must not fully lift (startswith is not liftable)"
    );

    let config = res
        .config
        .expect("the observable dest_ip disjunct should still lift");

    // Cases including ones that only the *unlifted* disjunct would allow.
    let cases = [
        r#"{"dest_ip":"10.0.0.1","host":"untrusted"}"#,
        r#"{"dest_ip":"9.9.9.9","host":"trusted-svc"}"#,
        r#"{"dest_ip":"9.9.9.9","host":"untrusted"}"#,
    ];
    for input_json in cases {
        let want_allow = full_eval(MIXED_POLICY, "data.mixed.allow", input_json);
        let input: serde_json::Value = serde_json::from_str(input_json).unwrap();
        let got = simulate(&config, &input);

        // Core property: never over-permit.
        if got == Verdict::Allow {
            assert!(
                want_allow,
                "OVER-PERMISSION on mixed policy for {input_json}"
            );
        }
    }

    // The enforcer correctly allows the observable case.
    let m: serde_json::Value =
        serde_json::from_str(r#"{"dest_ip":"10.0.0.1","host":"untrusted"}"#).unwrap();
    assert_eq!(simulate(&config, &m), Verdict::Allow);

    // And fails closed on the case only the unlifted disjunct covers
    // (under-approximation is allowed; over-approximation is not).
    let u: serde_json::Value =
        serde_json::from_str(r#"{"dest_ip":"9.9.9.9","host":"trusted-svc"}"#).unwrap();
    assert_eq!(simulate(&config, &u), Verdict::Deny);
}

const EXTENDED_POLICY: &str = r#"
package extended

default allow = false

allow if {
    net.cidr_contains("10.0.0.0/24", input.dest_ip)
    startswith(input.host, "trusted-")
    input.port >= 1024
    not input.role == "blocked"
}
"#;

#[test]
fn extended_atoms_lift_complete_and_never_overpermit() {
    let pe = run_pe_typed(EXTENDED_POLICY, "data.extended.allow");
    let schema = ContextSchema::new()
        .with("input.dest_ip", FieldType::Str)
        .with("input.host", FieldType::Str)
        .with("input.port", FieldType::Uint)
        .with("input.role", FieldType::Str);
    let res = lift(&pe, &schema);
    assert!(res.is_complete(), "rejections: {:?}", res.rejections);
    let config = res.config.expect("expected config");
    let cases = [
        r#"{"dest_ip":"10.0.0.1","host":"trusted-api","port":1024,"role":"user"}"#,
        r#"{"dest_ip":"10.0.1.1","host":"trusted-api","port":1024,"role":"user"}"#,
        r#"{"dest_ip":"10.0.0.1","host":"evil-api","port":1024,"role":"user"}"#,
        r#"{"dest_ip":"10.0.0.1","host":"trusted-api","port":80,"role":"user"}"#,
        r#"{"dest_ip":"10.0.0.1","host":"trusted-api","port":1024,"role":"blocked"}"#,
    ];
    for input_json in cases {
        let want_allow = full_eval(EXTENDED_POLICY, "data.extended.allow", input_json);
        let input: serde_json::Value = serde_json::from_str(input_json).unwrap();
        let got = simulate(&config, &input);
        if got == Verdict::Allow {
            assert!(want_allow, "OVER-PERMISSION for {input_json}");
        }
        assert_eq!(got == Verdict::Allow, want_allow, "{input_json}");
    }
}

const FIELD_CMP_POLICY: &str = r#"
package fieldcmp

default allow = false

allow if {
    input.uid == input.owner_uid
    input.start < input.end
}
"#;

#[test]
fn field_cmp_lifts_complete_and_never_overpermits() {
    let pe = run_pe_typed(FIELD_CMP_POLICY, "data.fieldcmp.allow");
    let schema = ContextSchema::new()
        .with("input.uid", FieldType::Uint)
        .with("input.owner_uid", FieldType::Uint)
        .with("input.start", FieldType::Uint)
        .with("input.end", FieldType::Uint);
    let res = lift(&pe, &schema);
    assert!(
        res.is_complete(),
        "rejections: {:?}; pe={pe:?}",
        res.rejections
    );
    let config = res.config.expect("expected config");
    let cases = [
        r#"{"uid":1000,"owner_uid":1000,"start":1,"end":2}"#,
        r#"{"uid":1000,"owner_uid":0,"start":1,"end":2}"#,
        r#"{"uid":1000,"start":1,"end":2}"#,
        r#"{"uid":"1000","owner_uid":1000,"start":1,"end":2}"#,
    ];
    for input_json in cases {
        let want_allow = full_eval(FIELD_CMP_POLICY, "data.fieldcmp.allow", input_json);
        let input: serde_json::Value = serde_json::from_str(input_json).unwrap();
        let got = simulate(&config, &input);
        if got == Verdict::Allow {
            assert!(want_allow, "OVER-PERMISSION for {input_json}");
        }
        assert_eq!(got == Verdict::Allow, want_allow, "{input_json}");
    }
}
