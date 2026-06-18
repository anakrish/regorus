// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Triple-path differential conformance for the eBPF backend:
//!
//! ```text
//!   full_eval(policy, input)          -- the ground truth (real RVM)
//!   simulate(lift(PE), input)         -- the IR-level reference enforcer
//!   enforce(export(lift(PE)), req)    -- the map-plan enforcer (this crate)
//! ```
//!
//! The non-negotiable property: the map-plan enforcer must **never
//! over-permit** relative to full evaluation. When the lift is complete AND the
//! export is complete (no clause dropped), all three paths must agree exactly.

use regorus::*;

use regorus_bpf::{enforce, export, extract_request, Verdict as BpfVerdict};
use regorus_lift::sim::simulate;
use regorus_lift::{lift, ContextSchema, EnforcerConfig, FieldType, Verdict as LiftVerdict};

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

fn full_eval(policy: &str, entrypoint_rule: &str, input_json: &str) -> bool {
    let mut engine = Engine::new();
    engine
        .add_policy("test.rego".into(), policy.into())
        .unwrap();
    engine.set_input(serde_json::from_str::<Value>(input_json).unwrap());
    match engine.eval_rule(entrypoint_rule.to_string()) {
        Ok(v) => matches!(serde_json::to_value(&v), Ok(serde_json::Value::Bool(true))),
        Err(_) => false,
    }
}

fn egress_schema() -> ContextSchema {
    ContextSchema::new()
        .with("input.dest_ip", FieldType::Ip)
        .with("input.dest_port", FieldType::Uint)
        .with("input.proto", FieldType::Str)
}

fn lifted_config(policy: &str, entrypoint: &str) -> EnforcerConfig {
    let pe = run_pe_typed(policy, entrypoint);
    let res = lift(&pe, &egress_schema());
    res.config
        .unwrap_or_else(|| panic!("expected a config; rejections: {:?}", res.rejections))
}

/// Cartesian sweep of representative egress inputs (plus some malformed ones).
fn egress_inputs() -> Vec<String> {
    let ips = [
        "10.0.0.1",
        "10.0.0.2",
        "192.168.1.5",
        "192.168.255.255",
        "172.16.0.1",
        "8.8.8.8",
    ];
    let ports = ["80", "443", "8080", "22"];
    let protos = ["tcp", "udp", "icmp"];
    let mut out = Vec::new();
    for ip in ips {
        for port in ports {
            for proto in protos {
                out.push(format!(
                    r#"{{"dest_ip":"{ip}","dest_port":{port},"proto":"{proto}"}}"#
                ));
            }
        }
    }
    // Malformed / partial inputs — must never be over-permitted.
    out.push(r#"{}"#.to_string());
    out.push(r#"{"dest_ip":"not-an-ip","dest_port":443,"proto":"tcp"}"#.to_string());
    out.push(r#"{"dest_ip":"10.0.0.1","proto":"tcp"}"#.to_string());
    out.push(r#"{"dest_ip":"10.0.0.1","dest_port":443}"#.to_string());
    out.push(r#"{"dest_ip":"10.0.0.1","dest_port":70000,"proto":"tcp"}"#.to_string());
    out
}

/// Run the triple-path check for `policy`. If `expect_exact` is true the lifted
/// config and exported plan must be complete, so all three paths agree exactly.
fn check_triple(policy: &str, entrypoint: &str, expect_exact: bool) {
    let config = lifted_config(policy, entrypoint);
    let plan = export(&config).expect("plan should export");

    if expect_exact {
        assert_eq!(
            plan.clauses.len(),
            config.allow_clauses.len(),
            "expected every clause to lower to exactly one row (rejections would drop allows)"
        );
    }

    for input_json in egress_inputs() {
        let input: serde_json::Value = serde_json::from_str(&input_json).unwrap();
        let want_allow = full_eval(policy, entrypoint, &input_json);

        let sim_v = simulate(&config, &input);
        let req = extract_request(&input);
        let bpf_v = enforce(&plan, &req);

        let sim_allow = sim_v == LiftVerdict::Allow;
        let bpf_allow = bpf_v == BpfVerdict::Allow;

        // Core invariant: the map-plan enforcer never over-permits.
        if bpf_allow {
            assert!(
                want_allow,
                "OVER-PERMISSION (bpf): plan allowed but full eval denied for {input_json}"
            );
        }

        // The map-plan enforcer must agree with the IR reference enforcer.
        assert_eq!(
            bpf_allow, sim_allow,
            "bpf/sim disagree for {input_json}: bpf={bpf_v:?} sim={sim_v:?}"
        );

        if expect_exact {
            assert_eq!(
                bpf_allow, want_allow,
                "verdict mismatch for {input_json}: bpf={bpf_v:?} full={want_allow}"
            );
        }
    }
}

const EXACT_POLICY: &str = r#"
package egress

default allow = false

allow if {
    input.dest_ip == "10.0.0.1"
    input.dest_port == 443
    input.proto == "tcp"
}

allow if {
    input.dest_ip == "10.0.0.2"
}
"#;

#[test]
fn exact_allow_list_round_trips_through_map_plan() {
    check_triple(EXACT_POLICY, "data.egress.allow", true);
}

const CIDR_POLICY: &str = r#"
package egress

default allow = false

allow if {
    net.cidr_contains("192.168.0.0/16", input.dest_ip)
    input.proto == "tcp"
}
"#;

#[test]
fn cidr_egress_lowers_and_never_over_permits() {
    check_triple(CIDR_POLICY, "data.egress.allow", true);
}

const MEMBERSHIP_POLICY: &str = r#"
package egress

default allow = false

allow if {
    input.dest_port == 80
    input.proto == "tcp"
}

allow if {
    input.dest_port == 443
    input.proto == "tcp"
}
"#;

#[test]
fn multiple_port_disjuncts_round_trip() {
    check_triple(MEMBERSHIP_POLICY, "data.egress.allow", true);
}

const MIXED_POLICY: &str = r#"
package egress

default allow = false

# Kernel-observable disjunct.
allow if {
    input.dest_ip == "10.0.0.1"
    input.proto == "tcp"
}

# Not kernel-observable: a builtin over an unknown string field.
allow if {
    startswith(input.host, "trusted-")
}
"#;

#[test]
fn mixed_policy_drops_unobservable_clause_without_over_permission() {
    // Only the observable disjunct lowers; the other stays in user space.
    // We cannot expect exact agreement, but the bpf enforcer must never
    // over-permit and must match the IR reference enforcer.
    let config = lifted_config(MIXED_POLICY, "data.egress.allow");
    let plan = export(&config).expect("plan should export");

    for input_json in egress_inputs() {
        let input: serde_json::Value = serde_json::from_str(&input_json).unwrap();
        let want_allow = full_eval(MIXED_POLICY, "data.egress.allow", &input_json);
        let req = extract_request(&input);
        let bpf_v = enforce(&plan, &req);
        if bpf_v == BpfVerdict::Allow {
            assert!(want_allow, "OVER-PERMISSION (bpf): {input_json}");
        }
        assert_eq!(
            bpf_v == BpfVerdict::Allow,
            simulate(&config, &input) == LiftVerdict::Allow,
            "bpf/sim disagree for {input_json}"
        );
    }
}
