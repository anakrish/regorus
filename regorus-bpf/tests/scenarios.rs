// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Real-world egress policy scenarios, locked down as regression tests.
//!
//! Each scenario is a named, realistic Rego egress policy that an operator
//! might actually deploy (bastion-only SSH, corp-CIDR allow-list, approved-SaaS
//! HTTPS + DNS, a web tier reaching a DB subnet, and a cloud-metadata block).
//! Every scenario is driven through the full triple path —
//!
//! ```text
//!   full_eval(policy, input)        (real RVM, the ground truth)
//!   simulate(lift(PE), input)       (IR reference enforcer)
//!   enforce(export(lift(PE)), req)  (this crate's map-plan enforcer)
//! ```
//!
//! — and asserts, for a curated table of `(input, expected_allow)` cases:
//!
//!  * the policy means what we claim (full eval matches the expectation),
//!  * the map-plan enforcer reproduces it **exactly** (these scenarios are
//!    fully kernel-observable, so the lift+export must be complete), and
//!  * the map-plan enforcer never over-permits relative to full eval.
//!
//! These are the "is the real-world behaviour pinned?" tests, distinct from the
//! mechanism/edge-case coverage in `conformance.rs` and `export.rs`.

use regorus::*;

use regorus_bpf::{enforce, export, extract_request, Verdict as BpfVerdict};
use regorus_lift::sim::simulate;
use regorus_lift::{lift, ContextSchema, EnforcerConfig, FieldType, Verdict as LiftVerdict};

const ENTRYPOINT: &str = "data.egress.allow";

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

fn full_eval(policy: &str, input_json: &str) -> bool {
    let mut engine = Engine::new();
    engine
        .add_policy("test.rego".into(), policy.into())
        .unwrap();
    engine.set_input(serde_json::from_str::<Value>(input_json).unwrap());
    match engine.eval_rule(ENTRYPOINT.to_string()) {
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

fn lifted_config(policy: &str) -> EnforcerConfig {
    let pe = run_pe_typed(policy, ENTRYPOINT);
    let res = lift(&pe, &egress_schema());
    assert!(
        res.is_complete(),
        "scenario must fully lift (kernel-observable); rejections: {:?}",
        res.rejections
    );
    res.config.expect("expected a config")
}

fn input_json(ip: &str, port: u16, proto: &str) -> String {
    format!(r#"{{"dest_ip":"{ip}","dest_port":{port},"proto":"{proto}"}}"#)
}

/// Drive a real-world scenario through the triple path against a curated case
/// table of `(dest_ip, dest_port, proto, expected_allow)`.
fn check_scenario(name: &str, policy: &str, cases: &[(&str, u16, &str, bool)]) {
    let config = lifted_config(policy);
    let plan = export(&config).unwrap_or_else(|e| panic!("[{name}] export failed: {e:?}"));
    assert_eq!(
        plan.clauses.len(),
        config.allow_clauses.len(),
        "[{name}] every clause must lower (no dropped allows)"
    );

    for &(ip, port, proto, expect_allow) in cases {
        let json = input_json(ip, port, proto);
        let input: serde_json::Value = serde_json::from_str(&json).unwrap();

        // 1. The policy means what the scenario claims.
        let full = full_eval(policy, &json);
        assert_eq!(
            full, expect_allow,
            "[{name}] policy/expectation mismatch for {json}: full_eval={full}, expected {expect_allow}"
        );

        // 2/3. The map-plan enforcer reproduces it exactly and never over-permits.
        let req = extract_request(&input);
        let bpf = enforce(&plan, &req) == BpfVerdict::Allow;
        let sim = simulate(&config, &input) == LiftVerdict::Allow;
        assert_eq!(
            bpf, expect_allow,
            "[{name}] map-plan verdict mismatch for {json}: bpf={bpf}, expected {expect_allow}"
        );
        assert_eq!(bpf, sim, "[{name}] bpf/sim disagree for {json}");
        if bpf {
            assert!(full, "[{name}] OVER-PERMISSION for {json}");
        }
    }
}

#[test]
fn scenario_bastion_only_ssh() {
    // SSH (22/tcp) is permitted only to the bastion host; nothing else.
    const POLICY: &str = r#"
package egress

default allow = false

allow if {
    input.dest_ip == "10.0.5.10"
    input.dest_port == 22
    input.proto == "tcp"
}
"#;
    check_scenario(
        "bastion-ssh",
        POLICY,
        &[
            ("10.0.5.10", 22, "tcp", true),    // the bastion, SSH
            ("10.0.5.10", 22, "udp", false),   // right host/port, wrong proto
            ("10.0.5.10", 2222, "tcp", false), // bastion, wrong port
            ("10.0.5.11", 22, "tcp", false),   // SSH to a non-bastion host
            ("8.8.8.8", 22, "tcp", false),     // SSH to the internet
        ],
    );
}

#[test]
fn scenario_corp_cidr_allow_list_blocks_metadata() {
    // Egress is allowed only into the corporate 10/8 range. This *implicitly*
    // blocks the cloud metadata endpoint (169.254.169.254) and the public
    // internet, since the default verdict is deny.
    const POLICY: &str = r#"
package egress

default allow = false

allow if {
    net.cidr_contains("10.0.0.0/8", input.dest_ip)
}
"#;
    check_scenario(
        "corp-cidr",
        POLICY,
        &[
            ("10.1.2.3", 443, "tcp", true),        // inside corp range
            ("10.255.255.254", 53, "udp", true),   // inside corp range
            ("169.254.169.254", 80, "tcp", false), // cloud metadata -> blocked
            ("8.8.8.8", 443, "tcp", false),        // public internet -> blocked
            ("172.16.0.1", 443, "tcp", false),     // a different private range
        ],
    );
}

#[test]
fn scenario_approved_saas_https_and_dns() {
    // Allow HTTPS to one approved SaaS IP, and DNS (tcp+udp) only to the
    // internal resolver. Everything else denied.
    const POLICY: &str = r#"
package egress

default allow = false

allow if {
    input.dest_ip == "104.18.0.1"
    input.dest_port == 443
    input.proto == "tcp"
}

allow if {
    input.dest_ip == "10.0.0.53"
    input.dest_port == 53
    input.proto == "udp"
}

allow if {
    input.dest_ip == "10.0.0.53"
    input.dest_port == 53
    input.proto == "tcp"
}
"#;
    check_scenario(
        "saas-https-dns",
        POLICY,
        &[
            ("104.18.0.1", 443, "tcp", true),  // approved SaaS over HTTPS
            ("104.18.0.1", 80, "tcp", false),  // same IP, plain HTTP -> denied
            ("104.18.0.2", 443, "tcp", false), // a different IP -> denied
            ("10.0.0.53", 53, "udp", true),    // DNS to the resolver (udp)
            ("10.0.0.53", 53, "tcp", true),    // DNS to the resolver (tcp, zone xfer)
            ("10.0.0.53", 54, "udp", false),   // resolver, wrong port
            ("1.1.1.1", 53, "udp", false),     // public DNS -> denied
        ],
    );
}

#[test]
fn scenario_web_tier_db_subnet_and_outbound_https() {
    // A web tier may reach Postgres (5432/tcp) anywhere in the DB subnet, and
    // may make outbound HTTPS (443/tcp) to *any* host (a deliberate dest_ip
    // wildcard, exercising the unconstrained-field path).
    const POLICY: &str = r#"
package egress

default allow = false

allow if {
    net.cidr_contains("10.20.0.0/16", input.dest_ip)
    input.dest_port == 5432
    input.proto == "tcp"
}

allow if {
    input.dest_port == 443
    input.proto == "tcp"
}
"#;
    check_scenario(
        "web-tier",
        POLICY,
        &[
            ("10.20.1.5", 5432, "tcp", true),  // Postgres in the DB subnet
            ("10.20.1.5", 5433, "tcp", false), // wrong DB port
            ("10.21.1.5", 5432, "tcp", false), // 5432 outside the DB subnet
            ("10.20.1.5", 5432, "udp", false), // right port, wrong proto
            ("203.0.113.9", 443, "tcp", true), // outbound HTTPS to the internet
            ("10.20.1.5", 443, "tcp", true),   // HTTPS anywhere (incl. DB subnet)
            ("203.0.113.9", 80, "tcp", false), // plain HTTP -> denied
        ],
    );
}
