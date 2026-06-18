// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Real-world *security* egress scenarios, locked down as regression tests
//! (scenarios 11–16).
//!
//! These pin the threat-driven egress postures a security team cares about —
//! blocking cloud-metadata SSRF, preventing C2/beacon callbacks, stopping
//! public-DNS / DoH bypass, allowing only the VPN tunnel, fanning out to a set
//! of regional API endpoints, and pinning microservice-to-microservice calls.
//! Each scenario is driven through the full triple path —
//!
//! ```text
//!   full_eval(policy, input)        (real RVM, the ground truth)
//!   simulate(lift(PE), input)       (IR reference enforcer)
//!   enforce(export(lift(PE)), req)  (this crate's map-plan enforcer)
//! ```
//!
//! — and asserts, for a curated table of `(input, expected_allow)` cases, that
//! the policy means what we claim, that the map-plan enforcer reproduces it
//! exactly (these scenarios are fully kernel-observable), and that it never
//! over-permits relative to full eval.
//!
//! The harness mirrors `scenarios.rs`; the helper fns are duplicated here on
//! purpose, since each integration-test file compiles to its own binary.

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

// 11. Cloud-metadata block via a corp-CIDR allow-list.
#[test]
fn scenario_cloud_metadata_block() {
    // Egress is allowed only into the corporate 10/8 range. This *implicitly*
    // blocks the well-known cloud metadata endpoints — 169.254.169.254
    // (AWS/Azure/GCP IMDS) and 100.100.100.200 (Alibaba) — defeating a common
    // SSRF credential-theft path, since the default verdict is deny.
    const POLICY: &str = r#"
package egress

default allow = false

allow if {
    net.cidr_contains("10.0.0.0/8", input.dest_ip)
}
"#;
    check_scenario(
        "cloud-metadata-block",
        POLICY,
        &[
            ("10.0.0.10", 443, "tcp", true),        // inside corp range
            ("10.200.13.7", 80, "tcp", true),       // inside corp range
            ("169.254.169.254", 80, "tcp", false),  // AWS/Azure/GCP IMDS -> blocked
            ("100.100.100.200", 80, "tcp", false),  // Alibaba metadata -> blocked
            ("169.254.169.254", 443, "tcp", false), // IMDS over HTTPS -> blocked
            ("8.8.8.8", 443, "tcp", false),         // public internet -> blocked
        ],
    );
}

// 12. C2 / beacon prevention.
#[test]
fn scenario_c2_beacon_prevention() {
    // Only a couple of vetted, known-good destinations are reachable on 443/tcp.
    // Arbitrary "C2" callbacks on common beacon ports are denied by default.
    const POLICY: &str = r#"
package egress

default allow = false

allow if {
    input.dest_ip == "203.0.113.10"
    input.dest_port == 443
    input.proto == "tcp"
}

allow if {
    input.dest_ip == "198.51.100.20"
    input.dest_port == 443
    input.proto == "tcp"
}
"#;
    check_scenario(
        "c2-beacon-prevention",
        POLICY,
        &[
            ("203.0.113.10", 443, "tcp", true),   // vetted endpoint A
            ("198.51.100.20", 443, "tcp", true),  // vetted endpoint B
            ("45.61.139.66", 443, "tcp", false),  // random C2 over HTTPS
            ("45.61.139.66", 8443, "tcp", false), // random C2, alt-HTTPS beacon
            ("185.220.101.1", 80, "tcp", false),  // random C2 over HTTP
            ("203.0.113.10", 4444, "tcp", false), // vetted host, classic C2 port
            ("203.0.113.10", 443, "udp", false),  // vetted host, wrong proto
        ],
    );
}

// 13. Public-DNS / DoH bypass block.
#[test]
fn scenario_public_dns_bypass_block() {
    // DNS (53, udp+tcp) is permitted ONLY to the internal resolver. This blocks
    // exfiltration/bypass via public resolvers (1.1.1.1:53) and DNS-over-HTTPS
    // (8.8.8.8:443), both of which fall through to the default deny.
    const POLICY: &str = r#"
package egress

default allow = false

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
        "public-dns-bypass-block",
        POLICY,
        &[
            ("10.0.0.53", 53, "udp", true),    // internal resolver, UDP
            ("10.0.0.53", 53, "tcp", true),    // internal resolver, TCP
            ("1.1.1.1", 53, "udp", false),     // public resolver -> blocked
            ("8.8.8.8", 53, "udp", false),     // public resolver -> blocked
            ("8.8.8.8", 443, "tcp", false),    // DoH (DNS-over-HTTPS) -> blocked
            ("1.1.1.1", 53, "tcp", false),     // public resolver, TCP -> blocked
            ("10.0.0.53", 5353, "udp", false), // resolver, mDNS port -> blocked
        ],
    );
}

// 14. VPN / WireGuard-only.
#[test]
fn scenario_vpn_wireguard_only() {
    // The only permitted egress is the WireGuard tunnel endpoint on 51820/udp;
    // all other traffic is expected to ride inside the tunnel.
    const POLICY: &str = r#"
package egress

default allow = false

allow if {
    input.dest_ip == "203.0.113.77"
    input.dest_port == 51820
    input.proto == "udp"
}
"#;
    check_scenario(
        "vpn-wireguard-only",
        POLICY,
        &[
            ("203.0.113.77", 51820, "udp", true),  // the tunnel endpoint
            ("203.0.113.77", 51820, "tcp", false), // WireGuard is UDP, not TCP
            ("203.0.113.77", 1194, "udp", false),  // endpoint, OpenVPN port
            ("203.0.113.78", 51820, "udp", false), // a different host
            ("8.8.8.8", 443, "tcp", false),        // direct internet -> denied
        ],
    );
}

// 15. Multi-region API fan-out.
#[test]
fn scenario_multi_region_api() {
    // Outbound API calls (443/tcp) are allowed to four regional API gateways and
    // nowhere else.
    const POLICY: &str = r#"
package egress

default allow = false

allow if {
    input.dest_ip == "198.51.100.10"
    input.dest_port == 443
    input.proto == "tcp"
}

allow if {
    input.dest_ip == "198.51.100.20"
    input.dest_port == 443
    input.proto == "tcp"
}

allow if {
    input.dest_ip == "198.51.100.30"
    input.dest_port == 443
    input.proto == "tcp"
}

allow if {
    input.dest_ip == "198.51.100.40"
    input.dest_port == 443
    input.proto == "tcp"
}
"#;
    check_scenario(
        "multi-region-api",
        POLICY,
        &[
            ("198.51.100.10", 443, "tcp", true),  // region us-east
            ("198.51.100.20", 443, "tcp", true),  // region us-west
            ("198.51.100.30", 443, "tcp", true),  // region eu
            ("198.51.100.40", 443, "tcp", true),  // region ap
            ("198.51.100.50", 443, "tcp", false), // not a known gateway
            ("198.51.100.10", 80, "tcp", false),  // gateway, plain HTTP
            ("198.51.100.10", 443, "udp", false), // gateway, wrong proto
        ],
    );
}

// 16. Microservice pinning.
#[test]
fn scenario_microservice_pinning() {
    // Within an RFC1918 range, each microservice may reach only its specific
    // dependency by exact IP:port:proto. Cross-talk between unrelated services
    // is denied — e.g. the orders service may call payments (8443/tcp) and
    // inventory (9000/tcp), and the payments service may call the ledger
    // (7000/tcp), but nothing else.
    const POLICY: &str = r#"
package egress

default allow = false

allow if {
    input.dest_ip == "172.16.4.10"
    input.dest_port == 8443
    input.proto == "tcp"
}

allow if {
    input.dest_ip == "172.16.4.20"
    input.dest_port == 9000
    input.proto == "tcp"
}

allow if {
    input.dest_ip == "172.16.4.30"
    input.dest_port == 7000
    input.proto == "tcp"
}
"#;
    check_scenario(
        "microservice-pinning",
        POLICY,
        &[
            ("172.16.4.10", 8443, "tcp", true),  // -> payments
            ("172.16.4.20", 9000, "tcp", true),  // -> inventory
            ("172.16.4.30", 7000, "tcp", true),  // -> ledger
            ("172.16.4.10", 9000, "tcp", false), // payments host, inventory port
            ("172.16.4.20", 8443, "tcp", false), // inventory host, payments port
            ("172.16.4.30", 7000, "udp", false), // ledger, wrong proto
            ("172.16.4.40", 8443, "tcp", false), // an unpinned service host
        ],
    );
}
