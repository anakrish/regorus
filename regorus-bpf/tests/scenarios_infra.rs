// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Real-world *infrastructure* egress scenarios, locked down as regression
//! tests (scenarios 1–10).
//!
//! These pin the kernel-observable egress policies that a platform team might
//! actually deploy — Kubernetes pod egress, database/cache/Kafka/registry
//! access, directory and time services, log shipping, metrics push, and a
//! proxy-only posture. Each scenario is driven through the full triple path —
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

// 1. Kubernetes pod egress.
#[test]
fn scenario_k8s_pod_egress_kube_dns_and_service_cidr() {
    // Pods may resolve names via kube-dns (10.96.0.10:53, tcp+udp) and reach
    // any ClusterIP service inside the service CIDR (10.96.0.0/12). Everything
    // off-cluster is denied. (kube-dns sits inside the service CIDR, so the DNS
    // disjuncts are a deliberately explicit, defence-in-depth statement of the
    // intent even though the CIDR already covers them.)
    const POLICY: &str = r#"
package egress

default allow = false

allow if {
    input.dest_ip == "10.96.0.10"
    input.dest_port == 53
    input.proto == "udp"
}

allow if {
    input.dest_ip == "10.96.0.10"
    input.dest_port == 53
    input.proto == "tcp"
}

allow if {
    net.cidr_contains("10.96.0.0/12", input.dest_ip)
}
"#;
    check_scenario(
        "k8s-pod-egress",
        POLICY,
        &[
            ("10.96.0.10", 53, "udp", true),      // kube-dns over UDP
            ("10.96.0.10", 53, "tcp", true),      // kube-dns over TCP
            ("10.96.1.20", 8080, "tcp", true),    // a ClusterIP service in-CIDR
            ("10.111.255.254", 443, "tcp", true), // top of the /12 service CIDR
            ("10.112.0.1", 443, "tcp", false),    // just outside the /12
            ("8.8.8.8", 53, "udp", false),        // public DNS -> denied
            ("8.8.8.8", 443, "tcp", false),       // internet -> denied
        ],
    );
}

// 2. Database tier.
#[test]
fn scenario_database_tier_postgres_and_mysql() {
    // The app tier may reach Postgres (5432/tcp) and MySQL (3306/tcp) only
    // within the dedicated DB subnet (10.50.0.0/16). The internet is denied.
    const POLICY: &str = r#"
package egress

default allow = false

allow if {
    net.cidr_contains("10.50.0.0/16", input.dest_ip)
    input.dest_port == 5432
    input.proto == "tcp"
}

allow if {
    net.cidr_contains("10.50.0.0/16", input.dest_ip)
    input.dest_port == 3306
    input.proto == "tcp"
}
"#;
    check_scenario(
        "database-tier",
        POLICY,
        &[
            ("10.50.1.10", 5432, "tcp", true),   // Postgres in the DB subnet
            ("10.50.2.20", 3306, "tcp", true),   // MySQL in the DB subnet
            ("10.50.1.10", 5432, "udp", false),  // right port, wrong proto
            ("10.50.1.10", 5433, "tcp", false),  // off-by-one Postgres port
            ("10.51.1.10", 5432, "tcp", false),  // Postgres outside the subnet
            ("8.8.8.8", 5432, "tcp", false),     // DB port to the internet
            ("203.0.113.7", 3306, "tcp", false), // MySQL to the internet
        ],
    );
}

// 3. Cache tier.
#[test]
fn scenario_cache_tier_redis_and_memcached() {
    // Redis (6379/tcp) and Memcached (11211/tcp), reachable only inside the
    // cache subnet (10.60.0.0/16).
    const POLICY: &str = r#"
package egress

default allow = false

allow if {
    net.cidr_contains("10.60.0.0/16", input.dest_ip)
    input.dest_port == 6379
    input.proto == "tcp"
}

allow if {
    net.cidr_contains("10.60.0.0/16", input.dest_ip)
    input.dest_port == 11211
    input.proto == "tcp"
}
"#;
    check_scenario(
        "cache-tier",
        POLICY,
        &[
            ("10.60.0.5", 6379, "tcp", true),  // Redis in-subnet
            ("10.60.9.9", 11211, "tcp", true), // Memcached in-subnet
            ("10.60.0.5", 6379, "udp", false), // wrong proto
            ("10.60.0.5", 6380, "tcp", false), // off-by-one Redis port
            ("10.61.0.5", 6379, "tcp", false), // outside the cache subnet
            ("8.8.8.8", 11211, "tcp", false),  // Memcached to the internet
        ],
    );
}

// 4. Kafka brokers (set of IPs via separate allow blocks).
#[test]
fn scenario_kafka_broker_set() {
    // Producers/consumers may reach 9092/tcp on exactly three known brokers.
    const POLICY: &str = r#"
package egress

default allow = false

allow if {
    input.dest_ip == "10.70.1.1"
    input.dest_port == 9092
    input.proto == "tcp"
}

allow if {
    input.dest_ip == "10.70.1.2"
    input.dest_port == 9092
    input.proto == "tcp"
}

allow if {
    input.dest_ip == "10.70.1.3"
    input.dest_port == 9092
    input.proto == "tcp"
}
"#;
    check_scenario(
        "kafka-brokers",
        POLICY,
        &[
            ("10.70.1.1", 9092, "tcp", true),  // broker 1
            ("10.70.1.2", 9092, "tcp", true),  // broker 2
            ("10.70.1.3", 9092, "tcp", true),  // broker 3
            ("10.70.1.4", 9092, "tcp", false), // a non-broker host
            ("10.70.1.1", 9093, "tcp", false), // broker, wrong port
            ("10.70.1.1", 9092, "udp", false), // broker, wrong proto
            ("8.8.8.8", 9092, "tcp", false),   // Kafka port to the internet
        ],
    );
}

// 5. Container registry pull.
#[test]
fn scenario_container_registry_pull() {
    // Image pulls (443/tcp) are allowed only to a small set of registry IPs.
    const POLICY: &str = r#"
package egress

default allow = false

allow if {
    input.dest_ip == "10.80.0.10"
    input.dest_port == 443
    input.proto == "tcp"
}

allow if {
    input.dest_ip == "10.80.0.11"
    input.dest_port == 443
    input.proto == "tcp"
}
"#;
    check_scenario(
        "registry-pull",
        POLICY,
        &[
            ("10.80.0.10", 443, "tcp", true),  // registry mirror A
            ("10.80.0.11", 443, "tcp", true),  // registry mirror B
            ("10.80.0.12", 443, "tcp", false), // not a registry
            ("10.80.0.10", 80, "tcp", false),  // registry, plain HTTP
            ("10.80.0.10", 443, "udp", false), // registry, wrong proto
            ("104.18.0.1", 443, "tcp", false), // arbitrary internet HTTPS
        ],
    );
}

// 6. LDAP / Active Directory.
#[test]
fn scenario_ldap_active_directory() {
    // Directory lookups: LDAP (389/tcp) and LDAPS (636/tcp) to two domain
    // controllers only.
    const POLICY: &str = r#"
package egress

default allow = false

allow if {
    input.dest_ip == "10.90.0.5"
    input.dest_port == 389
    input.proto == "tcp"
}

allow if {
    input.dest_ip == "10.90.0.5"
    input.dest_port == 636
    input.proto == "tcp"
}

allow if {
    input.dest_ip == "10.90.0.6"
    input.dest_port == 389
    input.proto == "tcp"
}

allow if {
    input.dest_ip == "10.90.0.6"
    input.dest_port == 636
    input.proto == "tcp"
}
"#;
    check_scenario(
        "ldap-ad",
        POLICY,
        &[
            ("10.90.0.5", 389, "tcp", true),  // DC1 LDAP
            ("10.90.0.5", 636, "tcp", true),  // DC1 LDAPS
            ("10.90.0.6", 389, "tcp", true),  // DC2 LDAP
            ("10.90.0.6", 636, "tcp", true),  // DC2 LDAPS
            ("10.90.0.7", 389, "tcp", false), // not a DC
            ("10.90.0.5", 389, "udp", false), // DC1, wrong proto
            ("10.90.0.5", 88, "tcp", false),  // DC1, Kerberos port not allowed
        ],
    );
}

// 7. NTP.
#[test]
fn scenario_ntp_time_servers() {
    // Time sync (123/udp) to approved NTP servers only.
    const POLICY: &str = r#"
package egress

default allow = false

allow if {
    input.dest_ip == "10.100.0.1"
    input.dest_port == 123
    input.proto == "udp"
}

allow if {
    input.dest_ip == "10.100.0.2"
    input.dest_port == 123
    input.proto == "udp"
}
"#;
    check_scenario(
        "ntp",
        POLICY,
        &[
            ("10.100.0.1", 123, "udp", true),    // time server 1
            ("10.100.0.2", 123, "udp", true),    // time server 2
            ("10.100.0.1", 123, "tcp", false),   // NTP is UDP, not TCP
            ("10.100.0.3", 123, "udp", false),   // unapproved time server
            ("216.239.35.0", 123, "udp", false), // public NTP -> denied
        ],
    );
}

// 8. Syslog / SIEM (514 over both udp and tcp to one collector).
#[test]
fn scenario_syslog_siem_collector() {
    // Log shipping to a single collector on 514, both UDP (classic syslog) and
    // TCP (reliable syslog).
    const POLICY: &str = r#"
package egress

default allow = false

allow if {
    input.dest_ip == "10.110.0.50"
    input.dest_port == 514
    input.proto == "udp"
}

allow if {
    input.dest_ip == "10.110.0.50"
    input.dest_port == 514
    input.proto == "tcp"
}
"#;
    check_scenario(
        "syslog-siem",
        POLICY,
        &[
            ("10.110.0.50", 514, "udp", true),  // collector, UDP syslog
            ("10.110.0.50", 514, "tcp", true),  // collector, TCP syslog
            ("10.110.0.51", 514, "udp", false), // a different host
            ("10.110.0.50", 515, "tcp", false), // collector, wrong port
            ("8.8.8.8", 514, "udp", false),     // syslog to the internet
        ],
    );
}

// 9. Metrics push (Prometheus remote-write).
#[test]
fn scenario_metrics_remote_write() {
    // Prometheus remote-write (443/tcp) to a single metrics endpoint.
    const POLICY: &str = r#"
package egress

default allow = false

allow if {
    input.dest_ip == "10.120.0.9"
    input.dest_port == 443
    input.proto == "tcp"
}
"#;
    check_scenario(
        "metrics-remote-write",
        POLICY,
        &[
            ("10.120.0.9", 443, "tcp", true),   // the metrics endpoint
            ("10.120.0.9", 9090, "tcp", false), // same host, wrong port
            ("10.120.0.9", 443, "udp", false),  // wrong proto
            ("10.120.0.10", 443, "tcp", false), // a different host
            ("203.0.113.9", 443, "tcp", false), // arbitrary internet HTTPS
        ],
    );
}

// 10. Proxy-only egress.
#[test]
fn scenario_proxy_only_egress() {
    // The only permitted destination is the corporate forward proxy on
    // 3128/tcp; all other egress is denied (apps must go through the proxy).
    const POLICY: &str = r#"
package egress

default allow = false

allow if {
    input.dest_ip == "10.130.0.3"
    input.dest_port == 3128
    input.proto == "tcp"
}
"#;
    check_scenario(
        "proxy-only",
        POLICY,
        &[
            ("10.130.0.3", 3128, "tcp", true),  // the corporate proxy
            ("10.130.0.3", 8080, "tcp", false), // proxy host, wrong port
            ("10.130.0.3", 3128, "udp", false), // wrong proto
            ("10.130.0.4", 3128, "tcp", false), // not the proxy
            ("8.8.8.8", 443, "tcp", false),     // direct internet -> denied
            ("104.18.0.1", 80, "tcp", false),   // direct HTTP -> denied
        ],
    );
}
