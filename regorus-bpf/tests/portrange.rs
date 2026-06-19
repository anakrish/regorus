// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Port-range lowering (#17): policies that express a port RANGE on
//! `input.dest_port` via `>=`/`>`/`<=`/`<` (including a closed range
//! `lo <= port <= hi`) lower into a single inclusive [`ScalarMatch::Range`]
//! clause row and are enforced soundly — instead of being dropped.
//!
//! This file mixes two styles:
//!
//!  * **Unit** tests over hand-built [`EnforcerConfig`]s (like `export.rs`),
//!    exercising the lowering/intersection/clamping logic precisely, and
//!  * **Triple-path conformance** (like `conformance.rs`): real Rego policies
//!    driven through `full_eval` vs `simulate` vs `enforce` over a fuzzed input
//!    sweep, asserting the map-plan enforcer NEVER over-permits and agrees
//!    exactly where the lift+export is complete.

use std::collections::BTreeMap;

use regorus::*;

use regorus_bpf::{enforce, export, extract_request, ClauseEntry, IpMatch, Request, ScalarMatch};
use regorus_bpf::{Verdict as BpfVerdict, MAX_CLAUSES};
use regorus_lift::ir::{
    Atom, CidrAtom, Clause, CmpAtom, CmpOp, EnforcerConfig, EqAtom, IpFamily, LiftScalar,
};
use regorus_lift::sim::simulate;
use regorus_lift::{lift, ContextSchema, FieldType, Verdict as LiftVerdict};

// ---------------------------------------------------------------------------
// Unit-level helpers (hand-built configs)
// ---------------------------------------------------------------------------

fn fields() -> BTreeMap<String, FieldType> {
    let mut m = BTreeMap::new();
    m.insert("input.dest_ip".to_string(), FieldType::Ip);
    m.insert("input.dest_port".to_string(), FieldType::Uint);
    m.insert("input.proto".to_string(), FieldType::Str);
    m
}

fn config(clauses: Vec<Clause>) -> EnforcerConfig {
    EnforcerConfig::new(fields(), clauses)
}

fn cmp_port(op: CmpOp, n: u64) -> Atom {
    Atom::Cmp(CmpAtom {
        input_path: "input.dest_port".into(),
        op,
        scalar: LiftScalar::Uint(n),
        missing_matches: false,
    })
}

fn cmp_port_missing_matches(op: CmpOp, n: u64) -> Atom {
    Atom::Cmp(CmpAtom {
        input_path: "input.dest_port".into(),
        op,
        scalar: LiftScalar::Uint(n),
        missing_matches: true,
    })
}

fn eq_port(p: u64) -> Atom {
    Atom::Eq(EqAtom {
        input_path: "input.dest_port".into(),
        scalar: LiftScalar::Uint(p),
    })
}

fn eq_proto(name: &str) -> Atom {
    Atom::Eq(EqAtom {
        input_path: "input.proto".into(),
        scalar: LiftScalar::Str(name.into()),
    })
}

fn req(ip: Option<&str>, port: Option<u16>, proto: Option<u8>) -> Request {
    Request {
        dest_ip: ip.map(|s| u32::from(s.parse::<std::net::Ipv4Addr>().unwrap())),
        dest_port: port,
        proto,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[test]
fn ge_lowers_to_open_top_range() {
    // input.dest_port >= 1024  ->  Range { 1024, 65535 }
    let cfg = config(vec![Clause {
        atoms: vec![cmp_port(CmpOp::Ge, 1024)],
    }]);
    let plan = export(&cfg).unwrap();
    assert_eq!(plan.clauses.len(), 1);
    assert_eq!(
        plan.clauses[0].port,
        ScalarMatch::Range {
            min: 1024,
            max: 65535
        }
    );
    assert_eq!(
        enforce(&plan, &req(None, Some(1024), None)),
        BpfVerdict::Allow
    );
    assert_eq!(
        enforce(&plan, &req(None, Some(65535), None)),
        BpfVerdict::Allow
    );
    assert_eq!(
        enforce(&plan, &req(None, Some(1023), None)),
        BpfVerdict::Undecided
    );
    // Missing port must not match a range (fail-closed).
    assert_eq!(
        enforce(&plan, &req(None, None, None)),
        BpfVerdict::Undecided
    );
}

#[test]
fn le_lowers_to_open_bottom_range() {
    // input.dest_port <= 2048  ->  Range { 0, 2048 }
    let cfg = config(vec![Clause {
        atoms: vec![cmp_port(CmpOp::Le, 2048)],
    }]);
    let plan = export(&cfg).unwrap();
    assert_eq!(
        plan.clauses[0].port,
        ScalarMatch::Range { min: 0, max: 2048 }
    );
    assert_eq!(enforce(&plan, &req(None, Some(0), None)), BpfVerdict::Allow);
    assert_eq!(
        enforce(&plan, &req(None, Some(2048), None)),
        BpfVerdict::Allow
    );
    assert_eq!(
        enforce(&plan, &req(None, Some(2049), None)),
        BpfVerdict::Undecided
    );
}

#[test]
fn closed_range_intersects_two_cmps() {
    // input.dest_port >= 1024 AND input.dest_port <= 2048 -> Range { 1024, 2048 }
    let cfg = config(vec![Clause {
        atoms: vec![cmp_port(CmpOp::Ge, 1024), cmp_port(CmpOp::Le, 2048)],
    }]);
    let plan = export(&cfg).unwrap();
    assert_eq!(plan.clauses.len(), 1);
    assert_eq!(
        plan.clauses[0].port,
        ScalarMatch::Range {
            min: 1024,
            max: 2048
        }
    );
    for (port, want) in [
        (1023u16, BpfVerdict::Undecided),
        (1024, BpfVerdict::Allow),
        (1500, BpfVerdict::Allow),
        (2048, BpfVerdict::Allow),
        (2049, BpfVerdict::Undecided),
    ] {
        assert_eq!(
            enforce(&plan, &req(None, Some(port), None)),
            want,
            "port={port}"
        );
    }
}

#[test]
fn strict_inequalities_are_half_open_equivalents() {
    // > 1023 is equivalent to >= 1024; < 2049 is equivalent to <= 2048.
    let strict = config(vec![Clause {
        atoms: vec![cmp_port(CmpOp::Gt, 1023), cmp_port(CmpOp::Lt, 2049)],
    }]);
    let inclusive = config(vec![Clause {
        atoms: vec![cmp_port(CmpOp::Ge, 1024), cmp_port(CmpOp::Le, 2048)],
    }]);
    let ps = export(&strict).unwrap();
    let pi = export(&inclusive).unwrap();
    assert_eq!(ps.clauses, pi.clauses);
    assert_eq!(
        ps.clauses[0].port,
        ScalarMatch::Range {
            min: 1024,
            max: 2048
        }
    );
}

#[test]
fn gt_max_port_yields_empty_range_and_drops_clause() {
    // port > 65535 is unsatisfiable for a u16 -> empty range -> clause dropped.
    let cfg = config(vec![Clause {
        atoms: vec![cmp_port(CmpOp::Gt, 65535)],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(
        plan.clauses.is_empty(),
        "unsatisfiable range must drop the clause"
    );
}

#[test]
fn inverted_bounds_yield_empty_range_and_drop_clause() {
    // >= 2048 AND <= 1024 -> empty intersection -> clause dropped (sound).
    let cfg = config(vec![Clause {
        atoms: vec![cmp_port(CmpOp::Ge, 2048), cmp_port(CmpOp::Le, 1024)],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(plan.clauses.is_empty(), "empty range must drop the clause");
}

#[test]
fn lt_zero_yields_empty_range_and_drops_clause() {
    // port < 0 is unsatisfiable -> empty range -> clause dropped.
    let cfg = config(vec![Clause {
        atoms: vec![cmp_port(CmpOp::Lt, 0)],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(plan.clauses.is_empty());
}

#[test]
fn range_above_u16_window_drops_clause() {
    // >= 100000: no observable u16 port satisfies this -> drop (fail-closed).
    let cfg = config(vec![Clause {
        atoms: vec![cmp_port(CmpOp::Ge, 100_000)],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(plan.clauses.is_empty());
}

#[test]
fn ne_cmp_on_port_is_not_representable_and_drops_clause() {
    // A `!=` comparison is not a single contiguous range -> reject (fail-closed).
    let cfg = config(vec![Clause {
        atoms: vec![cmp_port(CmpOp::Ne, 1024)],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(plan.clauses.is_empty());
}

#[test]
fn ne_mixed_with_range_drops_clause() {
    // A representable range bound mixed with an unrepresentable `!=` -> reject.
    let cfg = config(vec![Clause {
        atoms: vec![cmp_port(CmpOp::Ge, 1024), cmp_port(CmpOp::Ne, 1500)],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(plan.clauses.is_empty());
}

#[test]
fn negation_complement_cmp_drops_clause() {
    // A Cmp whose missing field would still match cannot be represented by a
    // presence-requiring range -> reject (fail-closed).
    let cfg = config(vec![Clause {
        atoms: vec![cmp_port_missing_matches(CmpOp::Ge, 1024)],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(plan.clauses.is_empty());
}

#[test]
fn range_combined_with_proto_and_cidr() {
    // CIDR(dest_ip) AND port range AND proto Eq -> a single fully-specified row.
    let cfg = config(vec![Clause {
        atoms: vec![
            Atom::Cidr(CidrAtom {
                input_path: "input.dest_ip".into(),
                network: "10.0.0.0/8".into(),
                prefix_len: 8,
                family: IpFamily::V4,
                negated: false,
            }),
            cmp_port(CmpOp::Ge, 49152),
            cmp_port(CmpOp::Le, 65535),
            eq_proto("tcp"),
        ],
    }]);
    let plan = export(&cfg).unwrap();
    assert_eq!(plan.clauses.len(), 1);
    let entry = plan.clauses[0];
    assert_eq!(
        entry,
        ClauseEntry {
            ip: IpMatch::Cidr {
                network: u32::from("10.0.0.0".parse::<std::net::Ipv4Addr>().unwrap()),
                prefix_len: 8,
            },
            port: ScalarMatch::Range {
                min: 49152,
                max: 65535,
            },
            proto: ScalarMatch::Exact(6),
        }
    );
    // In subnet, in range, right proto -> Allow.
    assert_eq!(
        enforce(&plan, &req(Some("10.1.2.3"), Some(50000), Some(6))),
        BpfVerdict::Allow
    );
    // In subnet but port below range -> Undecided.
    assert_eq!(
        enforce(&plan, &req(Some("10.1.2.3"), Some(443), Some(6))),
        BpfVerdict::Undecided
    );
    // Right port but wrong proto -> Undecided.
    assert_eq!(
        enforce(&plan, &req(Some("10.1.2.3"), Some(50000), Some(17))),
        BpfVerdict::Undecided
    );
    // Right port/proto but outside subnet -> Undecided.
    assert_eq!(
        enforce(&plan, &req(Some("192.168.1.1"), Some(50000), Some(6))),
        BpfVerdict::Undecided
    );
}

#[test]
fn range_conflicting_with_exact_port_drops_clause() {
    // A range bound mixed with an exact port (Eq) is a non-Cmp/Cmp mix -> reject.
    let cfg = config(vec![Clause {
        atoms: vec![cmp_port(CmpOp::Ge, 1024), eq_port(443)],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(
        plan.clauses.is_empty(),
        "range + exact-port conflict must drop the clause (fail-closed)"
    );
}

#[test]
fn single_point_range_collapses_to_one_port() {
    // >= 1024 AND <= 1024 -> Range { 1024, 1024 } matches exactly that port.
    let cfg = config(vec![Clause {
        atoms: vec![cmp_port(CmpOp::Ge, 1024), cmp_port(CmpOp::Le, 1024)],
    }]);
    let plan = export(&cfg).unwrap();
    assert_eq!(
        plan.clauses[0].port,
        ScalarMatch::Range {
            min: 1024,
            max: 1024
        }
    );
    assert_eq!(
        enforce(&plan, &req(None, Some(1024), None)),
        BpfVerdict::Allow
    );
    assert_eq!(
        enforce(&plan, &req(None, Some(1025), None)),
        BpfVerdict::Undecided
    );
}

#[test]
fn range_does_not_exceed_clause_budget() {
    // A single range is one row regardless of width; well within MAX_CLAUSES.
    let cfg = config(vec![Clause {
        atoms: vec![cmp_port(CmpOp::Ge, 0), cmp_port(CmpOp::Le, 65535)],
    }]);
    let plan = export(&cfg).unwrap();
    assert_eq!(plan.clauses.len(), 1);
    assert!(plan.clauses.len() <= MAX_CLAUSES);
}

// ---------------------------------------------------------------------------
// Triple-path conformance over real policies
// ---------------------------------------------------------------------------

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

/// A wide port-centric input sweep. `dest_port` values are all valid `u16`
/// (so the kernel's u16 extraction does not truncate), plus a couple of
/// out-of-range ports that are checked for no-over-permission only.
fn port_inputs() -> Vec<String> {
    let ips = ["10.0.0.1", "10.1.2.3", "192.168.1.5", "8.8.8.8"];
    let ports = [
        0u32, 22, 80, 443, 1023, 1024, 1025, 2048, 2049, 8080, 49151, 49152, 65534, 65535,
    ];
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
    // Out-of-u16-range and malformed/partial inputs: never over-permit.
    out.push(r#"{"dest_ip":"10.0.0.1","dest_port":70000,"proto":"tcp"}"#.to_string());
    out.push(r#"{"dest_ip":"10.0.0.1","dest_port":100000,"proto":"tcp"}"#.to_string());
    out.push(r#"{"dest_ip":"10.0.0.1","proto":"tcp"}"#.to_string());
    out.push(r#"{}"#.to_string());
    out
}

/// Returns the JSON value's `dest_port` if it is present and fits in a `u16`
/// (i.e. the kernel extraction would observe it without truncation).
fn observable_u16_port(input: &serde_json::Value) -> Option<bool> {
    match input.get("dest_port") {
        None => Some(true), // absent: both paths see "missing"
        Some(v) => match v.as_u64() {
            Some(n) => Some(u16::try_from(n).is_ok()),
            None => Some(false),
        },
    }
}

/// Triple-path check specialised for port-range policies. Always asserts no
/// over-permission and bpf/sim agreement. Asserts EXACT agreement with full
/// eval only for inputs whose `dest_port` is observable as a `u16` (the kernel
/// model cannot see ports above 65535; under-permitting those is sound).
fn check_port_triple(policy: &str, entrypoint: &str) {
    let config = lifted_config(policy, entrypoint);
    let plan = export(&config).expect("plan should export");

    for input_json in port_inputs() {
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

        // The map-plan enforcer must agree with the IR reference enforcer and
        // with full eval — but only within the kernel-observable domain. When
        // `dest_port` exceeds `u16::MAX` the kernel model truncates it to a
        // missing port (None), legitimately under-permitting relative to the
        // full-precision IR/RVM; we only require no-over-permission there.
        if observable_u16_port(&input) == Some(true) {
            assert_eq!(
                bpf_allow, sim_allow,
                "bpf/sim disagree for {input_json}: bpf={bpf_v:?} sim={sim_v:?}"
            );
            assert_eq!(
                bpf_allow, want_allow,
                "verdict mismatch for {input_json}: bpf={bpf_v:?} full={want_allow}"
            );
        } else {
            // Out-of-window: the IR sim may allow; the kernel model must not
            // over-permit relative to it either (it can only under-permit).
            assert!(
                !bpf_allow || sim_allow,
                "bpf over-permits vs sim for {input_json}: bpf={bpf_v:?} sim={sim_v:?}"
            );
        }
    }
}

const EPHEMERAL_POLICY: &str = r#"
package egress

default allow = false

# Allow ephemeral-port TCP egress to the 10/8 subnet.
allow if {
    net.cidr_contains("10.0.0.0/8", input.dest_ip)
    input.dest_port >= 49152
    input.dest_port <= 65535
    input.proto == "tcp"
}
"#;

#[test]
fn ephemeral_range_to_subnet_round_trips() {
    check_port_triple(EPHEMERAL_POLICY, "data.egress.allow");
}

const PRIVILEGED_BLOCK_POLICY: &str = r#"
package egress

default allow = false

# Allow only non-privileged ports (>= 1024), any TCP destination.
allow if {
    input.dest_port >= 1024
    input.proto == "tcp"
}
"#;

#[test]
fn non_privileged_open_top_range_never_over_permits() {
    check_port_triple(PRIVILEGED_BLOCK_POLICY, "data.egress.allow");
}

const CLOSED_RANGE_POLICY: &str = r#"
package egress

default allow = false

# A closed range with strict inequalities: 1023 < port < 2049  (i.e. 1024..=2048).
allow if {
    input.dest_port > 1023
    input.dest_port < 2049
}
"#;

#[test]
fn closed_strict_range_round_trips() {
    check_port_triple(CLOSED_RANGE_POLICY, "data.egress.allow");
}

const TWO_RANGE_DISJUNCTS_POLICY: &str = r#"
package egress

default allow = false

# Two independent port ranges (two disjuncts) to different subnets.
allow if {
    net.cidr_contains("10.0.0.0/8", input.dest_ip)
    input.dest_port >= 8000
    input.dest_port <= 8099
}

allow if {
    net.cidr_contains("192.168.0.0/16", input.dest_ip)
    input.dest_port >= 9000
    input.dest_port <= 9000
}
"#;

#[test]
fn multiple_range_disjuncts_round_trip() {
    check_port_triple(TWO_RANGE_DISJUNCTS_POLICY, "data.egress.allow");
}
