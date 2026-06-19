// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fail-closed lock-down tests for capabilities that are **deliberately not
//! implemented** by the connect4 egress backend (#18–#21). Each asserts that
//! the current behaviour is SOUND — the relevant clause is dropped / never
//! lowered into an over-permissive allow — and documents what a real
//! implementation would need.
//!
//! These are guard-rails: if a future change accidentally starts lowering one
//! of these constructs, the over-permission would be caught here.
//!
//! ## #18 — IPv6 egress / `connect6`
//!
//! The hook is cgroup/`connect4`; only IPv4 destinations are observable. The
//! exporter drops any IPv6 `Cidr` (and `extract_request` only parses IPv4, so a
//! v6 destination extracts as a missing `dest_ip`). A real implementation needs
//! a parallel `connect6` program, a 128-bit address representation in the clause
//! table (host-order `__u128` / `[u8; 16]`), and a v6 CIDR-containment routine.
//! Until then, v6 stays in user-space RVM (fail-closed).
//!
//! ## #19 — Deny-lists ("allow all except X")
//!
//! The model is allow-list / default-deny: a clause table enumerates what is
//! *permitted*. A "deny only X" policy (e.g. `input.dest_ip != "10.0.0.99"` or
//! `not net.cidr_contains(...)`) cannot be expressed as a positive allow-list
//! without enumerating the (astronomically large) complement, so it is either
//! rejected by the lift (no config) or lowered to a negated atom the exporter
//! drops. A real implementation would need an explicit deny-list map consulted
//! *before* the allow scan, plus a lowering that proves the residual is a pure
//! complement. Until then these stay fail-closed.
//!
//! ## #20 — Other hooks (`bind4` / `sendmsg4` / `connect6`)
//!
//! Out of scope for this connect4 egress enforcer. There is no enforceable test
//! to write here beyond this note: those hooks present different context
//! structures (e.g. `sendmsg4` is connectionless and per-datagram; `bind4` is a
//! local-address decision, not an egress destination). Supporting them needs
//! separate `SEC()` programs, separate field-extraction, and separate clause
//! tables; the current fixed program intentionally implements only
//! cgroup/`connect4`.
//!
//! ## #21 — Per-uid / per-cgroup scoping
//!
//! The connect4 model observes exactly three destination fields
//! (`dest_ip` / `dest_port` / `proto`); it has no notion of the calling `uid`,
//! cgroup id, or process identity. A policy that constrains `input.uid` (or any
//! other non-observable field) has that clause dropped by the exporter
//! (`FieldId::from_input_path` returns `None`), so it can never contribute an
//! allow. A real implementation needs extra context fields plumbed from the
//! hook (`bpf_get_current_uid_gid`, `bpf_get_current_cgroup_id`) into both the
//! `Request` and the clause table. Until then, uid-scoped allows stay
//! fail-closed.

use std::collections::BTreeMap;

use regorus::*;

use regorus_bpf::{enforce, export, extract_request, Verdict as BpfVerdict};
use regorus_lift::ir::{Atom, CidrAtom, Clause, EnforcerConfig, EqAtom, IpFamily, LiftScalar};
use regorus_lift::sim::simulate;
use regorus_lift::{lift, ContextSchema, FieldType, Verdict as LiftVerdict};

// ---------------------------------------------------------------------------
// Shared triple-path harness (parameterised by lift schema)
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

fn schema_with_uid() -> ContextSchema {
    ContextSchema::new()
        .with("input.dest_ip", FieldType::Ip)
        .with("input.dest_port", FieldType::Uint)
        .with("input.proto", FieldType::Str)
        .with("input.uid", FieldType::Uint)
}

/// Inputs spanning IPv4, IPv6, and a non-zero/zero uid; plus malformed ones.
fn mixed_inputs() -> Vec<String> {
    let dests = [
        "10.0.0.1",
        "10.1.2.3",
        "192.168.1.1",
        "8.8.8.8",
        "fd00::1",
        "2001:db8::1",
        "not-an-ip",
    ];
    let uids = [0u32, 1000];
    let mut out = Vec::new();
    for d in dests {
        for uid in uids {
            out.push(format!(
                r#"{{"dest_ip":"{d}","dest_port":443,"proto":"tcp","uid":{uid}}}"#
            ));
        }
    }
    out.push(r#"{}"#.to_string());
    out.push(r#"{"dest_port":443,"proto":"tcp"}"#.to_string());
    out
}

/// Assert the map-plan enforcer never over-permits relative to full eval, and
/// never over-permits relative to the IR reference enforcer, for every input.
fn assert_never_over_permits(policy: &str, entrypoint: &str, config: &EnforcerConfig) {
    let plan = export(config).expect("plan should export");
    for input_json in mixed_inputs() {
        let input: serde_json::Value = serde_json::from_str(&input_json).unwrap();
        let want_allow = full_eval(policy, entrypoint, &input_json);
        let req = extract_request(&input);
        let bpf_v = enforce(&plan, &req);

        if bpf_v == BpfVerdict::Allow {
            assert!(
                want_allow,
                "OVER-PERMISSION (bpf): plan allowed but full eval denied for {input_json}"
            );
            assert_eq!(
                simulate(config, &input),
                LiftVerdict::Allow,
                "bpf over-permits vs sim for {input_json}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// #18 — IPv6 egress / connect6
// ---------------------------------------------------------------------------

#[test]
fn ipv6_cidr_config_yields_empty_clauses() {
    let cfg = EnforcerConfig::new(
        {
            let mut m = BTreeMap::new();
            m.insert("input.dest_ip".to_string(), FieldType::Ip);
            m
        },
        vec![Clause {
            atoms: vec![Atom::Cidr(CidrAtom {
                input_path: "input.dest_ip".into(),
                network: "fd00::/8".into(),
                prefix_len: 8,
                family: IpFamily::V6,
                negated: false,
            })],
        }],
    );
    let plan = export(&cfg).unwrap();
    assert!(
        plan.clauses.is_empty(),
        "IPv6 CIDR is not observable on connect4 and must be dropped (fail-closed)"
    );
}

const MIXED_V4_V6_POLICY: &str = r#"
package egress

default allow = false

# IPv4 disjunct — kernel-observable on connect4.
allow if {
    net.cidr_contains("10.0.0.0/8", input.dest_ip)
}

# IPv6 disjunct — NOT observable on connect4; must stay fail-closed.
allow if {
    net.cidr_contains("fd00::/8", input.dest_ip)
}
"#;

#[test]
fn mixed_v4_v6_never_over_permits() {
    let pe = run_pe_typed(MIXED_V4_V6_POLICY, "data.egress.allow");
    let res = lift(&pe, &schema_with_uid());
    let config = res
        .config
        .unwrap_or_else(|| panic!("expected a config; rejections: {:?}", res.rejections));

    // The v4 clause lowers; the v6 clause is dropped — so only v4 enforces.
    let plan = export(&config).unwrap();
    assert_eq!(
        plan.clauses.len(),
        1,
        "only the IPv4 disjunct should lower; the IPv6 disjunct is dropped"
    );

    assert_never_over_permits(MIXED_V4_V6_POLICY, "data.egress.allow", &config);

    // Spot-check: a v6 destination the policy would allow is denied by bpf.
    let v6_req = extract_request(
        &serde_json::from_str::<serde_json::Value>(r#"{"dest_ip":"fd00::1","proto":"tcp"}"#)
            .unwrap(),
    );
    assert_eq!(
        enforce(&plan, &v6_req),
        BpfVerdict::Undecided,
        "IPv6 destination must not be allowed by the connect4 enforcer"
    );
}

// ---------------------------------------------------------------------------
// #19 — Deny-lists ("allow all except X")
// ---------------------------------------------------------------------------

const DENYLIST_NE_POLICY: &str = r#"
package egress

default allow = false

# "Allow everything except this one host" — a complement, not an allow-list.
allow if {
    input.dest_ip != "10.0.0.99"
}
"#;

#[test]
fn denylist_via_inequality_does_not_lower() {
    // The lift cannot turn a pure complement over an unbounded field into a
    // positive allow-list, so it rejects the whole policy — nothing lowers.
    let pe = run_pe_typed(DENYLIST_NE_POLICY, "data.egress.allow");
    let res = lift(&pe, &schema_with_uid());
    assert!(
        res.config.is_none(),
        "a deny-list (!=) over dest_ip must not lower into an allow-list; rejections: {:?}",
        res.rejections
    );
}

const DENYLIST_NOT_CIDR_POLICY: &str = r#"
package egress

default allow = false

# "Allow everything except the 10/8 subnet" via negation.
allow if {
    not net.cidr_contains("10.0.0.0/8", input.dest_ip)
}
"#;

#[test]
fn denylist_via_negated_cidr_drops_to_empty() {
    let pe = run_pe_typed(DENYLIST_NOT_CIDR_POLICY, "data.egress.allow");
    let res = lift(&pe, &schema_with_uid());
    let config = res
        .config
        .unwrap_or_else(|| panic!("expected a config; rejections: {:?}", res.rejections));

    // The lift produces a *negated* CIDR atom, which the exporter drops — the
    // allow-list backend cannot represent "everything outside this subnet".
    let plan = export(&config).unwrap();
    assert!(
        plan.clauses.is_empty(),
        "negated-CIDR deny-list must drop to an empty allow-list (fail-closed)"
    );

    // And it never over-permits: bpf denies everything here.
    assert_never_over_permits(DENYLIST_NOT_CIDR_POLICY, "data.egress.allow", &config);
}

// ---------------------------------------------------------------------------
// #21 — Per-uid / per-cgroup scoping
// ---------------------------------------------------------------------------

#[test]
fn uid_scoped_clause_is_dropped() {
    // input.uid is not a connect4-observable field, so a clause referencing it
    // is dropped wholesale (FieldId::from_input_path returns None).
    let cfg = EnforcerConfig::new(
        {
            let mut m = BTreeMap::new();
            m.insert("input.dest_ip".to_string(), FieldType::Ip);
            m.insert("input.uid".to_string(), FieldType::Uint);
            m
        },
        vec![Clause {
            atoms: vec![
                Atom::Eq(EqAtom {
                    input_path: "input.uid".into(),
                    scalar: LiftScalar::Uint(0),
                }),
                Atom::Eq(EqAtom {
                    input_path: "input.dest_ip".into(),
                    scalar: LiftScalar::Str("10.0.0.1".into()),
                }),
            ],
        }],
    );
    let plan = export(&cfg).unwrap();
    assert!(
        plan.clauses.is_empty(),
        "a clause constraining a non-observable field (uid) must be dropped (fail-closed)"
    );
}

const UID_POLICY: &str = r#"
package egress

default allow = false

# Root-only egress to a specific host. `uid` is not observable on connect4, so
# this clause must NOT lower into an unconditional dest_ip allow.
allow if {
    input.uid == 0
    input.dest_ip == "10.0.0.1"
}
"#;

#[test]
fn uid_policy_never_over_permits() {
    let pe = run_pe_typed(UID_POLICY, "data.egress.allow");
    let res = lift(&pe, &schema_with_uid());
    let config = res
        .config
        .unwrap_or_else(|| panic!("expected a config; rejections: {:?}", res.rejections));

    // The whole clause is dropped because it constrains uid.
    let plan = export(&config).unwrap();
    assert!(
        plan.clauses.is_empty(),
        "uid-scoped clause must be dropped; lowering only dest_ip would over-permit non-root"
    );

    assert_never_over_permits(UID_POLICY, "data.egress.allow", &config);
}
