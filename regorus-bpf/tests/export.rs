// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Direct unit tests for the exporter ([`regorus_bpf::export`]) and the
//! reference enforcer, driving hand-built [`EnforcerConfig`]s. These exercise
//! lowering paths (membership expansion, wildcards, rejection, bounds, static
//! verdicts) precisely, independent of what partial evaluation currently emits.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use regorus_bpf::{enforce, export, ClauseEntry, ExportError, IpMatch, Request, ScalarMatch};
use regorus_bpf::{Verdict as BpfVerdict, MAX_CLAUSES};
use regorus_lift::ir::{
    Atom, CidrAtom, Clause, EnforcerConfig, EqAtom, IpFamily, LiftScalar, MembershipAtom,
    PrefixAtom, PrefixKind,
};
use regorus_lift::{FieldType, Verdict as LiftVerdict};

fn ipv4(s: &str) -> u32 {
    u32::from(s.parse::<Ipv4Addr>().unwrap())
}

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

fn eq_ip(addr: &str) -> Atom {
    Atom::Eq(EqAtom {
        input_path: "input.dest_ip".into(),
        scalar: LiftScalar::Str(addr.into()),
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
        dest_ip: ip.map(ipv4),
        dest_port: port,
        proto,
    }
}

#[test]
fn exact_clause_lowers_to_single_row() {
    let cfg = config(vec![Clause {
        atoms: vec![eq_ip("10.0.0.1"), eq_port(443), eq_proto("tcp")],
    }]);
    let plan = export(&cfg).unwrap();
    assert_eq!(plan.clauses.len(), 1);
    assert_eq!(
        plan.clauses[0],
        ClauseEntry {
            ip: IpMatch::Exact(ipv4("10.0.0.1")),
            port: ScalarMatch::Exact(443),
            proto: ScalarMatch::Exact(6),
        }
    );
    assert_eq!(
        enforce(&plan, &req(Some("10.0.0.1"), Some(443), Some(6))),
        BpfVerdict::Allow
    );
    // Wrong port -> no match -> Undecided (fail-closed).
    assert_eq!(
        enforce(&plan, &req(Some("10.0.0.1"), Some(444), Some(6))),
        BpfVerdict::Undecided
    );
}

#[test]
fn unconstrained_fields_are_wildcards() {
    // Only dest_ip constrained; port and proto are Any.
    let cfg = config(vec![Clause {
        atoms: vec![eq_ip("10.0.0.2")],
    }]);
    let plan = export(&cfg).unwrap();
    assert_eq!(plan.clauses[0].port, ScalarMatch::Any);
    assert_eq!(plan.clauses[0].proto, ScalarMatch::Any);
    assert_eq!(
        enforce(&plan, &req(Some("10.0.0.2"), Some(1), Some(17))),
        BpfVerdict::Allow
    );
    assert_eq!(
        enforce(&plan, &req(Some("10.0.0.3"), Some(1), Some(17))),
        BpfVerdict::Undecided
    );
}

#[test]
fn membership_expands_to_cross_product() {
    // dest_ip in {a,b} AND dest_port in {80,443} -> 4 rows.
    let cfg = config(vec![Clause {
        atoms: vec![
            Atom::Membership(MembershipAtom {
                input_path: "input.dest_ip".into(),
                values: vec![
                    LiftScalar::Str("10.0.0.1".into()),
                    LiftScalar::Str("10.0.0.2".into()),
                ],
            }),
            Atom::Membership(MembershipAtom {
                input_path: "input.dest_port".into(),
                values: vec![LiftScalar::Uint(80), LiftScalar::Uint(443)],
            }),
        ],
    }]);
    let plan = export(&cfg).unwrap();
    assert_eq!(plan.clauses.len(), 4);
    for (ip, port, want) in [
        ("10.0.0.1", 80u16, BpfVerdict::Allow),
        ("10.0.0.2", 443, BpfVerdict::Allow),
        ("10.0.0.1", 22, BpfVerdict::Undecided),
        ("10.0.0.9", 80, BpfVerdict::Undecided),
    ] {
        assert_eq!(
            enforce(&plan, &req(Some(ip), Some(port), None)),
            want,
            "ip={ip} port={port}"
        );
    }
}

#[test]
fn cidr_clause_lowers_and_matches() {
    let cfg = config(vec![Clause {
        atoms: vec![
            Atom::Cidr(CidrAtom {
                input_path: "input.dest_ip".into(),
                network: "192.168.0.0/16".into(),
                prefix_len: 16,
                family: IpFamily::V4,
                negated: false,
            }),
            eq_proto("tcp"),
        ],
    }]);
    let plan = export(&cfg).unwrap();
    assert_eq!(plan.clauses.len(), 1);
    assert_eq!(
        enforce(&plan, &req(Some("192.168.5.5"), None, Some(6))),
        BpfVerdict::Allow
    );
    assert_eq!(
        enforce(&plan, &req(Some("10.0.0.1"), None, Some(6))),
        BpfVerdict::Undecided
    );
    // In CIDR but wrong proto -> the proto conjunct fails.
    assert_eq!(
        enforce(&plan, &req(Some("192.168.5.5"), None, Some(17))),
        BpfVerdict::Undecided
    );
}

#[test]
fn negated_cidr_clause_is_dropped() {
    let cfg = config(vec![Clause {
        atoms: vec![Atom::Cidr(CidrAtom {
            input_path: "input.dest_ip".into(),
            network: "10.0.0.0/8".into(),
            prefix_len: 8,
            family: IpFamily::V4,
            negated: true,
        })],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(plan.clauses.is_empty(), "negated CIDR must be dropped");
}

#[test]
fn ipv6_cidr_clause_is_dropped() {
    let cfg = config(vec![Clause {
        atoms: vec![Atom::Cidr(CidrAtom {
            input_path: "input.dest_ip".into(),
            network: "fd00::/8".into(),
            prefix_len: 8,
            family: IpFamily::V6,
            negated: false,
        })],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(plan.clauses.is_empty(), "IPv6 CIDR must be dropped");
}

#[test]
fn clause_referencing_unobservable_field_is_dropped() {
    // A clause with a non-hook field (and an otherwise valid atom) is dropped
    // entirely — never partially enforced.
    let cfg = config(vec![Clause {
        atoms: vec![
            eq_ip("10.0.0.1"),
            Atom::Eq(EqAtom {
                input_path: "input.user".into(),
                scalar: LiftScalar::Str("alice".into()),
            }),
        ],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(
        plan.clauses.is_empty(),
        "clause with unobservable field must be dropped (fail-closed)"
    );
}

#[test]
fn non_lowerable_atom_drops_clause() {
    let cfg = config(vec![Clause {
        atoms: vec![Atom::Prefix(PrefixAtom {
            input_path: "input.proto".into(),
            pattern: "t".into(),
            kind: PrefixKind::StartsWith,
            negated: false,
        })],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(plan.clauses.is_empty());
}

#[test]
fn two_atoms_on_same_field_drop_clause() {
    let cfg = config(vec![Clause {
        atoms: vec![eq_port(80), eq_port(443)],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(
        plan.clauses.is_empty(),
        "conflicting same-field atoms -> reject clause (fail-closed)"
    );
}

#[test]
fn too_many_clauses_is_an_error() {
    // A membership over many ports explodes past MAX_CLAUSES -> reject clause,
    // so the surviving plan is empty (and still sound).
    let many: Vec<LiftScalar> = (0..(MAX_CLAUSES as u64 + 1))
        .map(LiftScalar::Uint)
        .collect();
    let cfg = config(vec![Clause {
        atoms: vec![Atom::Membership(MembershipAtom {
            input_path: "input.dest_port".into(),
            values: many,
        })],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(plan.clauses.is_empty());

    // And a plan that totals past the bound across clauses is a hard error.
    let one_each: Vec<Clause> = (0..=(MAX_CLAUSES as u64))
        .map(|p| Clause {
            atoms: vec![eq_port(p)],
        })
        .collect();
    let cfg = config(one_each);
    assert!(matches!(
        export(&cfg),
        Err(ExportError::TooManyClauses { .. })
    ));
}

#[test]
fn static_allow_and_deny_short_circuit() {
    let allow = EnforcerConfig::with_static(LiftVerdict::Allow);
    let plan = export(&allow).unwrap();
    assert_eq!(plan.static_verdict, Some(BpfVerdict::Allow));
    assert_eq!(enforce(&plan, &req(None, None, None)), BpfVerdict::Allow);

    let deny = EnforcerConfig::with_static(LiftVerdict::Deny);
    let plan = export(&deny).unwrap();
    assert_eq!(
        enforce(&plan, &req(Some("10.0.0.1"), None, None)),
        BpfVerdict::Deny
    );
}

#[test]
fn empty_config_denies_everything() {
    let cfg = config(vec![]);
    let plan = export(&cfg).unwrap();
    assert_eq!(
        enforce(&plan, &req(Some("10.0.0.1"), Some(443), Some(6))),
        BpfVerdict::Undecided
    );
}
