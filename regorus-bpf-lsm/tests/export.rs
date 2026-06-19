// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Direct unit tests for the exporter ([`regorus_bpf_lsm::export`]) and the
//! reference enforcer, driving hand-built [`EnforcerConfig`]s. These exercise
//! lowering paths (membership expansion, wildcards, prefix lowering, rejection,
//! bounds, static verdicts) precisely, independent of what partial evaluation
//! currently emits.

use std::collections::BTreeMap;

use regorus_bpf_lsm::{
    enforce, export, ExportError, FileOp, FileRule, OpMatch, PathMatch, Request,
};
use regorus_bpf_lsm::{Verdict as BpfVerdict, MAX_RULES};
use regorus_lift::ir::{
    Atom, CidrAtom, Clause, EnforcerConfig, EqAtom, IpFamily, LiftScalar, MembershipAtom,
    PrefixAtom, PrefixKind,
};
use regorus_lift::{FieldType, Verdict as LiftVerdict};

fn fields() -> BTreeMap<String, FieldType> {
    let mut m = BTreeMap::new();
    m.insert("input.path".to_string(), FieldType::Str);
    m.insert("input.op".to_string(), FieldType::Str);
    m
}

fn config(clauses: Vec<Clause>) -> EnforcerConfig {
    EnforcerConfig::new(fields(), clauses)
}

fn eq_path(p: &str) -> Atom {
    Atom::Eq(EqAtom {
        input_path: "input.path".into(),
        scalar: LiftScalar::Str(p.into()),
    })
}

fn prefix_path(p: &str, negated: bool, kind: PrefixKind) -> Atom {
    Atom::Prefix(PrefixAtom {
        input_path: "input.path".into(),
        pattern: p.into(),
        kind,
        negated,
    })
}

fn eq_op(name: &str) -> Atom {
    Atom::Eq(EqAtom {
        input_path: "input.op".into(),
        scalar: LiftScalar::Str(name.into()),
    })
}

fn req(path: Option<&str>, op: Option<FileOp>) -> Request {
    Request {
        path: path.map(|s| s.to_string()),
        op,
    }
}

#[test]
fn exact_clause_lowers_to_single_row() {
    let cfg = config(vec![Clause {
        atoms: vec![eq_path("/etc/myapp/conf"), eq_op("read")],
    }]);
    let plan = export(&cfg).unwrap();
    assert_eq!(plan.rules.len(), 1);
    assert_eq!(
        plan.rules[0],
        FileRule {
            path_match: PathMatch::Exact("/etc/myapp/conf".into()),
            op_match: OpMatch::Exact(FileOp::Read),
        }
    );
    assert_eq!(
        enforce(&plan, &req(Some("/etc/myapp/conf"), Some(FileOp::Read))),
        BpfVerdict::Allow
    );
    // Wrong op -> no match -> Undecided (fail-closed).
    assert_eq!(
        enforce(&plan, &req(Some("/etc/myapp/conf"), Some(FileOp::Write))),
        BpfVerdict::Undecided
    );
    // Exact match must not be satisfied by a longer path sharing the prefix.
    assert_eq!(
        enforce(&plan, &req(Some("/etc/myapp/conf.bak"), Some(FileOp::Read))),
        BpfVerdict::Undecided
    );
}

#[test]
fn prefix_clause_lowers_and_matches() {
    let cfg = config(vec![Clause {
        atoms: vec![
            prefix_path("/usr/bin/", false, PrefixKind::StartsWith),
            eq_op("exec"),
        ],
    }]);
    let plan = export(&cfg).unwrap();
    assert_eq!(plan.rules.len(), 1);
    assert_eq!(
        plan.rules[0].path_match,
        PathMatch::Prefix("/usr/bin/".into())
    );
    assert_eq!(
        enforce(&plan, &req(Some("/usr/bin/ls"), Some(FileOp::Exec))),
        BpfVerdict::Allow
    );
    // Under the prefix but wrong op.
    assert_eq!(
        enforce(&plan, &req(Some("/usr/bin/ls"), Some(FileOp::Read))),
        BpfVerdict::Undecided
    );
    // Not under the prefix.
    assert_eq!(
        enforce(&plan, &req(Some("/tmp/ls"), Some(FileOp::Exec))),
        BpfVerdict::Undecided
    );
    // Shorter than the prefix.
    assert_eq!(
        enforce(&plan, &req(Some("/usr/b"), Some(FileOp::Exec))),
        BpfVerdict::Undecided
    );
}

#[test]
fn unconstrained_fields_are_wildcards() {
    // Only path constrained; op is Any.
    let cfg = config(vec![Clause {
        atoms: vec![prefix_path("/var/log/", false, PrefixKind::StartsWith)],
    }]);
    let plan = export(&cfg).unwrap();
    assert_eq!(plan.rules[0].op_match, OpMatch::Any);
    assert_eq!(
        enforce(&plan, &req(Some("/var/log/app.log"), Some(FileOp::Write))),
        BpfVerdict::Allow
    );
    assert_eq!(
        enforce(&plan, &req(Some("/var/log/app.log"), None)),
        BpfVerdict::Allow
    );
    assert_eq!(
        enforce(&plan, &req(Some("/etc/passwd"), Some(FileOp::Read))),
        BpfVerdict::Undecided
    );
}

#[test]
fn membership_expands_to_cross_product() {
    // path in {a,b} AND op in {read,write} -> 4 rows.
    let cfg = config(vec![Clause {
        atoms: vec![
            Atom::Membership(MembershipAtom {
                input_path: "input.path".into(),
                values: vec![LiftScalar::Str("/a".into()), LiftScalar::Str("/b".into())],
            }),
            Atom::Membership(MembershipAtom {
                input_path: "input.op".into(),
                values: vec![
                    LiftScalar::Str("read".into()),
                    LiftScalar::Str("write".into()),
                ],
            }),
        ],
    }]);
    let plan = export(&cfg).unwrap();
    assert_eq!(plan.rules.len(), 4);
    for (path, op, want) in [
        ("/a", FileOp::Read, BpfVerdict::Allow),
        ("/b", FileOp::Write, BpfVerdict::Allow),
        ("/a", FileOp::Exec, BpfVerdict::Undecided),
        ("/c", FileOp::Read, BpfVerdict::Undecided),
    ] {
        assert_eq!(
            enforce(&plan, &req(Some(path), Some(op))),
            want,
            "path={path} op={op:?}"
        );
    }
}

#[test]
fn endswith_prefix_is_dropped() {
    let cfg = config(vec![Clause {
        atoms: vec![prefix_path(".so", false, PrefixKind::EndsWith)],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(
        plan.rules.is_empty(),
        "EndsWith cannot be matched soundly by a fixed program -> dropped"
    );
}

#[test]
fn contains_prefix_is_dropped() {
    let cfg = config(vec![Clause {
        atoms: vec![prefix_path("secret", false, PrefixKind::Contains)],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(plan.rules.is_empty(), "Contains -> dropped (fail-closed)");
}

#[test]
fn negated_prefix_is_dropped() {
    let cfg = config(vec![Clause {
        atoms: vec![prefix_path("/etc/", true, PrefixKind::StartsWith)],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(plan.rules.is_empty(), "negated prefix -> dropped");
}

#[test]
fn empty_prefix_is_dropped() {
    // An empty prefix matches everything; refuse to lower it.
    let cfg = config(vec![Clause {
        atoms: vec![prefix_path("", false, PrefixKind::StartsWith)],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(plan.rules.is_empty(), "empty prefix -> dropped");
}

#[test]
fn unknown_op_drops_clause() {
    let cfg = config(vec![Clause {
        atoms: vec![eq_path("/etc/x"), eq_op("append")],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(
        plan.rules.is_empty(),
        "an op the kernel can't represent -> drop clause (fail-closed)"
    );
}

#[test]
fn clause_referencing_unobservable_field_is_dropped() {
    let cfg = config(vec![Clause {
        atoms: vec![
            eq_path("/etc/x"),
            Atom::Eq(EqAtom {
                input_path: "input.user".into(),
                scalar: LiftScalar::Str("alice".into()),
            }),
        ],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(
        plan.rules.is_empty(),
        "clause with unobservable field must be dropped (fail-closed)"
    );
}

#[test]
fn cidr_atom_on_path_is_dropped() {
    // A non-lowerable atom kind for this hook drops the clause.
    let cfg = config(vec![Clause {
        atoms: vec![Atom::Cidr(CidrAtom {
            input_path: "input.path".into(),
            network: "10.0.0.0/8".into(),
            prefix_len: 8,
            family: IpFamily::V4,
            negated: false,
        })],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(plan.rules.is_empty());
}

#[test]
fn two_atoms_on_same_field_drop_clause() {
    let cfg = config(vec![Clause {
        atoms: vec![eq_path("/a"), eq_path("/b")],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(
        plan.rules.is_empty(),
        "conflicting same-field atoms -> reject clause (fail-closed)"
    );
}

#[test]
fn too_many_rules_is_handled() {
    // A membership over many paths explodes past MAX_RULES -> reject clause,
    // so the surviving plan is empty (and still sound).
    let many: Vec<LiftScalar> = (0..(MAX_RULES as u64 + 1))
        .map(|i| LiftScalar::Str(format!("/p{i}")))
        .collect();
    let cfg = config(vec![Clause {
        atoms: vec![Atom::Membership(MembershipAtom {
            input_path: "input.path".into(),
            values: many,
        })],
    }]);
    let plan = export(&cfg).unwrap();
    assert!(plan.rules.is_empty());

    // And a plan that totals past the bound across clauses is a hard error.
    let one_each: Vec<Clause> = (0..=(MAX_RULES as u64))
        .map(|p| Clause {
            atoms: vec![eq_path(&format!("/p{p}"))],
        })
        .collect();
    let cfg = config(one_each);
    assert!(matches!(
        export(&cfg),
        Err(ExportError::TooManyRules { .. })
    ));
}

#[test]
fn static_allow_and_deny_short_circuit() {
    let allow = EnforcerConfig::with_static(LiftVerdict::Allow);
    let plan = export(&allow).unwrap();
    assert_eq!(plan.static_verdict, Some(BpfVerdict::Allow));
    assert_eq!(enforce(&plan, &req(None, None)), BpfVerdict::Allow);

    let deny = EnforcerConfig::with_static(LiftVerdict::Deny);
    let plan = export(&deny).unwrap();
    assert_eq!(
        enforce(&plan, &req(Some("/etc/x"), Some(FileOp::Read))),
        BpfVerdict::Deny
    );
}

#[test]
fn empty_config_denies_everything() {
    let cfg = config(vec![]);
    let plan = export(&cfg).unwrap();
    assert_eq!(
        enforce(&plan, &req(Some("/etc/x"), Some(FileOp::Read))),
        BpfVerdict::Undecided
    );
}

#[test]
fn missing_path_never_matches_a_constrained_rule() {
    let cfg = config(vec![Clause {
        atoms: vec![prefix_path("/etc/", false, PrefixKind::StartsWith)],
    }]);
    let plan = export(&cfg).unwrap();
    assert_eq!(
        enforce(&plan, &req(None, Some(FileOp::Read))),
        BpfVerdict::Undecided
    );
}
