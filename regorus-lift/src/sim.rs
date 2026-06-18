//! A faithful user-space simulator of the fixed kernel enforcer.
//!
//! Given an [`EnforcerConfig`] and a concrete input (as `serde_json::Value`,
//! the way a kernel hook would present extracted fields), this reproduces the
//! verdict the kernel enforcer would return — *without* a kernel. It exists so
//! the lift can be conformance-tested against full RVM evaluation, asserting the
//! soundness property `sim_allow ⟹ rvm_allow` (no over-permission).
//!
//! Fail-closed ABI: anything not provably `Allow` is `Deny`.

use std::cmp::Ordering;
use std::net::IpAddr;

use crate::ir::{Atom, Clause, CmpOp, EnforcerConfig, LiftScalar, PrefixKind, Verdict};

/// Simulate the enforcer for `input`.
pub fn simulate(config: &EnforcerConfig, input: &serde_json::Value) -> Verdict {
    if let Some(v) = config.static_verdict {
        return v;
    }
    for clause in &config.allow_clauses {
        if clause_matches(clause, input) {
            return Verdict::Allow;
        }
    }
    // Fail closed.
    Verdict::Deny
}

fn clause_matches(clause: &Clause, input: &serde_json::Value) -> bool {
    clause.atoms.iter().all(|atom| atom_matches(atom, input))
}

fn atom_matches(atom: &Atom, input: &serde_json::Value) -> bool {
    match atom {
        Atom::Eq(atom) => {
            extract_scalar(input, &atom.input_path).is_some_and(|actual| actual == atom.scalar)
        }
        Atom::Cmp(atom) => match extract_scalar(input, &atom.input_path) {
            Some(actual) => match atom.op {
                CmpOp::Ne => actual != atom.scalar,
                CmpOp::Lt => scalar_cmp(&actual, &atom.scalar).is_some_and(Ordering::is_lt),
                CmpOp::Le => scalar_cmp(&actual, &atom.scalar).is_some_and(|o| !o.is_gt()),
                CmpOp::Gt => scalar_cmp(&actual, &atom.scalar).is_some_and(Ordering::is_gt),
                CmpOp::Ge => scalar_cmp(&actual, &atom.scalar).is_some_and(|o| !o.is_lt()),
            },
            None => atom.missing_matches,
        },
        Atom::Membership(atom) => {
            extract_scalar(input, &atom.input_path)
                .is_some_and(|actual| atom.values.iter().any(|value| value == &actual))
                || extract_json(input, &atom.input_path).is_some_and(|actual| {
                    actual.as_array().is_some_and(|items| {
                        items
                            .iter()
                            .filter_map(LiftScalar::from_json)
                            .any(|item| atom.values.iter().any(|expected| expected == &item))
                    })
                })
        }
        Atom::Cidr(atom) => match extract_scalar(input, &atom.input_path) {
            Some(LiftScalar::Str(ip)) => {
                let matched = cidr_contains(&atom.network, &ip);
                if atom.negated {
                    matched != Some(true)
                } else {
                    matched == Some(true)
                }
            }
            _ => atom.negated,
        },
        Atom::Prefix(atom) => match extract_scalar(input, &atom.input_path) {
            Some(LiftScalar::Str(s)) => {
                let matched = match atom.kind {
                    PrefixKind::StartsWith => s.as_bytes().starts_with(atom.pattern.as_bytes()),
                    PrefixKind::EndsWith => s.as_bytes().ends_with(atom.pattern.as_bytes()),
                };
                if atom.negated {
                    !matched
                } else {
                    matched
                }
            }
            _ => atom.negated,
        },
        Atom::Exists(atom) => extract_json(input, &atom.input_path)
            .is_some_and(|value| value != &serde_json::Value::Bool(false)),
    }
}

/// Extract the scalar at a dotted `input_path` (e.g. `input.dest_ip`) from a
/// concrete input object. The leading `input` segment is stripped because the
/// concrete input *is* the input object.
pub fn extract_scalar(input: &serde_json::Value, input_path: &str) -> Option<LiftScalar> {
    extract_json(input, input_path).and_then(LiftScalar::from_json)
}

fn extract_json<'a>(
    input: &'a serde_json::Value,
    input_path: &str,
) -> Option<&'a serde_json::Value> {
    let mut cur = input;
    for (i, seg) in input_path.split('.').enumerate() {
        if i == 0 && seg == "input" {
            continue;
        }
        cur = cur.get(seg)?;
    }
    Some(cur)
}

fn scalar_cmp(left: &LiftScalar, right: &LiftScalar) -> Option<Ordering> {
    match (left, right) {
        (LiftScalar::Int(a), LiftScalar::Int(b)) => Some(a.cmp(b)),
        (LiftScalar::Uint(a), LiftScalar::Uint(b)) => Some(a.cmp(b)),
        (LiftScalar::Int(a), LiftScalar::Uint(b)) => {
            if *a < 0 {
                Some(Ordering::Less)
            } else {
                u64::try_from(*a).ok().map(|a| a.cmp(b))
            }
        }
        (LiftScalar::Uint(a), LiftScalar::Int(b)) => {
            if *b < 0 {
                Some(Ordering::Greater)
            } else {
                u64::try_from(*b).ok().map(|b| a.cmp(&b))
            }
        }
        (LiftScalar::Str(a), LiftScalar::Str(b)) => Some(a.cmp(b)),
        (LiftScalar::Bool(a), LiftScalar::Bool(b)) => Some(a.cmp(b)),
        _ => None,
    }
}

fn cidr_contains(cidr: &str, ip: &str) -> Option<bool> {
    let (network, prefix) = cidr.split_once('/')?;
    let prefix_len = prefix.parse::<u8>().ok()?;
    let network = network.parse::<IpAddr>().ok()?;
    let ip = ip.parse::<IpAddr>().ok()?;
    match (network, ip) {
        (IpAddr::V4(net), IpAddr::V4(addr)) if prefix_len <= 32 => {
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX.checked_shl(u32::from(32u8.saturating_sub(prefix_len)))?
            };
            Some((u32::from(net) & mask) == (u32::from(addr) & mask))
        }
        (IpAddr::V6(net), IpAddr::V6(addr)) if prefix_len <= 128 => {
            let mask = if prefix_len == 0 {
                0
            } else {
                u128::MAX.checked_shl(u32::from(128u8.saturating_sub(prefix_len)))?
            };
            Some((u128::from(net) & mask) == (u128::from(addr) & mask))
        }
        _ => None,
    }
}
