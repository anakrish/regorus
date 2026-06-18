// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Lower a [`regorus_lift::EnforcerConfig`] into a [`MapPlan`] for the fixed
//! cgroup/connect4 egress enforcer.
//!
//! Each lift allow-clause (a conjunction of atoms) becomes one or more
//! [`ClauseEntry`] rows. A field with no constraining atom is a **wildcard**
//! (`Any`), so the full conjunction — including unconstrained fields — is
//! preserved exactly; nothing is dropped or cross-producted across disjuncts.
//!
//! Any atom this hook cannot represent (a non-observable field, a second atom
//! on the same field, an unparseable/typed-wrong value, IPv6, negated CIDR, or
//! any non-`Eq`/`Membership`/`Cidr`/representable-`Cmp` atom) makes the
//! **whole clause** non-lowerable, and the clause is dropped from the plan.
//! Dropping an allow clause can only remove allows, never add them —
//! fail-closed.
//!
//! ## Port ranges
//!
//! As a special case, the `dest_port` field accepts **multiple** `Cmp` atoms
//! in one clause (e.g. `input.dest_port >= 1024` AND `input.dest_port <= 2048`).
//! These are intersected into a single inclusive [`ScalarMatch::Range`]. The
//! ordered comparisons `Ge`/`Gt`/`Le`/`Lt` map to half-open bounds clamped to
//! `[0, u16::MAX]`; if the intersection is empty the clause matches nothing and
//! is dropped (sound). Any `Cmp` that cannot be represented as a range bound
//! (e.g. `Ne`, or a `negation_complement` where a missing field would match),
//! or any mix of a `Cmp` with an `Eq`/`Membership` on the same `dest_port`
//! field, makes the whole clause non-lowerable (fail-closed).

use std::net::Ipv4Addr;

use regorus_lift::ir::{Atom, Clause, CmpOp, EnforcerConfig, IpFamily, LiftScalar};

use crate::abi::{FieldId, Proto, Verdict, MAX_CLAUSES};

/// Per-field scalar match: wildcard, an exact value, or an inclusive range.
///
/// `Range { min, max }` matches a present value `v` iff `min <= v <= max`
/// (inclusive on both ends). A `Range` therefore requires the field to be
/// **present** — a missing/None value never matches a `Range`, mirroring the
/// fail-closed semantics of a Rego comparison over a missing field
/// (`missing_matches = false`). Only `dest_port` ever lowers to a `Range`
/// (from `>=`/`>`/`<=`/`<` comparisons); `proto` only ever uses `Any`/`Exact`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarMatch<T> {
    Any,
    Exact(T),
    Range { min: T, max: T },
}

/// `dest_ip` match: wildcard, exact host-order IPv4, or an IPv4 CIDR network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpMatch {
    Any,
    Exact(u32),
    Cidr { network: u32, prefix_len: u8 },
}

/// One compiled allow clause: a full conjunction over the three hook fields.
/// A request matches iff every field matches (a wildcard matches anything).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClauseEntry {
    pub ip: IpMatch,
    pub port: ScalarMatch<u16>,
    pub proto: ScalarMatch<u8>,
}

/// The concrete plan consumed by the enforcer. `static_verdict`, when set,
/// determines the verdict independent of any request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapPlan {
    pub static_verdict: Option<Verdict>,
    pub clauses: Vec<ClauseEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportError {
    /// The lowered clause table would exceed [`MAX_CLAUSES`]; the plan is not
    /// exported (the caller must route to user-space RVM). Fail-closed.
    TooManyClauses { needed: usize, max: usize },
}

/// Lower an [`EnforcerConfig`] into a [`MapPlan`].
pub fn export(config: &EnforcerConfig) -> Result<MapPlan, ExportError> {
    if let Some(v) = config.static_verdict {
        return Ok(MapPlan {
            static_verdict: Some(map_verdict(v)),
            clauses: Vec::new(),
        });
    }

    let mut clauses = Vec::new();
    for clause in &config.allow_clauses {
        // A non-lowerable clause is dropped (fail-closed). Only fully
        // representable clauses contribute allow entries.
        if let Some(entries) = lower_clause(clause) {
            clauses.extend(entries);
        }
    }

    if clauses.len() > MAX_CLAUSES {
        return Err(ExportError::TooManyClauses {
            needed: clauses.len(),
            max: MAX_CLAUSES,
        });
    }

    Ok(MapPlan {
        static_verdict: None,
        clauses,
    })
}

fn map_verdict(v: regorus_lift::Verdict) -> Verdict {
    match v {
        regorus_lift::Verdict::Allow => Verdict::Allow,
        regorus_lift::Verdict::Deny => Verdict::Deny,
        regorus_lift::Verdict::Undecided => Verdict::Undecided,
    }
}

/// Lower a single conjunction clause to one or more [`ClauseEntry`] rows, or
/// `None` if any atom is not representable by this hook (reject the clause).
fn lower_clause(clause: &Clause) -> Option<Vec<ClauseEntry>> {
    // Gather atoms per field. The `dest_port` field may carry more than one
    // atom (intersected `Cmp` range bounds); the others accept at most one.
    let mut ip_atoms: Vec<&Atom> = Vec::new();
    let mut port_atoms: Vec<&Atom> = Vec::new();
    let mut proto_atoms: Vec<&Atom> = Vec::new();

    for atom in &clause.atoms {
        let field = FieldId::from_input_path(atom.input_path())?; // non-observable -> reject
        match field {
            FieldId::DestIp => ip_atoms.push(atom),
            FieldId::DestPort => port_atoms.push(atom),
            FieldId::Proto => proto_atoms.push(atom),
        }
    }

    let ip_alts = lower_ip_field(&ip_atoms)?;
    let port_alts = lower_port_atoms(&port_atoms)?;
    let proto_alts = lower_single_field(&proto_atoms, lower_proto_atom)?;

    // Bounded cross-product across the per-field alternatives.
    let product = ip_alts.len() * port_alts.len() * proto_alts.len();
    if product > MAX_CLAUSES {
        return None; // explosion -> reject clause (fail-closed)
    }
    let mut entries = Vec::with_capacity(product);
    for &ip in &ip_alts {
        for &port in &port_alts {
            for &proto in &proto_alts {
                entries.push(ClauseEntry { ip, port, proto });
            }
        }
    }
    Some(entries)
}

/// Lower a field that accepts at most one constraining atom. Zero atoms is a
/// wildcard; two or more atoms on the same field reject the clause (fail-closed).
fn lower_single_field<T: Copy>(
    atoms: &[&Atom],
    lower: impl Fn(&Atom) -> Option<Vec<ScalarMatch<T>>>,
) -> Option<Vec<ScalarMatch<T>>> {
    match atoms {
        [] => Some(vec![ScalarMatch::Any]),
        [atom] => lower(atom),
        _ => None, // two atoms on the same field -> reject (fail-closed)
    }
}

/// Specialised variant of [`lower_single_field`] for the `dest_ip` field, whose
/// matches use [`IpMatch`] rather than [`ScalarMatch`].
fn lower_ip_field(atoms: &[&Atom]) -> Option<Vec<IpMatch>> {
    match atoms {
        [] => Some(vec![IpMatch::Any]),
        [atom] => lower_ip_atom(atom),
        _ => None,
    }
}

fn lower_ip_atom(atom: &Atom) -> Option<Vec<IpMatch>> {
    match atom {
        Atom::Eq(eq) => Some(vec![IpMatch::Exact(parse_ipv4_scalar(&eq.scalar)?)]),
        Atom::Membership(m) => {
            let mut out = Vec::with_capacity(m.values.len());
            for v in &m.values {
                out.push(IpMatch::Exact(parse_ipv4_scalar(v)?));
            }
            (!out.is_empty()).then_some(out)
        }
        Atom::Cidr(c) => {
            // MVP: only non-negated IPv4 CIDR is representable on connect4.
            if c.negated || c.family != IpFamily::V4 {
                return None;
            }
            // `network` is the full CIDR string (e.g. "192.168.0.0/16"); the
            // address part precedes the slash. `prefix_len` is also supplied
            // separately and must agree with the textual prefix when present.
            let (addr_str, prefix_from_str) = match c.network.split_once('/') {
                Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
                None => (c.network.as_str(), None),
            };
            if let Some(p) = prefix_from_str {
                if p != c.prefix_len {
                    return None;
                }
            }
            if c.prefix_len > 32 {
                return None;
            }
            let network = parse_ipv4_str(addr_str)?;
            Some(vec![IpMatch::Cidr {
                network,
                prefix_len: c.prefix_len,
            }])
        }
        _ => None,
    }
}

/// Lower the `dest_port` atoms of a clause.
///
/// - Zero atoms -> wildcard (`Any`).
/// - A single `Eq` or `Membership` atom -> exact value(s), as before.
/// - One or more `Cmp` atoms -> intersect into a single inclusive
///   [`ScalarMatch::Range`]. An empty intersection drops the clause (sound).
/// - Any other combination (a second `Eq`/`Membership`, or a `Cmp` mixed with
///   an `Eq`/`Membership`, or an unrepresentable `Cmp`) -> reject (fail-closed).
fn lower_port_atoms(atoms: &[&Atom]) -> Option<Vec<ScalarMatch<u16>>> {
    if atoms.is_empty() {
        return Some(vec![ScalarMatch::Any]);
    }

    // If every atom is a comparison, fold them into one intersected range.
    if atoms.iter().all(|a| matches!(a, Atom::Cmp(_))) {
        // Work in i64 so half-open adjustments and out-of-`u16` bounds can be
        // represented before clamping to the observable `[0, u16::MAX]` window.
        let mut lo: i64 = 0;
        let mut hi: i64 = u16::MAX as i64;
        for atom in atoms {
            let Atom::Cmp(cmp) = atom else { return None };
            // A comparison whose missing field would still match cannot be
            // soundly represented by a presence-requiring range; reject.
            if cmp.missing_matches {
                return None;
            }
            let n = scalar_to_i64(&cmp.scalar)?;
            match cmp.op {
                CmpOp::Ge => lo = lo.max(n),
                CmpOp::Gt => lo = lo.max(n.saturating_add(1)),
                CmpOp::Le => hi = hi.min(n),
                CmpOp::Lt => hi = hi.min(n.saturating_sub(1)),
                CmpOp::Ne => return None, // not a single contiguous range
            }
        }
        // Clamp to the observable u16 window, then test for emptiness.
        let min = lo.max(0);
        let max = hi.min(u16::MAX as i64);
        if min > max {
            return None; // empty range -> clause matches nothing -> drop
        }
        return Some(vec![ScalarMatch::Range {
            min: min as u16,
            max: max as u16,
        }]);
    }

    // Otherwise only a single Eq/Membership atom is representable.
    match atoms {
        [atom] => lower_port_atom(atom),
        _ => None,
    }
}

fn lower_port_atom(atom: &Atom) -> Option<Vec<ScalarMatch<u16>>> {
    match atom {
        Atom::Eq(eq) => Some(vec![ScalarMatch::Exact(scalar_to_u16(&eq.scalar)?)]),
        Atom::Membership(m) => {
            let mut out = Vec::with_capacity(m.values.len());
            for v in &m.values {
                out.push(ScalarMatch::Exact(scalar_to_u16(v)?));
            }
            (!out.is_empty()).then_some(out)
        }
        _ => None,
    }
}

fn lower_proto_atom(atom: &Atom) -> Option<Vec<ScalarMatch<u8>>> {
    match atom {
        Atom::Eq(eq) => Some(vec![ScalarMatch::Exact(scalar_to_proto(&eq.scalar)?)]),
        Atom::Membership(m) => {
            let mut out = Vec::with_capacity(m.values.len());
            for v in &m.values {
                out.push(ScalarMatch::Exact(scalar_to_proto(v)?));
            }
            (!out.is_empty()).then_some(out)
        }
        _ => None,
    }
}

fn parse_ipv4_scalar(scalar: &LiftScalar) -> Option<u32> {
    match scalar {
        LiftScalar::Str(s) => parse_ipv4_str(s),
        _ => None,
    }
}

fn parse_ipv4_str(s: &str) -> Option<u32> {
    s.parse::<Ipv4Addr>().ok().map(u32::from)
}

fn scalar_to_u16(scalar: &LiftScalar) -> Option<u16> {
    match scalar {
        LiftScalar::Uint(u) => u16::try_from(*u).ok(),
        LiftScalar::Int(i) => u16::try_from(*i).ok(),
        _ => None,
    }
}

/// Convert an integer scalar to `i64` for range-bound arithmetic. A `Uint`
/// larger than `i64::MAX` saturates to `i64::MAX` (a port bound far above the
/// observable `u16` window, which clamps to an empty/degenerate range — sound).
fn scalar_to_i64(scalar: &LiftScalar) -> Option<i64> {
    match scalar {
        LiftScalar::Int(i) => Some(*i),
        LiftScalar::Uint(u) => Some(i64::try_from(*u).unwrap_or(i64::MAX)),
        _ => None,
    }
}

fn scalar_to_proto(scalar: &LiftScalar) -> Option<u8> {
    match scalar {
        LiftScalar::Str(s) => Proto::from_name(s).map(Proto::as_u8),
        _ => None,
    }
}
