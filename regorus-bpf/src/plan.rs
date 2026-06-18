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
//! any non-`Eq`/`Membership`/`Cidr` atom) makes the **whole clause**
//! non-lowerable, and the clause is dropped from the plan. Dropping an allow
//! clause can only remove allows, never add them — fail-closed.

use std::net::Ipv4Addr;

use regorus_lift::ir::{Atom, Clause, EnforcerConfig, IpFamily, LiftScalar};

use crate::abi::{FieldId, Proto, Verdict, MAX_CLAUSES};

/// Per-field scalar match: wildcard or an exact value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarMatch<T> {
    Any,
    Exact(T),
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
    // Alternatives per field. `None` = no constraining atom yet (wildcard).
    let mut ip_alts: Option<Vec<IpMatch>> = None;
    let mut port_alts: Option<Vec<ScalarMatch<u16>>> = None;
    let mut proto_alts: Option<Vec<ScalarMatch<u8>>> = None;

    for atom in &clause.atoms {
        let field = FieldId::from_input_path(atom.input_path())?; // non-observable -> reject
        match field {
            FieldId::DestIp => {
                if ip_alts.is_some() {
                    return None; // two atoms on the same field -> reject (fail-closed)
                }
                ip_alts = Some(lower_ip_atom(atom)?);
            }
            FieldId::DestPort => {
                if port_alts.is_some() {
                    return None;
                }
                port_alts = Some(lower_port_atom(atom)?);
            }
            FieldId::Proto => {
                if proto_alts.is_some() {
                    return None;
                }
                proto_alts = Some(lower_proto_atom(atom)?);
            }
        }
    }

    let ip_alts = ip_alts.unwrap_or_else(|| vec![IpMatch::Any]);
    let port_alts = port_alts.unwrap_or_else(|| vec![ScalarMatch::Any]);
    let proto_alts = proto_alts.unwrap_or_else(|| vec![ScalarMatch::Any]);

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

fn scalar_to_proto(scalar: &LiftScalar) -> Option<u8> {
    match scalar {
        LiftScalar::Str(s) => Proto::from_name(s).map(Proto::as_u8),
        _ => None,
    }
}
