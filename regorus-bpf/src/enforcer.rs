// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! User-space reference enforcer for a [`MapPlan`].
//!
//! This mirrors, byte-for-byte in behaviour, what the fixed kernel C program
//! (`bpf/egress.bpf.c`) does: extract the three observable fields from the
//! request, scan the bounded clause table, and `Allow` iff some clause's full
//! conjunction matches. No clause match -> `Undecided`, which collapses to
//! `Deny` at the boundary (fail-closed).
//!
//! Extraction is fail-closed: a missing or wrongly-typed/unparseable field
//! becomes `None`, so any clause that constrains it cannot match.

use std::net::Ipv4Addr;

use crate::abi::{Proto, Request, Verdict};
use crate::plan::{ClauseEntry, IpMatch, MapPlan, ScalarMatch};

/// Extract a [`Request`] from a concrete `input` JSON object, fail-closed.
pub fn extract_request(input: &serde_json::Value) -> Request {
    Request {
        dest_ip: input
            .get("dest_ip")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<Ipv4Addr>().ok())
            .map(u32::from),
        dest_port: input.get("dest_port").and_then(extract_u16),
        proto: input
            .get("proto")
            .and_then(|v| v.as_str())
            .and_then(Proto::from_name)
            .map(Proto::as_u8),
    }
}

fn extract_u16(v: &serde_json::Value) -> Option<u16> {
    let n = v.as_u64()?;
    u16::try_from(n).ok()
}

/// Evaluate the plan against a request. `Allow` iff some clause matches;
/// otherwise `Undecided` (fail-closed). A `static_verdict` short-circuits.
pub fn enforce(plan: &MapPlan, request: &Request) -> Verdict {
    if let Some(v) = plan.static_verdict {
        return v;
    }
    for clause in &plan.clauses {
        if clause_matches(clause, request) {
            return Verdict::Allow;
        }
    }
    Verdict::Undecided
}

fn clause_matches(clause: &ClauseEntry, request: &Request) -> bool {
    ip_matches(clause.ip, request.dest_ip)
        && scalar_matches(clause.port, request.dest_port)
        && scalar_matches(clause.proto, request.proto)
}

fn ip_matches(m: IpMatch, value: Option<u32>) -> bool {
    match m {
        IpMatch::Any => true,
        IpMatch::Exact(n) => value == Some(n),
        IpMatch::Cidr {
            network,
            prefix_len,
        } => match value {
            Some(v) => cidr_contains(network, prefix_len, v),
            None => false,
        },
    }
}

fn scalar_matches<T: PartialOrd + Copy>(m: ScalarMatch<T>, value: Option<T>) -> bool {
    match m {
        ScalarMatch::Any => true,
        ScalarMatch::Exact(t) => value == Some(t),
        // A range requires the field to be present (None never matches), which
        // mirrors a Rego comparison over a missing field (fail-closed).
        ScalarMatch::Range { min, max } => value.is_some_and(|v| v >= min && v <= max),
    }
}

/// Host-order IPv4 CIDR containment.
fn cidr_contains(network: u32, prefix_len: u8, addr: u32) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len > 32 {
        return false;
    }
    let mask: u32 = u32::MAX << (32 - prefix_len as u32);
    (addr & mask) == (network & mask)
}
