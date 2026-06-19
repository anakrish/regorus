// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Serialise a [`MapPlan`] into the flat `#[repr(C)]` clause layout shared with
//! the kernel program ([`regorus_bpf_common::ClauseEntry`]).
//!
//! The rich [`crate::plan`] enums (`IpMatch`, `ScalarMatch`) are the exporter's
//! internal representation; this module flattens them into the byte layout the
//! BPF `Array` map stores. There is exactly **one** such layout, defined in
//! `regorus-bpf-common` and used verbatim by both the user-space loader and the
//! kernel eBPF program — so there is no second hand-maintained struct to drift.
//!
//! The conversion is total and lossless for every `MapPlan` the exporter can
//! produce; the conformance test in this module pins that scanning the
//! serialised clauses with [`regorus_bpf_common::scan`] agrees byte-for-byte
//! with the user-space reference [`crate::enforce`].

use regorus_bpf_common as common;
use regorus_bpf_common::ClauseEntry as PodClause;

use crate::abi::{Request, Verdict};
use crate::plan::{ClauseEntry, IpMatch, MapPlan, ScalarMatch};

/// The serialised form of a [`MapPlan`], ready to write into BPF maps.
///
/// * `static_verdict` — when set, enforcement is request-independent (the
///   loader can short-circuit; the kernel program treats it as a global
///   allow/deny without consulting the clause table).
/// * `clauses` — the populated clause rows (`len()` is the `clause_count` the
///   kernel loop bounds on).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodPlan {
    pub static_verdict: Option<Verdict>,
    pub clauses: Vec<PodClause>,
}

impl PodPlan {
    /// Number of populated clause rows (the kernel `clause_count`).
    pub fn count(&self) -> usize {
        self.clauses.len()
    }
}

/// Flatten a [`MapPlan`] into the shared `#[repr(C)]` clause layout.
pub fn to_pod(plan: &MapPlan) -> PodPlan {
    PodPlan {
        static_verdict: plan.static_verdict,
        clauses: plan.clauses.iter().map(clause_to_pod).collect(),
    }
}

fn clause_to_pod(c: &ClauseEntry) -> PodClause {
    let mut pod = PodClause::zeroed();
    match c.ip {
        IpMatch::Any => pod.ip_kind = common::IP_ANY,
        IpMatch::Exact(addr) => {
            pod.ip_kind = common::IP_EXACT;
            pod.ip_value = addr;
        }
        IpMatch::Cidr {
            network,
            prefix_len,
        } => {
            pod.ip_kind = common::IP_CIDR;
            pod.ip_value = network;
            pod.prefix_len = prefix_len;
        }
    }
    match c.port {
        ScalarMatch::Any => pod.port_kind = common::MATCH_ANY,
        ScalarMatch::Exact(p) => {
            pod.port_kind = common::MATCH_EXACT;
            pod.port_value = p;
        }
        ScalarMatch::Range { min, max } => {
            pod.port_kind = common::MATCH_RANGE;
            pod.port_min = min;
            pod.port_max = max;
        }
    }
    match c.proto {
        ScalarMatch::Any => pod.proto_kind = common::MATCH_ANY,
        ScalarMatch::Exact(p) => {
            pod.proto_kind = common::MATCH_EXACT;
            pod.proto_value = p;
        }
        // `proto` only ever lowers to `Any`/`Exact` (the exporter never emits a
        // proto range). Treat a hypothetical range fail-closed: a kind the
        // kernel does not recognise matches nothing, never over-permits.
        ScalarMatch::Range { .. } => pod.proto_kind = u8::MAX,
    }
    pod
}

/// Evaluate a [`PodPlan`] exactly as the kernel program does: honour a
/// `static_verdict`, else scan the flat clauses with [`common::scan`] and
/// collapse `Undecided -> Deny` at the boundary is left to the caller.
///
/// Returns the raw verdict byte (`VERDICT_*`). Used by the conformance test to
/// prove the serialised/scanned path matches the reference [`crate::enforce`].
pub fn enforce_pod(plan: &PodPlan, req: &Request) -> u8 {
    if let Some(v) = plan.static_verdict {
        return v as u8;
    }
    common::scan(
        &plan.clauses,
        plan.count(),
        req.dest_ip,
        req.dest_port,
        req.proto,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::Verdict;
    use crate::enforce;
    use crate::plan::{ClauseEntry, IpMatch, MapPlan, ScalarMatch};

    /// Build a representative plan exercising every match kind.
    fn sample_plan() -> MapPlan {
        MapPlan {
            static_verdict: None,
            clauses: vec![
                // exact ip + exact port + exact proto
                ClauseEntry {
                    ip: IpMatch::Exact(0x0a00_0001),
                    port: ScalarMatch::Exact(22),
                    proto: ScalarMatch::Exact(6),
                },
                // cidr + port range + any proto
                ClauseEntry {
                    ip: IpMatch::Cidr {
                        network: 0x0a00_0000,
                        prefix_len: 8,
                    },
                    port: ScalarMatch::Range {
                        min: 1024,
                        max: 2048,
                    },
                    proto: ScalarMatch::Any,
                },
                // any ip + any port + exact proto (udp)
                ClauseEntry {
                    ip: IpMatch::Any,
                    port: ScalarMatch::Any,
                    proto: ScalarMatch::Exact(17),
                },
            ],
        }
    }

    #[test]
    fn pod_layout_size() {
        assert_eq!(std::mem::size_of::<PodClause>(), 16);
    }

    /// Scanning the serialised pod clauses must agree byte-for-byte with the
    /// rich user-space reference enforcer for every request — the soundness
    /// link between the (single) shared layout and the conformance reference.
    #[test]
    fn pod_scan_matches_reference_enforce() {
        let plan = sample_plan();
        let pod = to_pod(&plan);

        let ips = [
            None,
            Some(0x0a00_0001u32),
            Some(0x0a01_0203),
            Some(0x0b00_0001),
        ];
        let ports = [
            None,
            Some(0u16),
            Some(22),
            Some(443),
            Some(1024),
            Some(2048),
            Some(4000),
        ];
        let protos = [None, Some(6u8), Some(17), Some(1)];

        for &dest_ip in &ips {
            for &dest_port in &ports {
                for &proto in &protos {
                    let req = Request {
                        dest_ip,
                        dest_port,
                        proto,
                    };
                    let reference = enforce(&plan, &req);
                    let pod_verdict = enforce_pod(&pod, &req);
                    assert_eq!(
                        reference as u8, pod_verdict,
                        "mismatch for {req:?}: reference={reference:?} pod={pod_verdict}"
                    );
                }
            }
        }
    }

    #[test]
    fn static_verdict_round_trips() {
        for v in [Verdict::Allow, Verdict::Deny, Verdict::Undecided] {
            let plan = MapPlan {
                static_verdict: Some(v),
                clauses: vec![],
            };
            let pod = to_pod(&plan);
            assert_eq!(pod.static_verdict, Some(v));
            let req = Request::default();
            assert_eq!(enforce_pod(&pod, &req), v as u8);
        }
    }
}
