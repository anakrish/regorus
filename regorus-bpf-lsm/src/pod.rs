// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Serialise a [`FilePlan`] into the flat `#[repr(C)]` rule layout shared with
//! the kernel program ([`regorus_bpf_lsm_common::FileRule`]).
//!
//! The rich [`crate::plan`] enums (`PathMatch`, `OpMatch`) are the exporter's
//! internal representation; this module flattens them into the byte layout the
//! BPF `Array` map stores. There is exactly **one** such layout, defined in
//! `regorus-bpf-lsm-common` and used verbatim by both the user-space loader and
//! the kernel eBPF program — so there is no second hand-maintained struct.
//!
//! A path pattern longer than [`regorus_bpf_lsm_common::MAX_PATH_PREFIX`] cannot
//! be stored or verified soundly in-kernel, so [`to_pod`] **drops** any rule
//! whose pattern exceeds that bound (fail-closed: dropping an allow rule can
//! only remove allows, never add them). The conformance test pins that scanning
//! the serialised rules with [`regorus_bpf_lsm_common::scan`] agrees with the
//! user-space reference [`crate::enforce`] over the in-bounds domain.

use regorus_bpf_lsm_common as common;
use regorus_bpf_lsm_common::FileRule as PodRule;

use crate::abi::{FileOp, Request, Verdict};
use crate::plan::{FilePlan, FileRule, OpMatch, PathMatch};

/// The serialised form of a [`FilePlan`], ready to write into BPF maps.
#[derive(Clone)]
pub struct PodFilePlan {
    pub static_verdict: Option<Verdict>,
    pub rules: Vec<PodRule>,
}

impl PodFilePlan {
    /// Number of populated rule rows (the kernel `rule_count`).
    pub fn count(&self) -> usize {
        self.rules.len()
    }
}

/// Flatten a [`FilePlan`] into the shared `#[repr(C)]` rule layout. Rules whose
/// path pattern exceeds [`common::MAX_PATH_PREFIX`] are dropped (fail-closed).
pub fn to_pod(plan: &FilePlan) -> PodFilePlan {
    let mut rules = Vec::with_capacity(plan.rules.len());
    for r in &plan.rules {
        if let Some(pod) = rule_to_pod(r) {
            rules.push(pod);
        }
    }
    PodFilePlan {
        static_verdict: plan.static_verdict,
        rules,
    }
}

fn rule_to_pod(r: &FileRule) -> Option<PodRule> {
    let mut pod = PodRule::zeroed();

    match &r.path_match {
        PathMatch::Any => pod.path_kind = common::PATH_ANY,
        PathMatch::Exact(s) => {
            pod.path_kind = common::PATH_EXACT;
            write_pattern(&mut pod, s.as_bytes())?;
        }
        PathMatch::Prefix(s) => {
            pod.path_kind = common::PATH_PREFIX;
            write_pattern(&mut pod, s.as_bytes())?;
        }
    }

    match r.op_match {
        OpMatch::Any => pod.op_kind = common::OP_MATCH_ANY,
        OpMatch::Exact(op) => {
            pod.op_kind = common::OP_MATCH_EXACT;
            pod.op_value = file_op_to_u8(op);
        }
    }

    Some(pod)
}

/// Copy `bytes` into the rule's fixed pattern buffer, setting `pattern_len`.
/// Returns `None` (drop the rule) if the pattern exceeds the bounded buffer —
/// the kernel could not verify it soundly, so fail closed.
fn write_pattern(pod: &mut PodRule, bytes: &[u8]) -> Option<()> {
    if bytes.is_empty() || bytes.len() > common::MAX_PATH_PREFIX {
        return None;
    }
    pod.pattern[..bytes.len()].copy_from_slice(bytes);
    pod.pattern_len = bytes.len() as u32;
    Some(())
}

fn file_op_to_u8(op: FileOp) -> u8 {
    match op {
        FileOp::Read => common::OP_READ,
        FileOp::Write => common::OP_WRITE,
        FileOp::Exec => common::OP_EXEC,
    }
}

/// Build the bounded path buffer the kernel/common matcher expects from a path
/// string. A path longer than [`common::MAX_PATH_PREFIX`] is truncated to the
/// bound (matching the kernel's bounded `bpf_d_path` read); the returned length
/// is likewise clamped.
pub fn path_buffer(path: &str) -> ([u8; common::MAX_PATH_PREFIX], u32) {
    let mut buf = [0u8; common::MAX_PATH_PREFIX];
    let bytes = path.as_bytes();
    let n = bytes.len().min(common::MAX_PATH_PREFIX);
    buf[..n].copy_from_slice(&bytes[..n]);
    (buf, n as u32)
}

fn file_op_opt_to_u8(op: Option<FileOp>) -> Option<u8> {
    op.map(file_op_to_u8)
}

/// Evaluate a [`PodFilePlan`] exactly as the kernel program does: honour a
/// `static_verdict`, else scan the flat rules with [`common::scan`]. Returns the
/// raw verdict byte (`VERDICT_*`). Used by the conformance test.
pub fn enforce_pod(plan: &PodFilePlan, req: &Request) -> u8 {
    if let Some(v) = plan.static_verdict {
        return v as u8;
    }
    let (buf, len) = match &req.path {
        Some(p) => path_buffer(p),
        // No path -> empty buffer of length 0. A constrained path rule then
        // cannot match (fail-closed), mirroring the kernel's failure path.
        None => ([0u8; common::MAX_PATH_PREFIX], 0),
    };
    common::scan(
        &plan.rules,
        plan.count(),
        &buf,
        len,
        file_op_opt_to_u8(req.op),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{FileOp, Verdict};
    use crate::enforce;
    use crate::plan::{FilePlan, FileRule, OpMatch, PathMatch};

    fn sample_plan() -> FilePlan {
        FilePlan {
            static_verdict: None,
            rules: vec![
                FileRule {
                    path_match: PathMatch::Exact("/etc/hosts".to_string()),
                    op_match: OpMatch::Exact(FileOp::Read),
                },
                FileRule {
                    path_match: PathMatch::Prefix("/var/log/".to_string()),
                    op_match: OpMatch::Any,
                },
                FileRule {
                    path_match: PathMatch::Any,
                    op_match: OpMatch::Exact(FileOp::Exec),
                },
            ],
        }
    }

    #[test]
    fn pod_layout_size() {
        assert_eq!(std::mem::size_of::<PodRule>(), 264);
    }

    /// Scanning the serialised pod rules must agree with the rich user-space
    /// reference enforcer for every request whose path/pattern fit the kernel's
    /// bounded window (the domain the kernel actually handles).
    #[test]
    fn pod_scan_matches_reference_enforce() {
        let plan = sample_plan();
        let pod = to_pod(&plan);

        let paths = [
            None,
            Some("/etc/hosts".to_string()),
            Some("/etc/hosts2".to_string()),
            Some("/var/log/syslog".to_string()),
            Some("/var/lo".to_string()),
            Some("/usr/bin/ls".to_string()),
            Some("/".to_string()),
        ];
        let ops = [
            None,
            Some(FileOp::Read),
            Some(FileOp::Write),
            Some(FileOp::Exec),
        ];

        for path in &paths {
            for &op in &ops {
                let req = Request {
                    path: path.clone(),
                    op,
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

    #[test]
    fn static_verdict_round_trips() {
        for v in [Verdict::Allow, Verdict::Deny, Verdict::Undecided] {
            let plan = FilePlan {
                static_verdict: Some(v),
                rules: vec![],
            };
            let pod = to_pod(&plan);
            assert_eq!(pod.static_verdict, Some(v));
            let req = Request::default();
            assert_eq!(enforce_pod(&pod, &req), v as u8);
        }
    }

    #[test]
    fn overlong_pattern_is_dropped_fail_closed() {
        let long = "/".to_string() + &"a".repeat(common::MAX_PATH_PREFIX);
        let plan = FilePlan {
            static_verdict: None,
            rules: vec![FileRule {
                path_match: PathMatch::Exact(long.clone()),
                op_match: OpMatch::Any,
            }],
        };
        let pod = to_pod(&plan);
        // The single rule had an over-long pattern -> dropped entirely.
        assert_eq!(pod.count(), 0);
        let req = Request {
            path: Some(long),
            op: Some(FileOp::Read),
        };
        // Reference would allow (unbounded exact match), pod denies (dropped).
        // This is the documented sound under-approximation (never over-permits).
        assert_eq!(enforce(&plan, &req), Verdict::Allow);
        assert_eq!(enforce_pod(&pod, &req), common::VERDICT_UNDECIDED);
    }
}
