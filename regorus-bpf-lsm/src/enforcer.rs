// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! User-space reference enforcer for a [`FilePlan`].
//!
//! This is the **conformance reference** for the backend. It mirrors what the
//! fixed kernel C program (`bpf/file_open.bpf.c`) is *intended* to do — extract
//! the two observable fields, scan the bounded rule table, and `Allow` iff some
//! rule's full conjunction matches — but, unlike the kernel program, it does so
//! with no path-length bound and with exact (not best-effort) path comparison.
//! The triple-path conformance tests pin this enforcer against `regorus-lift`'s
//! [`simulate`](regorus_lift::sim::simulate) and full RVM evaluation.
//!
//! No rule match -> `Undecided`, which collapses to `Deny` at the boundary
//! (fail-closed). Extraction is fail-closed too: a missing or
//! wrongly-typed/unknown field becomes `None`, so any rule that constrains it
//! cannot match.
//!
//! Path canonicalization is assumed to have already happened in user space:
//! both `request.path` and the rule patterns are treated as canonical absolute
//! paths, and a `Prefix` match is a plain `starts_with` over those bytes.

use crate::abi::{FileOp, Request, Verdict};
use crate::plan::{FilePlan, FileRule, OpMatch, PathMatch};

/// Extract a [`Request`] from a concrete `input` JSON object, fail-closed.
pub fn extract_request(input: &serde_json::Value) -> Request {
    Request {
        path: input
            .get("path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        op: input
            .get("op")
            .and_then(|v| v.as_str())
            .and_then(FileOp::from_name),
    }
}

/// Evaluate the plan against a request. `Allow` iff some rule matches;
/// otherwise `Undecided` (fail-closed). A `static_verdict` short-circuits.
pub fn enforce(plan: &FilePlan, request: &Request) -> Verdict {
    if let Some(v) = plan.static_verdict {
        return v;
    }
    for rule in &plan.rules {
        if rule_matches(rule, request) {
            return Verdict::Allow;
        }
    }
    Verdict::Undecided
}

fn rule_matches(rule: &FileRule, request: &Request) -> bool {
    path_matches(&rule.path_match, request.path.as_deref()) && op_matches(rule.op_match, request.op)
}

fn path_matches(m: &PathMatch, value: Option<&str>) -> bool {
    match m {
        PathMatch::Any => true,
        PathMatch::Exact(p) => value == Some(p.as_str()),
        PathMatch::Prefix(prefix) => match value {
            Some(v) => v.as_bytes().starts_with(prefix.as_bytes()),
            None => false,
        },
    }
}

fn op_matches(m: OpMatch, value: Option<FileOp>) -> bool {
    match m {
        OpMatch::Any => true,
        OpMatch::Exact(op) => value == Some(op),
    }
}
