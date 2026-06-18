// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `regorus-bpf` — Phase 1 eBPF backend (MVP).
//!
//! This crate lowers a [`regorus_lift::EnforcerConfig`] (the kernel-enforceable
//! subset of a Rego policy, already proven sound by `regorus-lift`) into a
//! concrete map plan for a **fixed, hand-audited cgroup/connect4 egress
//! enforcer**, and provides a user-space reference enforcer that reads that map
//! plan exactly as the kernel program does.
//!
//! # Scope (MVP)
//!
//! One hook: cgroup/`connect4` egress allow-list. Three observable fields,
//! extracted from the connect4 context:
//!
//! - `input.dest_ip`   — IPv4 destination (`ctx->user_ip4`),
//! - `input.dest_port` — destination port (`ctx->user_port`),
//! - `input.proto`     — L4 protocol (`ctx->protocol`, e.g. `tcp`/`udp`).
//!
//! Supported atoms per allow-clause: `Eq` and `Membership` over those fields,
//! non-negated IPv4 `Cidr` over `input.dest_ip`, and `Cmp` (`>=`/`>`/`<=`/`<`)
//! port ranges over `input.dest_port` (multiple comparisons in one clause are
//! intersected into a single inclusive range). Everything else makes the clause
//! **non-lowerable** and it is dropped from the exported plan (it stays in
//! user-space RVM). Dropping a clause can only *remove* allows, never add them.
//!
//! # The non-negotiable invariant
//!
//! ```text
//!   enforce(plan, request) == Allow   ⟹   full_eval(policy, request) == allow
//! ```
//!
//! The enforcer may *under*-permit (deny what RVM allows) via enumerated
//! fail-closed cases, but must **never over-permit**. To preserve this, the
//! exporter lowers each clause as a complete conjunction with **explicit
//! wildcards** for unconstrained fields (so no dropped sibling constraint, no
//! cross-product of inverted tuples, no key-arity confusion), and the enforcer
//! treats any extraction failure, unknown verdict, or unmatched request as
//! `Undecided`, which collapses to `Deny` at the boundary.

pub mod abi;
pub mod enforcer;
pub mod plan;

pub use abi::{FieldId, Proto, Request, Verdict, MAX_CLAUSES};
pub use enforcer::{enforce, extract_request};
pub use plan::{export, ClauseEntry, ExportError, IpMatch, MapPlan, ScalarMatch};
