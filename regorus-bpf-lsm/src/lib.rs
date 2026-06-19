// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `regorus-bpf-lsm` — Phase 1 LSM file-access eBPF backend (MVP).
//!
//! This crate lowers a [`regorus_lift::EnforcerConfig`] (the kernel-enforceable
//! subset of a Rego policy, already proven sound by `regorus-lift`) into a
//! concrete rule plan for a **fixed, hand-audited `lsm/file_open` enforcer**,
//! and provides a user-space reference enforcer that reads that plan exactly as
//! the kernel program is intended to.
//!
//! It is the sibling of [`regorus-bpf`](../regorus_bpf/index.html) (egress
//! `connect4`): same fail-closed discipline, same triple-path conformance
//! harness, different hook.
//!
//! # Scope (MVP)
//!
//! One hook: `lsm/file_open` file-access allow-list. Two observable fields,
//! extracted from `struct file`:
//!
//! - `input.path` — the file path being opened. **Assumed already
//!   canonicalized by user space**: path canonicalization stays in user space,
//!   *not* in the kernel. The kernel program reads only a bounded, un-canonical
//!   prefix and is therefore best-effort (see below); this crate's user-space
//!   enforcer is the conformance reference.
//! - `input.op` — the access mode (`read` / `write` / `exec`), derived from
//!   `file->f_mode`.
//!
//! Supported atoms per allow-clause: `Eq` and `Membership` over both fields
//! (exact paths / exact ops), and a non-negated `startswith(input.path, …)`
//! (lowered to a leading-byte prefix). Everything else — a non-observable
//! field, a second atom on the same field, a negated prefix, or an
//! `endswith` / `contains` (suffix/substring, which a fixed program cannot
//! match soundly) — makes the clause **non-lowerable** and it is dropped from
//! the exported plan (it stays in user-space RVM). Dropping a clause can only
//! *remove* allows, never add them.
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
//! cross-product of inverted tuples), and the enforcer treats any extraction
//! failure, unknown verdict, or unmatched request as `Undecided`, which
//! collapses to `Deny` at the boundary.
//!
//! # Kernel best-effort caveat (Phase-2 risk)
//!
//! In-kernel path matching (`bpf/file_open.bpf.c`) is bounded and operates on
//! the raw `bpf_d_path` output, which is neither canonicalized nor unbounded.
//! Getting it sound is explicitly a Phase-2 problem. The **user-space reference
//! enforcer** ([`enforce`]) is what the conformance tests treat as ground truth
//! for the lowered IR; the kernel program is a documented, fail-closed,
//! best-effort companion.

pub mod abi;
pub mod enforcer;
pub mod plan;
pub mod pod;

pub use abi::{FieldId, FileOp, Request, Verdict, MAX_PATH_PREFIX, MAX_RULES};
pub use enforcer::{enforce, extract_request};
pub use plan::{export, ExportError, FilePlan, FileRule, OpMatch, PathMatch};
pub use pod::{enforce_pod, path_buffer, to_pod, PodFilePlan};
