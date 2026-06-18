// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The stable enforcement ABI shared between the user-space reference enforcer
//! ([`crate::enforcer`]) and the kernel C program (`bpf/file_open.bpf.c`).
//!
//! Both sides MUST agree on these layouts and constants byte-for-byte; the
//! conformance tests pin them.
//!
//! # Kernel ↔ user ABI (LSM `file_open`)
//!
//! The fixed kernel program is attached to the `lsm/file_open` hook. For each
//! open it extracts two observable fields and scans a bounded rule table that
//! user space populated from the exported [`crate::plan::FilePlan`]:
//!
//! - `input.path` (string) — the file path being opened. **User space is
//!   responsible for canonicalization**: the Rego policy, the lift, the
//!   exporter, and this reference enforcer all assume `input.path` is an
//!   already-canonical absolute path. The kernel program reads a *bounded*
//!   prefix of `bpf_d_path(&file->f_path, …)`, which is **not** canonicalized
//!   and is length-limited — see [`MAX_PATH_PREFIX`] and the Phase-2 caveats in
//!   `bpf/file_open.bpf.c`. The kernel path is therefore best-effort; the
//!   conformance reference is this user-space enforcer.
//! - `input.op` (string) — the access mode, one of `read` / `write` / `exec`,
//!   derived in the kernel from `file->f_mode` (`FMODE_EXEC` → `exec`,
//!   `FMODE_WRITE` → `write`, else `read`), and from the JSON `op` field in user
//!   space. See [`FileOp`].
//!
//! Each rule row stores a path match (`PathMatch`) and an op match (`OpMatch`).
//! A request is `Allow` iff some rule's full conjunction matches; otherwise it
//! is `Undecided`, which collapses to `Deny` at the boundary (fail-closed). For
//! the LSM hook the boundary `Deny` means returning `-EPERM`.

/// Fail-closed verdict ABI. `Undecided` collapses to `Deny` at the boundary.
///
/// The discriminants mirror [`regorus_lift::Verdict`] (`Deny = 0`, `Allow = 1`,
/// `Undecided = 2`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Verdict {
    Deny = 0,
    Allow = 1,
    Undecided = 2,
}

impl Verdict {
    /// Boundary collapse: `Undecided -> Deny`. The kernel hook adapter applies
    /// the same rule before converting to the hook-native return value
    /// (`0` to allow, `-EPERM` to deny).
    pub fn at_boundary(self) -> Verdict {
        match self {
            Verdict::Allow => Verdict::Allow,
            _ => Verdict::Deny,
        }
    }

    pub fn is_allow(self) -> bool {
        matches!(self, Verdict::Allow)
    }
}

/// Stable field identifiers for the `file_open` hook. The kernel program
/// extracts exactly these from `struct file`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FieldId {
    Path = 0,
    Op = 1,
}

impl FieldId {
    /// The Rego `input.*` path this hook field binds to.
    pub fn input_path(self) -> &'static str {
        match self {
            FieldId::Path => "input.path",
            FieldId::Op => "input.op",
        }
    }

    pub fn from_input_path(path: &str) -> Option<FieldId> {
        match path {
            "input.path" => Some(FieldId::Path),
            "input.op" => Some(FieldId::Op),
            _ => None,
        }
    }
}

/// File access operation. The kernel derives this from `file->f_mode`; the
/// exporter maps a policy's `input.op` string to one of these. An unknown
/// string makes the clause non-lowerable (fail-closed).
///
/// The `u8` discriminants are the on-the-wire ABI shared with the kernel rule
/// table (`OP_READ` / `OP_WRITE` / `OP_EXEC` in `bpf/file_open.bpf.c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileOp {
    Read = 0,
    Write = 1,
    Exec = 2,
}

impl FileOp {
    pub fn from_name(name: &str) -> Option<FileOp> {
        match name {
            "read" => Some(FileOp::Read),
            "write" => Some(FileOp::Write),
            "exec" => Some(FileOp::Exec),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A concrete `file_open` request, as the kernel extracts it from the hook
/// context. A `None` field models an extraction failure (an unobservable,
/// missing, or wrongly-typed field); any rule that constrains such a field
/// cannot match, so the request can only be denied (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Request {
    pub path: Option<String>,
    pub op: Option<FileOp>,
}

/// Maximum number of rule-table rows the fixed enforcer scans. The kernel
/// program uses a bounded loop of this size; the exporter rejects a plan that
/// would exceed it (fail-closed: an un-exportable allow stays in user space).
pub const MAX_RULES: usize = 64;

/// The number of leading path bytes the *kernel* program can compare against a
/// rule's bounded prefix/exact pattern. A prefix or exact pattern longer than
/// this cannot be verified soundly in-kernel and the kernel program treats such
/// a rule as a non-match (fail-closed). The user-space reference enforcer
/// ([`crate::enforcer`]) is unbounded and is the conformance reference; this
/// constant only documents the kernel's Phase-2 limitation.
pub const MAX_PATH_PREFIX: usize = 256;
