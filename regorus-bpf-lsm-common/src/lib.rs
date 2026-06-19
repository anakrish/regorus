// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared enforcement ABI for the `regorus-bpf-lsm` aya `file_open` backend.
//!
//! Like `regorus-bpf-common` (the egress sibling), this crate is `#![no_std]`
//! and dependency-free by default so the *exact same* `#[repr(C)]` rule layout
//! and matching logic compile into both:
//!
//!   * the kernel eBPF program (`regorus-bpf-lsm-aya/ebpf`, `bpfel-unknown-none`),
//!   * the user-space loader (`regorus-bpf-lsm-aya/loader`, `user` feature for
//!     `aya::Pod`),
//!
//! eliminating the ABI-drift / over-permission risk of two hand-maintained
//! struct definitions (the previous C `struct file_rule` and the Rust
//! `FileRule` enum had to be kept in sync by comment).
//!
//! The byte layout of [`FileRule`] mirrors the legacy C `struct file_rule`
//! exactly (264 bytes), so the conformance tests can pin it.
//!
//! # Bounded, best-effort path matching (Phase-2 caveat — preserved)
//!
//! The kernel reads a **bounded, non-canonical** path prefix
//! (`bpf_d_path`, at most [`MAX_PATH_PREFIX`] bytes). The matcher here mirrors
//! that exactly: an `Exact` match requires equal length *and* equal bytes; a
//! `Prefix` match requires the path to be at least as long and share the
//! leading bytes; a pattern longer than [`MAX_PATH_PREFIX`] is a **non-match**
//! (fail-closed, never a truncated over-permissive match). Canonicalization
//! stays in user space; the unbounded user-space reference enforcer
//! (`regorus_bpf_lsm::enforce`) remains the conformance reference.

#![no_std]

// ---------------------------------------------------------------------------
// Verdict ABI. `Undecided` collapses to `Deny` at the hook boundary.
// For the LSM hook: ALLOW -> return 0 (permit), else -> return -EPERM (block).
// ---------------------------------------------------------------------------

pub const VERDICT_DENY: u8 = 0;
pub const VERDICT_ALLOW: u8 = 1;
pub const VERDICT_UNDECIDED: u8 = 2;

// ---------------------------------------------------------------------------
// Per-field match kinds.
// ---------------------------------------------------------------------------

/// `input.path` wildcard (matches anything, including a missing path).
pub const PATH_ANY: u8 = 0;
/// `input.path` exact match (equal length + equal bytes).
pub const PATH_EXACT: u8 = 1;
/// `input.path` leading-byte prefix match.
pub const PATH_PREFIX: u8 = 2;

/// `input.op` wildcard.
pub const OP_MATCH_ANY: u8 = 0;
/// `input.op` exact match.
pub const OP_MATCH_EXACT: u8 = 1;

/// File operation values (mirror `regorus_bpf_lsm::abi::FileOp`).
pub const OP_READ: u8 = 0;
pub const OP_WRITE: u8 = 1;
pub const OP_EXEC: u8 = 2;

/// `FMODE_*` bits from `include/linux/fs.h` (stable UAPI-adjacent constants).
pub const FMODE_READ_BIT: u32 = 0x1;
pub const FMODE_WRITE_BIT: u32 = 0x2;
pub const FMODE_EXEC_BIT: u32 = 0x20;

/// Classify a `struct file::f_mode` value into an access op. Exec is the most
/// restrictive intent and is classified first, then write, else read. This is
/// the single shared definition used by the kernel program (and pinned by a
/// unit test) so the C-era classification cannot drift.
#[inline(always)]
pub fn op_from_fmode(f_mode: u32) -> u8 {
    if f_mode & FMODE_EXEC_BIT != 0 {
        OP_EXEC
    } else if f_mode & FMODE_WRITE_BIT != 0 {
        OP_WRITE
    } else {
        OP_READ
    }
}

/// Maximum number of rule rows the fixed enforcer scans.
pub const MAX_RULES: usize = 64;

/// The number of leading path bytes the kernel program can compare. A pattern
/// or path longer than this cannot be verified soundly in-kernel and is treated
/// as a non-match (fail-closed).
pub const MAX_PATH_PREFIX: usize = 256;

/// One compiled allow rule: a full conjunction over the two observable
/// `file_open` fields. A request is allowed iff **both** fields match (a
/// wildcard matches anything).
///
/// The layout mirrors the legacy C `struct file_rule` byte-for-byte (264
/// bytes): a 4-byte header (`path_kind`, `op_kind`, `op_value`, `_pad`), a
/// `u32` `pattern_len`, then a fixed [`MAX_PATH_PREFIX`]-byte `pattern` buffer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileRule {
    /// `PATH_ANY` | `PATH_EXACT` | `PATH_PREFIX`.
    pub path_kind: u8,
    /// `OP_MATCH_ANY` | `OP_MATCH_EXACT`.
    pub op_kind: u8,
    /// `OP_READ` | `OP_WRITE` | `OP_EXEC`, valid when `op_kind == OP_MATCH_EXACT`.
    pub op_value: u8,
    /// Explicit padding to a 4-byte boundary.
    pub _pad: u8,
    /// Length of the path pattern in bytes (`<= MAX_PATH_PREFIX`).
    pub pattern_len: u32,
    /// The path pattern bytes (exact or prefix); only the first `pattern_len`
    /// bytes are significant.
    pub pattern: [u8; MAX_PATH_PREFIX],
}

impl FileRule {
    /// A zeroed rule (`PATH_ANY` + `OP_MATCH_ANY` = match everything). Used as a
    /// default for map initialisation and for a static-`Allow` wildcard.
    pub const fn zeroed() -> Self {
        FileRule {
            path_kind: PATH_ANY,
            op_kind: OP_MATCH_ANY,
            op_value: 0,
            _pad: 0,
            pattern_len: 0,
            pattern: [0u8; MAX_PATH_PREFIX],
        }
    }

    /// True iff this rule's full conjunction matches the request.
    ///
    /// `path` is the bounded path buffer; `path_len` its valid byte length
    /// (clamped to [`MAX_PATH_PREFIX`] by the caller). `op` is `None` when the
    /// operation could not be extracted (a constrained `op` then cannot match —
    /// fail-closed; in the kernel `op` is always `Some`).
    #[inline(always)]
    pub fn matches(&self, path: &[u8; MAX_PATH_PREFIX], path_len: u32, op: Option<u8>) -> bool {
        self.path_matches(path, path_len) && self.op_matches(op)
    }

    #[inline(always)]
    pub fn path_matches(&self, path: &[u8; MAX_PATH_PREFIX], path_len: u32) -> bool {
        let plen = self.pattern_len;

        if self.path_kind == PATH_ANY {
            return true;
        }

        // A pattern we could not fully store cannot be verified soundly.
        if plen == 0 || plen as usize > MAX_PATH_PREFIX {
            return false;
        }

        match self.path_kind {
            PATH_EXACT => {
                // Exact requires equal length AND equal bytes; otherwise a
                // longer path sharing a prefix could masquerade as the pattern.
                if path_len != plen {
                    return false;
                }
                bytes_equal(path, &self.pattern, plen)
            }
            PATH_PREFIX => {
                // The path must be at least as long as the prefix and share it.
                if path_len < plen {
                    return false;
                }
                bytes_equal(path, &self.pattern, plen)
            }
            _ => false,
        }
    }

    #[inline(always)]
    pub fn op_matches(&self, op: Option<u8>) -> bool {
        match self.op_kind {
            OP_MATCH_ANY => true,
            OP_MATCH_EXACT => op == Some(self.op_value),
            _ => false,
        }
    }
}

/// Bounded comparison of the first `n` bytes of `a` and `b`. The loop is
/// statically bounded by [`MAX_PATH_PREFIX`] (verifier-friendly); `n` is clamped
/// to that bound by the caller.
#[inline(always)]
pub fn bytes_equal(a: &[u8; MAX_PATH_PREFIX], b: &[u8; MAX_PATH_PREFIX], n: u32) -> bool {
    let mut i: usize = 0;
    while i < MAX_PATH_PREFIX {
        if i as u32 >= n {
            break;
        }
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Scan the first `count` rules and return the verdict. `Allow` iff some rule's
/// full conjunction matches; otherwise `Undecided` (the caller collapses to
/// `Deny`). This is the user-space form; the kernel runs an equivalent bounded
/// loop over its `Array` map calling [`FileRule::matches`] per row.
pub fn scan(
    rules: &[FileRule],
    count: usize,
    path: &[u8; MAX_PATH_PREFIX],
    path_len: u32,
    op: Option<u8>,
) -> u8 {
    let n = count.min(rules.len()).min(MAX_RULES);
    let mut i = 0;
    while i < n {
        if rules[i].matches(path, path_len, op) {
            return VERDICT_ALLOW;
        }
        i += 1;
    }
    VERDICT_UNDECIDED
}

// SAFETY: `FileRule` is `#[repr(C)]`, contains only fixed-size unsigned integer
// fields and a fixed-size byte array with explicit padding, has no invalid bit
// patterns, and requires no Drop. It is therefore valid to read/write as raw
// bytes — exactly aya's `Pod` contract for a BPF map value.
#[cfg(feature = "user")]
unsafe impl aya::Pod for FileRule {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a fixed buffer from a byte slice (truncated to MAX_PATH_PREFIX).
    fn buf(s: &[u8]) -> ([u8; MAX_PATH_PREFIX], u32) {
        let mut b = [0u8; MAX_PATH_PREFIX];
        let n = s.len().min(MAX_PATH_PREFIX);
        b[..n].copy_from_slice(&s[..n]);
        (b, n as u32)
    }

    fn rule_exact(path: &[u8], op: Option<u8>) -> FileRule {
        let (pattern, pattern_len) = buf(path);
        FileRule {
            path_kind: PATH_EXACT,
            op_kind: op.map_or(OP_MATCH_ANY, |_| OP_MATCH_EXACT),
            op_value: op.unwrap_or(0),
            _pad: 0,
            pattern_len,
            pattern,
        }
    }

    fn rule_prefix(path: &[u8]) -> FileRule {
        let (pattern, pattern_len) = buf(path);
        FileRule {
            path_kind: PATH_PREFIX,
            op_kind: OP_MATCH_ANY,
            op_value: 0,
            _pad: 0,
            pattern_len,
            pattern,
        }
    }

    #[test]
    fn layout_is_264_bytes() {
        assert_eq!(core::mem::size_of::<FileRule>(), 264);
        assert_eq!(core::mem::align_of::<FileRule>(), 4);
    }

    #[test]
    fn wildcard_matches_anything() {
        let r = FileRule::zeroed();
        let (b, n) = buf(b"/anything");
        assert!(r.matches(&b, n, Some(OP_READ)));
        let (e, en) = buf(b"");
        assert!(r.matches(&e, en, None));
    }

    #[test]
    fn exact_requires_equal_length_and_bytes() {
        let r = rule_exact(b"/etc/passwd", Some(OP_READ));
        let (b, n) = buf(b"/etc/passwd");
        assert!(r.matches(&b, n, Some(OP_READ)));
        // wrong op
        assert!(!r.matches(&b, n, Some(OP_WRITE)));
        // longer path sharing the prefix must NOT match an exact rule
        let (b2, n2) = buf(b"/etc/passwd2");
        assert!(!r.matches(&b2, n2, Some(OP_READ)));
        // shorter prefix must not match
        let (b3, n3) = buf(b"/etc/pass");
        assert!(!r.matches(&b3, n3, Some(OP_READ)));
    }

    #[test]
    fn prefix_matches_longer_paths() {
        let r = rule_prefix(b"/var/log/");
        let (b, n) = buf(b"/var/log/syslog");
        assert!(r.matches(&b, n, Some(OP_WRITE)));
        let (b2, n2) = buf(b"/var/log/");
        assert!(r.matches(&b2, n2, None));
        // too short
        let (b3, n3) = buf(b"/var/lo");
        assert!(!r.matches(&b3, n3, None));
        // different prefix
        let (b4, n4) = buf(b"/var/tmp/x");
        assert!(!r.matches(&b4, n4, None));
    }

    #[test]
    fn scan_first_match_else_undecided() {
        let rules = [rule_exact(b"/a", Some(OP_READ)), rule_prefix(b"/b/")];
        let (b, n) = buf(b"/b/c");
        assert_eq!(scan(&rules, 2, &b, n, Some(OP_EXEC)), VERDICT_ALLOW);
        let (b2, n2) = buf(b"/z");
        assert_eq!(scan(&rules, 2, &b2, n2, Some(OP_READ)), VERDICT_UNDECIDED);
        // count clamps
        assert_eq!(scan(&rules, 1, &b, n, Some(OP_EXEC)), VERDICT_UNDECIDED);
    }

    #[test]
    fn op_from_fmode_classifies_exec_write_read() {
        assert_eq!(op_from_fmode(FMODE_EXEC_BIT), OP_EXEC);
        // exec takes precedence over write
        assert_eq!(op_from_fmode(FMODE_EXEC_BIT | FMODE_WRITE_BIT), OP_EXEC);
        assert_eq!(op_from_fmode(FMODE_WRITE_BIT), OP_WRITE);
        assert_eq!(op_from_fmode(FMODE_READ_BIT), OP_READ);
        assert_eq!(op_from_fmode(0), OP_READ);
    }
}
