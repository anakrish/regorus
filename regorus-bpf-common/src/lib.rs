// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared enforcement ABI for the `regorus-bpf` aya egress backend.
//!
//! This crate is `#![no_std]` and dependency-free by default so the *exact
//! same* `#[repr(C)]` clause layout and matching logic can be compiled into:
//!
//!   * the kernel eBPF program (`regorus-bpf-ebpf`, target `bpfel-unknown-none`),
//!   * the user-space loader (`regorus-bpf-loader`, with the `user` feature for
//!     `aya::Pod`),
//!
//! eliminating the ABI-drift / over-permission risk of two hand-maintained
//! struct definitions (the previous C `struct clause_entry` and the Rust
//! `ClauseEntry` enum had to be kept in sync by comment).
//!
//! The byte layout of [`ClauseEntry`] mirrors the legacy C `struct clause_entry`
//! exactly (16 bytes, all integers HOST byte order), so the two backends remain
//! wire-compatible during the migration and the conformance tests can pin it.

#![no_std]

// ---------------------------------------------------------------------------
// Verdict ABI. `Undecided` collapses to `Deny` at the hook boundary.
// ---------------------------------------------------------------------------

/// Deny (and the boundary collapse target of `Undecided`).
pub const VERDICT_DENY: u8 = 0;
/// Allow.
pub const VERDICT_ALLOW: u8 = 1;
/// Undecided — collapses to `Deny` at the boundary (fail-closed).
pub const VERDICT_UNDECIDED: u8 = 2;

// ---------------------------------------------------------------------------
// Per-field match kinds.
// ---------------------------------------------------------------------------

/// `dest_ip` wildcard (matches anything, including a missing field).
pub const IP_ANY: u8 = 0;
/// `dest_ip` exact host-order IPv4.
pub const IP_EXACT: u8 = 1;
/// `dest_ip` IPv4 CIDR network + `prefix_len`.
pub const IP_CIDR: u8 = 2;

/// Scalar wildcard (matches anything, including a missing field).
pub const MATCH_ANY: u8 = 0;
/// Scalar exact value.
pub const MATCH_EXACT: u8 = 1;
/// Scalar inclusive range `[min, max]` — requires the field to be present.
pub const MATCH_RANGE: u8 = 2;

/// Maximum number of clause rows the fixed enforcer scans. The kernel program
/// uses a bounded loop of this size; the user-space exporter rejects a plan
/// that would exceed it (fail-closed).
pub const MAX_CLAUSES: usize = 64;

/// One compiled allow clause: a full conjunction over the three observable
/// connect4 fields. A request is allowed iff **every** field matches (a
/// wildcard matches anything). All integer values are HOST byte order.
///
/// The layout mirrors the legacy C `struct clause_entry` byte-for-byte (16
/// bytes) so the kernel and user-space halves share one definition.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClauseEntry {
    /// `IP_ANY` | `IP_EXACT` | `IP_CIDR`.
    pub ip_kind: u8,
    /// CIDR prefix length (`0..=32`), valid when `ip_kind == IP_CIDR`.
    pub prefix_len: u8,
    /// `MATCH_ANY` | `MATCH_EXACT` | `MATCH_RANGE`.
    pub port_kind: u8,
    /// `MATCH_ANY` | `MATCH_EXACT`.
    pub proto_kind: u8,
    /// Exact address or CIDR network (host order).
    pub ip_value: u32,
    /// Exact port (host order), valid when `port_kind == MATCH_EXACT`.
    pub port_value: u16,
    /// Inclusive low bound, valid when `port_kind == MATCH_RANGE`.
    pub port_min: u16,
    /// Inclusive high bound, valid when `port_kind == MATCH_RANGE`.
    pub port_max: u16,
    /// Exact `IPPROTO_*`, valid when `proto_kind == MATCH_EXACT`.
    pub proto_value: u8,
    /// Explicit padding to a 16-byte, 4-byte-aligned layout.
    pub _pad: u8,
}

impl ClauseEntry {
    /// A clause that matches nothing (every field exact-matches an impossible
    /// sentinel is overkill; instead use a deny-everything wildcard guard in
    /// the caller). Provided as a zeroed default for map initialisation.
    pub const fn zeroed() -> Self {
        ClauseEntry {
            ip_kind: IP_ANY,
            prefix_len: 0,
            port_kind: MATCH_ANY,
            proto_kind: MATCH_ANY,
            ip_value: 0,
            port_value: 0,
            port_min: 0,
            port_max: 0,
            proto_value: 0,
            _pad: 0,
        }
    }

    /// True iff this clause's full conjunction matches the request.
    ///
    /// Each field is an `Option`: `None` models a missing/unextractable field.
    /// A constrained field (anything but the `*_ANY` wildcard) never matches a
    /// `None` value — fail-closed, mirroring a Rego comparison over a missing
    /// field. In the kernel every field is always `Some`, so this collapses to
    /// the present-value path there.
    #[inline(always)]
    pub fn matches(&self, ip: Option<u32>, port: Option<u16>, proto: Option<u8>) -> bool {
        self.ip_matches(ip) && self.port_matches(port) && self.proto_matches(proto)
    }

    #[inline(always)]
    fn ip_matches(&self, ip: Option<u32>) -> bool {
        match self.ip_kind {
            IP_ANY => true,
            IP_EXACT => ip == Some(self.ip_value),
            IP_CIDR => match ip {
                Some(addr) => cidr_contains(self.ip_value, self.prefix_len, addr),
                None => false,
            },
            _ => false,
        }
    }

    #[inline(always)]
    fn port_matches(&self, port: Option<u16>) -> bool {
        match self.port_kind {
            MATCH_ANY => true,
            MATCH_EXACT => port == Some(self.port_value),
            MATCH_RANGE => match port {
                Some(p) => p >= self.port_min && p <= self.port_max,
                None => false,
            },
            _ => false,
        }
    }

    #[inline(always)]
    fn proto_matches(&self, proto: Option<u8>) -> bool {
        match self.proto_kind {
            MATCH_ANY => true,
            MATCH_EXACT => proto == Some(self.proto_value),
            _ => false,
        }
    }
}

/// Host-order IPv4 CIDR containment. `prefix_len == 0` matches everything;
/// `prefix_len > 32` matches nothing (fail-closed on a malformed entry).
#[inline(always)]
pub fn cidr_contains(network: u32, prefix_len: u8, addr: u32) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len > 32 {
        return false;
    }
    let mask: u32 = u32::MAX << (32 - prefix_len as u32);
    (addr & mask) == (network & mask)
}

/// Scan the first `count` clauses and return the verdict.
///
/// `Allow` iff some clause's full conjunction matches; otherwise `Undecided`
/// (which the caller collapses to `Deny` at the boundary). `count` is clamped
/// to the slice length and to [`MAX_CLAUSES`]. This is the user-space form (a
/// slice loop); the kernel program runs an equivalent bounded loop over its
/// `Array` map, calling [`ClauseEntry::matches`] per row.
pub fn scan(
    clauses: &[ClauseEntry],
    count: usize,
    ip: Option<u32>,
    port: Option<u16>,
    proto: Option<u8>,
) -> u8 {
    let n = count.min(clauses.len()).min(MAX_CLAUSES);
    let mut i = 0;
    while i < n {
        if clauses[i].matches(ip, port, proto) {
            return VERDICT_ALLOW;
        }
        i += 1;
    }
    VERDICT_UNDECIDED
}

// SAFETY: `ClauseEntry` is `#[repr(C)]`, contains only fixed-size unsigned
// integer fields with explicit padding, has no invalid bit patterns, and
// requires no Drop. It is therefore valid to read/write as raw bytes, which is
// exactly aya's `Pod` contract for a BPF map value.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ClauseEntry {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_16_bytes_aligned_4() {
        assert_eq!(core::mem::size_of::<ClauseEntry>(), 16);
        assert_eq!(core::mem::align_of::<ClauseEntry>(), 4);
    }

    #[test]
    fn wildcard_matches_anything_including_missing() {
        let c = ClauseEntry::zeroed();
        assert!(c.matches(Some(1), Some(2), Some(3)));
        assert!(c.matches(None, None, None));
    }

    #[test]
    fn exact_requires_present_value() {
        let c = ClauseEntry {
            ip_kind: IP_EXACT,
            ip_value: 0x0a00_0001,
            port_kind: MATCH_EXACT,
            port_value: 443,
            proto_kind: MATCH_EXACT,
            proto_value: 6,
            ..ClauseEntry::zeroed()
        };
        assert!(c.matches(Some(0x0a00_0001), Some(443), Some(6)));
        assert!(!c.matches(None, Some(443), Some(6)));
        assert!(!c.matches(Some(0x0a00_0001), None, Some(6)));
        assert!(!c.matches(Some(0x0a00_0001), Some(443), None));
        assert!(!c.matches(Some(0x0a00_0002), Some(443), Some(6)));
    }

    #[test]
    fn range_requires_present_and_in_bounds() {
        let c = ClauseEntry {
            port_kind: MATCH_RANGE,
            port_min: 1024,
            port_max: 2048,
            ..ClauseEntry::zeroed()
        };
        assert!(c.matches(None, Some(1024), None));
        assert!(c.matches(None, Some(2048), None));
        assert!(!c.matches(None, Some(1023), None));
        assert!(!c.matches(None, Some(2049), None));
        assert!(!c.matches(None, None, None));
    }

    #[test]
    fn cidr_containment() {
        // 10.0.0.0/8
        let c = ClauseEntry {
            ip_kind: IP_CIDR,
            prefix_len: 8,
            ip_value: 0x0a00_0000,
            ..ClauseEntry::zeroed()
        };
        assert!(c.matches(Some(0x0a01_0203), None, None));
        assert!(!c.matches(Some(0x0b00_0001), None, None));
        assert!(!c.matches(None, None, None));
        // prefix 0 matches everything
        let any = ClauseEntry {
            ip_kind: IP_CIDR,
            prefix_len: 0,
            ip_value: 0,
            ..ClauseEntry::zeroed()
        };
        assert!(any.matches(Some(0xdead_beef), None, None));
    }

    #[test]
    fn scan_allows_on_first_match_else_undecided() {
        let clauses = [
            ClauseEntry {
                ip_kind: IP_EXACT,
                ip_value: 1,
                ..ClauseEntry::zeroed()
            },
            ClauseEntry {
                ip_kind: IP_EXACT,
                ip_value: 2,
                ..ClauseEntry::zeroed()
            },
        ];
        assert_eq!(scan(&clauses, 2, Some(2), None, None), VERDICT_ALLOW);
        assert_eq!(scan(&clauses, 2, Some(3), None, None), VERDICT_UNDECIDED);
        // count clamps: row 1 (ip==2) is ignored when count==1
        assert_eq!(scan(&clauses, 1, Some(2), None, None), VERDICT_UNDECIDED);
    }
}
