// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The stable enforcement ABI shared between the user-space reference enforcer
//! ([`crate::enforcer`]) and the kernel C program (`bpf/egress.bpf.c`).
//!
//! Both sides MUST agree on these layouts and constants byte-for-byte; the
//! conformance tests pin them.

/// Fail-closed verdict ABI. `Undecided` collapses to `Deny` at the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Verdict {
    Deny = 0,
    Allow = 1,
    Undecided = 2,
}

impl Verdict {
    /// Boundary collapse: `Undecided -> Deny`. The kernel hook adapter applies
    /// the same rule before converting to a hook-native return value.
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

/// Stable field identifiers for the connect4 hook. The kernel program extracts
/// exactly these from `bpf_sock_addr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FieldId {
    DestIp = 0,
    DestPort = 1,
    Proto = 2,
}

impl FieldId {
    /// The Rego `input.*` path this hook field binds to.
    pub fn input_path(self) -> &'static str {
        match self {
            FieldId::DestIp => "input.dest_ip",
            FieldId::DestPort => "input.dest_port",
            FieldId::Proto => "input.proto",
        }
    }

    pub fn from_input_path(path: &str) -> Option<FieldId> {
        match path {
            "input.dest_ip" => Some(FieldId::DestIp),
            "input.dest_port" => Some(FieldId::DestPort),
            "input.proto" => Some(FieldId::Proto),
            _ => None,
        }
    }
}

/// L4 protocol numbers (IANA / `IPPROTO_*`). The exporter maps a policy's
/// `input.proto` string to one of these; unknown strings make the clause
/// non-lowerable (fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Proto {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Sctp = 132,
}

impl Proto {
    pub fn from_name(name: &str) -> Option<Proto> {
        match name {
            "tcp" => Some(Proto::Tcp),
            "udp" => Some(Proto::Udp),
            "icmp" => Some(Proto::Icmp),
            "sctp" => Some(Proto::Sctp),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A concrete connect4 request, as the kernel extracts it from the hook context.
/// `dest_ip` is host-order IPv4; `None` fields model an extraction failure
/// (which in the kernel cannot happen for a real connection, but is used by the
/// conformance harness when a test input omits a field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Request {
    pub dest_ip: Option<u32>,
    pub dest_port: Option<u16>,
    pub proto: Option<u8>,
}

/// Maximum number of clause-table rows the fixed enforcer scans. The kernel
/// program uses a bounded loop of this size; the exporter rejects a plan that
/// would exceed it (fail-closed: an un-exportable allow stays in user space).
pub const MAX_CLAUSES: usize = 64;
