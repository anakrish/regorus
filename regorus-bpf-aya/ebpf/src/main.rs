// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Kernel-side aya eBPF `cgroup/connect4` egress enforcer for `regorus-bpf`.
//!
//! This is the Rust replacement for the hand-written `regorus-bpf/bpf/egress.bpf.c`.
//! It is a **fixed** program: policy is data, not code. The user-space loader
//! (`regorus-bpf-loader`) serialises a `regorus-lift` `EnforcerConfig` into the
//! clause table this program scans; the program merely evaluates that table.
//!
//! Crucially, the clause layout and the per-clause matcher are imported from
//! [`regorus_bpf_common`] — the **same** code the user-space loader uses to fill
//! the maps. There is no second hand-maintained struct: the ABI cannot drift.
//!
//! Behaviour (mirrors the user-space reference `regorus_bpf::enforce`):
//!   * extract `dest_ip` / `dest_port` / `proto` from the connect4 context,
//!   * scan up to `MAX_CLAUSES` clause rows,
//!   * ALLOW iff some clause's full conjunction matches; otherwise UNDECIDED,
//!     which collapses to DENY at the boundary (return 0 = block).
//!
//! Map values are HOST byte order (matching the Rust user-space side); the
//! context fields are network byte order and converted with `u32::from_be` /
//! `u16::from_be`.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_sock_addr,
    macros::{cgroup_sock_addr, map},
    maps::Array,
    programs::SockAddrContext,
};
use regorus_bpf_common::{ClauseEntry, MAX_CLAUSES, VERDICT_ALLOW};

/// The clause table, populated by user space from the serialised `PodPlan`.
#[map]
static EGRESS_CLAUSES: Array<ClauseEntry> = Array::with_max_entries(MAX_CLAUSES as u32, 0);

/// Number of populated clause rows (index 0). Rows `[0, count)` are live.
#[map]
static EGRESS_CLAUSE_COUNT: Array<u32> = Array::with_max_entries(1, 0);

/// Single-entry control map: when value `== 0`, enforcement is disabled and the
/// program fails *open* (allow). This is an explicit opt-in for rollout; the
/// default (no entry / non-zero) is fail-closed enforcement.
#[map]
static EGRESS_ENABLED: Array<u32> = Array::with_max_entries(1, 0);

/// cgroup/connect4 entry point. Returns `1` to permit the connection, `0` to
/// block it (the cgroup connect4 convention).
#[cgroup_sock_addr(connect4)]
pub fn regorus_egress_connect4(ctx: SockAddrContext) -> i32 {
    match try_connect4(&ctx) {
        Ok(ret) => ret,
        // On any internal error, fail closed: block.
        Err(_) => 0,
    }
}

fn try_connect4(ctx: &SockAddrContext) -> Result<i32, i32> {
    // Enforcement gate: when explicitly disabled, allow (fail-open opt-in).
    if let Some(enabled) = EGRESS_ENABLED.get(0) {
        if *enabled == 0 {
            return Ok(1);
        }
    }

    // SAFETY: for cgroup_sock_addr programs the context pointer and its fields
    // are directly readable by the verifier; `sock_addr` is a valid pointer for
    // the duration of the program.
    let sa: &bpf_sock_addr = unsafe { &*ctx.sock_addr };

    // Context fields are network byte order; the clause table is host order.
    let dest_ip = u32::from_be(sa.user_ip4);
    let dest_port = u16::from_be((sa.user_port & 0xffff) as u16);
    let proto = (sa.protocol & 0xff) as u8;

    let count = EGRESS_CLAUSE_COUNT.get(0).copied().unwrap_or(0);
    let count = if (count as usize) > MAX_CLAUSES {
        MAX_CLAUSES as u32
    } else {
        count
    };

    // Bounded scan, matching `regorus_bpf_common::scan` (the user-space form).
    let mut i: u32 = 0;
    while i < MAX_CLAUSES as u32 {
        if i >= count {
            break;
        }
        if let Some(c) = EGRESS_CLAUSES.get(i) {
            if c.matches(Some(dest_ip), Some(dest_port), Some(proto)) {
                // VERDICT_ALLOW -> permit.
                let _ = VERDICT_ALLOW;
                return Ok(1);
            }
        }
        i += 1;
    }

    // No clause matched: UNDECIDED -> collapses to DENY at the boundary.
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // The verifier rejects unbounded loops; `loop {}` is the conventional eBPF
    // panic handler. It is unreachable in a verified program.
    loop {}
}
