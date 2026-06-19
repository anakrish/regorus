// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Kernel-side aya eBPF `lsm/file_open` access enforcer for `regorus-bpf-lsm`.
//!
//! Rust replacement for the hand-written `regorus-bpf-lsm/bpf/file_open.bpf.c`.
//! It is a **fixed** program: policy is data, not code. The user-space loader
//! (`regorus-bpf-lsm-loader`) serialises a `regorus-lift` `EnforcerConfig` into
//! the rule table this program scans.
//!
//! The rule layout and the per-rule matcher are imported from
//! [`regorus_bpf_lsm_common`] — the **same** code the user-space loader uses to
//! fill the maps. No second hand-maintained struct; the ABI cannot drift.
//!
//! Behaviour (mirrors the user-space reference `regorus_bpf_lsm::enforce`):
//!   * extract a bounded, non-canonical path (`bpf_d_path`) and the access op
//!     (read/write/exec from `file->f_mode`),
//!   * scan up to `MAX_RULES` rule rows,
//!   * ALLOW iff some rule's full conjunction matches; otherwise UNDECIDED,
//!     which collapses to DENY -> return `-EPERM` (block the open).
//!
//! # Field access (Phase-2 caveat)
//!
//! Pure-Rust aya-ebpf cannot emit clang-style CO-RE field relocations, so the
//! two `struct file` fields we read (`f_path`, `f_mode`) are accessed at offsets
//! baked at build time from the build host's BTF (see `build.rs`). This is
//! correct for the kernel the program is built on. The path read is bounded and
//! non-canonical exactly as in the C version; the user-space enforcer remains
//! the conformance reference.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::path,
    helpers::{bpf_probe_read_kernel, gen::bpf_d_path},
    macros::{lsm, map},
    maps::{Array, PerCpuArray},
    programs::LsmContext,
};
use regorus_bpf_lsm_common::{op_from_fmode, FileRule, MAX_PATH_PREFIX, MAX_RULES, VERDICT_ALLOW};

/// Byte offsets of `struct file` fields, resolved from BTF by `build.rs`.
const F_PATH_OFFSET: usize = parse_usize(env!("F_PATH_OFFSET"));
const F_MODE_OFFSET: usize = parse_usize(env!("F_MODE_OFFSET"));

/// `const`-evaluable decimal parse for the build-script-provided offsets.
const fn parse_usize(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut acc: usize = 0;
    let mut i = 0;
    while i < bytes.len() {
        acc = acc * 10 + (bytes[i] - b'0') as usize;
        i += 1;
    }
    acc
}

/// `-EPERM`: deny the open.
const EPERM: i32 = 1;

/// The rule table, populated by user space from the serialised `PodFilePlan`.
#[map]
static FILE_RULES: Array<FileRule> = Array::with_max_entries(MAX_RULES as u32, 0);

/// Number of populated rule rows (index 0). Rows `[0, count)` are live.
#[map]
static FILE_RULE_COUNT: Array<u32> = Array::with_max_entries(1, 0);

/// Control map: when value `== 0`, enforcement is disabled (fail-open opt-in).
#[map]
static FILE_ENABLED: Array<u32> = Array::with_max_entries(1, 0);

/// Per-CPU scratch buffer to read the bounded path into (the stack is too small
/// for `MAX_PATH_PREFIX`).
#[map]
static FILE_PATH_SCRATCH: PerCpuArray<[u8; MAX_PATH_PREFIX]> = PerCpuArray::with_max_entries(1, 0);

/// `lsm/file_open` entry point. Returns `0` to permit the open, `-EPERM` to
/// block it.
#[lsm(hook = "file_open")]
pub fn regorus_file_open(ctx: LsmContext) -> i32 {
    match unsafe { try_file_open(ctx) } {
        Ok(ret) => ret,
        // On any internal error, fail closed: block.
        Err(_) => -EPERM,
    }
}

unsafe fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    // file_open(struct file *file): arg 0 is the file pointer, arg 1 is the
    // prior LSM retval. Defer to a prior denial (good LSM hygiene).
    let file: *const u8 = ctx.arg(0);
    let prev_ret: i32 = ctx.arg(1);
    if prev_ret != 0 {
        return Ok(prev_ret);
    }
    if file.is_null() {
        return Err(-EPERM);
    }

    // Enforcement gate: when explicitly disabled, allow (fail-open opt-in).
    if let Some(enabled) = FILE_ENABLED.get(0) {
        if *enabled == 0 {
            return Ok(0);
        }
    }

    let buf_ptr = FILE_PATH_SCRATCH.get_ptr_mut(0).ok_or(-EPERM)?; // no scratch -> cannot evaluate -> fail closed
    let buf: &mut [u8; MAX_PATH_PREFIX] = &mut *buf_ptr;

    // Best-effort: read a bounded, NON-canonical path string. `&file->f_path`
    // is computed from the build-time field offset (no Rust CO-RE).
    let path_ptr = file.add(F_PATH_OFFSET) as *mut path;
    let ret = bpf_d_path(
        path_ptr,
        buf.as_mut_ptr() as *mut core::ffi::c_char,
        MAX_PATH_PREFIX as u32,
    );
    if ret <= 0 {
        return Err(-EPERM); // could not extract the path -> fail closed
    }

    // `ret` includes the trailing NUL; the byte length is ret - 1.
    let mut path_len = ret as u32;
    if path_len > 0 {
        path_len -= 1;
    }
    if path_len > MAX_PATH_PREFIX as u32 {
        path_len = MAX_PATH_PREFIX as u32;
    }

    // Read f_mode (u32) and classify the access op.
    let f_mode: u32 =
        bpf_probe_read_kernel(file.add(F_MODE_OFFSET) as *const u32).map_err(|_| -EPERM)?;
    let op = op_from_fmode(f_mode);

    let count = FILE_RULE_COUNT.get(0).copied().unwrap_or(0);
    let count = if (count as usize) > MAX_RULES {
        MAX_RULES as u32
    } else {
        count
    };

    // Bounded scan, matching `regorus_bpf_lsm_common::scan` (user-space form).
    let mut i: u32 = 0;
    while i < MAX_RULES as u32 {
        if i >= count {
            break;
        }
        if let Some(r) = FILE_RULES.get(i) {
            if r.matches(buf, path_len, Some(op)) {
                let _ = VERDICT_ALLOW;
                return Ok(0); // ALLOW -> permit the open
            }
        }
        i += 1;
    }

    // No rule matched: UNDECIDED -> DENY -> block the open.
    Err(-EPERM)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
