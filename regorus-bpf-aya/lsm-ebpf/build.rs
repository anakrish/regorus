// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resolve the byte offsets of `struct file::f_path` and `struct file::f_mode`
//! from the build host's kernel BTF and emit them as compile-time env vars
//! (`F_PATH_OFFSET`, `F_MODE_OFFSET`).
//!
//! Pure-Rust aya-ebpf cannot emit clang-style CO-RE field relocations (Rust has
//! no `preserve_access_index`), so the program reads these two kernel-struct
//! fields at offsets fixed at build time. Baking them from the build host's
//! `/sys/kernel/btf/vmlinux` makes the result correct for the kernel it is
//! built on (the common case: build and run on the same host). When BTF or
//! `bpftool` is unavailable we fall back to the standard x86_64 offsets and emit
//! a build warning.

use std::process::Command;

// Standard offsets on modern x86_64 kernels (see the struct file BTF layout):
//   f_mode at byte 4, f_path at byte 64.
const DEFAULT_F_MODE_OFFSET: u32 = 4;
const DEFAULT_F_PATH_OFFSET: u32 = 64;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=/sys/kernel/btf/vmlinux");

    let (f_mode, f_path) = resolve_offsets().unwrap_or_else(|| {
        println!(
            "cargo:warning=could not resolve struct file offsets from BTF; \
             falling back to x86_64 defaults (f_mode={DEFAULT_F_MODE_OFFSET}, \
             f_path={DEFAULT_F_PATH_OFFSET}). The lsm program may misread fields \
             on a kernel with a different layout."
        );
        (DEFAULT_F_MODE_OFFSET, DEFAULT_F_PATH_OFFSET)
    });

    println!("cargo:rustc-env=F_MODE_OFFSET={f_mode}");
    println!("cargo:rustc-env=F_PATH_OFFSET={f_path}");
}

/// Parse `bpftool btf dump` output to find the `f_mode` and `f_path` bit offsets
/// inside `struct file`, returning their **byte** offsets.
fn resolve_offsets() -> Option<(u32, u32)> {
    let out = Command::new("bpftool")
        .args([
            "btf",
            "dump",
            "file",
            "/sys/kernel/btf/vmlinux",
            "format",
            "raw",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;

    // Find the line `[N] STRUCT 'file' size=... vlen=...`, then scan its member
    // lines (which follow, indented) until the next top-level `[` entry.
    let mut in_file = false;
    let mut f_mode: Option<u32> = None;
    let mut f_path: Option<u32> = None;

    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('[') && trimmed.contains("STRUCT 'file'") {
            in_file = true;
            continue;
        }
        if in_file {
            // A new top-level type entry ends the struct's member list.
            if trimmed.starts_with('[') {
                break;
            }
            if let Some(off) = member_bits_offset(trimmed, "f_mode") {
                f_mode = Some(off / 8);
            }
            if let Some(off) = member_bits_offset(trimmed, "f_path") {
                f_path = Some(off / 8);
            }
        }
        if f_mode.is_some() && f_path.is_some() {
            break;
        }
    }

    Some((f_mode?, f_path?))
}

/// If `line` is the member named `name`, return its `bits_offset` value.
/// Example line: `'f_path' type_id=1026 bits_offset=512`.
fn member_bits_offset(line: &str, name: &str) -> Option<u32> {
    let needle = format!("'{name}'");
    if !line.starts_with(&needle) {
        return None;
    }
    let marker = "bits_offset=";
    let idx = line.find(marker)? + marker.len();
    let rest = &line[idx..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse::<u32>().ok()
}
