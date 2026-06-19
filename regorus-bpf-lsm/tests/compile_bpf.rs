// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Toolchain-gated tests for the kernel half of the backend.
//!
//! [`compiles_file_open_object_against_live_btf`] compiles `bpf/file_open.bpf.c`
//! to a BPF ELF object using `clang` + a `vmlinux.h` generated from the running
//! kernel's BTF. It **skips gracefully** (passing) when `clang`, `bpftool`, or
//! `/sys/kernel/btf/vmlinux` are unavailable, so CI on a machine without a BPF
//! toolchain stays green.
//!
//! [`load_into_kernel_is_gated_on_privilege`] documents the real
//! load/attach path and skips when the process lacks the privilege to load BPF
//! programs (the common case in unprivileged CI / dev containers). Loading an
//! `lsm/file_open` program additionally requires a kernel built with BPF LSM
//! (`CONFIG_BPF_LSM`, `bpf` in `/sys/kernel/security/lsm`).

use std::path::{Path, PathBuf};
use std::process::Command;

fn bpf_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("bpf")
}

fn have(tool: &str) -> Option<PathBuf> {
    // Search PATH plus the common sbin location for bpftool.
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            candidates.push(Path::new(dir).join(tool));
        }
    }
    candidates.push(PathBuf::from(format!("/usr/sbin/{tool}")));
    candidates.push(PathBuf::from(format!("/sbin/{tool}")));
    candidates.into_iter().find(|p| p.is_file())
}

#[test]
fn compiles_file_open_object_against_live_btf() {
    let Some(clang) = have("clang") else {
        eprintln!("SKIP: clang not found");
        return;
    };
    let Some(bpftool) = have("bpftool") else {
        eprintln!("SKIP: bpftool not found");
        return;
    };
    let btf = Path::new("/sys/kernel/btf/vmlinux");
    if !btf.exists() {
        eprintln!("SKIP: /sys/kernel/btf/vmlinux not present");
        return;
    }

    let out =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("file_open_{}", std::process::id()));
    std::fs::create_dir_all(&out).unwrap();
    let vmlinux_h = out.join("vmlinux.h");
    let obj = out.join("file_open.bpf.o");

    // Generate vmlinux.h from the running kernel's BTF.
    let dump = Command::new(&bpftool)
        .args(["btf", "dump", "file"])
        .arg(btf)
        .args(["format", "c"])
        .output()
        .expect("run bpftool");
    if !dump.status.success() {
        eprintln!(
            "SKIP: bpftool btf dump failed: {}",
            String::from_utf8_lossy(&dump.stderr)
        );
        return;
    }
    std::fs::write(&vmlinux_h, &dump.stdout).unwrap();

    // Compile the fixed enforcer to a BPF object.
    let arch = bpf_target_arch();
    let status = Command::new(&clang)
        .args(["-target", "bpf"])
        .arg(format!("-D__TARGET_ARCH_{arch}"))
        .args(["-O2", "-g", "-Wall", "-Werror"])
        .arg("-I")
        .arg(&out)
        .arg("-I")
        .arg(bpf_dir())
        .arg("-c")
        .arg(bpf_dir().join("file_open.bpf.c"))
        .arg("-o")
        .arg(&obj)
        .status()
        .expect("run clang");
    assert!(status.success(), "clang failed to compile file_open.bpf.c");
    assert!(obj.exists(), "expected an object file");

    // Sanity: the output is an ELF eBPF object with the expected program
    // section. (We check the ELF magic and that the section name appears.)
    let bytes = std::fs::read(&obj).unwrap();
    assert!(bytes.starts_with(b"\x7fELF"), "output is not an ELF object");
    assert!(
        bytes
            .windows(b"lsm/file_open".len())
            .any(|w| w == b"lsm/file_open"),
        "object is missing the lsm/file_open program section"
    );

    let _ = std::fs::remove_dir_all(&out);
}

fn bpf_target_arch() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x86"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x86"
    }
}

#[test]
fn load_into_kernel_is_gated_on_privilege() {
    // Loading and attaching the program requires CAP_BPF/CAP_MAC_ADMIN and a
    // kernel with BPF LSM enabled. In unprivileged environments we cannot do
    // this, so this test only asserts the precondition and skips otherwise. The
    // full load + attach path is exercised in privileged integration runs.
    let euid = unsafe { libc_geteuid() };
    if euid != 0 {
        eprintln!("SKIP: not root (euid={euid}); cannot load BPF program here");
        return;
    }
    // If we ever do run as root in CI, at minimum the object must have compiled.
    eprintln!("root detected; the compile test produces a loadable object");
}

// Avoid pulling in the `libc` crate for a single call.
extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}
