// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script: compile the kernel-side `regorus-bpf-lsm-ebpf` crate to a BPF
//! ELF using `aya-build`, placing the artifact in `OUT_DIR/regorus-file-open`.
//!
//! Requires a nightly toolchain with `rust-src` and `bpf-linker` on PATH. Only
//! runs when this loader crate is built (excluded from the main workspace).

use aya_build::{build_ebpf, Package, Toolchain};

fn main() {
    let ebpf = Package {
        name: "regorus-bpf-lsm-ebpf",
        root_dir: concat!(env!("CARGO_MANIFEST_DIR"), "/../lsm-ebpf"),
        no_default_features: false,
        features: &[],
    };

    if let Err(err) = build_ebpf([ebpf], Toolchain::default()) {
        panic!(
            "failed to build regorus-bpf-lsm-ebpf (need nightly toolchain with \
             rust-src and bpf-linker on PATH): {err:?}"
        );
    }
}
