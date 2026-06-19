// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script: compile the kernel-side `regorus-bpf-ebpf` crate to a BPF ELF
//! using `aya-build`, and place the artifact in `OUT_DIR/regorus-egress` so the
//! loader can `include_bytes_aligned!` it.
//!
//! This requires a nightly toolchain with `rust-src` and `bpf-linker` on PATH.
//! It only runs when this loader crate is built (which is excluded from the main
//! workspace), so the default host test suite never pays this cost.

use aya_build::{build_ebpf, Package, Toolchain};

fn main() {
    let ebpf = Package {
        name: "regorus-bpf-ebpf",
        root_dir: concat!(env!("CARGO_MANIFEST_DIR"), "/../ebpf"),
        no_default_features: false,
        features: &[],
    };

    if let Err(err) = build_ebpf([ebpf], Toolchain::default()) {
        // Surface a clear message; the ebpf build needs nightly + bpf-linker.
        panic!(
            "failed to build regorus-bpf-ebpf (need nightly toolchain with \
             rust-src and bpf-linker on PATH): {err:?}"
        );
    }
}
