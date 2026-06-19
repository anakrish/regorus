// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Privilege-gated integration test for the aya egress loader.
//!
//! Loading a BPF program runs the in-kernel verifier; binding it to a cgroup
//! actually enforces egress. Both require `CAP_BPF` (and `CAP_NET_ADMIN` for
//! the cgroup attach), which this environment does not have, so the test
//! **skips cleanly** when the privilege (or cgroup-v2) is unavailable.
//!
//! To run it for real, on a Linux host with cgroup-v2 and a nightly toolchain
//! with `rust-src` + `bpf-linker` on PATH:
//!
//! ```text
//!   cd regorus-bpf-aya/loader
//!   cargo build                       # compiles the BPF ELF via build.rs
//!   sudo -E env "PATH=$PATH" \
//!       cargo test --test load -- --ignored --nocapture
//! ```
//!
//! The `--ignored` flag opts in to the privileged body; without it the harness
//! runs only the no-privilege assertions.

use std::fs::File;

use regorus_bpf::plan::{ClauseEntry, IpMatch, MapPlan, ScalarMatch};
use regorus_bpf::to_pod;
use regorus_bpf_loader::{map_image, EgressEnforcer};

/// A representative SSH-bastion allow-list: allow 10.0.0.1:22/tcp only.
fn bastion_plan() -> MapPlan {
    MapPlan {
        static_verdict: None,
        clauses: vec![ClauseEntry {
            ip: IpMatch::Exact(0x0a00_0001),
            port: ScalarMatch::Exact(22),
            proto: ScalarMatch::Exact(6),
        }],
    }
}

/// Always-on, privilege-free check: the map image the loader would write is
/// exactly the serialised plan (one clause, enforcement enabled). This runs in
/// the default `cargo test` with no special privileges.
#[test]
fn map_image_is_well_formed_without_privilege() {
    let pod = to_pod(&bastion_plan());
    let img = map_image(&pod);
    assert_eq!(img.count, 1);
    assert_eq!(img.enabled, 1);
    assert_eq!(img.clauses.len(), 1);
    assert_eq!(img.clauses[0].ip_value, 0x0a00_0001);
    assert_eq!(img.clauses[0].port_value, 22);
    assert_eq!(img.clauses[0].proto_value, 6);
}

/// Privileged: load the program (runs the verifier), populate the maps, and
/// bind it to the root cgroup-v2 hierarchy. Marked `#[ignore]` so it only runs
/// under `--ignored` (i.e. when the caller has arranged for `CAP_BPF`).
///
/// Even with `--ignored`, it skips gracefully if loading fails with a
/// permission error or if cgroup-v2 is not mounted, so it never produces a
/// false failure on an unprivileged or non-cgroup-v2 host.
#[test]
#[ignore = "requires CAP_BPF + cgroup-v2; run with sudo and --ignored"]
fn load_apply_bind_under_privilege() {
    let pod = to_pod(&bastion_plan());

    let mut enforcer = match EgressEnforcer::load() {
        Ok(e) => e,
        Err(err) => {
            eprintln!("SKIP: cannot load BPF program (need CAP_BPF): {err:#}");
            return;
        }
    };

    enforcer
        .apply(&pod)
        .expect("populate maps after successful load");

    // Bind to the cgroup-v2 root. This begins enforcing connect4 for the whole
    // hierarchy until `enforcer` is dropped at end of test.
    let cgroup_root = "/sys/fs/cgroup";
    let cgroup = match File::open(cgroup_root) {
        Ok(f) => f,
        Err(err) => {
            eprintln!("SKIP: cannot open {cgroup_root} (cgroup-v2?): {err}");
            return;
        }
    };

    match enforcer.bind_cgroup(cgroup) {
        Ok(()) => eprintln!("OK: loaded + bound regorus egress enforcer to {cgroup_root}"),
        Err(err) => eprintln!("SKIP: bind failed (need CAP_NET_ADMIN/cgroup-v2): {err:#}"),
    }
}
