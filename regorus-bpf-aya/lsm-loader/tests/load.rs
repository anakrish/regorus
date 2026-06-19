// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the file_open LSM loader.
//!
//! The privilege-free test exercises [`map_image`] serialisation. The gated
//! `#[ignore]` test additionally loads + binds the program; it requires
//! `CAP_BPF`/`CAP_MAC_ADMIN` and a kernel with BPF-LSM enabled at boot, and is
//! skipped (passes trivially) when those are absent.

use regorus_bpf_lsm::plan::{FileRule, OpMatch, PathMatch};
use regorus_bpf_lsm::{to_pod, FileOp, FilePlan, Verdict};
use regorus_bpf_lsm_common::{OP_READ, PATH_EXACT, PATH_PREFIX};
use regorus_bpf_lsm_loader::{map_image, FileEnforcer};

fn sample_plan() -> FilePlan {
    FilePlan {
        static_verdict: None,
        rules: vec![
            FileRule {
                path_match: PathMatch::Exact("/etc/hosts".to_string()),
                op_match: OpMatch::Exact(FileOp::Read),
            },
            FileRule {
                path_match: PathMatch::Prefix("/var/log/".to_string()),
                op_match: OpMatch::Any,
            },
        ],
    }
}

#[test]
fn map_image_serialises_rules_without_privilege() {
    let pod = to_pod(&sample_plan());
    let img = map_image(&pod);
    assert_eq!(img.count, 2);
    assert_eq!(img.enabled, 1);
    assert_eq!(img.rules[0].path_kind, PATH_EXACT);
    assert_eq!(img.rules[0].op_value, OP_READ);
    assert_eq!(&img.rules[0].pattern[..10], b"/etc/hosts");
    assert_eq!(img.rules[1].path_kind, PATH_PREFIX);
    assert_eq!(&img.rules[1].pattern[..9], b"/var/log/");
}

#[test]
fn static_allow_serialises_to_single_wildcard() {
    let pod = to_pod(&FilePlan {
        static_verdict: Some(Verdict::Allow),
        rules: vec![],
    });
    let img = map_image(&pod);
    assert_eq!(img.count, 1);
    assert_eq!(img.rules.len(), 1);
}

/// Privileged end-to-end: load the BPF ELF, populate maps, and bind to the
/// `file_open` LSM hook. Run with:
///   `sudo -E env "PATH=$PATH" cargo test --test load -- --ignored --nocapture`
/// Requires CONFIG_BPF_LSM + `lsm=...,bpf` at boot (`cat /sys/kernel/security/lsm`
/// should list `bpf`).
#[test]
#[ignore = "requires CAP_BPF/CAP_MAC_ADMIN and BPF-LSM enabled at boot"]
fn load_apply_bind_under_privilege() {
    let bpf_lsm_enabled = std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|s| s.split(',').any(|m| m.trim() == "bpf"))
        .unwrap_or(false);
    if !bpf_lsm_enabled {
        eprintln!("SKIP: BPF LSM not enabled at boot (no `bpf` in /sys/kernel/security/lsm)");
        return;
    }

    let mut enforcer = match FileEnforcer::load() {
        Ok(e) => e,
        Err(err) => {
            eprintln!("SKIP: cannot load BPF program (need CAP_BPF): {err:#}");
            return;
        }
    };

    let pod = to_pod(&sample_plan());
    enforcer.apply(&pod).expect("apply plan to maps");
    enforcer.bind().expect("bind lsm/file_open");
    eprintln!("OK: loaded + bound regorus file_open enforcer to lsm/file_open");
}
