// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! User-space aya loader for the `regorus-bpf-lsm` `lsm/file_open` enforcer.
//!
//! Responsibilities:
//!   1. load the kernel ELF (compiled from `regorus-bpf-lsm-ebpf` by `build.rs`),
//!   2. serialise a `regorus_bpf_lsm` [`FilePlan`]/[`PodFilePlan`] into the BPF
//!      maps (`FILE_RULES`, `FILE_RULE_COUNT`, `FILE_ENABLED`), using the
//!      **shared** `#[repr(C)]` [`FileRule`] layout (no second definition),
//!   3. bind the program to the kernel's `file_open` LSM hook so it enforces
//!      file-access policy system-wide.
//!
//! Loading + binding requires `CAP_BPF`/`CAP_MAC_ADMIN`, a kernel built with
//! `CONFIG_BPF_LSM=y`, and the BPF LSM enabled at boot (`lsm=...,bpf`). The
//! serialisation step ([`map_image`]) is privilege-free and is the part the
//! conformance tests exercise without root.
//!
//! [`FilePlan`]: regorus_bpf_lsm::FilePlan
//! [`PodFilePlan`]: regorus_bpf_lsm::PodFilePlan

use anyhow::{Context, Result};
use aya::maps::Array as BpfArray;
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfLoader};

use regorus_bpf_lsm::{FilePlan, PodFilePlan, Verdict};
use regorus_bpf_lsm_common::{FileRule, MAX_RULES};

/// The program function name (the `lsm/file_open` entry point).
const PROG_NAME: &str = "regorus_file_open";
/// The LSM hook this program binds to.
const HOOK: &str = "file_open";

/// The compiled kernel ELF, produced by `build.rs` via `aya-build`.
static FILE_OPEN_ELF: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/regorus-file-open"));

/// A plain, privilege-free image of what the loader will write into the maps.
#[derive(Clone)]
pub struct MapImage {
    /// The rule rows to write into `FILE_RULES` (length <= [`MAX_RULES`]).
    pub rules: Vec<FileRule>,
    /// The `FILE_RULE_COUNT` value (== `rules.len()`).
    pub count: u32,
    /// The `FILE_ENABLED` value (1 = enforce, 0 = fail-open).
    pub enabled: u32,
}

/// Translate a serialised [`PodFilePlan`] into the concrete map image.
///
/// `static_verdict` is folded into the rule table so the *fixed* kernel program
/// needs no special-casing:
///   * `Allow`            -> a single all-wildcard rule (matches everything),
///   * `Deny`/`Undecided` -> an empty table (nothing matches -> deny),
///   * `None`             -> the plan's rules verbatim.
pub fn map_image(plan: &PodFilePlan) -> MapImage {
    let rules: Vec<FileRule> = match plan.static_verdict {
        Some(Verdict::Allow) => vec![FileRule::zeroed()], // all-Any wildcard
        Some(Verdict::Deny) | Some(Verdict::Undecided) => Vec::new(),
        None => plan.rules.clone(),
    };
    let count = rules.len() as u32;
    MapImage {
        rules,
        count,
        enabled: 1,
    }
}

/// Convenience: lower a rich [`FilePlan`] straight to a [`MapImage`].
pub fn map_image_from_plan(plan: &FilePlan) -> MapImage {
    map_image(&regorus_bpf_lsm::to_pod(plan))
}

/// A loaded file-open enforcer. Holds the BPF objects alive; dropping it
/// detaches the program and frees the maps.
pub struct FileEnforcer {
    ebpf: Ebpf,
}

impl FileEnforcer {
    /// Build the privilege-free map image for a plan (no `CAP_BPF` needed).
    pub fn map_image(plan: &PodFilePlan) -> MapImage {
        map_image(plan)
    }

    /// Load the program into the kernel (requires `CAP_BPF` + BPF-LSM support).
    /// The program is loaded but not yet bound; call [`Self::apply`] to populate
    /// the maps and [`Self::bind`] to begin enforcing.
    pub fn load() -> Result<Self> {
        let mut ebpf = EbpfLoader::new()
            .load(FILE_OPEN_ELF)
            .context("loading regorus file_open BPF ELF")?;
        let btf = Btf::from_sys_fs().context("reading kernel BTF from /sys/kernel/btf/vmlinux")?;
        let prog: &mut Lsm = ebpf
            .program_mut(PROG_NAME)
            .with_context(|| format!("program {PROG_NAME} not found in ELF"))?
            .try_into()
            .context("program is not an Lsm program")?;
        prog.load(HOOK, &btf)
            .with_context(|| format!("loading lsm/{HOOK} program"))?;
        Ok(Self { ebpf })
    }

    /// Populate the maps from a plan (requires the program to be loaded).
    pub fn apply(&mut self, plan: &PodFilePlan) -> Result<()> {
        let image = map_image(plan);

        let mut rules: BpfArray<_, FileRule> =
            BpfArray::try_from(self.ebpf.map_mut("FILE_RULES").context("FILE_RULES")?)?;
        for (i, r) in image.rules.iter().enumerate() {
            rules
                .set(i as u32, *r, 0)
                .with_context(|| format!("set rule {i}"))?;
        }
        // Zero out any stale rows beyond the new count (defensive).
        for i in image.rules.len()..MAX_RULES {
            rules.set(i as u32, FileRule::zeroed(), 0).ok();
        }

        let mut count: BpfArray<_, u32> = BpfArray::try_from(
            self.ebpf
                .map_mut("FILE_RULE_COUNT")
                .context("FILE_RULE_COUNT")?,
        )?;
        count.set(0, image.count, 0).context("set rule count")?;

        let mut enabled: BpfArray<_, u32> =
            BpfArray::try_from(self.ebpf.map_mut("FILE_ENABLED").context("FILE_ENABLED")?)?;
        enabled.set(0, image.enabled, 0).context("set enabled")?;

        Ok(())
    }

    /// Bind the loaded program to the `file_open` LSM hook (system-wide).
    /// Requires `CAP_BPF`/`CAP_MAC_ADMIN` and BPF-LSM enabled at boot.
    pub fn bind(&mut self) -> Result<()> {
        let prog: &mut Lsm = self
            .ebpf
            .program_mut(PROG_NAME)
            .context("program not found")?
            .try_into()
            .context("program is not an Lsm program")?;
        prog.attach().context("binding lsm/file_open program")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use regorus_bpf_lsm::plan::{FileRule as RichRule, OpMatch, PathMatch};
    use regorus_bpf_lsm::to_pod;
    use regorus_bpf_lsm_common::{OP_READ, PATH_EXACT, PATH_PREFIX};

    #[test]
    fn static_allow_becomes_wildcard_rule() {
        let plan = to_pod(&FilePlan {
            static_verdict: Some(Verdict::Allow),
            rules: vec![],
        });
        let img = map_image(&plan);
        assert_eq!(img.count, 1);
        assert_eq!(img.enabled, 1);
        assert_eq!(img.rules.len(), 1);
        assert_eq!(img.rules[0].path_kind, regorus_bpf_lsm_common::PATH_ANY);
    }

    #[test]
    fn static_deny_becomes_empty_table() {
        for v in [Verdict::Deny, Verdict::Undecided] {
            let plan = to_pod(&FilePlan {
                static_verdict: Some(v),
                rules: vec![],
            });
            let img = map_image(&plan);
            assert_eq!(img.count, 0);
            assert!(img.rules.is_empty());
        }
    }

    #[test]
    fn rules_serialise_in_order() {
        let plan = to_pod(&FilePlan {
            static_verdict: None,
            rules: vec![
                RichRule {
                    path_match: PathMatch::Exact("/etc/hosts".to_string()),
                    op_match: OpMatch::Exact(regorus_bpf_lsm::FileOp::Read),
                },
                RichRule {
                    path_match: PathMatch::Prefix("/var/log/".to_string()),
                    op_match: OpMatch::Any,
                },
            ],
        });
        let img = map_image(&plan);
        assert_eq!(img.count, 2);
        assert_eq!(img.rules[0].path_kind, PATH_EXACT);
        assert_eq!(img.rules[0].op_value, OP_READ);
        assert_eq!(img.rules[1].path_kind, PATH_PREFIX);
        assert_eq!(&img.rules[1].pattern[..9], b"/var/log/");
    }
}
