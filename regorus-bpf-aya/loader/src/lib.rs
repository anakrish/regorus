// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! User-space aya loader for the `regorus-bpf` cgroup/connect4 egress enforcer.
//!
//! Responsibilities:
//!   1. load the kernel ELF (compiled from `regorus-bpf-ebpf` by `build.rs`),
//!   2. serialise a `regorus_bpf` [`MapPlan`]/[`PodPlan`] into the BPF maps
//!      (`EGRESS_CLAUSES`, `EGRESS_CLAUSE_COUNT`, `EGRESS_ENABLED`), using the
//!      **shared** `#[repr(C)]` [`ClauseEntry`] layout (no second definition),
//!   3. bind the program to a cgroup so it enforces egress for that cgroup.
//!
//! Loading/binding requires `CAP_BPF` (+ `CAP_NET_ADMIN` for cgroup attach).
//! The serialisation step ([`EgressEnforcer::map_image`]) is privilege-free and
//! is the part the conformance tests exercise without root.
//!
//! [`MapPlan`]: regorus_bpf::MapPlan
//! [`PodPlan`]: regorus_bpf::PodPlan

use std::os::fd::AsFd;

use anyhow::{Context, Result};
use aya::maps::Array as BpfArray;
use aya::programs::{CgroupAttachMode, CgroupSockAddr};
use aya::{Ebpf, EbpfLoader};

use regorus_bpf::{MapPlan, PodPlan, Verdict};
use regorus_bpf_common::{ClauseEntry, MAX_CLAUSES};

/// The program function name (the `cgroup/connect4` entry point).
const PROG_NAME: &str = "regorus_egress_connect4";

/// The compiled kernel ELF, produced by `build.rs` via `aya-build`.
static EGRESS_ELF: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/regorus-egress"));

/// A plain, privilege-free image of what the loader will write into the maps.
/// Producing and asserting on this needs no `CAP_BPF`, so it is fully unit- and
/// conformance-testable without root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapImage {
    /// The clause rows to write into `EGRESS_CLAUSES` (length <= [`MAX_CLAUSES`]).
    pub clauses: Vec<ClauseEntry>,
    /// The `EGRESS_CLAUSE_COUNT` value (== `clauses.len()`).
    pub count: u32,
    /// The `EGRESS_ENABLED` value (1 = enforce, 0 = fail-open).
    pub enabled: u32,
}

/// Translate a serialised [`PodPlan`] into the concrete map image.
///
/// `static_verdict` is folded into the clause table so the *fixed* kernel
/// program needs no special-casing:
///   * `Allow`     -> a single all-wildcard clause (matches everything),
///   * `Deny`/`Undecided` -> an empty table (nothing matches -> deny),
///   * `None`      -> the plan's clauses verbatim.
///
/// Enforcement is always enabled (`enabled = 1`); fail-open is not selected
/// automatically — a static `Allow` is expressed as an explicit allow-all
/// clause so the verdict path is identical to a normal policy.
pub fn map_image(plan: &PodPlan) -> MapImage {
    let clauses: Vec<ClauseEntry> = match plan.static_verdict {
        Some(Verdict::Allow) => vec![ClauseEntry::zeroed()], // all-Any wildcard
        Some(Verdict::Deny) | Some(Verdict::Undecided) => Vec::new(),
        None => plan.clauses.clone(),
    };
    let count = clauses.len() as u32;
    MapImage {
        clauses,
        count,
        enabled: 1,
    }
}

/// Convenience: lower a rich [`MapPlan`] straight to a [`MapImage`].
pub fn map_image_from_plan(plan: &MapPlan) -> MapImage {
    map_image(&regorus_bpf::to_pod(plan))
}

/// A loaded egress enforcer. Holds the BPF objects alive; dropping it detaches
/// the program and frees the maps.
pub struct EgressEnforcer {
    ebpf: Ebpf,
}

impl EgressEnforcer {
    /// Build the privilege-free map image for a plan (no `CAP_BPF` needed).
    pub fn map_image(plan: &PodPlan) -> MapImage {
        map_image(plan)
    }

    /// Load the program into the kernel (requires `CAP_BPF`). The program is
    /// loaded but not yet bound to any cgroup; call [`Self::apply`] to populate
    /// the maps and [`Self::bind_cgroup`] to begin enforcing.
    pub fn load() -> Result<Self> {
        let mut ebpf = EbpfLoader::new()
            .load(EGRESS_ELF)
            .context("loading regorus egress BPF ELF")?;
        let prog: &mut CgroupSockAddr = ebpf
            .program_mut(PROG_NAME)
            .with_context(|| format!("program {PROG_NAME} not found in ELF"))?
            .try_into()
            .context("program is not a CgroupSockAddr")?;
        prog.load().context("loading connect4 program")?;
        Ok(Self { ebpf })
    }

    /// Populate the maps from a plan (requires the program to be loaded).
    pub fn apply(&mut self, plan: &PodPlan) -> Result<()> {
        let image = map_image(plan);

        let mut clauses: BpfArray<_, ClauseEntry> = BpfArray::try_from(
            self.ebpf
                .map_mut("EGRESS_CLAUSES")
                .context("EGRESS_CLAUSES")?,
        )?;
        for (i, c) in image.clauses.iter().enumerate() {
            clauses
                .set(i as u32, *c, 0)
                .with_context(|| format!("set clause {i}"))?;
        }
        // Zero out any stale rows beyond the new count (defensive; the count
        // bound already prevents them from being scanned).
        for i in image.clauses.len()..MAX_CLAUSES {
            clauses.set(i as u32, ClauseEntry::zeroed(), 0).ok();
        }

        let mut count: BpfArray<_, u32> = BpfArray::try_from(
            self.ebpf
                .map_mut("EGRESS_CLAUSE_COUNT")
                .context("EGRESS_CLAUSE_COUNT")?,
        )?;
        count.set(0, image.count, 0).context("set clause count")?;

        let mut enabled: BpfArray<_, u32> = BpfArray::try_from(
            self.ebpf
                .map_mut("EGRESS_ENABLED")
                .context("EGRESS_ENABLED")?,
        )?;
        enabled.set(0, image.enabled, 0).context("set enabled")?;

        Ok(())
    }

    /// Bind the loaded program to a cgroup (requires `CAP_NET_ADMIN`/`CAP_BPF`).
    /// `cgroup` is typically an open handle to a cgroup-v2 directory, e.g.
    /// `std::fs::File::open("/sys/fs/cgroup/<name>")`.
    pub fn bind_cgroup<T: AsFd>(&mut self, cgroup: T) -> Result<()> {
        let prog: &mut CgroupSockAddr = self
            .ebpf
            .program_mut(PROG_NAME)
            .context("program not found")?
            .try_into()
            .context("program is not a CgroupSockAddr")?;
        prog.attach(cgroup, CgroupAttachMode::Single)
            .context("binding connect4 program to cgroup")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use regorus_bpf::plan::{ClauseEntry as RichClause, IpMatch, MapPlan, ScalarMatch};
    use regorus_bpf::to_pod;

    #[test]
    fn static_allow_becomes_wildcard_clause() {
        let plan = to_pod(&MapPlan {
            static_verdict: Some(Verdict::Allow),
            clauses: vec![],
        });
        let img = map_image(&plan);
        assert_eq!(img.count, 1);
        assert_eq!(img.clauses, vec![ClauseEntry::zeroed()]);
        assert_eq!(img.enabled, 1);
    }

    #[test]
    fn static_deny_becomes_empty_table() {
        for v in [Verdict::Deny, Verdict::Undecided] {
            let plan = to_pod(&MapPlan {
                static_verdict: Some(v),
                clauses: vec![],
            });
            let img = map_image(&plan);
            assert_eq!(img.count, 0);
            assert!(img.clauses.is_empty());
        }
    }

    #[test]
    fn clauses_serialise_in_order() {
        let plan = to_pod(&MapPlan {
            static_verdict: None,
            clauses: vec![
                RichClause {
                    ip: IpMatch::Exact(0x0a00_0001),
                    port: ScalarMatch::Exact(22),
                    proto: ScalarMatch::Exact(6),
                },
                RichClause {
                    ip: IpMatch::Cidr {
                        network: 0x0a00_0000,
                        prefix_len: 8,
                    },
                    port: ScalarMatch::Range {
                        min: 1024,
                        max: 2048,
                    },
                    proto: ScalarMatch::Any,
                },
            ],
        });
        let img = map_image(&plan);
        assert_eq!(img.count, 2);
        assert_eq!(img.clauses.len(), 2);
        assert_eq!(img.clauses[0].ip_value, 0x0a00_0001);
        assert_eq!(img.clauses[1].prefix_len, 8);
        assert_eq!(img.clauses[1].port_min, 1024);
    }
}
