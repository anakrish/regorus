// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fail-closed and design tests for LSM capabilities **beyond** the file-open
//! MVP (scenarios #24–#27). These are deliberately *not implemented* in this
//! crate; the purpose of each test is to pin the SOUND behaviour ("does not
//! lower into over-permission") and to record the design intent so a future
//! phase can pick it up without re-deriving the soundness argument.
//!
//! The unifying rule, identical to the file-open hook: anything the fixed
//! kernel program cannot observe or decide must be **dropped** from the exported
//! plan, never approximated. Dropping can only remove allows, never add them.
//!
//! # #24 — Binary allow-listing via signatures (`bprm_check_security`)
//!
//! Goal: only allow `execve` of binaries whose code signature / hash is on an
//! allow-list. The natural Rego shape is a builtin over content the kernel hook
//! does not expose as a simple scalar — e.g. `crypto.sha256(input.file_bytes)`
//! or a signature-verification builtin over an opaque blob. Such a condition is
//! NOT an [`Atom`](regorus_lift::ir::Atom) the file-open schema can bind (there
//! is no observable field for "verified signature"), so it is rejected at lift
//! and the disjunct stays in user space. The kernel never sees a half-checked
//! exec allowed. A real implementation would add a `bprm_check_security` hook
//! plus an `input.exe_sha256` observable field populated by the kernel; until
//! then it must fail closed. [`signature_gated_exec_does_not_over_permit`]
//! asserts exactly this.
//!
//! # #25 — Kernel-module lockdown
//!
//! Goal: block loading unsigned/unexpected kernel modules
//! (`kernel_module_request` / `kernel_read_file` LSM hooks). This is a distinct
//! hook with its own observable fields (module name, signature state). It is
//! note-only here: the file-open exporter has no module fields, so any
//! module-oriented policy simply does not lower onto this hook. No test can
//! falsely claim it works; the design note is the deliverable.
//!
//! # #26 — ptrace / raw-socket restrictions
//!
//! Goal: restrict `ptrace` attach (`ptrace_access_check`) and raw-socket
//! creation (`socket_create` with `SOCK_RAW`). Again distinct hooks with
//! distinct contexts (tracer/tracee creds, socket family/type). Note-only: not
//! expressible on the file-open hook, so it does not lower here.
//!
//! # #27 — AI-agent guardrail (composition)
//!
//! Goal: confine an autonomous agent process so it can only read/write an
//! allow-listed workspace and reach an allow-listed set of network endpoints.
//! This is the *composition* of two fixed enforcers:
//!
//!   * THIS crate (`regorus-bpf-lsm`, `lsm/file_open`) constrains file access —
//!     e.g. `startswith(input.path, "/home/agent/workspace/")`.
//!   * `regorus-bpf` (`cgroup/connect4`) constrains egress — e.g.
//!     `input.dest_ip in {…allowed API endpoints…}`.
//!
//! Both share the same fail-closed verdict ABI and the same no-over-permission
//! invariant, so attaching both to the agent's cgroup yields a confinement whose
//! soundness is just the conjunction of the two backends' soundness. There is no
//! single Rego rule that spans both hooks; the guardrail is expressed as two
//! policies, each lifted against its own hook schema. This is a documentation
//! note — no false unified test is asserted.

use std::collections::BTreeMap;

use regorus_bpf_lsm::{enforce, export, extract_request, FileOp, Request, Verdict as BpfVerdict};
use regorus_lift::ir::{Atom, Clause, EnforcerConfig, EqAtom, LiftScalar, PrefixAtom, PrefixKind};
use regorus_lift::FieldType;

fn file_fields() -> BTreeMap<String, FieldType> {
    let mut m = BTreeMap::new();
    m.insert("input.path".to_string(), FieldType::Str);
    m.insert("input.op".to_string(), FieldType::Str);
    m
}

/// #24 — A policy that needs a signature/hash check over an opaque blob has no
/// observable field on the file-open hook. Modelled here as a clause that
/// constrains a non-observable field (`input.exe_sha256`): the exporter drops
/// the whole clause, so the plan can never allow such an exec. Fail-closed.
#[test]
fn signature_gated_exec_does_not_over_permit() {
    // allow exec if path under /usr/bin AND exe_sha256 == <trusted hash>.
    // The hash field is not observable on file_open -> the clause is dropped.
    let cfg = EnforcerConfig::new(
        file_fields(),
        vec![Clause {
            atoms: vec![
                Atom::Prefix(PrefixAtom {
                    input_path: "input.path".into(),
                    pattern: "/usr/bin/".into(),
                    kind: PrefixKind::StartsWith,
                    negated: false,
                }),
                Atom::Eq(EqAtom {
                    input_path: "input.op".into(),
                    scalar: LiftScalar::Str("exec".into()),
                }),
                // The signature constraint over an unobservable field.
                Atom::Eq(EqAtom {
                    input_path: "input.exe_sha256".into(),
                    scalar: LiftScalar::Str("deadbeef".into()),
                }),
            ],
        }],
    );
    let plan = export(&cfg).unwrap();
    assert!(
        plan.rules.is_empty(),
        "a signature-gated exec must NOT lower (no observable hash field) -> fail closed"
    );

    // Therefore no exec is allowed by the plan, even one matching the path/op.
    let req = Request {
        path: Some("/usr/bin/ls".into()),
        op: Some(FileOp::Exec),
    };
    assert_eq!(
        enforce(&plan, &req),
        BpfVerdict::Undecided,
        "dropping the signature clause must under-permit (deny), never over-permit"
    );
}

/// #25/#26 — A module-lockdown or ptrace/raw-socket policy references fields
/// that belong to other LSM hooks and are absent from the file-open schema, so
/// it cannot lower onto this hook. We assert the generic property: a clause over
/// a non-file-open field is dropped (the design notes above describe the
/// dedicated hooks a real implementation would add).
#[test]
fn other_hook_policies_do_not_lower_onto_file_open() {
    // e.g. "module signature must be valid" / "ptrace mode is read-only".
    for field in [
        "input.module_sig_ok",
        "input.ptrace_mode",
        "input.sock_type",
    ] {
        let cfg = EnforcerConfig::new(
            file_fields(),
            vec![Clause {
                atoms: vec![Atom::Eq(EqAtom {
                    input_path: field.into(),
                    scalar: LiftScalar::Str("x".into()),
                })],
            }],
        );
        let plan = export(&cfg).unwrap();
        assert!(
            plan.rules.is_empty(),
            "policy over {field} must not lower onto file_open (fail-closed)"
        );
    }
}

/// #27 — AI-agent guardrail composition. There is no unified rule across hooks;
/// the file half is just an ordinary file-open allow-list. We assert that the
/// file half is sound on its own (workspace reads/writes allowed, everything
/// else denied), and document that egress is enforced by the sibling
/// `regorus-bpf` crate attached to the same cgroup.
#[test]
fn agent_guardrail_file_half_is_sound() {
    let cfg = EnforcerConfig::new(
        file_fields(),
        vec![Clause {
            atoms: vec![Atom::Prefix(PrefixAtom {
                input_path: "input.path".into(),
                pattern: "/home/agent/workspace/".into(),
                kind: PrefixKind::StartsWith,
                negated: false,
            })],
        }],
    );
    let plan = export(&cfg).unwrap();
    assert_eq!(plan.rules.len(), 1);

    let allowed = Request {
        path: Some("/home/agent/workspace/notes.md".into()),
        op: Some(FileOp::Write),
    };
    assert_eq!(enforce(&plan, &allowed), BpfVerdict::Allow);

    // Anything outside the workspace is denied (fail-closed), e.g. exfiltrating
    // host secrets or writing outside the sandbox.
    for bad in ["/etc/shadow", "/home/agent/.ssh/id_rsa", "/proc/self/mem"] {
        let req = extract_request(&serde_json::json!({ "path": bad, "op": "read" }));
        assert_eq!(
            enforce(&plan, &req),
            BpfVerdict::Undecided,
            "agent must not reach {bad}"
        );
    }
}
