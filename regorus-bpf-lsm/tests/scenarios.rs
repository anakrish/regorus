// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Real-world LSM file-access policy scenarios, locked down as regression tests.
//!
//! Each scenario is a named, realistic Rego `file_open` policy that an operator
//! might actually deploy (a read allow-list, and a no-exec-from-tmp guardrail).
//! Every scenario is driven through the full triple path —
//!
//! ```text
//!   full_eval(policy, input)        (real RVM, the ground truth)
//!   simulate(lift(PE), input)       (IR reference enforcer)
//!   enforce(export(lift(PE)), req)  (this crate's map-plan enforcer)
//! ```
//!
//! — and asserts, for a curated table of `(path, op, expected_allow)` cases:
//!
//!  * the policy means what we claim (full eval matches the expectation),
//!  * the map-plan enforcer reproduces it **exactly** (these scenarios are
//!    fully kernel-observable, so the lift+export must be complete), and
//!  * the map-plan enforcer never over-permits relative to full eval.
//!
//! Soundness note: the classic "allow reads under a prefix BUT deny a specific
//! sub-path" pattern is a deny-exception that a prefix allow-list cannot express
//! soundly, so scenario #22 instead encodes the **sound** version (allow only
//! the narrow sub-trees, and let everything else — including `/etc/shadow` —
//! fall through to the default deny). Scenarios use ONLY `startswith` and `==`
//! with separate allow blocks; `endswith` / `contains` are intentionally
//! avoided (they would drop on lowering).

use regorus::*;

use regorus_bpf_lsm::{enforce, export, extract_request, Verdict as BpfVerdict};
use regorus_lift::sim::simulate;
use regorus_lift::{lift, ContextSchema, EnforcerConfig, FieldType, Verdict as LiftVerdict};

const ENTRYPOINT: &str = "data.file.allow";

fn run_pe_typed(
    policy: &str,
    entrypoint_str: &str,
) -> regorus::causality_report::PartialEvalResult {
    let mut engine = Engine::new();
    engine
        .add_policy("test.rego".into(), policy.into())
        .unwrap();

    let entrypoint: Rc<str> = entrypoint_str.into();
    let compiled = engine.compile_with_entrypoint(&entrypoint).unwrap();
    let program =
        languages::rego::compiler::Compiler::compile_from_policy(&compiled, &[entrypoint.as_ref()])
            .unwrap();

    let mut vm = rvm::RegoVM::new_with_policy(compiled);
    vm.load_program(program);
    vm.set_explanation_settings(evaluation_trace::ExplanationSettings {
        enabled: true,
        value_mode: evaluation_trace::ValueMode::Full,
        condition_mode: evaluation_trace::ConditionMode::AllContributing,
        scope: evaluation_trace::ExplanationScope::AllEmissions,
        detail: evaluation_trace::ExplanationDetail::Full,
        emission_index: None,
        emission_value: None,
        assume_unknown_input: true,
        eval_mode: evaluation_trace::EvaluationMode::PartialEval,
        unknowns: vec!["input".into()],
    });
    vm.set_input(Value::new_object());

    let value = vm.execute_entry_point_by_name(entrypoint_str).unwrap();
    vm.take_partial_eval_result_typed(value)
}

fn full_eval(policy: &str, input_json: &str) -> bool {
    let mut engine = Engine::new();
    engine
        .add_policy("test.rego".into(), policy.into())
        .unwrap();
    engine.set_input(serde_json::from_str::<Value>(input_json).unwrap());
    match engine.eval_rule(ENTRYPOINT.to_string()) {
        Ok(v) => matches!(serde_json::to_value(&v), Ok(serde_json::Value::Bool(true))),
        Err(_) => false,
    }
}

fn file_schema() -> ContextSchema {
    ContextSchema::new()
        .with("input.path", FieldType::Str)
        .with("input.op", FieldType::Str)
}

fn lifted_config(policy: &str) -> EnforcerConfig {
    let pe = run_pe_typed(policy, ENTRYPOINT);
    let res = lift(&pe, &file_schema());
    assert!(
        res.is_complete(),
        "scenario must fully lift (kernel-observable); rejections: {:?}",
        res.rejections
    );
    res.config.expect("expected a config")
}

fn input_json(path: &str, op: &str) -> String {
    format!(r#"{{"path":"{path}","op":"{op}"}}"#)
}

/// Drive a real-world scenario through the triple path against a curated case
/// table of `(path, op, expected_allow)`.
fn check_scenario(name: &str, policy: &str, cases: &[(&str, &str, bool)]) {
    let config = lifted_config(policy);
    let plan = export(&config).unwrap_or_else(|e| panic!("[{name}] export failed: {e}"));
    assert_eq!(
        plan.rules.len(),
        config.allow_clauses.len(),
        "[{name}] every clause must lower (no dropped allows)"
    );

    for &(path, op, expect_allow) in cases {
        let json = input_json(path, op);
        let input: serde_json::Value = serde_json::from_str(&json).unwrap();

        // 1. The policy means what the scenario claims.
        let full = full_eval(policy, &json);
        assert_eq!(
            full, expect_allow,
            "[{name}] policy/expectation mismatch for {json}: full_eval={full}, expected {expect_allow}"
        );

        // 2/3. The map-plan enforcer reproduces it exactly and never over-permits.
        let req = extract_request(&input);
        let bpf = enforce(&plan, &req) == BpfVerdict::Allow;
        let sim = simulate(&config, &input) == LiftVerdict::Allow;
        assert_eq!(
            bpf, expect_allow,
            "[{name}] map-plan verdict mismatch for {json}: bpf={bpf}, expected {expect_allow}"
        );
        assert_eq!(bpf, sim, "[{name}] bpf/sim disagree for {json}");
        if bpf {
            assert!(full, "[{name}] OVER-PERMISSION for {json}");
        }
    }
}

#[test]
fn scenario_22_file_read_allow_list() {
    // Allow reads ONLY under the application's own sub-trees. This is the sound
    // formulation of "allow reads under /etc and /usr but not /etc/shadow":
    // rather than carve a deny exception out of a broad prefix (which a prefix
    // allow-list cannot express soundly), we allow only the narrow trees and let
    // /etc/shadow (and everything else) fall through to the default deny.
    // Writes are never allowed.
    const POLICY: &str = r#"
package file

default allow = false

allow if {
    startswith(input.path, "/etc/myapp/")
    input.op == "read"
}

allow if {
    startswith(input.path, "/usr/share/myapp/")
    input.op == "read"
}
"#;
    check_scenario(
        "file-read-allow-list",
        POLICY,
        &[
            ("/etc/myapp/config.yaml", "read", true), // allowed sub-tree
            ("/etc/myapp/secrets/key", "read", true), // deeper under the prefix
            ("/usr/share/myapp/data.db", "read", true), // second allowed sub-tree
            ("/etc/shadow", "read", false),           // NOT in the allow-list -> denied
            ("/etc/passwd", "read", false),           // outside the app tree -> denied
            ("/etc/myapp/config.yaml", "write", false), // writes denied everywhere
            ("/usr/share/myapp/data.db", "write", false), // writes denied everywhere
            ("/etc/myapp/config.yaml", "exec", false), // exec denied everywhere
            ("/tmp/whatever", "read", false),         // unrelated path -> denied
            ("/etc/my", "read", false),               // shorter than the prefix -> denied
        ],
    );
}

#[test]
fn scenario_23_no_exec_from_tmp() {
    // Executables may run only out of trusted bin directories; this implicitly
    // blocks exec of anything under /tmp or /dev/shm (the classic
    // drop-a-binary-and-run attack). Reads are separately permitted under
    // /usr/share (so "reads elsewhere per policy" is exercised), but exec there
    // is not.
    const POLICY: &str = r#"
package file

default allow = false

allow if {
    startswith(input.path, "/usr/bin/")
    input.op == "exec"
}

allow if {
    startswith(input.path, "/opt/app/bin/")
    input.op == "exec"
}

allow if {
    startswith(input.path, "/usr/share/")
    input.op == "read"
}
"#;
    check_scenario(
        "no-exec-from-tmp",
        POLICY,
        &[
            ("/usr/bin/ls", "exec", true),            // trusted bin -> exec ok
            ("/opt/app/bin/server", "exec", true),    // trusted app bin -> exec ok
            ("/tmp/evil", "exec", false),             // exec from /tmp -> blocked
            ("/dev/shm/x", "exec", false),            // exec from /dev/shm -> blocked
            ("/usr/share/doc/readme", "read", true),  // read under /usr/share -> ok
            ("/usr/bin/ls", "read", false),           // /usr/bin is exec-only here
            ("/usr/share/doc/readme", "exec", false), // exec under /usr/share -> denied
            ("/opt/app/bin/server", "write", false),  // writes never allowed
            ("/tmp/evil", "read", false),             // unrelated read -> denied
        ],
    );
}
