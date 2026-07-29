// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end checks for the portable (`RVMP`) RVM artifact format.
//!
//! These mirror what the `compile-rvm` / `eval-rvm` example commands do:
//! compile a small policy, write the artifact to a real file, read it back,
//! and evaluate it.

use std::path::PathBuf;
use std::sync::Arc;

use regorus::languages::rego::compiler::Compiler;
use regorus::rvm::program::{DeserializationResult, PortableWriteOptions};
use regorus::rvm::{Program, RegoVM};
use regorus::{Engine, Rc, Value};

const POLICY: &str = r#"
package example.authz

import rego.v1

default allow := false

allow if {
    some role in data.roles[input.user]
    some permission in data.role_permissions[role]
    permission.action == input.action
    permission.resource == input.resource
}

user_roles contains role if {
    some role in data.roles[input.user]
}

reason := sprintf("user %v requested %v on %v", [input.user, input.action, input.resource])

limits := {"max_items": 128, "ratio": 0.25, "tiers": [1, 2, 3]}
"#;

const DATA: &str = r#"{
    "roles": {"alice": ["admin", "reader"], "bob": ["reader"]},
    "role_permissions": {
        "admin": [
            {"action": "read", "resource": "server"},
            {"action": "write", "resource": "server"}
        ],
        "reader": [{"action": "read", "resource": "server"}]
    }
}"#;

const ENTRY_POINTS: &[&str] = &[
    "data.example.authz.allow",
    "data.example.authz.user_roles",
    "data.example.authz.reason",
    "data.example.authz.limits",
];

fn data_value() -> Value {
    Value::from_json_str(DATA).expect("data is valid json")
}

fn compile() -> Arc<Program> {
    let mut engine = Engine::new();
    engine
        .add_policy("policy.rego".to_string(), POLICY.to_string())
        .expect("policy compiles");
    engine.add_data(data_value()).expect("data is accepted");
    let compiled = engine
        .compile_with_entrypoint(&Rc::from(ENTRY_POINTS[0]))
        .expect("policy compiles for entry point");
    Compiler::compile_from_policy(&compiled, ENTRY_POINTS).expect("RVM program is produced")
}

fn artifact_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    path.push(name);
    path
}

fn evaluate(program: Arc<Program>, entry_point: &str, user: &str, action: &str) -> Value {
    let mut vm = RegoVM::new();
    vm.load_program(program);
    vm.set_data(data_value()).expect("data is accepted");
    vm.set_input(
        Value::from_json_str(&format!(
            r#"{{"user": "{user}", "action": "{action}", "resource": "server"}}"#
        ))
        .expect("input is valid json"),
    );
    vm.execute_entry_point_by_name(entry_point)
        .expect("execution succeeds")
}

/// Compile → write file → read file → evaluate, the way `compile-rvm` and
/// `eval-rvm` do it.
#[test]
fn portable_artifact_round_trips_through_a_file() {
    let program = compile();
    let artifact = program
        .serialize_portable()
        .expect("program is serializable");

    let path = artifact_path("portable_round_trip.rvmp");
    std::fs::write(&path, &artifact).expect("artifact is writable");
    let read_back = std::fs::read(&path).expect("artifact is readable");
    assert_eq!(
        read_back, artifact,
        "file contents must survive a round trip"
    );

    assert!(Program::is_portable_artifact(&read_back));
    let decoded =
        Arc::new(Program::deserialize_portable(&read_back).expect("artifact is decodable"));

    assert_eq!(
        decoded.entry_points.keys().cloned().collect::<Vec<_>>(),
        ENTRY_POINTS.to_vec(),
        "entry point order must be preserved"
    );

    // Allowed: alice has the admin role, which grants write on server.
    assert_eq!(
        evaluate(
            Arc::clone(&decoded),
            "data.example.authz.allow",
            "alice",
            "write"
        ),
        Value::from(true)
    );
    // Denied: bob only has reader.
    assert_eq!(
        evaluate(
            Arc::clone(&decoded),
            "data.example.authz.allow",
            "bob",
            "write"
        ),
        Value::from(false)
    );
    // Strings, sets and nested literals survive too.
    assert_eq!(
        evaluate(
            Arc::clone(&decoded),
            "data.example.authz.reason",
            "alice",
            "write"
        ),
        Value::from("user alice requested write on server")
    );
    assert_eq!(
        evaluate(
            Arc::clone(&decoded),
            "data.example.authz.limits",
            "alice",
            "read"
        ),
        Value::from_json_str(r#"{"max_items": 128, "ratio": 0.25, "tiers": [1, 2, 3]}"#).unwrap()
    );

    // The decoded program must evaluate exactly like the original.
    for entry_point in ENTRY_POINTS {
        assert_eq!(
            evaluate(Arc::clone(&decoded), entry_point, "alice", "write"),
            evaluate(Arc::clone(&program), entry_point, "alice", "write"),
            "entry point {entry_point} diverged after a round trip"
        );
    }

    std::fs::remove_file(&path).ok();
}

/// `--execution-only` must drop debug sections and still execute.
#[test]
fn execution_only_artifact_is_smaller_and_still_runs() {
    let program = compile();
    let full = program.serialize_portable().expect("full artifact");
    let lean = program
        .serialize_portable_with_options(&PortableWriteOptions::execution_only())
        .expect("lean artifact");

    assert!(
        lean.len() < full.len(),
        "execution-only artifact ({} bytes) should be smaller than the full one ({} bytes)",
        lean.len(),
        full.len()
    );

    let decoded = Arc::new(Program::deserialize_portable(&lean).expect("lean artifact decodes"));
    assert!(decoded.sources.is_empty());
    assert_eq!(
        evaluate(decoded, "data.example.authz.allow", "alice", "write"),
        Value::from(true)
    );
}

/// The header can be read without decoding the body, and it agrees with it.
#[test]
fn inspect_agrees_with_a_full_decode() {
    let program = compile();
    let artifact = program.serialize_portable().expect("artifact");
    let info = Program::inspect_portable(&artifact).expect("header is inspectable");

    assert_eq!(info.format_version, 1);
    assert_eq!(info.total_size as usize, artifact.len());
    assert!(info.has_debug_info);
    assert!(info.has_metadata);

    let decoded = Program::deserialize_portable(&artifact).expect("artifact decodes");
    assert_eq!(info.uses_host_await, decoded.has_host_await);
    assert_eq!(info.rego_v0, decoded.rego_v0);
}

/// Both containers must be readable and must agree on results.
#[test]
fn portable_and_legacy_containers_agree() {
    let program = compile();

    let portable = program.serialize_portable().expect("portable artifact");
    let legacy = program.serialize_binary().expect("legacy artifact");

    assert!(Program::is_portable_artifact(&portable));
    assert!(!Program::is_portable_artifact(&legacy));

    let from_portable =
        Arc::new(Program::deserialize_portable(&portable).expect("portable decodes"));
    let from_legacy = match Program::deserialize_binary(&legacy).expect("legacy decodes") {
        DeserializationResult::Complete(program) => Arc::new(program),
        DeserializationResult::Partial(_) => panic!("legacy artifact decoded only partially"),
    };

    for entry_point in ENTRY_POINTS {
        assert_eq!(
            evaluate(Arc::clone(&from_portable), entry_point, "alice", "write"),
            evaluate(Arc::clone(&from_legacy), entry_point, "alice", "write"),
            "containers disagree on {entry_point}"
        );
    }
}

/// A corrupted artifact must be rejected rather than silently mis-executed.
#[test]
fn corrupted_artifact_is_rejected() {
    let program = compile();
    let mut artifact = program.serialize_portable().expect("artifact");
    let last = artifact.len() - 1;
    artifact[last] ^= 0xFF;
    assert!(Program::deserialize_portable(&artifact).is_err());
}
