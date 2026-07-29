// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Round-trip, malformed-input, limit, determinism, and compatibility tests
//! for the portable `RVMP` artifact format.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::assertions_on_result_states)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::panic)]
#![allow(clippy::as_conversions)]

use alloc::string::ToString as _;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::errors::{PortableError, PortableLimits, PortableWriteOptions};
use super::format::{
    HEADER_SIZE, MAGIC, SECTION_ENTRY_POINTS, SECTION_FLAG_REQUIRED, SECTION_METADATA,
    SECTION_SPANS,
};
use crate::rvm::Program;
use crate::value::Value;
use crate::Engine;

// ── Helpers ──────────────────────────────────────────────────────────────────

const SAMPLE_POLICY: &str = r#"
package test

import rego.v1

default allow := false

allow if {
    input.user == "alice"
    some role in data.roles[input.user]
    role == "admin"
}

numbers := [1, -2, 3.5, 1e300]

names contains name if {
    some name in ["a", "b", "c"]
}

square(x) := x * x

doubled := square(21)
"#;

const SAMPLE_DATA: &str = r#"{"roles": {"alice": ["admin", "reader"], "bob": ["reader"]}}"#;

fn compile_sample(entry_points: &[&str]) -> Arc<Program> {
    let mut engine = Engine::new();
    engine
        .add_policy("test.rego".to_string(), SAMPLE_POLICY.to_string())
        .expect("failed to add policy");
    engine
        .add_data(Value::from_json_str(SAMPLE_DATA).expect("bad data json"))
        .expect("failed to add data");
    let first = entry_points.first().copied().unwrap_or("data.test.allow");
    let compiled = engine
        .compile_with_entrypoint(&crate::Rc::from(first))
        .expect("failed to compile policy");
    crate::languages::rego::compiler::Compiler::compile_from_policy(&compiled, entry_points)
        .expect("failed to compile RVM program")
}

fn sample_program() -> Arc<Program> {
    compile_sample(&[
        "data.test.allow",
        "data.test.numbers",
        "data.test.names",
        "data.test.doubled",
    ])
}

fn assert_programs_equivalent(left: &Program, right: &Program) {
    assert_eq!(left.instructions.len(), right.instructions.len());
    for (index, (lhs, rhs)) in left
        .instructions
        .iter()
        .zip(right.instructions.iter())
        .enumerate()
    {
        assert_eq!(
            super::instructions::encode_instruction(*lhs),
            super::instructions::encode_instruction(*rhs),
            "instruction {index} differs"
        );
    }
    assert_eq!(left.literals, right.literals);
    assert_eq!(left.rule_tree, right.rule_tree);
    assert_eq!(left.main_entry_point, right.main_entry_point);
    assert_eq!(left.max_rule_window_size, right.max_rule_window_size);
    assert_eq!(left.dispatch_window_size, right.dispatch_window_size);
    assert_eq!(left.rego_v0, right.rego_v0);
    assert_eq!(left.has_host_await, right.has_host_await);
    assert_eq!(
        left.needs_runtime_recursion_check,
        right.needs_runtime_recursion_check
    );
    assert_eq!(left.entry_points.len(), right.entry_points.len());
    for ((left_path, left_index), (right_path, right_index)) in
        left.entry_points.iter().zip(right.entry_points.iter())
    {
        assert_eq!(left_path, right_path, "entry point order must be preserved");
        assert_eq!(left_index, right_index);
    }
    assert_eq!(left.rule_infos.len(), right.rule_infos.len());
    for (lhs, rhs) in left.rule_infos.iter().zip(right.rule_infos.iter()) {
        assert_eq!(lhs.name, rhs.name);
        assert_eq!(lhs.rule_type, rhs.rule_type);
        assert_eq!(lhs.result_reg, rhs.result_reg);
        assert_eq!(lhs.num_registers, rhs.num_registers);
        assert_eq!(lhs.default_literal_index, rhs.default_literal_index);
        assert_eq!(*lhs.definitions, *rhs.definitions);
        assert_eq!(lhs.destructuring_blocks, rhs.destructuring_blocks);
        assert_eq!(
            lhs.early_exit_on_first_success,
            rhs.early_exit_on_first_success
        );
    }
    assert_eq!(
        left.builtin_info_table.len(),
        right.builtin_info_table.len()
    );
    for (lhs, rhs) in left
        .builtin_info_table
        .iter()
        .zip(right.builtin_info_table.iter())
    {
        assert_eq!(lhs.name, rhs.name);
        assert_eq!(lhs.num_args, rhs.num_args);
    }
}

fn evaluate(program: Arc<Program>, entry_point: &str) -> Value {
    let mut vm = crate::rvm::RegoVM::new();
    vm.load_program(program);
    vm.set_data(Value::from_json_str(SAMPLE_DATA).expect("bad data json"))
        .expect("set_data failed");
    vm.set_input(Value::from_json_str(r#"{"user": "alice"}"#).expect("bad input json"));
    vm.execute_entry_point_by_name(entry_point)
        .expect("execution failed")
}

fn read_u32(artifact: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        artifact[offset],
        artifact[offset + 1],
        artifact[offset + 2],
        artifact[offset + 3],
    ])
}

/// Locate a directory entry and return the offset of one of its `u32` fields.
fn directory_field_offset(artifact: &[u8], section_id: u32, field_index: usize) -> usize {
    let section_count = read_u32(artifact, 12) as usize;
    for entry in 0..section_count {
        let base = HEADER_SIZE + entry * 16;
        if read_u32(artifact, base) == section_id {
            return base + field_index * 4;
        }
    }
    panic!("section {section_id} not found in directory");
}

fn patch_u32(artifact: &mut [u8], offset: usize, value: u32) {
    artifact[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn recompute_checksum(artifact: &mut [u8]) {
    let checksum = super::format::crc32(&artifact[HEADER_SIZE..]);
    patch_u32(artifact, 24, checksum);
}

// ── Round-trip ───────────────────────────────────────────────────────────────

#[test]
fn empty_program_round_trips() {
    let program = Program::new();
    let artifact = program.serialize_portable().unwrap();
    let decoded = Program::deserialize_portable(&artifact).unwrap();
    assert_programs_equivalent(&program, &decoded);
    assert!(decoded.instructions.is_empty());
    assert!(!decoded.needs_recompilation());
}

#[test]
fn compiled_program_round_trips() {
    let program = sample_program();
    let artifact = program.serialize_portable().unwrap();
    let decoded = Program::deserialize_portable(&artifact).unwrap();
    assert_programs_equivalent(&program, &decoded);
    assert_eq!(decoded.sources.len(), program.sources.len());
    assert_eq!(
        decoded.instruction_spans.len(),
        program.instruction_spans.len()
    );
    assert_eq!(
        decoded.metadata.compiler_version,
        program.metadata.compiler_version
    );
}

#[test]
fn decoded_program_executes_identically() {
    let program = sample_program();
    let artifact = program.serialize_portable().unwrap();
    let decoded = Arc::new(Program::deserialize_portable(&artifact).unwrap());

    for entry_point in [
        "data.test.allow",
        "data.test.numbers",
        "data.test.names",
        "data.test.doubled",
    ] {
        let expected = evaluate(Arc::clone(&program), entry_point);
        let actual = evaluate(Arc::clone(&decoded), entry_point);
        assert_eq!(expected, actual, "entry point {entry_point} diverged");
    }
}

#[test]
fn execution_only_artifact_is_smaller_and_still_executes() {
    let program = sample_program();
    let full = program.serialize_portable().unwrap();
    let lean = program
        .serialize_portable_with_options(&PortableWriteOptions::execution_only())
        .unwrap();
    assert!(
        lean.len() < full.len(),
        "execution-only artifact ({} bytes) should be smaller than the full artifact ({} bytes)",
        lean.len(),
        full.len()
    );

    let decoded = Arc::new(Program::deserialize_portable(&lean).unwrap());
    assert!(decoded.sources.is_empty());
    assert_eq!(
        evaluate(Arc::clone(&decoded), "data.test.allow"),
        evaluate(Arc::clone(&program), "data.test.allow")
    );
}

#[test]
fn undefined_set_and_bignum_literals_round_trip() {
    let mut program = Program::new();
    program.literals.push(Value::Undefined);
    program.literals.push(Value::Null);
    program
        .literals
        .push(Value::from_json_str(r#"{"a": [1, 2, {"b": true}]}"#).unwrap());

    let mut set = alloc::collections::BTreeSet::new();
    set.insert(Value::from(3_i64));
    set.insert(Value::from("x"));
    program.literals.push(Value::from(set));

    let mut object = crate::value::Object::new();
    object.insert(Value::from(1_i64), Value::from("int key"));
    object.insert(Value::Null, Value::Undefined);
    program.literals.push(Value::Object(crate::Rc::new(object)));

    let big = "170141183460469231731687303715884105728000000000000";
    program.literals.push(Value::Number(
        core::str::FromStr::from_str(big).expect("big number"),
    ));

    let artifact = program.serialize_portable().unwrap();
    let decoded = Program::deserialize_portable(&artifact).unwrap();
    assert_eq!(decoded.literals, program.literals);
    assert_eq!(decoded.literals[0], Value::Undefined);
    assert_ne!(decoded.literals[0], Value::Null);
}

// ── Determinism ──────────────────────────────────────────────────────────────

#[test]
fn encoding_is_byte_stable() {
    let program = sample_program();
    let first = program.serialize_portable().unwrap();
    let second = program.serialize_portable().unwrap();
    assert_eq!(first, second, "repeat encoding must be byte identical");
}

#[test]
fn re_encoding_a_decoded_program_is_byte_stable() {
    let program = sample_program();
    let first = program.serialize_portable().unwrap();
    let decoded = Program::deserialize_portable(&first).unwrap();
    let second = decoded.serialize_portable().unwrap();
    assert_eq!(
        first, second,
        "decode -> encode must reproduce the original bytes"
    );

    let decoded_again = Program::deserialize_portable(&second).unwrap();
    let third = decoded_again.serialize_portable().unwrap();
    assert_eq!(second, third);
}

#[test]
fn object_key_order_does_not_affect_output() {
    let build = |reversed: bool| {
        let mut object = crate::value::Object::new();
        let keys = ["zeta", "alpha", "mid"];
        let ordered: Vec<&str> = if reversed {
            keys.iter().rev().copied().collect()
        } else {
            keys.to_vec()
        };
        for key in ordered {
            object.insert(Value::from(key), Value::from(key));
        }
        let mut program = Program::new();
        program.literals.push(Value::Object(crate::Rc::new(object)));
        program.serialize_portable().unwrap()
    };
    assert_eq!(build(false), build(true));
}

// ── Header inspection ────────────────────────────────────────────────────────

#[test]
fn header_can_be_inspected_without_full_decode() {
    let program = sample_program();
    let artifact = program.serialize_portable().unwrap();
    let info = Program::inspect_portable(&artifact).unwrap();
    assert_eq!(info.format_version, super::format::FORMAT_VERSION);
    assert!(info.has_debug_info);
    assert!(info.has_metadata);
    assert_eq!(info.uses_host_await, program.has_host_await);
    assert_eq!(info.rego_v0, program.rego_v0);
    assert_eq!(info.total_size as usize, artifact.len());

    let lean = program
        .serialize_portable_with_options(&PortableWriteOptions::execution_only())
        .unwrap();
    let lean_info = Program::inspect_portable(&lean).unwrap();
    assert!(!lean_info.has_debug_info);
    assert!(!lean_info.has_metadata);
}

#[test]
fn artifact_families_are_distinguishable() {
    let program = sample_program();
    let portable = program.serialize_portable().unwrap();
    let legacy = program.serialize_binary().unwrap();

    assert!(Program::is_portable_artifact(&portable));
    assert!(!Program::is_portable_artifact(&legacy));
    assert!(!Program::is_portable_artifact(&[]));

    // The legacy path is untouched and still round-trips.
    assert!(Program::can_deserialize(&legacy).unwrap());
    assert!(!Program::can_deserialize(&portable).unwrap());
    let restored = match Program::deserialize_binary(&legacy).unwrap() {
        crate::rvm::program::DeserializationResult::Complete(restored) => restored,
        crate::rvm::program::DeserializationResult::Partial(_) => {
            panic!("legacy round-trip regressed to a partial program")
        }
    };
    assert_eq!(restored.instructions.len(), program.instructions.len());

    // A portable artifact must be rejected by the legacy reader and vice versa.
    assert!(Program::deserialize_binary(&portable).is_err());
    assert!(matches!(
        Program::deserialize_portable(&legacy),
        Err(PortableError::InvalidMagic)
    ));
}

// ── Malformed input ──────────────────────────────────────────────────────────

#[test]
fn empty_input_is_rejected() {
    assert!(matches!(
        Program::deserialize_portable(&[]),
        Err(PortableError::Truncated { .. })
    ));
}

#[test]
fn bad_magic_is_rejected() {
    let program = Program::new();
    let mut artifact = program.serialize_portable().unwrap();
    artifact[0] = b'X';
    assert!(matches!(
        Program::deserialize_portable(&artifact),
        Err(PortableError::InvalidMagic)
    ));
}

#[test]
fn unsupported_version_is_rejected() {
    let program = Program::new();
    let mut artifact = program.serialize_portable().unwrap();
    artifact[4..6].copy_from_slice(&999_u16.to_le_bytes());
    assert!(matches!(
        Program::deserialize_portable(&artifact),
        Err(PortableError::UnsupportedVersion { found: 999, .. })
    ));
}

#[test]
fn unknown_required_feature_is_rejected() {
    let program = Program::new();
    let mut artifact = program.serialize_portable().unwrap();
    patch_u32(&mut artifact, 8, 0x0001_0000);
    assert!(matches!(
        Program::deserialize_portable(&artifact),
        Err(PortableError::UnsupportedFeatures { .. })
    ));
}

#[test]
fn every_truncation_is_rejected_without_panicking() {
    let program = sample_program();
    let artifact = program.serialize_portable().unwrap();
    let mut step = 1_usize;
    let mut length = 0_usize;
    while length < artifact.len() {
        let result = Program::deserialize_portable(&artifact[..length]);
        assert!(
            result.is_err(),
            "truncation to {length} bytes unexpectedly succeeded"
        );
        length += step;
        // Sample densely at first, then stride to keep the test fast.
        if length > 512 {
            step = 97;
        }
    }
}

#[test]
fn single_byte_corruption_is_always_detected() {
    let program = sample_program();
    let artifact = program.serialize_portable().unwrap();
    let mut checked = 0_usize;
    let mut offset = HEADER_SIZE;
    while offset < artifact.len() {
        let mut corrupted = artifact.clone();
        corrupted[offset] ^= 0x01;
        assert!(
            Program::deserialize_portable(&corrupted).is_err(),
            "corruption at offset {offset} was not detected"
        );
        checked += 1;
        offset += 61;
    }
    assert!(checked > 0);
}

#[test]
fn declared_total_size_must_match() {
    let program = Program::new();
    let mut artifact = program.serialize_portable().unwrap();
    let bogus = (artifact.len() + 16) as u32;
    patch_u32(&mut artifact, 20, bogus);
    recompute_checksum(&mut artifact);
    assert!(matches!(
        Program::deserialize_portable(&artifact),
        Err(PortableError::MalformedHeader { .. })
    ));
}

#[test]
fn section_outside_the_artifact_is_rejected() {
    let program = sample_program();
    let mut artifact = program.serialize_portable().unwrap();
    let offset_field = directory_field_offset(&artifact, SECTION_ENTRY_POINTS, 1);
    patch_u32(&mut artifact, offset_field, u32::MAX - 8);
    recompute_checksum(&mut artifact);
    assert!(matches!(
        Program::deserialize_portable(&artifact),
        Err(PortableError::SectionOutOfBounds { .. })
    ));
}

#[test]
fn overlapping_sections_are_rejected() {
    let program = sample_program();
    let mut artifact = program.serialize_portable().unwrap();
    let length_field = directory_field_offset(&artifact, SECTION_ENTRY_POINTS, 2);
    let current = read_u32(&artifact, length_field);
    patch_u32(&mut artifact, length_field, current + 4096);
    recompute_checksum(&mut artifact);
    let result = Program::deserialize_portable(&artifact);
    assert!(
        matches!(
            result,
            Err(PortableError::SectionOverlap { .. } | PortableError::SectionOutOfBounds { .. })
        ),
        "unexpected result: {result:?}"
    );
}

#[test]
fn duplicate_section_ids_are_rejected() {
    let program = sample_program();
    let mut artifact = program.serialize_portable().unwrap();
    let first_id = directory_field_offset(&artifact, SECTION_SPANS, 0);
    patch_u32(&mut artifact, first_id, SECTION_METADATA);
    recompute_checksum(&mut artifact);
    let result = Program::deserialize_portable(&artifact);
    assert!(
        matches!(result, Err(PortableError::DuplicateSection { .. })),
        "unexpected result: {result:?}"
    );
}

#[test]
fn unknown_optional_section_is_skipped_but_required_one_is_rejected() {
    let program = sample_program();
    let artifact = program.serialize_portable().unwrap();

    // Relabel the (optional) spans section with an unknown id and keep it
    // optional: the decoder must ignore it.
    let mut skippable = artifact.clone();
    let id_field = directory_field_offset(&skippable, SECTION_SPANS, 0);
    patch_u32(&mut skippable, id_field, 4242);
    recompute_checksum(&mut skippable);
    let decoded = Program::deserialize_portable(&skippable).unwrap();
    assert_eq!(decoded.instructions.len(), program.instructions.len());

    // The same section flagged must-understand has to be rejected.
    let mut fatal = skippable;
    let flags_field = directory_field_offset(&fatal, 4242, 3);
    patch_u32(&mut fatal, flags_field, SECTION_FLAG_REQUIRED);
    recompute_checksum(&mut fatal);
    assert!(matches!(
        Program::deserialize_portable(&fatal),
        Err(PortableError::UnknownRequiredSection { id: 4242 })
    ));
}

#[test]
fn missing_required_section_is_rejected() {
    let program = sample_program();
    let mut artifact = program.serialize_portable().unwrap();
    let id_field = directory_field_offset(&artifact, SECTION_ENTRY_POINTS, 0);
    let flags_field = directory_field_offset(&artifact, SECTION_ENTRY_POINTS, 3);
    patch_u32(&mut artifact, flags_field, 0);
    patch_u32(&mut artifact, id_field, 5000);
    recompute_checksum(&mut artifact);
    assert!(matches!(
        Program::deserialize_portable(&artifact),
        Err(PortableError::MissingSection {
            id: SECTION_ENTRY_POINTS
        })
    ));
}

#[test]
fn random_garbage_never_panics() {
    let mut state = 0x2545_F491_4F6C_DD1D_u64;
    for size in [0_usize, 1, 7, 32, 40, 96, 200, 1024] {
        for _ in 0..64 {
            let mut buffer = Vec::with_capacity(size);
            for _ in 0..size {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                buffer.push((state >> 33) as u8);
            }
            // Occasionally give it a valid magic so we get past the first gate.
            if size >= 8 && state & 1 == 0 {
                buffer[..4].copy_from_slice(&MAGIC);
                buffer[4..6].copy_from_slice(&1_u16.to_le_bytes());
            }
            let _ = Program::deserialize_portable(&buffer);
            let _ = Program::inspect_portable(&buffer);
            let _ = Program::is_portable_artifact(&buffer);
        }
    }
}

// ── Limits ───────────────────────────────────────────────────────────────────

#[test]
fn total_size_limit_is_enforced() {
    let program = sample_program();
    let artifact = program.serialize_portable().unwrap();
    let mut limits = PortableLimits::new();
    limits.max_total_size = 16;
    assert!(matches!(
        Program::deserialize_portable_with_limits(&artifact, &limits),
        Err(PortableError::LimitExceeded {
            limit: "artifact size",
            ..
        })
    ));
}

#[test]
fn string_table_limit_is_enforced() {
    let program = sample_program();
    let artifact = program.serialize_portable().unwrap();
    let mut limits = PortableLimits::new();
    limits.max_strings = 1;
    assert!(matches!(
        Program::deserialize_portable_with_limits(&artifact, &limits),
        Err(PortableError::LimitExceeded { .. })
    ));
}

#[test]
fn section_count_limit_is_enforced() {
    let program = sample_program();
    let artifact = program.serialize_portable().unwrap();
    let mut limits = PortableLimits::new();
    limits.max_sections = 2;
    assert!(matches!(
        Program::deserialize_portable_with_limits(&artifact, &limits),
        Err(PortableError::LimitExceeded {
            limit: "section count",
            ..
        })
    ));
}

#[test]
fn instruction_limit_is_enforced() {
    let program = sample_program();
    let artifact = program.serialize_portable().unwrap();
    let mut limits = PortableLimits::new();
    limits.max_instructions = 1;
    assert!(matches!(
        Program::deserialize_portable_with_limits(&artifact, &limits),
        Err(PortableError::LimitExceeded { .. })
    ));
}

#[test]
fn a_tiny_artifact_cannot_request_a_huge_allocation() {
    // Claim a huge literal count in a tiny artifact.  The decoder must reject
    // it from the declared-count check and never attempt the allocation.
    let program = Program::new();
    let mut artifact = program.serialize_portable().unwrap();
    let offset_field = directory_field_offset(&artifact, super::format::SECTION_LITERALS, 1);
    let literal_offset = read_u32(&artifact, offset_field) as usize;
    patch_u32(&mut artifact, literal_offset, u32::MAX);
    recompute_checksum(&mut artifact);
    let result = Program::deserialize_portable(&artifact);
    assert!(
        matches!(
            result,
            Err(PortableError::LimitExceeded { .. } | PortableError::Truncated { .. })
        ),
        "unexpected result: {result:?}"
    );
}

#[test]
fn deeply_nested_values_are_rejected() {
    let mut nested = Value::Null;
    for _ in 0..200 {
        nested = Value::from(alloc::vec![nested]);
    }
    let mut program = Program::new();
    program.literals.push(nested);
    assert!(matches!(
        program.serialize_portable(),
        Err(PortableError::DepthExceeded { .. })
    ));
}

// ── Encoder guards ───────────────────────────────────────────────────────────

#[test]
fn programs_needing_recompilation_cannot_be_exported() {
    let mut program = Program::new();
    program.set_needs_recompilation(true);
    assert!(matches!(
        program.serialize_portable(),
        Err(PortableError::ProgramInvalid(_))
    ));
}

#[test]
fn resolved_builtins_are_not_serialized_but_are_reresolved() {
    let program = compile_sample(&["data.test.doubled"]);
    let artifact = program.serialize_portable().unwrap();

    // The Rust-only function pointer table must never appear on the wire; the
    // decoder rebuilds it from the builtin name table.
    let decoded = Program::deserialize_portable(&artifact).unwrap();
    assert_eq!(
        decoded.builtin_info_table.len(),
        program.builtin_info_table.len()
    );
    assert_eq!(
        decoded.has_resolved_builtins(),
        !decoded.builtin_info_table.is_empty()
    );
    for info in &decoded.builtin_info_table {
        assert!(
            crate::builtins::BUILTINS.contains_key(info.name.as_str()),
            "builtin {} was not re-resolved",
            info.name
        );
    }
}

#[test]
fn error_messages_are_actionable() {
    let error = PortableError::LimitExceeded {
        limit: "literals",
        value: 10,
        max: 5,
    };
    let text = alloc::format!("{error}");
    assert!(text.contains("literals"), "unexpected message: {text}");
    assert!(text.contains("10"), "unexpected message: {text}");
}
