// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test utility functions for RVM serialization

use crate::rvm::program::{binaries_to_values, BinaryValue, Program};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use bincode::config::standard;
use bincode::serde::decode_from_slice;

/// Test utility function for round-trip serialization
/// Serializes program, deserializes it, and serializes again to check for consistency
pub fn test_round_trip_serialization(program: &Program) -> Result<(), String> {
    // First serialization
    let serialized1 = program.serialize_binary()?;

    // Basic validation: ensure literal section decodes cleanly under the current format.
    if serialized1.len() >= 8 && serialized1.starts_with(&Program::MAGIC) {
        let read_u32 = |offset: usize| -> Option<u32> {
            let bytes = serialized1.get(offset..offset + 4)?;
            let mut array = [0u8; 4];
            array.copy_from_slice(bytes);
            Some(u32::from_le_bytes(array))
        };

        let version = match read_u32(4) {
            Some(v) => v,
            None => {
                return Err("Failed to read version from serialized data".into());
            }
        };

        if version == 2 && serialized1.len() >= 25 {
            let entry_points_len = match read_u32(8) {
                Some(v) => v as usize,
                None => return Err("Failed to read entry_points_len".into()),
            };
            let sources_len = match read_u32(12) {
                Some(v) => v as usize,
                None => return Err("Failed to read sources_len".into()),
            };
            let literals_len = match read_u32(16) {
                Some(v) => v as usize,
                None => return Err("Failed to read literals_len".into()),
            };

            let entry_points_start = 25;
            let sources_start = entry_points_start + entry_points_len;
            let literals_start = sources_start + sources_len;
            let rule_tree_start = literals_start + literals_len;

            if literals_len > 0 {
                let literals_slice = serialized1
                    .get(literals_start..rule_tree_start)
                    .ok_or_else(|| String::from("Failed to read literal section"))?;

                match decode_from_slice::<Vec<BinaryValue>, _>(literals_slice, standard()) {
                    Ok((decoded_literals, _)) => {
                        if binaries_to_values(decoded_literals).is_err() {
                            return Err(
                                "Failed to convert literal table from binary representation".into(),
                            );
                        }
                    }
                    Err(err) => {
                        return Err(format!(
                            "Failed to decode literal table with bincode: {}",
                            err
                        ));
                    }
                }
            }
        }
    }

    // Deserialize
    let deserialized = match Program::deserialize_binary(&serialized1)? {
        crate::rvm::program::DeserializationResult::Complete(program) => program,
        crate::rvm::program::DeserializationResult::Partial(program) => {
            let info = format!(
                "Deserialization resulted in partial program during round-trip test \
                 (instructions={}, literals={}, needs_recompilation={})",
                program.instructions.len(),
                program.literals.len(),
                program.needs_recompilation()
            );
            return Err(info);
        }
    };

    // Second serialization
    let serialized2 = deserialized.serialize_binary()?;

    // Compare the two serialized versions
    if serialized1 == serialized2 {
        Ok(())
    } else {
        Err(format!(
            "Round-trip serialization failed: serialized data differs. \
            First serialization: {} bytes, Second: {} bytes",
            serialized1.len(),
            serialized2.len()
        ))
    }
}
