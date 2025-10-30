// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use indexmap::IndexMap;

use super::super::types::SourceFile;
use super::{DeserializationResult, Program};
use crate::value::Value;

impl Program {
    /// Serialize program to MessagePack format (cross-language compatible)
    pub fn serialize_messagepack(&self) -> Result<Vec<u8>, String> {
        rmp_serde::to_vec(self).map_err(|e| format!("MessagePack serialization failed: {}", e))
    }

    /// Deserialize program from MessagePack format
    pub fn deserialize_messagepack(data: &[u8]) -> Result<Program, String> {
        rmp_serde::from_slice(data)
            .map_err(|e| format!("MessagePack deserialization failed: {}", e))
    }

    /// Serialize to MessagePack with hybrid format (similar to binary format)
    /// This uses MessagePack for structure but JSON for literals for maximum compatibility
    pub fn serialize_messagepack_hybrid(&self) -> Result<Vec<u8>, String> {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(b"RVM_MSGPACK_V1");

        let entry_points_data = rmp_serde::to_vec(&self.entry_points)
            .map_err(|e| format!("Entry points MessagePack serialization failed: {}", e))?;

        let sources_data = rmp_serde::to_vec(&self.sources)
            .map_err(|e| format!("Sources MessagePack serialization failed: {}", e))?;

        let program_data = rmp_serde::to_vec(self)
            .map_err(|e| format!("Program structure MessagePack serialization failed: {}", e))?;

        let combined_json_data = serde_json::json!({
            "literals": self.literals,
            "rule_tree": self.rule_tree
        });
        let json_data = serde_json::to_vec(&combined_json_data)
            .map_err(|e| format!("Combined JSON serialization failed: {}", e))?;

        buffer.extend_from_slice(&(entry_points_data.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&(sources_data.len() as u32).to_le_bytes());
        buffer.push(if self.rego_v0 { 1 } else { 0 });
        buffer.extend_from_slice(&(program_data.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&(json_data.len() as u32).to_le_bytes());

        buffer.extend_from_slice(&entry_points_data);
        buffer.extend_from_slice(&sources_data);
        buffer.extend_from_slice(&program_data);
        buffer.extend_from_slice(&json_data);

        Ok(buffer)
    }

    /// Deserialize program from MessagePack hybrid format
    pub fn deserialize_messagepack_hybrid(data: &[u8]) -> Result<DeserializationResult, String> {
        if data.len() < 30 {
            return Err("Data too short for MessagePack hybrid format".to_string());
        }

        if &data[0..14] != b"RVM_MSGPACK_V1" {
            return Err("Invalid MessagePack format - magic number mismatch".to_string());
        }

        let mut offset = 14;

        let entry_points_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;
        let sources_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;
        let rego_v0 = data[offset] != 0;
        offset += 1;
        let program_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;
        let json_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        let entry_points_start = offset;
        let sources_start = entry_points_start + entry_points_len;
        let program_start = sources_start + sources_len;
        let json_start = program_start + program_len;
        let json_end = json_start + json_len;

        if data.len() < json_end {
            return Err("Data too short for all sections".to_string());
        }

        let entry_points: IndexMap<String, usize> =
            rmp_serde::from_slice(&data[entry_points_start..sources_start])
                .map_err(|e| format!("Entry points MessagePack deserialization failed: {}", e))?;

        let sources: Vec<SourceFile> =
            rmp_serde::from_slice(&data[sources_start..program_start])
                .map_err(|e| format!("Sources MessagePack deserialization failed: {}", e))?;

        let mut needs_recompilation = false;

        let mut program = match rmp_serde::from_slice::<Program>(&data[program_start..json_start]) {
            Ok(prog) => prog,
            Err(_e) => {
                needs_recompilation = true;
                Program::new()
            }
        };

        let (literals, rule_tree) =
            match serde_json::from_slice::<serde_json::Value>(&data[json_start..json_end]) {
                Ok(combined_data) => {
                    let literals = combined_data
                        .get("literals")
                        .and_then(|l| serde_json::from_value(l.clone()).ok())
                        .unwrap_or_else(Vec::new);
                    let rule_tree = combined_data
                        .get("rule_tree")
                        .and_then(|rt| serde_json::from_value::<Value>(rt.clone()).ok())
                        .unwrap_or_else(|| Value::new_object());
                    (literals, rule_tree)
                }
                Err(_e) => {
                    needs_recompilation = true;
                    (Vec::new(), Value::new_object())
                }
            };

        program.entry_points = entry_points;
        program.sources = sources;
        program.literals = literals;
        program.rule_tree = rule_tree;
        program.rego_v0 = rego_v0;
        program.needs_recompilation = needs_recompilation;

        if !program.builtin_info_table.is_empty() {
            if let Err(_e) = program.initialize_resolved_builtins() {
                program.needs_recompilation = true;
            }
        }

        if program.needs_recompilation {
            Ok(DeserializationResult::Partial(program))
        } else {
            Ok(DeserializationResult::Complete(program))
        }
    }
}
