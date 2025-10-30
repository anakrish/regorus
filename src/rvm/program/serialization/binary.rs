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
    /// Serialize program to binary format with hybrid approach:
    /// - Binary serialization for most data (fast)
    /// - JSON serialization for Value fields (compatible)
    pub fn serialize_binary(&self) -> Result<Vec<u8>, String> {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(&Self::MAGIC);
        buffer.extend_from_slice(&Self::SERIALIZATION_VERSION.to_le_bytes());

        let entry_points_bin = bincode::serialize(&self.entry_points)
            .map_err(|e| format!("Entry points bincode serialization failed: {}", e))?;

        let sources_bin = bincode::serialize(&self.sources)
            .map_err(|e| format!("Sources bincode serialization failed: {}", e))?;

        let binary_data = bincode::serialize(self)
            .map_err(|e| format!("Program structure binary serialization failed: {}", e))?;

        let combined_json_data = serde_json::json!({
            "literals": self.literals,
            "rule_tree": self.rule_tree
        });
        let json_data = serde_json::to_vec(&combined_json_data)
            .map_err(|e| format!("Combined JSON serialization failed: {}", e))?;

        buffer.extend_from_slice(&(entry_points_bin.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&(sources_bin.len() as u32).to_le_bytes());
        buffer.push(if self.rego_v0 { 1 } else { 0 });
        buffer.extend_from_slice(&entry_points_bin);
        buffer.extend_from_slice(&sources_bin);

        buffer.extend_from_slice(&(binary_data.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&binary_data);
        buffer.extend_from_slice(&(json_data.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&json_data);

        Ok(buffer)
    }

    /// Deserialize only the artifact section (entry_points and sources) from binary format
    pub fn deserialize_artifacts_only(
        data: &[u8],
    ) -> Result<(IndexMap<String, usize>, Vec<SourceFile>, bool), String> {
        if data.len() < 17 {
            return Err("Data too short for artifact header".to_string());
        }

        if data[0..4] != Self::MAGIC {
            return Err("Invalid file format - magic number mismatch".to_string());
        }

        let entry_points_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let sources_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
        let rego_v0 = data[16] != 0;
        let entry_points_start = 17;
        let sources_start = entry_points_start + entry_points_len;
        let sources_end = sources_start + sources_len;

        if data.len() < sources_end {
            return Err("Data truncated in artifact section".to_string());
        }

        let entry_points = bincode::deserialize(&data[entry_points_start..sources_start])
            .unwrap_or_else(|_| IndexMap::new());

        let sources =
            bincode::deserialize(&data[sources_start..sources_end]).unwrap_or_else(|_| Vec::new());

        Ok((entry_points, sources, rego_v0))
    }

    /// Deserialize program from binary format with version checking
    pub fn deserialize_binary(data: &[u8]) -> Result<DeserializationResult, String> {
        if data.len() < 25 {
            return Err("Data too short for header".to_string());
        }

        if data[0..4] != Self::MAGIC {
            return Err("Invalid file format - magic number mismatch".to_string());
        }

        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if version > Self::SERIALIZATION_VERSION {
            return Err(format!(
                "Unsupported version {}. Maximum supported version is {}",
                version,
                Self::SERIALIZATION_VERSION
            ));
        }

        let entry_points_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let sources_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
        let rego_v0 = data[16] != 0;
        let entry_points_start = 17;
        let sources_start = entry_points_start + entry_points_len;
        let binary_len_start = sources_start + sources_len;

        if data.len() < binary_len_start + 4 {
            return Err("Data too short for binary length".to_string());
        }

        let binary_len = u32::from_le_bytes([
            data[binary_len_start],
            data[binary_len_start + 1],
            data[binary_len_start + 2],
            data[binary_len_start + 3],
        ]) as usize;

        let json_len_start = binary_len_start + 4 + binary_len;
        if data.len() < json_len_start + 4 {
            return Err("Data too short for JSON length".to_string());
        }

        let json_len = u32::from_le_bytes([
            data[json_len_start],
            data[json_len_start + 1],
            data[json_len_start + 2],
            data[json_len_start + 3],
        ]) as usize;

        let total_expected = json_len_start + 4 + json_len;
        if data.len() < total_expected {
            return Err("Data truncated".to_string());
        }

        match version {
            1 => {
                let binary_start = binary_len_start + 4;
                let json_start = json_len_start + 4;

                let entry_points =
                    bincode::deserialize(&data[entry_points_start..sources_start])
                        .map_err(|e| format!("Entry points deserialization failed: {}", e))?;

                let sources = bincode::deserialize(&data[sources_start..binary_len_start])
                    .map_err(|e| format!("Sources deserialization failed: {}", e))?;

                let mut needs_recompilation = false;

                let mut program =
                    match bincode::deserialize::<Program>(&data[binary_start..json_start]) {
                        Ok(prog) => prog,
                        Err(_e) => {
                            needs_recompilation = true;
                            Program::new()
                        }
                    };

                let (literals, rule_tree) = match serde_json::from_slice::<serde_json::Value>(
                    &data[json_start..json_start + json_len],
                ) {
                    Ok(combined) => {
                        let literals = combined
                            .get("literals")
                            .and_then(|v| serde_json::from_value::<Vec<Value>>(v.clone()).ok())
                            .unwrap_or_else(|| {
                                needs_recompilation = true;
                                Vec::new()
                            });

                        let rule_tree = combined
                            .get("rule_tree")
                            .and_then(|v| serde_json::from_value::<Value>(v.clone()).ok())
                            .unwrap_or_else(|| {
                                needs_recompilation = true;
                                Value::new_object()
                            });

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
            v => Err(format!("Unsupported version {}", v)),
        }
    }

    /// Check if data can be deserialized without actually deserializing
    pub fn can_deserialize(data: &[u8]) -> Result<bool, String> {
        if data.len() < 8 {
            return Ok(false);
        }

        if data[0..4] != Self::MAGIC {
            return Ok(false);
        }

        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        match version {
            1 => Ok(true),
            _ => Ok(false),
        }
    }

    /// Get file format information without deserializing
    pub fn get_file_info(data: &[u8]) -> Result<(u32, usize), String> {
        if data.len() < 12 {
            return Err("Data too short for header".to_string());
        }

        if data[0..4] != Self::MAGIC {
            return Err("Invalid file format".to_string());
        }

        let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let data_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;

        Ok((version, data_len))
    }
}
