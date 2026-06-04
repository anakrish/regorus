// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use bincode::config::standard;
use bincode::serde::{decode_from_slice, encode_to_vec};
use indexmap::IndexMap;

use super::super::types::SourceFile;
use super::{DeserializationResult, Program};
use crate::value::Value;

use super::value::{
    binaries_to_values, binary_to_value, BinaryValue, BinaryValueRef, BinaryValueSlice,
};
type ArtifactData = (IndexMap<String, usize>, Vec<SourceFile>, bool);

impl Program {
    /// Serialize program to binary format.
    /// Uses pure bincode for all sections now that `Value` supports serde.
    pub fn serialize_binary(&self) -> Result<Vec<u8>, String> {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(&Self::MAGIC);
        buffer.extend_from_slice(&Self::SERIALIZATION_VERSION.to_le_bytes());

        let entry_points_bin = encode_to_vec(&self.entry_points, standard())
            .map_err(|e| format!("Entry points bincode serialization failed: {}", e))?;

        let sources_bin = encode_to_vec(&self.sources, standard())
            .map_err(|e| format!("Sources bincode serialization failed: {}", e))?;

        let literals_bin = encode_to_vec(BinaryValueSlice(self.literals.as_slice()), standard())
            .map_err(|e| format!("Literals bincode serialization failed: {}", e))?;

        let rule_tree_bin = encode_to_vec(BinaryValueRef(&self.rule_tree), standard())
            .map_err(|e| format!("Rule tree bincode serialization failed: {}", e))?;

        let binary_data = encode_to_vec(self, standard())
            .map_err(|e| format!("Program structure binary serialization failed: {}", e))?;

        buffer.extend_from_slice(&(entry_points_bin.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&(sources_bin.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&(literals_bin.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&(rule_tree_bin.len() as u32).to_le_bytes());
        buffer.push(if self.rego_v0 { 1 } else { 0 });

        buffer.extend_from_slice(&entry_points_bin);
        buffer.extend_from_slice(&sources_bin);
        buffer.extend_from_slice(&literals_bin);
        buffer.extend_from_slice(&rule_tree_bin);

        buffer.extend_from_slice(&(binary_data.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&binary_data);

        Ok(buffer)
    }

    /// Deserialize only the artifact section (entry_points and sources) from binary format
    pub fn deserialize_artifacts_only(data: &[u8]) -> Result<ArtifactData, String> {
        if data.len() < 9 {
            return Err("Data too short for artifact header".to_string());
        }

        if data
            .get(0..4)
            .filter(|magic| *magic == Self::MAGIC.as_slice())
            .is_none()
        {
            return Err("Invalid file format - magic number mismatch".to_string());
        }

        let version = read_u32_le(data, 4, "Data too short for artifact header")?;

        match version {
            1 => {
                if data.len() < 17 {
                    return Err("Data too short for artifact header".to_string());
                }

                let entry_points_len =
                    read_u32_le(data, 8, "Data too short for artifact header")? as usize;
                let sources_len =
                    read_u32_le(data, 12, "Data too short for artifact header")? as usize;
                let rego_v0 = *data
                    .get(16)
                    .ok_or_else(|| "Data too short for artifact header".to_string())?
                    != 0;
                let entry_points_start = 17;
                let sources_start = entry_points_start + entry_points_len;
                let sources_end = sources_start + sources_len;

                let entry_points_bytes = take_range(
                    data,
                    entry_points_start,
                    sources_start,
                    "Data truncated in artifact section",
                )?;
                let sources_bytes = take_range(
                    data,
                    sources_start,
                    sources_end,
                    "Data truncated in artifact section",
                )?;

                let entry_points = decode_from_slice(entry_points_bytes, standard())
                    .map(|(value, _)| value)
                    .unwrap_or_else(|_| IndexMap::new());

                let sources = decode_from_slice(sources_bytes, standard())
                    .map(|(value, _)| value)
                    .unwrap_or_else(|_| Vec::new());

                Ok((entry_points, sources, rego_v0))
            }
            2 | 3 => {
                if data.len() < 25 {
                    return Err("Data too short for artifact header".to_string());
                }

                let entry_points_len =
                    read_u32_le(data, 8, "Data too short for artifact header")? as usize;
                let sources_len =
                    read_u32_le(data, 12, "Data too short for artifact header")? as usize;
                let literals_len =
                    read_u32_le(data, 16, "Data too short for artifact header")? as usize;
                let _rule_tree_len =
                    read_u32_le(data, 20, "Data too short for artifact header")? as usize;
                let rego_v0 = *data
                    .get(24)
                    .ok_or_else(|| "Data too short for artifact header".to_string())?
                    != 0;

                let entry_points_start = 25;
                let sources_start = entry_points_start + entry_points_len;
                let literals_start = sources_start + sources_len;
                let _rule_tree_start = literals_start + literals_len;

                let entry_points_bytes = take_range(
                    data,
                    entry_points_start,
                    sources_start,
                    "Data truncated in artifact section",
                )?;
                let sources_bytes = take_range(
                    data,
                    sources_start,
                    literals_start,
                    "Data truncated in artifact section",
                )?;

                let entry_points = decode_from_slice(entry_points_bytes, standard())
                    .map(|(value, _)| value)
                    .unwrap_or_else(|_| IndexMap::new());

                let sources = decode_from_slice(sources_bytes, standard())
                    .map(|(value, _)| value)
                    .unwrap_or_else(|_| Vec::new());

                Ok((entry_points, sources, rego_v0))
            }
            v => Err(format!("Unsupported version {}", v)),
        }
    }

    /// Deserialize program from binary format with version checking
    pub fn deserialize_binary(data: &[u8]) -> Result<DeserializationResult, String> {
        if data.len() < 9 {
            return Err("Data too short for header".to_string());
        }

        if data
            .get(0..4)
            .filter(|magic| *magic == Self::MAGIC.as_slice())
            .is_none()
        {
            return Err("Invalid file format - magic number mismatch".to_string());
        }

        let version = read_u32_le(data, 4, "Data too short for header")?;
        if version > Self::SERIALIZATION_VERSION {
            return Err(format!(
                "Unsupported version {}. Maximum supported version is {}",
                version,
                Self::SERIALIZATION_VERSION
            ));
        }

        match version {
            1 => {
                if data.len() < 25 {
                    return Err("Data too short for header".to_string());
                }

                let entry_points_len = read_u32_le(data, 8, "Data too short for header")? as usize;
                let sources_len = read_u32_le(data, 12, "Data too short for header")? as usize;
                let rego_v0 = *data
                    .get(16)
                    .ok_or_else(|| "Data too short for header".to_string())?
                    != 0;
                let entry_points_start = 17;
                let sources_start = entry_points_start + entry_points_len;
                let binary_len_start = sources_start + sources_len;

                let binary_len =
                    read_u32_le(data, binary_len_start, "Data too short for binary length")?
                        as usize;

                let json_len_start = binary_len_start + 4 + binary_len;
                let json_len =
                    read_u32_le(data, json_len_start, "Data too short for JSON length")? as usize;

                let total_expected = json_len_start + 4 + json_len;
                if data.len() < total_expected {
                    return Err("Data truncated".to_string());
                }

                let binary_start = binary_len_start + 4;
                let json_start = json_len_start + 4;

                let entry_points_bytes =
                    take_range(data, entry_points_start, sources_start, "Data truncated")?;
                let sources_bytes =
                    take_range(data, sources_start, binary_len_start, "Data truncated")?;

                let entry_points = decode_from_slice(entry_points_bytes, standard())
                    .map(|(value, _)| value)
                    .map_err(|e| format!("Entry points deserialization failed: {}", e))?;

                let sources = decode_from_slice(sources_bytes, standard())
                    .map(|(value, _)| value)
                    .map_err(|e| format!("Sources deserialization failed: {}", e))?;

                let mut needs_recompilation = false;

                let program_bytes = take_range(data, binary_start, json_start, "Data truncated")?;

                let mut program = match decode_from_slice::<Program, _>(program_bytes, standard()) {
                    Ok((prog, _)) => prog,
                    Err(_e) => {
                        needs_recompilation = true;
                        Program::new()
                    }
                };

                let json_bytes =
                    take_range(data, json_start, json_start + json_len, "Data truncated")?;

                let (literals, rule_tree) =
                    match serde_json::from_slice::<serde_json::Value>(json_bytes) {
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
            2 | 3 => {
                if data.len() < 29 {
                    return Err("Data too short for header".to_string());
                }

                let entry_points_len = read_u32_le(data, 8, "Data too short for header")? as usize;
                let sources_len = read_u32_le(data, 12, "Data too short for header")? as usize;
                let literals_len = read_u32_le(data, 16, "Data too short for header")? as usize;
                let rule_tree_len = read_u32_le(data, 20, "Data too short for header")? as usize;
                let rego_v0 = *data
                    .get(24)
                    .ok_or_else(|| "Data too short for header".to_string())?
                    != 0;

                let entry_points_start = 25;
                let sources_start = entry_points_start + entry_points_len;
                let literals_start = sources_start + sources_len;
                let rule_tree_start = literals_start + literals_len;
                let binary_len_start = rule_tree_start + rule_tree_len;

                let binary_len =
                    read_u32_le(data, binary_len_start, "Data too short for binary length")?
                        as usize;

                let binary_start = binary_len_start + 4;
                let binary_end = binary_start + binary_len;

                if data.len() < binary_end {
                    return Err("Data truncated".to_string());
                }

                let entry_points_bytes =
                    take_range(data, entry_points_start, sources_start, "Data truncated")?;
                let sources_bytes =
                    take_range(data, sources_start, literals_start, "Data truncated")?;

                let entry_points = decode_from_slice(entry_points_bytes, standard())
                    .map(|(value, _)| value)
                    .map_err(|e| format!("Entry points deserialization failed: {}", e))?;

                let sources = decode_from_slice(sources_bytes, standard())
                    .map(|(value, _)| value)
                    .map_err(|e| format!("Sources deserialization failed: {}", e))?;

                let mut needs_recompilation = false;

                let literals_bytes =
                    take_range(data, literals_start, rule_tree_start, "Data truncated")?;

                let literals =
                    match decode_from_slice::<Vec<BinaryValue>, _>(literals_bytes, standard()) {
                        Ok((binary_literals, _)) => match binaries_to_values(binary_literals) {
                            Ok(values) => values,
                            Err(_e) => {
                                needs_recompilation = true;
                                Vec::new()
                            }
                        },
                        Err(_e) => {
                            needs_recompilation = true;
                            Vec::new()
                        }
                    };

                let rule_tree_bytes =
                    take_range(data, rule_tree_start, binary_len_start, "Data truncated")?;

                let rule_tree =
                    match decode_from_slice::<BinaryValue, _>(rule_tree_bytes, standard()) {
                        Ok((binary_tree, _)) => match binary_to_value(binary_tree) {
                            Ok(value) => value,
                            Err(_e) => {
                                needs_recompilation = true;
                                Value::new_object()
                            }
                        },
                        Err(_e) => {
                            needs_recompilation = true;
                            Value::new_object()
                        }
                    };

                let program_bytes = take_range(data, binary_start, binary_end, "Data truncated")?;

                let mut program = match decode_from_slice::<Program, _>(program_bytes, standard()) {
                    Ok((prog, _)) => prog,
                    Err(_e) => {
                        needs_recompilation = true;
                        Program::new()
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

        if data
            .get(0..4)
            .filter(|magic| *magic == Self::MAGIC.as_slice())
            .is_none()
        {
            return Ok(false);
        }

        let version = match read_u32_le(data, 4, "Data too short for header") {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };

        match version {
            1..=3 => Ok(true),
            _ => Ok(false),
        }
    }

    /// Get file format information without deserializing
    pub fn get_file_info(data: &[u8]) -> Result<(u32, usize), String> {
        if data.len() < 9 {
            return Err("Data too short for header".to_string());
        }

        if data
            .get(0..4)
            .filter(|magic| *magic == Self::MAGIC.as_slice())
            .is_none()
        {
            return Err("Invalid file format".to_string());
        }

        let version = read_u32_le(data, 4, "Data too short for header")?;

        match version {
            1 => {
                if data.len() < 25 {
                    return Err("Data too short for header".to_string());
                }

                let entry_points_len = read_u32_le(data, 8, "Data too short for header")? as usize;
                let sources_len = read_u32_le(data, 12, "Data too short for header")? as usize;
                let binary_len_start = 17 + entry_points_len + sources_len;

                let binary_len =
                    read_u32_le(data, binary_len_start, "Data too short for binary length")?
                        as usize;

                Ok((version, binary_len))
            }
            2 | 3 => {
                if data.len() < 29 {
                    return Err("Data too short for header".to_string());
                }

                let entry_points_len = read_u32_le(data, 8, "Data too short for header")? as usize;
                let sources_len = read_u32_le(data, 12, "Data too short for header")? as usize;
                let literals_len = read_u32_le(data, 16, "Data too short for header")? as usize;
                let rule_tree_len = read_u32_le(data, 20, "Data too short for header")? as usize;
                let binary_len_start =
                    25 + entry_points_len + sources_len + literals_len + rule_tree_len;

                let binary_len =
                    read_u32_le(data, binary_len_start, "Data too short for binary length")?
                        as usize;

                Ok((version, binary_len))
            }
            v => Err(format!("Unsupported version {}", v)),
        }
    }
}

fn read_u32_le(data: &[u8], offset: usize, err: &str) -> Result<u32, String> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| err.to_string())?;
    let array: [u8; 4] = bytes.try_into().map_err(|_| err.to_string())?;
    Ok(u32::from_le_bytes(array))
}

fn take_range<'a>(data: &'a [u8], start: usize, end: usize, err: &str) -> Result<&'a [u8], String> {
    data.get(start..end).ok_or_else(|| err.to_string())
}
