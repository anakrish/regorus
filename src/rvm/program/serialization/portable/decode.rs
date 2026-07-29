// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Decoder for the RVMP portable execution artifact format.
//!
//! Decoding is strictly validating and allocation-bounded:
//!
//! * the header, directory, and CRC-32 are checked before any section is read;
//! * every declared count is checked against [`PortableLimits`] *and* against
//!   the bytes actually available, so a small artifact can never request a
//!   large allocation;
//! * unknown optional sections are skipped, unknown required sections are
//!   rejected;
//! * every index (literal, rule, builtin, string, jump target) is verified
//!   against the table it points into.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use indexmap::IndexMap;

use super::errors::{PortableError, PortableInfo, PortableLimits, PortableResult};
use super::format::{
    crc32, is_known_section, path_component, rule_type, DIRECTORY_ENTRY_SIZE, FEATURE_DEBUG_INFO,
    FEATURE_HOST_AWAIT, FEATURE_METADATA, FEATURE_REGO_V0, FEATURE_REQUIRED_MASK, FORMAT_VERSION,
    HEADER_SIZE, INSTRUCTION_WORD_SIZE, KNOWN_REQUIRED_FEATURES, MAGIC, MIN_FORMAT_VERSION,
    PROGRAM_FLAGS_KNOWN, PROGRAM_FLAG_HOST_AWAIT, PROGRAM_FLAG_REGO_V0,
    PROGRAM_FLAG_RUNTIME_RECURSION_CHECK, SECTION_BUILTINS, SECTION_ENTRY_POINTS,
    SECTION_FLAG_REQUIRED, SECTION_INSTRUCTIONS, SECTION_INSTRUCTION_PARAMS, SECTION_LITERALS,
    SECTION_METADATA, SECTION_PROGRAM_HEADER, SECTION_RULES, SECTION_RULE_TREE, SECTION_SOURCES,
    SECTION_SPANS, SECTION_STRINGS, SPAN_ABSENT,
};
use super::instructions::{
    comprehension_mode_from_code, decode_instruction, loop_mode_from_code, InstructionWord,
};
use super::io::Reader;
use super::strings::StringTable;
use super::values::{decode_value, ValueBudget};
use crate::rvm::instructions::{
    ArrayCreateParams, BuiltinCallParams, ChainedIndexParams, ComprehensionBeginParams,
    FunctionCallParams, InstructionData, LiteralOrRegister, LoopStartParams, ObjectCreateParams,
    SetCreateParams, VirtualDataDocumentLookupParams,
};
use crate::rvm::program::{
    BuiltinInfo, FunctionInfo, ProgramMetadata, RuleInfo, RuleType, SourceFile, SpanInfo,
};
use crate::rvm::Program;
use crate::value::Value;

/// A validated view of a single directory entry.
#[derive(Debug, Clone, Copy)]
struct SectionRef {
    id: u32,
    offset: usize,
    length: usize,
    flags: u32,
}

/// Parsed and validated file header.
#[derive(Debug, Clone, Copy)]
struct Header {
    format_version: u16,
    feature_flags: u32,
    section_count: u32,
    directory_offset: usize,
    total_size: usize,
    checksum: u32,
}

fn parse_header(data: &[u8], limits: &PortableLimits) -> PortableResult<Header> {
    PortableLimits::check("artifact size", data.len(), limits.max_total_size)?;

    if data.len() < HEADER_SIZE {
        return Err(PortableError::Truncated {
            offset: 0,
            needed: HEADER_SIZE,
            available: data.len(),
        });
    }

    let mut reader = Reader::new(data);
    let magic = reader.take(4)?;
    if magic != MAGIC {
        return Err(PortableError::InvalidMagic);
    }

    let format_version = reader.u16()?;
    if format_version < MIN_FORMAT_VERSION || format_version > FORMAT_VERSION {
        return Err(PortableError::UnsupportedVersion {
            found: format_version,
            min: MIN_FORMAT_VERSION,
            max: FORMAT_VERSION,
        });
    }

    let header_size = reader.u16()?;
    if usize::from(header_size) != HEADER_SIZE {
        return Err(PortableError::MalformedHeader {
            reason: "unexpected header size",
        });
    }

    let feature_flags = reader.u32()?;
    let unknown_required = feature_flags & FEATURE_REQUIRED_MASK & !KNOWN_REQUIRED_FEATURES;
    if unknown_required != 0 {
        return Err(PortableError::UnsupportedFeatures {
            flags: unknown_required,
        });
    }

    let section_count = reader.u32()?;
    let directory_offset = reader.u32()?;
    let total_size = reader.u32()?;
    let checksum = reader.u32()?;
    let reserved = reader.u32()?;
    if reserved != 0 {
        return Err(PortableError::MalformedHeader {
            reason: "reserved header word must be zero",
        });
    }

    let section_count_usize =
        usize::try_from(section_count).map_err(|_| PortableError::IntegerOverflow {
            context: "section count",
        })?;
    PortableLimits::check("section count", section_count_usize, limits.max_sections)?;

    let directory_offset_usize =
        usize::try_from(directory_offset).map_err(|_| PortableError::IntegerOverflow {
            context: "directory offset",
        })?;
    if directory_offset_usize != HEADER_SIZE {
        return Err(PortableError::MalformedHeader {
            reason: "directory must immediately follow the header",
        });
    }

    let total_size_usize =
        usize::try_from(total_size).map_err(|_| PortableError::IntegerOverflow {
            context: "artifact size",
        })?;
    if total_size_usize != data.len() {
        return Err(PortableError::MalformedHeader {
            reason: "declared total size does not match the input length",
        });
    }

    let directory_bytes = section_count_usize
        .checked_mul(DIRECTORY_ENTRY_SIZE)
        .ok_or(PortableError::IntegerOverflow {
            context: "directory size",
        })?;
    let directory_end = directory_offset_usize.checked_add(directory_bytes).ok_or(
        PortableError::IntegerOverflow {
            context: "directory size",
        },
    )?;
    if directory_end > total_size_usize {
        return Err(PortableError::MalformedHeader {
            reason: "section directory extends past the end of the artifact",
        });
    }

    Ok(Header {
        format_version,
        feature_flags,
        section_count,
        directory_offset: directory_offset_usize,
        total_size: total_size_usize,
        checksum,
    })
}

fn verify_checksum(data: &[u8], header: &Header) -> PortableResult<()> {
    let payload =
        data.get(HEADER_SIZE..header.total_size)
            .ok_or(PortableError::MalformedHeader {
                reason: "payload range is outside the artifact",
            })?;
    let computed = crc32(payload);
    if computed != header.checksum {
        return Err(PortableError::ChecksumMismatch {
            stored: header.checksum,
            computed,
        });
    }
    Ok(())
}

fn parse_directory(data: &[u8], header: &Header) -> PortableResult<Vec<SectionRef>> {
    let count =
        usize::try_from(header.section_count).map_err(|_| PortableError::IntegerOverflow {
            context: "section count",
        })?;
    let directory_bytes =
        count
            .checked_mul(DIRECTORY_ENTRY_SIZE)
            .ok_or(PortableError::IntegerOverflow {
                context: "directory size",
            })?;
    let directory_end = header.directory_offset.checked_add(directory_bytes).ok_or(
        PortableError::IntegerOverflow {
            context: "directory size",
        },
    )?;
    let directory =
        data.get(header.directory_offset..directory_end)
            .ok_or(PortableError::MalformedHeader {
                reason: "section directory extends past the end of the artifact",
            })?;

    let mut reader = Reader::new(directory);
    let mut sections: Vec<SectionRef> = Vec::with_capacity(count);
    let mut seen_ids: Vec<u32> = Vec::with_capacity(count);

    for _ in 0..count {
        let id = reader.u32()?;
        let offset = reader.u32()?;
        let length = reader.u32()?;
        let flags = reader.u32()?;

        if seen_ids.contains(&id) {
            return Err(PortableError::DuplicateSection { id });
        }
        seen_ids.push(id);

        let offset_usize = usize::try_from(offset).map_err(|_| PortableError::IntegerOverflow {
            context: "section offset",
        })?;
        let length_usize = usize::try_from(length).map_err(|_| PortableError::IntegerOverflow {
            context: "section length",
        })?;
        let end = offset_usize
            .checked_add(length_usize)
            .ok_or(PortableError::SectionOutOfBounds { id, offset, length })?;
        if offset_usize < directory_end || end > header.total_size {
            return Err(PortableError::SectionOutOfBounds { id, offset, length });
        }

        sections.push(SectionRef {
            id,
            offset: offset_usize,
            length: length_usize,
            flags,
        });
    }

    // Reject overlapping sections; ordering by offset makes this an O(n log n)
    // scan rather than a quadratic comparison.
    let mut ordered = sections.clone();
    ordered.sort_by_key(|section| section.offset);
    let mut previous_end = directory_end;
    for section in &ordered {
        if section.offset < previous_end {
            return Err(PortableError::SectionOverlap { id: section.id });
        }
        previous_end = section
            .offset
            .checked_add(section.length)
            .ok_or(PortableError::SectionOverlap { id: section.id })?;
    }

    for section in &sections {
        if !is_known_section(section.id) && section.flags & SECTION_FLAG_REQUIRED != 0 {
            return Err(PortableError::UnknownRequiredSection { id: section.id });
        }
    }

    Ok(sections)
}

fn section_body<'a>(
    data: &'a [u8],
    sections: &[SectionRef],
    id: u32,
) -> PortableResult<Option<&'a [u8]>> {
    let Some(section) = sections.iter().find(|section| section.id == id) else {
        return Ok(None);
    };
    let end = section
        .offset
        .checked_add(section.length)
        .ok_or(PortableError::IntegerOverflow {
            context: "section range",
        })?;
    let body = data
        .get(section.offset..end)
        .ok_or(PortableError::SectionOutOfBounds {
            id,
            offset: u32::try_from(section.offset).unwrap_or(u32::MAX),
            length: u32::try_from(section.length).unwrap_or(u32::MAX),
        })?;
    Ok(Some(body))
}

fn required_section<'a>(
    data: &'a [u8],
    sections: &[SectionRef],
    id: u32,
) -> PortableResult<&'a [u8]> {
    section_body(data, sections, id)?.ok_or(PortableError::MissingSection { id })
}

/// Inspect an artifact header without decoding the program.
pub fn inspect(data: &[u8]) -> PortableResult<PortableInfo> {
    let limits = PortableLimits::new();
    let header = parse_header(data, &limits)?;
    Ok(PortableInfo {
        format_version: header.format_version,
        feature_flags: header.feature_flags,
        section_count: header.section_count,
        total_size: u32::try_from(header.total_size).unwrap_or(u32::MAX),
        has_debug_info: header.feature_flags & FEATURE_DEBUG_INFO != 0,
        has_metadata: header.feature_flags & FEATURE_METADATA != 0,
        uses_host_await: header.feature_flags & FEATURE_HOST_AWAIT != 0,
        rego_v0: header.feature_flags & FEATURE_REGO_V0 != 0,
    })
}

/// Returns `true` when `data` looks like a portable artifact this build can read.
pub fn is_portable_artifact(data: &[u8]) -> bool {
    let Some(prefix) = data.get(..6) else {
        return false;
    };
    let Some(magic) = prefix.get(..4) else {
        return false;
    };
    if magic != MAGIC {
        return false;
    }
    let Some(version_bytes) = prefix.get(4..6) else {
        return false;
    };
    let Ok(version_array) = <[u8; 2]>::try_from(version_bytes) else {
        return false;
    };
    let version = u16::from_le_bytes(version_array);
    version >= MIN_FORMAT_VERSION && version <= FORMAT_VERSION
}

/// Decode a portable artifact into a [`Program`].
pub fn decode_program(data: &[u8], limits: &PortableLimits) -> PortableResult<Program> {
    let header = parse_header(data, limits)?;
    verify_checksum(data, &header)?;
    let sections = parse_directory(data, &header)?;

    let strings_body = required_section(data, &sections, SECTION_STRINGS)?;
    let strings = StringTable::decode(strings_body, limits)?;
    let mut budget = ValueBudget::new(limits);

    let mut program = Program::new();

    decode_program_header(
        required_section(data, &sections, SECTION_PROGRAM_HEADER)?,
        &mut program,
    )?;

    program.instructions = decode_instructions(
        required_section(data, &sections, SECTION_INSTRUCTIONS)?,
        limits,
    )?;
    program.instruction_data = decode_instruction_params(
        required_section(data, &sections, SECTION_INSTRUCTION_PARAMS)?,
        limits,
    )?;
    program.literals = decode_literals(
        required_section(data, &sections, SECTION_LITERALS)?,
        &strings,
        limits,
        &mut budget,
    )?;
    program.builtin_info_table = decode_builtins(
        required_section(data, &sections, SECTION_BUILTINS)?,
        &strings,
        limits,
    )?;
    program.entry_points = decode_entry_points(
        required_section(data, &sections, SECTION_ENTRY_POINTS)?,
        &strings,
        limits,
    )?;
    program.rule_infos = decode_rules(
        required_section(data, &sections, SECTION_RULES)?,
        &strings,
        limits,
    )?;
    program.rule_tree = decode_rule_tree(
        required_section(data, &sections, SECTION_RULE_TREE)?,
        &strings,
        limits,
        &mut budget,
    )?;

    program.sources = match section_body(data, &sections, SECTION_SOURCES)? {
        Some(body) => decode_sources(body, &strings, limits)?,
        None => Vec::new(),
    };

    program.instruction_spans = match section_body(data, &sections, SECTION_SPANS)? {
        Some(body) => decode_spans(body, limits)?,
        None => alloc::vec![None; program.instructions.len()],
    };

    if let Some(body) = section_body(data, &sections, SECTION_METADATA)? {
        program.metadata = decode_metadata(body, &strings, limits, &mut budget)?;
    }

    validate_consistency(&program, &header)?;

    program
        .initialize_resolved_builtins()
        .map_err(|err| PortableError::ProgramInvalid(err.to_string()))?;

    Ok(program)
}

fn decode_program_header(body: &[u8], program: &mut Program) -> PortableResult<()> {
    let mut reader = Reader::new(body);
    program.main_entry_point = reader.u32()?;
    program.max_rule_window_size = reader.u8()?;
    program.dispatch_window_size = reader.u8()?;
    let flags = reader.u8()?;
    if flags & !PROGRAM_FLAGS_KNOWN != 0 {
        return Err(PortableError::MalformedHeader {
            reason: "unknown program header flag bits",
        });
    }
    let reserved = reader.u8()?;
    if reserved != 0 {
        return Err(PortableError::MalformedHeader {
            reason: "reserved program header byte must be zero",
        });
    }
    reader.expect_end(SECTION_PROGRAM_HEADER)?;

    program.rego_v0 = flags & PROGRAM_FLAG_REGO_V0 != 0;
    program.needs_runtime_recursion_check = flags & PROGRAM_FLAG_RUNTIME_RECURSION_CHECK != 0;
    program.has_host_await = flags & PROGRAM_FLAG_HOST_AWAIT != 0;
    program.needs_recompilation = false;
    Ok(())
}

fn read_count(
    reader: &mut Reader<'_>,
    label: &'static str,
    max: usize,
    per_item_bytes: usize,
) -> PortableResult<usize> {
    let raw = reader.u32()?;
    let count = usize::try_from(raw).map_err(|_| PortableError::IntegerOverflow {
        context: "table count",
    })?;
    PortableLimits::check(label, count, max)?;
    if per_item_bytes > 0 {
        let needed = count
            .checked_mul(per_item_bytes)
            .ok_or(PortableError::IntegerOverflow {
                context: "table size",
            })?;
        if needed > reader.remaining() {
            return Err(PortableError::Truncated {
                offset: reader.position(),
                needed,
                available: reader.remaining(),
            });
        }
    } else if count > reader.remaining() {
        // Every variable-length record occupies at least one byte.
        return Err(PortableError::Truncated {
            offset: reader.position(),
            needed: count,
            available: reader.remaining(),
        });
    }
    Ok(count)
}

fn decode_instructions(
    body: &[u8],
    limits: &PortableLimits,
) -> PortableResult<Vec<crate::rvm::Instruction>> {
    let mut reader = Reader::new(body);
    let count = read_count(
        &mut reader,
        "instructions",
        limits.max_instructions,
        INSTRUCTION_WORD_SIZE,
    )?;
    let mut instructions = Vec::with_capacity(count);
    for index in 0..count {
        let bytes = reader.take(INSTRUCTION_WORD_SIZE)?;
        let word_bytes = <[u8; INSTRUCTION_WORD_SIZE]>::try_from(bytes).map_err(|_| {
            PortableError::Truncated {
                offset: reader.position(),
                needed: INSTRUCTION_WORD_SIZE,
                available: 0,
            }
        })?;
        instructions.push(decode_instruction(
            InstructionWord::from_bytes(word_bytes),
            index,
        )?);
    }
    reader.expect_end(SECTION_INSTRUCTIONS)?;
    Ok(instructions)
}

fn decode_instruction_params(
    body: &[u8],
    limits: &PortableLimits,
) -> PortableResult<InstructionData> {
    let mut reader = Reader::new(body);
    let mut data = InstructionData::new();

    let loop_count = read_count(&mut reader, "loop params", limits.max_params_per_table, 10)?;
    data.loop_params.reserve(loop_count);
    for _ in 0..loop_count {
        let mode = loop_mode_from_code(reader.u8()?)?;
        let collection = reader.u8()?;
        let key_reg = reader.u8()?;
        let value_reg = reader.u8()?;
        let result_reg = reader.u8()?;
        let _reserved = reader.u8()?;
        let body_start = reader.u16()?;
        let loop_end = reader.u16()?;
        data.loop_params.push(LoopStartParams {
            mode,
            collection,
            key_reg,
            value_reg,
            result_reg,
            body_start,
            loop_end,
        });
    }

    let builtin_count = read_count(
        &mut reader,
        "builtin calls",
        limits.max_params_per_table,
        12,
    )?;
    data.builtin_call_params.reserve(builtin_count);
    for _ in 0..builtin_count {
        let dest = reader.u8()?;
        let num_args = reader.u8()?;
        let args = read_arg_registers(&mut reader)?;
        let builtin_index = reader.u16()?;
        if usize::from(num_args) > args.len() {
            return Err(PortableError::Inconsistent {
                reason: "builtin call declares more arguments than the register slots allow",
            });
        }
        data.builtin_call_params.push(BuiltinCallParams {
            dest,
            builtin_index,
            num_args,
            args,
        });
    }

    let function_count = read_count(
        &mut reader,
        "function calls",
        limits.max_params_per_table,
        12,
    )?;
    data.function_call_params.reserve(function_count);
    for _ in 0..function_count {
        let dest = reader.u8()?;
        let num_args = reader.u8()?;
        let args = read_arg_registers(&mut reader)?;
        let func_rule_index = reader.u16()?;
        if usize::from(num_args) > args.len() {
            return Err(PortableError::Inconsistent {
                reason: "function call declares more arguments than the register slots allow",
            });
        }
        data.function_call_params.push(FunctionCallParams {
            dest,
            func_rule_index,
            num_args,
            args,
        });
    }

    let object_count = read_count(
        &mut reader,
        "object creates",
        limits.max_params_per_table,
        0,
    )?;
    data.object_create_params.reserve(object_count);
    for _ in 0..object_count {
        let dest = reader.u8()?;
        let template_literal_idx = reader.u16()?;
        let literal_field_count = reader.varint_usize()?;
        PortableLimits::check(
            "object create literal fields",
            literal_field_count,
            limits.max_object_create_fields,
        )?;
        if literal_field_count > reader.remaining() {
            return Err(PortableError::Truncated {
                offset: reader.position(),
                needed: literal_field_count,
                available: reader.remaining(),
            });
        }
        let mut literal_key_fields = Vec::with_capacity(literal_field_count);
        for _ in 0..literal_field_count {
            let literal_index = reader.u16()?;
            let register = reader.u8()?;
            literal_key_fields.push((literal_index, register));
        }

        let dynamic_field_count = reader.varint_usize()?;
        PortableLimits::check(
            "object create dynamic fields",
            dynamic_field_count,
            limits.max_object_create_fields,
        )?;
        if dynamic_field_count > reader.remaining() {
            return Err(PortableError::Truncated {
                offset: reader.position(),
                needed: dynamic_field_count,
                available: reader.remaining(),
            });
        }
        let mut fields = Vec::with_capacity(dynamic_field_count);
        for _ in 0..dynamic_field_count {
            let key_register = reader.u8()?;
            let value_register = reader.u8()?;
            fields.push((key_register, value_register));
        }

        data.object_create_params.push(ObjectCreateParams {
            dest,
            template_literal_idx,
            literal_key_fields,
            fields,
        });
    }

    let array_count = read_count(&mut reader, "array creates", limits.max_params_per_table, 0)?;
    data.array_create_params.reserve(array_count);
    for _ in 0..array_count {
        let dest = reader.u8()?;
        let elements = read_register_list(&mut reader, limits)?;
        data.array_create_params
            .push(ArrayCreateParams { dest, elements });
    }

    let set_count = read_count(&mut reader, "set creates", limits.max_params_per_table, 0)?;
    data.set_create_params.reserve(set_count);
    for _ in 0..set_count {
        let dest = reader.u8()?;
        let elements = read_register_list(&mut reader, limits)?;
        data.set_create_params
            .push(SetCreateParams { dest, elements });
    }

    let lookup_count = read_count(
        &mut reader,
        "virtual data lookups",
        limits.max_params_per_table,
        0,
    )?;
    data.virtual_data_document_lookup_params
        .reserve(lookup_count);
    for _ in 0..lookup_count {
        let dest = reader.u8()?;
        let path_components = read_path_components(&mut reader, limits)?;
        data.virtual_data_document_lookup_params
            .push(VirtualDataDocumentLookupParams {
                dest,
                path_components,
            });
    }

    let chained_count = read_count(
        &mut reader,
        "chained indexes",
        limits.max_params_per_table,
        0,
    )?;
    data.chained_index_params.reserve(chained_count);
    for _ in 0..chained_count {
        let dest = reader.u8()?;
        let root = reader.u8()?;
        let path_components = read_path_components(&mut reader, limits)?;
        data.chained_index_params.push(ChainedIndexParams {
            dest,
            root,
            path_components,
        });
    }

    let comprehension_count = read_count(
        &mut reader,
        "comprehensions",
        limits.max_params_per_table,
        10,
    )?;
    data.comprehension_begin_params.reserve(comprehension_count);
    for _ in 0..comprehension_count {
        let mode = comprehension_mode_from_code(reader.u8()?)?;
        let collection_reg = reader.u8()?;
        let result_reg = reader.u8()?;
        let key_reg = reader.u8()?;
        let value_reg = reader.u8()?;
        let _reserved = reader.u8()?;
        let body_start = reader.u16()?;
        let comprehension_end = reader.u16()?;
        data.comprehension_begin_params
            .push(ComprehensionBeginParams {
                mode,
                collection_reg,
                result_reg,
                key_reg,
                value_reg,
                body_start,
                comprehension_end,
            });
    }

    reader.expect_end(SECTION_INSTRUCTION_PARAMS)?;
    Ok(data)
}

fn read_arg_registers(reader: &mut Reader<'_>) -> PortableResult<[u8; 8]> {
    let bytes = reader.take(8)?;
    <[u8; 8]>::try_from(bytes).map_err(|_| PortableError::Truncated {
        offset: reader.position(),
        needed: 8,
        available: 0,
    })
}

fn read_register_list(reader: &mut Reader<'_>, limits: &PortableLimits) -> PortableResult<Vec<u8>> {
    let count = reader.varint_usize()?;
    PortableLimits::check("create elements", count, limits.max_create_elements)?;
    Ok(reader.take(count)?.to_vec())
}

fn read_path_components(
    reader: &mut Reader<'_>,
    limits: &PortableLimits,
) -> PortableResult<Vec<LiteralOrRegister>> {
    let count = reader.varint_usize()?;
    PortableLimits::check("path components", count, limits.max_path_components)?;
    if count > reader.remaining() {
        return Err(PortableError::Truncated {
            offset: reader.position(),
            needed: count,
            available: reader.remaining(),
        });
    }
    let mut components = Vec::with_capacity(count);
    for _ in 0..count {
        let tag = reader.u8()?;
        match tag {
            path_component::LITERAL => {
                components.push(LiteralOrRegister::Literal(reader.u16()?));
            }
            path_component::REGISTER => {
                components.push(LiteralOrRegister::Register(reader.u8()?));
            }
            other => {
                return Err(PortableError::InvalidDiscriminant {
                    kind: "LiteralOrRegister",
                    value: u32::from(other),
                })
            }
        }
    }
    Ok(components)
}

fn decode_literals(
    body: &[u8],
    strings: &StringTable<'_>,
    limits: &PortableLimits,
    budget: &mut ValueBudget,
) -> PortableResult<Vec<Value>> {
    let mut reader = Reader::new(body);
    let count = read_count(&mut reader, "literals", limits.max_literals, 0)?;
    let mut literals = Vec::with_capacity(count);
    for _ in 0..count {
        literals.push(decode_value(&mut reader, strings, 0, limits, budget)?);
    }
    reader.expect_end(SECTION_LITERALS)?;
    Ok(literals)
}

fn decode_builtins(
    body: &[u8],
    strings: &StringTable<'_>,
    limits: &PortableLimits,
) -> PortableResult<Vec<BuiltinInfo>> {
    let mut reader = Reader::new(body);
    let count = read_count(&mut reader, "builtins", limits.max_builtins, 0)?;
    let mut builtins = Vec::with_capacity(count);
    for _ in 0..count {
        let name = strings.get(reader.varint_u32()?)?;
        let num_args = reader.u16()?;
        builtins.push(BuiltinInfo {
            name: String::from(name),
            num_args,
        });
    }
    reader.expect_end(SECTION_BUILTINS)?;
    Ok(builtins)
}

fn decode_entry_points(
    body: &[u8],
    strings: &StringTable<'_>,
    limits: &PortableLimits,
) -> PortableResult<IndexMap<String, usize>> {
    let mut reader = Reader::new(body);
    let count = read_count(&mut reader, "entry points", limits.max_entry_points, 0)?;
    let mut entry_points = IndexMap::with_capacity(count);
    for _ in 0..count {
        let path = strings.get(reader.varint_u32()?)?;
        let rule_index = reader.varint_usize()?;
        entry_points.insert(String::from(path), rule_index);
    }
    reader.expect_end(SECTION_ENTRY_POINTS)?;
    Ok(entry_points)
}

const RULE_FLAG_HAS_FUNCTION_INFO: u8 = 1 << 0;
const RULE_FLAG_HAS_DEFAULT_LITERAL: u8 = 1 << 1;
const RULE_FLAG_EARLY_EXIT: u8 = 1 << 2;
const RULE_FLAGS_KNOWN: u8 =
    RULE_FLAG_HAS_FUNCTION_INFO | RULE_FLAG_HAS_DEFAULT_LITERAL | RULE_FLAG_EARLY_EXIT;

fn rule_type_from_code(code: u8) -> PortableResult<RuleType> {
    match code {
        rule_type::COMPLETE => Ok(RuleType::Complete),
        rule_type::PARTIAL_SET => Ok(RuleType::PartialSet),
        rule_type::PARTIAL_OBJECT => Ok(RuleType::PartialObject),
        other => Err(PortableError::InvalidDiscriminant {
            kind: "RuleType",
            value: u32::from(other),
        }),
    }
}

fn decode_rules(
    body: &[u8],
    strings: &StringTable<'_>,
    limits: &PortableLimits,
) -> PortableResult<Vec<RuleInfo>> {
    let mut reader = Reader::new(body);
    let count = read_count(&mut reader, "rules", limits.max_rules, 0)?;
    let mut rules = Vec::with_capacity(count);

    for _ in 0..count {
        let name = strings.get(reader.varint_u32()?)?;
        let kind = rule_type_from_code(reader.u8()?)?;
        let flags = reader.u8()?;
        if flags & !RULE_FLAGS_KNOWN != 0 {
            return Err(PortableError::Inconsistent {
                reason: "unknown rule flag bits",
            });
        }
        let result_reg = reader.u8()?;
        let num_registers = reader.u8()?;
        let default_literal_index = if flags & RULE_FLAG_HAS_DEFAULT_LITERAL != 0 {
            Some(reader.u16()?)
        } else {
            None
        };

        let definition_count = reader.varint_usize()?;
        PortableLimits::check(
            "rule definitions",
            definition_count,
            limits.max_definitions_per_rule,
        )?;
        if definition_count > reader.remaining() {
            return Err(PortableError::Truncated {
                offset: reader.position(),
                needed: definition_count,
                available: reader.remaining(),
            });
        }
        let mut definitions = Vec::with_capacity(definition_count);
        for _ in 0..definition_count {
            let block_count = reader.varint_usize()?;
            PortableLimits::check(
                "rule definition blocks",
                block_count,
                limits.max_definition_len,
            )?;
            if block_count > reader.remaining() {
                return Err(PortableError::Truncated {
                    offset: reader.position(),
                    needed: block_count,
                    available: reader.remaining(),
                });
            }
            let mut blocks = Vec::with_capacity(block_count);
            for _ in 0..block_count {
                blocks.push(reader.varint_u32()?);
            }
            definitions.push(blocks);
        }

        let destructuring_count = reader.varint_usize()?;
        PortableLimits::check(
            "rule destructuring blocks",
            destructuring_count,
            limits.max_definitions_per_rule,
        )?;
        if destructuring_count > reader.remaining() {
            return Err(PortableError::Truncated {
                offset: reader.position(),
                needed: destructuring_count,
                available: reader.remaining(),
            });
        }
        let mut destructuring_blocks = Vec::with_capacity(destructuring_count);
        for _ in 0..destructuring_count {
            let raw = reader.varint()?;
            if raw == 0 {
                destructuring_blocks.push(None);
            } else {
                let value = raw.checked_sub(1).ok_or(PortableError::IntegerOverflow {
                    context: "destructuring block",
                })?;
                destructuring_blocks.push(Some(u32::try_from(value).map_err(|_| {
                    PortableError::FieldTooLarge {
                        field: "destructuring block",
                        value,
                    }
                })?));
            }
        }

        let function_info = if flags & RULE_FLAG_HAS_FUNCTION_INFO != 0 {
            let num_params = reader.varint_u32()?;
            let name_count = reader.varint_usize()?;
            PortableLimits::check(
                "rule function parameters",
                name_count,
                limits.max_function_params,
            )?;
            if name_count > reader.remaining() {
                return Err(PortableError::Truncated {
                    offset: reader.position(),
                    needed: name_count,
                    available: reader.remaining(),
                });
            }
            let mut param_names = Vec::with_capacity(name_count);
            for _ in 0..name_count {
                param_names.push(String::from(strings.get(reader.varint_u32()?)?));
            }
            Some(FunctionInfo {
                param_names,
                num_params,
            })
        } else {
            None
        };

        rules.push(RuleInfo {
            name: String::from(name),
            rule_type: kind,
            definitions: crate::Rc::new(definitions),
            function_info,
            default_literal_index,
            result_reg,
            num_registers,
            destructuring_blocks,
            early_exit_on_first_success: flags & RULE_FLAG_EARLY_EXIT != 0,
        });
    }

    reader.expect_end(SECTION_RULES)?;
    Ok(rules)
}

fn decode_rule_tree(
    body: &[u8],
    strings: &StringTable<'_>,
    limits: &PortableLimits,
    budget: &mut ValueBudget,
) -> PortableResult<Value> {
    let mut reader = Reader::new(body);
    let tree = decode_value(&mut reader, strings, 0, limits, budget)?;
    reader.expect_end(SECTION_RULE_TREE)?;
    Ok(tree)
}

fn decode_sources(
    body: &[u8],
    strings: &StringTable<'_>,
    limits: &PortableLimits,
) -> PortableResult<Vec<SourceFile>> {
    let mut reader = Reader::new(body);
    let count = read_count(&mut reader, "sources", limits.max_sources, 0)?;
    let mut sources = Vec::with_capacity(count);
    for _ in 0..count {
        let name = strings.get(reader.varint_u32()?)?;
        let content = strings.get(reader.varint_u32()?)?;
        sources.push(SourceFile::new(String::from(name), String::from(content)));
    }
    reader.expect_end(SECTION_SOURCES)?;
    Ok(sources)
}

fn decode_spans(body: &[u8], limits: &PortableLimits) -> PortableResult<Vec<Option<SpanInfo>>> {
    let mut reader = Reader::new(body);
    let count = read_count(
        &mut reader,
        "spans",
        limits.max_instructions,
        super::format::SPAN_RECORD_SIZE,
    )?;
    let mut spans = Vec::with_capacity(count);
    for _ in 0..count {
        let source_index = reader.u32()?;
        let line = reader.u32()?;
        let column = reader.u32()?;
        let length = reader.u32()?;
        if source_index == SPAN_ABSENT {
            spans.push(None);
        } else {
            spans.push(Some(SpanInfo::new(
                usize::try_from(source_index).unwrap_or(0),
                usize::try_from(line).unwrap_or(0),
                usize::try_from(column).unwrap_or(0),
                usize::try_from(length).unwrap_or(0),
            )));
        }
    }
    reader.expect_end(SECTION_SPANS)?;
    Ok(spans)
}

fn decode_metadata(
    body: &[u8],
    strings: &StringTable<'_>,
    limits: &PortableLimits,
    budget: &mut ValueBudget,
) -> PortableResult<ProgramMetadata> {
    let mut reader = Reader::new(body);
    let compiler_version = strings.get(reader.varint_u32()?)?;
    let compiled_at = strings.get(reader.varint_u32()?)?;
    let source_info = strings.get(reader.varint_u32()?)?;
    let optimization_level = reader.u8()?;
    let language = strings.get(reader.varint_u32()?)?;

    let annotation_count = reader.varint_usize()?;
    PortableLimits::check(
        "metadata annotations",
        annotation_count,
        limits.max_annotations,
    )?;
    if annotation_count > reader.remaining() {
        return Err(PortableError::Truncated {
            offset: reader.position(),
            needed: annotation_count,
            available: reader.remaining(),
        });
    }
    let mut annotations = BTreeMap::new();
    for _ in 0..annotation_count {
        let key = strings.get(reader.varint_u32()?)?;
        let annotation = decode_value(&mut reader, strings, 0, limits, budget)?;
        annotations.insert(String::from(key), annotation);
    }

    reader.expect_end(SECTION_METADATA)?;

    Ok(ProgramMetadata {
        compiler_version: String::from(compiler_version),
        compiled_at: String::from(compiled_at),
        source_info: String::from(source_info),
        optimization_level,
        language: String::from(language),
        annotations,
    })
}

/// Cross-section validation performed before the program is handed back.
fn validate_consistency(program: &Program, header: &Header) -> PortableResult<()> {
    program
        .validate_limits()
        .map_err(PortableError::ProgramInvalid)?;

    let instruction_count = program.instructions.len();
    let literal_count = program.literals.len();
    let rule_count = program.rule_infos.len();
    let builtin_count = program.builtin_info_table.len();

    if !program.instruction_spans.is_empty() && program.instruction_spans.len() != instruction_count
    {
        return Err(PortableError::Inconsistent {
            reason: "span table length does not match the instruction count",
        });
    }

    for span in program.instruction_spans.iter().flatten() {
        if span.source_index >= program.sources.len() && !program.sources.is_empty() {
            return Err(PortableError::Inconsistent {
                reason: "span references a source file that is not present",
            });
        }
    }

    let header_flags_rego_v0 = header.feature_flags & FEATURE_REGO_V0 != 0;
    if header_flags_rego_v0 != program.rego_v0 {
        return Err(PortableError::Inconsistent {
            reason: "header rego_v0 feature flag disagrees with the program header",
        });
    }
    let header_flags_host_await = header.feature_flags & FEATURE_HOST_AWAIT != 0;
    if header_flags_host_await != program.has_host_await {
        return Err(PortableError::Inconsistent {
            reason: "header host-await feature flag disagrees with the program header",
        });
    }

    for instruction in &program.instructions {
        validate_instruction(instruction, literal_count, rule_count, program)?;
    }

    for params in &program.instruction_data.builtin_call_params {
        if usize::from(params.builtin_index) >= builtin_count {
            return Err(PortableError::Inconsistent {
                reason: "builtin call references an undeclared builtin",
            });
        }
    }
    for params in &program.instruction_data.function_call_params {
        if usize::from(params.func_rule_index) >= rule_count {
            return Err(PortableError::Inconsistent {
                reason: "function call references an undeclared rule",
            });
        }
    }
    for params in &program.instruction_data.object_create_params {
        if usize::from(params.template_literal_idx) >= literal_count {
            return Err(PortableError::Inconsistent {
                reason: "object create template references an undeclared literal",
            });
        }
        for &(literal_index, _) in &params.literal_key_fields {
            if usize::from(literal_index) >= literal_count {
                return Err(PortableError::Inconsistent {
                    reason: "object create key references an undeclared literal",
                });
            }
        }
    }
    for params in &program.instruction_data.virtual_data_document_lookup_params {
        validate_path_components(&params.path_components, literal_count)?;
    }
    for params in &program.instruction_data.chained_index_params {
        validate_path_components(&params.path_components, literal_count)?;
    }

    for rule in &program.rule_infos {
        if let Some(default_index) = rule.default_literal_index {
            if usize::from(default_index) >= literal_count {
                return Err(PortableError::Inconsistent {
                    reason: "rule default value references an undeclared literal",
                });
            }
        }
        for definition in rule.definitions.iter() {
            for &block in definition {
                if usize::try_from(block).unwrap_or(usize::MAX) > instruction_count {
                    return Err(PortableError::Inconsistent {
                        reason: "rule definition references an out-of-range instruction",
                    });
                }
            }
        }
        for entry_point in rule.destructuring_blocks.iter().flatten() {
            if usize::try_from(*entry_point).unwrap_or(usize::MAX) > instruction_count {
                return Err(PortableError::Inconsistent {
                    reason: "destructuring block references an out-of-range instruction",
                });
            }
        }
    }

    // NOTE: despite `Program::add_entry_point`'s parameter name, the value
    // stored in `entry_points` is the *instruction index* (program counter) of
    // the entry point's dispatch stub, not a rule index.  See
    // `RegoVM::execute_entry_point_by_name`.
    for &entry_pc in program.entry_points.values() {
        if entry_pc >= instruction_count {
            return Err(PortableError::Inconsistent {
                reason: "entry point program counter is outside the instruction table",
            });
        }
    }

    if usize::try_from(program.main_entry_point).unwrap_or(usize::MAX) > instruction_count {
        return Err(PortableError::Inconsistent {
            reason: "main entry point is outside the instruction table",
        });
    }

    Ok(())
}

fn validate_path_components(
    components: &[LiteralOrRegister],
    literal_count: usize,
) -> PortableResult<()> {
    for component in components {
        if let LiteralOrRegister::Literal(index) = *component {
            if usize::from(index) >= literal_count {
                return Err(PortableError::Inconsistent {
                    reason: "path component references an undeclared literal",
                });
            }
        }
    }
    Ok(())
}

fn validate_instruction(
    instruction: &crate::rvm::Instruction,
    literal_count: usize,
    rule_count: usize,
    program: &Program,
) -> PortableResult<()> {
    use crate::rvm::Instruction as Ins;
    let data = &program.instruction_data;
    match *instruction {
        Ins::Load { literal_idx, .. } | Ins::IndexLiteral { literal_idx, .. } => {
            check_literal_index(literal_idx, literal_count)?;
        }
        Ins::CallRule { rule_index, .. } | Ins::RuleInit { rule_index, .. } => {
            check_rule_index(rule_index, rule_count)?;
        }
        Ins::BuiltinCall { params_index } => {
            check_params_index(params_index, data.builtin_call_params.len())?;
        }
        Ins::FunctionCall { params_index } => {
            check_params_index(params_index, data.function_call_params.len())?;
        }
        Ins::ObjectCreate { params_index } => {
            check_params_index(params_index, data.object_create_params.len())?;
        }
        Ins::ArrayCreate { params_index } => {
            check_params_index(params_index, data.array_create_params.len())?;
        }
        Ins::SetCreate { params_index } => {
            check_params_index(params_index, data.set_create_params.len())?;
        }
        Ins::ChainedIndex { params_index } => {
            check_params_index(params_index, data.chained_index_params.len())?;
        }
        Ins::VirtualDataDocumentLookup { params_index } => {
            check_params_index(params_index, data.virtual_data_document_lookup_params.len())?;
        }
        Ins::LoopStart { params_index } => {
            check_params_index(params_index, data.loop_params.len())?;
        }
        Ins::ComprehensionBegin { params_index } => {
            check_params_index(params_index, data.comprehension_begin_params.len())?;
        }
        _ => {}
    }
    Ok(())
}

fn check_params_index(index: u16, table_len: usize) -> PortableResult<()> {
    if usize::from(index) >= table_len {
        return Err(PortableError::Inconsistent {
            reason: "instruction references a missing parameter table entry",
        });
    }
    Ok(())
}

fn check_literal_index(index: u16, literal_count: usize) -> PortableResult<()> {
    if usize::from(index) >= literal_count {
        return Err(PortableError::Inconsistent {
            reason: "instruction references an undeclared literal",
        });
    }
    Ok(())
}

fn check_rule_index(index: u16, rule_count: usize) -> PortableResult<()> {
    if usize::from(index) >= rule_count {
        return Err(PortableError::Inconsistent {
            reason: "instruction references an undeclared rule",
        });
    }
    Ok(())
}
