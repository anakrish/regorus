// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Encoder for the RVMP portable execution artifact format.
//!
//! Output is **deterministic**: the same [`Program`] and the same
//! [`PortableWriteOptions`] always produce byte-identical output.  This is
//! achieved by writing every table in a fixed order, sorting object keys and
//! sets by `Value::Ord`, using canonical LEB128, and zeroing every reserved
//! field.

use alloc::vec::Vec;

use super::errors::{PortableError, PortableLimits, PortableResult, PortableWriteOptions};
use super::format::{
    crc32, path_component, rule_type, DIRECTORY_ENTRY_SIZE, FEATURE_DEBUG_INFO, FEATURE_HOST_AWAIT,
    FEATURE_METADATA, FEATURE_REGO_V0, FORMAT_VERSION, HEADER_SIZE, MAGIC, PROGRAM_FLAG_HOST_AWAIT,
    PROGRAM_FLAG_REGO_V0, PROGRAM_FLAG_RUNTIME_RECURSION_CHECK, SECTION_ALIGNMENT,
    SECTION_BUILTINS, SECTION_ENTRY_POINTS, SECTION_FLAG_REQUIRED, SECTION_INSTRUCTIONS,
    SECTION_INSTRUCTION_PARAMS, SECTION_LITERALS, SECTION_METADATA, SECTION_PROGRAM_HEADER,
    SECTION_RULES, SECTION_RULE_TREE, SECTION_SOURCES, SECTION_SPANS, SECTION_STRINGS, SPAN_ABSENT,
};
use super::instructions::{comprehension_mode_to_code, encode_instruction, loop_mode_to_code};
use super::io::Writer;
use super::strings::StringTableBuilder;
use super::values::encode_value;
use crate::rvm::instructions::LiteralOrRegister;
use crate::rvm::program::{RuleInfo, RuleType};
use crate::rvm::Program;

struct PendingSection {
    id: u32,
    flags: u32,
    body: Vec<u8>,
}

/// Encode `program` into a portable artifact.
pub fn encode_program(
    program: &Program,
    options: &PortableWriteOptions,
) -> PortableResult<Vec<u8>> {
    program
        .validate_limits()
        .map_err(PortableError::ProgramInvalid)?;

    if program.needs_recompilation {
        return Err(PortableError::ProgramInvalid(alloc::string::String::from(
            "a program that needs recompilation cannot be exported as a portable artifact",
        )));
    }

    let limits = PortableLimits::new();
    let mut strings = StringTableBuilder::new();
    let mut sections: Vec<PendingSection> = alloc::vec![
        PendingSection {
            id: SECTION_PROGRAM_HEADER,
            flags: SECTION_FLAG_REQUIRED,
            body: encode_program_header(program),
        },
        PendingSection {
            id: SECTION_INSTRUCTIONS,
            flags: SECTION_FLAG_REQUIRED,
            body: encode_instructions(program)?,
        },
        PendingSection {
            id: SECTION_INSTRUCTION_PARAMS,
            flags: SECTION_FLAG_REQUIRED,
            body: encode_instruction_params(program)?,
        },
        PendingSection {
            id: SECTION_LITERALS,
            flags: SECTION_FLAG_REQUIRED,
            body: encode_literals(program, &mut strings, &limits)?,
        },
        PendingSection {
            id: SECTION_BUILTINS,
            flags: SECTION_FLAG_REQUIRED,
            body: encode_builtins(program, &mut strings)?,
        },
        PendingSection {
            id: SECTION_ENTRY_POINTS,
            flags: SECTION_FLAG_REQUIRED,
            body: encode_entry_points(program, &mut strings)?,
        },
        PendingSection {
            id: SECTION_RULES,
            flags: SECTION_FLAG_REQUIRED,
            body: encode_rules(program, &mut strings)?,
        },
        PendingSection {
            id: SECTION_RULE_TREE,
            flags: SECTION_FLAG_REQUIRED,
            body: encode_rule_tree(program, &mut strings, &limits)?,
        },
    ];

    if options.include_sources {
        sections.push(PendingSection {
            id: SECTION_SOURCES,
            flags: 0,
            body: encode_sources(program, &mut strings)?,
        });
    }
    if options.include_spans {
        sections.push(PendingSection {
            id: SECTION_SPANS,
            flags: 0,
            body: encode_spans(program)?,
        });
    }
    if options.include_metadata {
        sections.push(PendingSection {
            id: SECTION_METADATA,
            flags: 0,
            body: encode_metadata(program, &mut strings, &limits)?,
        });
    }

    // The string table is finalized last because every other section feeds it,
    // but it is placed at its fixed directory position (id 2).
    sections.push(PendingSection {
        id: SECTION_STRINGS,
        flags: SECTION_FLAG_REQUIRED,
        body: strings.encode()?,
    });

    sections.sort_by_key(|section| section.id);

    let feature_flags = compute_feature_flags(program, options);
    assemble(&sections, feature_flags)
}

const fn compute_feature_flags(program: &Program, options: &PortableWriteOptions) -> u32 {
    let mut flags = 0_u32;
    if options.include_sources || options.include_spans {
        flags |= FEATURE_DEBUG_INFO;
    }
    if options.include_metadata {
        flags |= FEATURE_METADATA;
    }
    if program.has_host_await {
        flags |= FEATURE_HOST_AWAIT;
    }
    if program.rego_v0 {
        flags |= FEATURE_REGO_V0;
    }
    flags
}

fn assemble(sections: &[PendingSection], feature_flags: u32) -> PortableResult<Vec<u8>> {
    let section_count =
        u32::try_from(sections.len()).map_err(|_| PortableError::IntegerOverflow {
            context: "section count",
        })?;

    let directory_bytes =
        sections
            .len()
            .checked_mul(DIRECTORY_ENTRY_SIZE)
            .ok_or(PortableError::IntegerOverflow {
                context: "directory size",
            })?;
    let directory_offset = HEADER_SIZE;
    let mut cursor =
        directory_offset
            .checked_add(directory_bytes)
            .ok_or(PortableError::IntegerOverflow {
                context: "directory size",
            })?;

    let mut placements: Vec<(u32, u32, u32, u32)> = Vec::with_capacity(sections.len());
    for section in sections {
        cursor = align_up(cursor)?;
        let offset = u32::try_from(cursor).map_err(|_| PortableError::IntegerOverflow {
            context: "section offset",
        })?;
        let length =
            u32::try_from(section.body.len()).map_err(|_| PortableError::IntegerOverflow {
                context: "section length",
            })?;
        placements.push((section.id, offset, length, section.flags));
        cursor = cursor
            .checked_add(section.body.len())
            .ok_or(PortableError::IntegerOverflow {
                context: "artifact size",
            })?;
    }

    let total_size = u32::try_from(cursor).map_err(|_| PortableError::IntegerOverflow {
        context: "artifact size",
    })?;

    let mut writer = Writer::new();
    writer.bytes(&MAGIC);
    writer.u16(FORMAT_VERSION);
    writer.u16(
        u16::try_from(HEADER_SIZE).map_err(|_| PortableError::IntegerOverflow {
            context: "header size",
        })?,
    );
    writer.u32(feature_flags);
    writer.u32(section_count);
    writer.u32(
        u32::try_from(directory_offset).map_err(|_| PortableError::IntegerOverflow {
            context: "directory offset",
        })?,
    );
    writer.u32(total_size);
    let checksum_offset = writer.len();
    writer.u32(0);
    writer.u32(0);

    for &(id, offset, length, flags) in &placements {
        writer.u32(id);
        writer.u32(offset);
        writer.u32(length);
        writer.u32(flags);
    }

    for (section, &(_, offset, _, _)) in sections.iter().zip(placements.iter()) {
        let target = usize::try_from(offset).map_err(|_| PortableError::IntegerOverflow {
            context: "section offset",
        })?;
        while writer.len() < target {
            writer.u8(0);
        }
        writer.bytes(&section.body);
    }

    let payload = writer
        .as_slice()
        .get(HEADER_SIZE..)
        .ok_or(PortableError::IntegerOverflow {
            context: "payload range",
        })?;
    let checksum = crc32(payload);
    writer.patch_u32(checksum_offset, checksum)?;

    Ok(writer.into_vec())
}

fn align_up(value: usize) -> PortableResult<usize> {
    let remainder = value
        .checked_rem(SECTION_ALIGNMENT)
        .ok_or(PortableError::IntegerOverflow {
            context: "section alignment",
        })?;
    if remainder == 0 {
        return Ok(value);
    }
    value
        .checked_add(SECTION_ALIGNMENT.saturating_sub(remainder))
        .ok_or(PortableError::IntegerOverflow {
            context: "section alignment",
        })
}

// ── Section encoders ─────────────────────────────────────────────────────────

fn encode_program_header(program: &Program) -> Vec<u8> {
    let mut flags = 0_u8;
    if program.rego_v0 {
        flags |= PROGRAM_FLAG_REGO_V0;
    }
    if program.needs_runtime_recursion_check {
        flags |= PROGRAM_FLAG_RUNTIME_RECURSION_CHECK;
    }
    if program.has_host_await {
        flags |= PROGRAM_FLAG_HOST_AWAIT;
    }

    let mut writer = Writer::new();
    writer.u32(program.main_entry_point);
    writer.u8(program.max_rule_window_size);
    writer.u8(program.dispatch_window_size);
    writer.u8(flags);
    writer.u8(0);
    writer.into_vec()
}

fn encode_instructions(program: &Program) -> PortableResult<Vec<u8>> {
    let mut writer = Writer::new();
    writer.u32(count_u32(program.instructions.len(), "instructions")?);
    for &instruction in &program.instructions {
        writer.bytes(&encode_instruction(instruction).to_bytes());
    }
    Ok(writer.into_vec())
}

fn encode_instruction_params(program: &Program) -> PortableResult<Vec<u8>> {
    let data = &program.instruction_data;
    let mut writer = Writer::new();

    writer.u32(count_u32(data.loop_params.len(), "loop params")?);
    for entry in &data.loop_params {
        writer.u8(loop_mode_to_code(entry.mode));
        writer.u8(entry.collection);
        writer.u8(entry.key_reg);
        writer.u8(entry.value_reg);
        writer.u8(entry.result_reg);
        writer.u8(0);
        writer.u16(entry.body_start);
        writer.u16(entry.loop_end);
    }

    writer.u32(count_u32(data.builtin_call_params.len(), "builtin calls")?);
    for entry in &data.builtin_call_params {
        writer.u8(entry.dest);
        writer.u8(entry.num_args);
        writer.bytes(&entry.args);
        writer.u16(entry.builtin_index);
    }

    writer.u32(count_u32(
        data.function_call_params.len(),
        "function calls",
    )?);
    for entry in &data.function_call_params {
        writer.u8(entry.dest);
        writer.u8(entry.num_args);
        writer.bytes(&entry.args);
        writer.u16(entry.func_rule_index);
    }

    writer.u32(count_u32(
        data.object_create_params.len(),
        "object creates",
    )?);
    for entry in &data.object_create_params {
        writer.u8(entry.dest);
        writer.u16(entry.template_literal_idx);
        writer.varint_usize(entry.literal_key_fields.len());
        for &(literal_index, register) in &entry.literal_key_fields {
            writer.u16(literal_index);
            writer.u8(register);
        }
        writer.varint_usize(entry.fields.len());
        for &(key_register, value_register) in &entry.fields {
            writer.u8(key_register);
            writer.u8(value_register);
        }
    }

    writer.u32(count_u32(data.array_create_params.len(), "array creates")?);
    for entry in &data.array_create_params {
        writer.u8(entry.dest);
        writer.varint_usize(entry.elements.len());
        writer.bytes(&entry.elements);
    }

    writer.u32(count_u32(data.set_create_params.len(), "set creates")?);
    for entry in &data.set_create_params {
        writer.u8(entry.dest);
        writer.varint_usize(entry.elements.len());
        writer.bytes(&entry.elements);
    }

    writer.u32(count_u32(
        data.virtual_data_document_lookup_params.len(),
        "virtual data lookups",
    )?);
    for entry in &data.virtual_data_document_lookup_params {
        writer.u8(entry.dest);
        encode_path_components(&mut writer, &entry.path_components);
    }

    writer.u32(count_u32(
        data.chained_index_params.len(),
        "chained indexes",
    )?);
    for entry in &data.chained_index_params {
        writer.u8(entry.dest);
        writer.u8(entry.root);
        encode_path_components(&mut writer, &entry.path_components);
    }

    writer.u32(count_u32(
        data.comprehension_begin_params.len(),
        "comprehensions",
    )?);
    for entry in &data.comprehension_begin_params {
        writer.u8(comprehension_mode_to_code(&entry.mode));
        writer.u8(entry.collection_reg);
        writer.u8(entry.result_reg);
        writer.u8(entry.key_reg);
        writer.u8(entry.value_reg);
        writer.u8(0);
        writer.u16(entry.body_start);
        writer.u16(entry.comprehension_end);
    }

    Ok(writer.into_vec())
}

fn encode_path_components(writer: &mut Writer, components: &[LiteralOrRegister]) {
    writer.varint_usize(components.len());
    for component in components {
        match *component {
            LiteralOrRegister::Literal(index) => {
                writer.u8(path_component::LITERAL);
                writer.u16(index);
            }
            LiteralOrRegister::Register(register) => {
                writer.u8(path_component::REGISTER);
                writer.u8(register);
            }
        }
    }
}

fn encode_literals<'a>(
    program: &'a Program,
    strings: &mut StringTableBuilder<'a>,
    limits: &PortableLimits,
) -> PortableResult<Vec<u8>> {
    let mut writer = Writer::new();
    writer.u32(count_u32(program.literals.len(), "literals")?);
    for literal in &program.literals {
        encode_value(&mut writer, strings, literal, 0, limits)?;
    }
    Ok(writer.into_vec())
}

fn encode_builtins<'a>(
    program: &'a Program,
    strings: &mut StringTableBuilder<'a>,
) -> PortableResult<Vec<u8>> {
    let mut writer = Writer::new();
    writer.u32(count_u32(program.builtin_info_table.len(), "builtins")?);
    for entry in &program.builtin_info_table {
        let name_index = strings.intern(entry.name.as_str())?;
        writer.varint(u64::from(name_index));
        writer.u16(entry.num_args);
    }
    Ok(writer.into_vec())
}

fn encode_entry_points<'a>(
    program: &'a Program,
    strings: &mut StringTableBuilder<'a>,
) -> PortableResult<Vec<u8>> {
    let mut writer = Writer::new();
    writer.u32(count_u32(program.entry_points.len(), "entry points")?);
    // `IndexMap` iteration preserves declaration order, which is part of the
    // artifact contract: entry points are addressable by index.
    for (path, &rule_index) in &program.entry_points {
        let path_index = strings.intern(path.as_str())?;
        writer.varint(u64::from(path_index));
        writer.varint_usize(rule_index);
    }
    Ok(writer.into_vec())
}

const RULE_FLAG_HAS_FUNCTION_INFO: u8 = 1 << 0;
const RULE_FLAG_HAS_DEFAULT_LITERAL: u8 = 1 << 1;
const RULE_FLAG_EARLY_EXIT: u8 = 1 << 2;

const fn rule_type_to_code(kind: &RuleType) -> u8 {
    match *kind {
        RuleType::Complete => rule_type::COMPLETE,
        RuleType::PartialSet => rule_type::PARTIAL_SET,
        RuleType::PartialObject => rule_type::PARTIAL_OBJECT,
    }
}

fn encode_rules<'a>(
    program: &'a Program,
    strings: &mut StringTableBuilder<'a>,
) -> PortableResult<Vec<u8>> {
    let mut writer = Writer::new();
    writer.u32(count_u32(program.rule_infos.len(), "rules")?);
    for rule in &program.rule_infos {
        encode_rule(&mut writer, strings, rule)?;
    }
    Ok(writer.into_vec())
}

fn encode_rule<'a>(
    writer: &mut Writer,
    strings: &mut StringTableBuilder<'a>,
    rule: &'a RuleInfo,
) -> PortableResult<()> {
    let name_index = strings.intern(rule.name.as_str())?;
    writer.varint(u64::from(name_index));
    writer.u8(rule_type_to_code(&rule.rule_type));

    let mut flags = 0_u8;
    if rule.function_info.is_some() {
        flags |= RULE_FLAG_HAS_FUNCTION_INFO;
    }
    if rule.default_literal_index.is_some() {
        flags |= RULE_FLAG_HAS_DEFAULT_LITERAL;
    }
    if rule.early_exit_on_first_success {
        flags |= RULE_FLAG_EARLY_EXIT;
    }
    writer.u8(flags);
    writer.u8(rule.result_reg);
    writer.u8(rule.num_registers);

    if let Some(default_index) = rule.default_literal_index {
        writer.u16(default_index);
    }

    writer.varint_usize(rule.definitions.len());
    for definition in rule.definitions.iter() {
        writer.varint_usize(definition.len());
        for &instruction_index in definition {
            writer.varint(u64::from(instruction_index));
        }
    }

    writer.varint_usize(rule.destructuring_blocks.len());
    for slot in &rule.destructuring_blocks {
        match *slot {
            None => writer.varint(0),
            Some(entry_point) => writer.varint(u64::from(entry_point).checked_add(1).ok_or(
                PortableError::IntegerOverflow {
                    context: "destructuring block",
                },
            )?),
        }
    }

    if let Some(ref function_info) = rule.function_info {
        writer.varint(u64::from(function_info.num_params));
        writer.varint_usize(function_info.param_names.len());
        for param_name in &function_info.param_names {
            let param_index = strings.intern(param_name.as_str())?;
            writer.varint(u64::from(param_index));
        }
    }

    Ok(())
}

fn encode_rule_tree<'a>(
    program: &'a Program,
    strings: &mut StringTableBuilder<'a>,
    limits: &PortableLimits,
) -> PortableResult<Vec<u8>> {
    let mut writer = Writer::new();
    encode_value(&mut writer, strings, &program.rule_tree, 0, limits)?;
    Ok(writer.into_vec())
}

fn encode_sources<'a>(
    program: &'a Program,
    strings: &mut StringTableBuilder<'a>,
) -> PortableResult<Vec<u8>> {
    let mut writer = Writer::new();
    writer.u32(count_u32(program.sources.len(), "sources")?);
    for source_file in &program.sources {
        let name_index = strings.intern(source_file.name.as_str())?;
        let content_index = strings.intern(source_file.content.as_str())?;
        writer.varint(u64::from(name_index));
        writer.varint(u64::from(content_index));
    }
    Ok(writer.into_vec())
}

fn encode_spans(program: &Program) -> PortableResult<Vec<u8>> {
    let mut writer = Writer::new();
    writer.u32(count_u32(program.instruction_spans.len(), "spans")?);
    for slot in &program.instruction_spans {
        match *slot {
            None => {
                writer.u32(SPAN_ABSENT);
                writer.u32(0);
                writer.u32(0);
                writer.u32(0);
            }
            Some(ref span) => {
                let source_index = span_field(span.source_index, "span source index")?;
                if source_index == SPAN_ABSENT {
                    return Err(PortableError::FieldTooLarge {
                        field: "span source index",
                        value: u64::try_from(span.source_index).unwrap_or(u64::MAX),
                    });
                }
                writer.u32(source_index);
                writer.u32(span_field(span.line, "span line")?);
                writer.u32(span_field(span.column, "span column")?);
                writer.u32(span_field(span.length, "span length")?);
            }
        }
    }
    Ok(writer.into_vec())
}

fn span_field(value: usize, field: &'static str) -> PortableResult<u32> {
    u32::try_from(value).map_err(|_| PortableError::FieldTooLarge {
        field,
        value: u64::try_from(value).unwrap_or(u64::MAX),
    })
}

fn encode_metadata<'a>(
    program: &'a Program,
    strings: &mut StringTableBuilder<'a>,
    limits: &PortableLimits,
) -> PortableResult<Vec<u8>> {
    let metadata = &program.metadata;
    let compiler_version = strings.intern(metadata.compiler_version.as_str())?;
    let compiled_at = strings.intern(metadata.compiled_at.as_str())?;
    let source_info = strings.intern(metadata.source_info.as_str())?;
    let language = strings.intern(metadata.language.as_str())?;

    let mut writer = Writer::new();
    writer.varint(u64::from(compiler_version));
    writer.varint(u64::from(compiled_at));
    writer.varint(u64::from(source_info));
    writer.u8(metadata.optimization_level);
    writer.varint(u64::from(language));

    PortableLimits::check(
        "metadata annotations",
        metadata.annotations.len(),
        limits.max_annotations,
    )?;
    writer.varint_usize(metadata.annotations.len());
    // `BTreeMap` iteration is key-sorted, so annotation order is deterministic.
    for (key, annotation) in &metadata.annotations {
        let key_index = strings.intern(key.as_str())?;
        writer.varint(u64::from(key_index));
        encode_value(&mut writer, strings, annotation, 0, limits)?;
    }

    Ok(writer.into_vec())
}

fn count_u32(value: usize, label: &'static str) -> PortableResult<u32> {
    u32::try_from(value).map_err(|_| PortableError::LimitExceeded {
        limit: label,
        value,
        max: usize::try_from(u32::MAX).unwrap_or(usize::MAX),
    })
}
