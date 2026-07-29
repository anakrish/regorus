// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Typed errors and resource limits for the RVMP portable format.

use alloc::string::String;
use thiserror::Error;

/// Errors produced while encoding or decoding a portable RVM artifact.
///
/// Every failure mode is explicit: the codec never panics, never indexes
/// unchecked, and never allocates based on an unvalidated length.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PortableError {
    /// The input ended before a required field could be read.
    #[error("truncated artifact: need {needed} byte(s) at offset {offset}, {available} available")]
    Truncated {
        /// Offset at which the read was attempted.
        offset: usize,
        /// Number of bytes required.
        needed: usize,
        /// Number of bytes actually remaining.
        available: usize,
    },

    /// The file does not start with the `RVMP` magic.
    #[error("invalid artifact magic: expected 'RVMP'")]
    InvalidMagic,

    /// The format version is outside the supported range.
    #[error("unsupported portable format version {found} (this build supports {min}..={max})")]
    UnsupportedVersion {
        /// Version found in the artifact.
        found: u16,
        /// Lowest version supported by this build.
        min: u16,
        /// Highest version supported by this build.
        max: u16,
    },

    /// A required-range feature flag is not understood by this build.
    #[error("artifact requires unsupported features (unknown required flag bits: {flags:#010x})")]
    UnsupportedFeatures {
        /// The unknown required flag bits.
        flags: u32,
    },

    /// A structural header field is inconsistent.
    #[error("malformed artifact header: {reason}")]
    MalformedHeader {
        /// Human readable reason.
        reason: &'static str,
    },

    /// A section could not be located inside the artifact.
    #[error("section {id} lies outside the artifact (offset {offset}, length {length})")]
    SectionOutOfBounds {
        /// Section identifier.
        id: u32,
        /// Declared section offset.
        offset: u32,
        /// Declared section length.
        length: u32,
    },

    /// Two directory entries overlap or are not sorted by offset.
    #[error("section {id} overlaps a previously declared section")]
    SectionOverlap {
        /// Section identifier.
        id: u32,
    },

    /// The directory lists the same section identifier twice.
    #[error("duplicate section {id} in directory")]
    DuplicateSection {
        /// Section identifier.
        id: u32,
    },

    /// A section required for execution is missing.
    #[error("required section {id} is missing")]
    MissingSection {
        /// Section identifier.
        id: u32,
    },

    /// An unknown section is flagged as must-understand.
    #[error("artifact contains unknown required section {id}")]
    UnknownRequiredSection {
        /// Section identifier.
        id: u32,
    },

    /// A section contained bytes after its last well-formed record.
    #[error("section {id} has {remaining} unexpected trailing byte(s)")]
    TrailingSectionData {
        /// Section identifier.
        id: u32,
        /// Number of unconsumed bytes.
        remaining: usize,
    },

    /// The stored CRC-32 does not match the payload.
    #[error("artifact checksum mismatch (stored {stored:#010x}, computed {computed:#010x})")]
    ChecksumMismatch {
        /// Checksum stored in the header.
        stored: u32,
        /// Checksum computed over the payload.
        computed: u32,
    },

    /// A declared count or size exceeded the configured limit.
    #[error("{limit} limit exceeded: {value} > {max}")]
    LimitExceeded {
        /// Name of the limit.
        limit: &'static str,
        /// Observed value.
        value: usize,
        /// Configured maximum.
        max: usize,
    },

    /// Arithmetic on offsets or sizes would have overflowed.
    #[error("integer overflow while computing {context}")]
    IntegerOverflow {
        /// Where the overflow occurred.
        context: &'static str,
    },

    /// A LEB128 varint was malformed, overlong, or too wide.
    #[error("malformed varint at offset {offset}")]
    MalformedVarint {
        /// Offset of the first varint byte.
        offset: usize,
    },

    /// A string table entry was not valid UTF-8.
    #[error("string table entry {index} is not valid UTF-8")]
    InvalidUtf8 {
        /// String table index.
        index: u32,
    },

    /// A string reference pointed outside the string table.
    #[error("string index {index} out of range (table holds {count} entries)")]
    StringIndexOutOfRange {
        /// Requested index.
        index: u32,
        /// Number of entries in the table.
        count: usize,
    },

    /// The string table offsets were not monotonically increasing.
    #[error("string table offsets are not monotonic at entry {index}")]
    MalformedStringTable {
        /// Offending entry index.
        index: u32,
    },

    /// An unrecognized opcode was encountered.
    #[error("unknown opcode {opcode:#04x} at instruction {index}")]
    UnknownOpcode {
        /// The opcode byte.
        opcode: u8,
        /// Instruction index within the section.
        index: usize,
    },

    /// An enum sub-code was outside its defined range.
    #[error("invalid {kind} discriminant {value}")]
    InvalidDiscriminant {
        /// Name of the enum.
        kind: &'static str,
        /// Observed value.
        value: u32,
    },

    /// An unrecognized value tag was encountered.
    #[error("unknown value tag {tag:#04x}")]
    UnknownValueTag {
        /// The tag byte.
        tag: u8,
    },

    /// Value nesting exceeded the configured depth limit.
    #[error("value nesting depth exceeded limit of {max}")]
    DepthExceeded {
        /// Configured maximum depth.
        max: usize,
    },

    /// A decimal big-integer literal could not be parsed.
    #[error("invalid arbitrary-precision number literal")]
    InvalidNumber,

    /// A cross-section invariant was violated.
    #[error("inconsistent artifact: {reason}")]
    Inconsistent {
        /// Human readable reason.
        reason: &'static str,
    },

    /// The in-memory program violates the documented program limits.
    #[error("program cannot be encoded: {0}")]
    ProgramInvalid(String),

    /// A field of the in-memory program does not fit the wire representation.
    #[error("field '{field}' value {value} does not fit the portable encoding")]
    FieldTooLarge {
        /// Field name.
        field: &'static str,
        /// Observed value.
        value: u64,
    },
}

/// Result alias used across the portable codec.
pub type PortableResult<T> = core::result::Result<T, PortableError>;

/// Resource limits applied while decoding a portable artifact.
///
/// The decoder validates every declared count against these limits *before*
/// allocating, so a malicious artifact cannot force a large allocation with a
/// few bytes of input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableLimits {
    /// Maximum accepted artifact size in bytes.
    pub max_total_size: usize,
    /// Maximum number of directory entries.
    pub max_sections: usize,
    /// Maximum number of string table entries.
    pub max_strings: usize,
    /// Maximum total size of the string table blob in bytes.
    pub max_string_bytes: usize,
    /// Maximum number of instructions.
    pub max_instructions: usize,
    /// Maximum number of literals.
    pub max_literals: usize,
    /// Maximum number of rules.
    pub max_rules: usize,
    /// Maximum number of entry points.
    pub max_entry_points: usize,
    /// Maximum number of source files.
    pub max_sources: usize,
    /// Maximum number of builtin declarations.
    pub max_builtins: usize,
    /// Maximum number of entries in any single instruction parameter table.
    pub max_params_per_table: usize,
    /// Maximum nesting depth of an encoded value.
    pub max_value_depth: usize,
    /// Maximum number of value nodes decoded from a single artifact.
    pub max_value_nodes: usize,
    /// Maximum number of elements in a single array/set/object.
    pub max_collection_len: usize,
    /// Maximum number of definitions attached to a single rule.
    pub max_definitions_per_rule: usize,
    /// Maximum number of instruction indices in a single rule definition.
    pub max_definition_len: usize,
    /// Maximum number of path components in a lookup parameter entry.
    pub max_path_components: usize,
    /// Maximum number of fields in an `ObjectCreate` parameter entry.
    pub max_object_create_fields: usize,
    /// Maximum number of elements in an `ArrayCreate`/`SetCreate` entry.
    pub max_create_elements: usize,
    /// Maximum number of metadata annotations.
    pub max_annotations: usize,
    /// Maximum number of function parameter names on a single rule.
    pub max_function_params: usize,
}

impl PortableLimits {
    /// Default artifact size ceiling (64 MiB).
    pub const DEFAULT_MAX_TOTAL_SIZE: usize = 64 * 1024 * 1024;
    /// Default string blob ceiling (32 MiB).
    pub const DEFAULT_MAX_STRING_BYTES: usize = 32 * 1024 * 1024;

    /// Limits used by [`Program::deserialize_portable`](crate::rvm::Program::deserialize_portable).
    pub const fn new() -> Self {
        Self {
            max_total_size: Self::DEFAULT_MAX_TOTAL_SIZE,
            max_sections: 64,
            max_strings: 262_144,
            max_string_bytes: Self::DEFAULT_MAX_STRING_BYTES,
            max_instructions: crate::rvm::Program::MAX_INSTRUCTIONS,
            max_literals: crate::rvm::Program::MAX_LITERALS,
            max_rules: crate::rvm::Program::MAX_RULES,
            max_entry_points: crate::rvm::Program::MAX_ENTRY_POINTS,
            max_sources: crate::rvm::Program::MAX_SOURCES,
            max_builtins: crate::rvm::Program::MAX_BUILTINS,
            max_params_per_table: 65_536,
            max_value_depth: 64,
            max_value_nodes: 4_000_000,
            max_collection_len: 1_000_000,
            max_definitions_per_rule: 65_536,
            max_definition_len: 65_536,
            max_path_components: 256,
            max_object_create_fields: 65_536,
            max_create_elements: 65_536,
            max_annotations: 4_096,
            max_function_params: 256,
        }
    }

    /// Check `value` against `max`, returning [`PortableError::LimitExceeded`].
    pub const fn check(limit: &'static str, value: usize, max: usize) -> PortableResult<()> {
        if value > max {
            return Err(PortableError::LimitExceeded { limit, value, max });
        }
        Ok(())
    }
}

impl Default for PortableLimits {
    fn default() -> Self {
        Self::new()
    }
}

/// Options controlling which optional sections an encoder emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortableWriteOptions {
    /// Emit the source file section (needed for diagnostics/recompilation).
    pub include_sources: bool,
    /// Emit the per-instruction span section (debug only).
    pub include_spans: bool,
    /// Emit the program metadata section.
    pub include_metadata: bool,
}

impl PortableWriteOptions {
    /// Emit every section, including debug information (default).
    pub const fn all() -> Self {
        Self {
            include_sources: true,
            include_spans: true,
            include_metadata: true,
        }
    }

    /// Emit only the execution-critical sections.
    ///
    /// Produces the smallest artifact.  The resulting program can still be
    /// executed but has no source text, spans, or provenance metadata.
    pub const fn execution_only() -> Self {
        Self {
            include_sources: false,
            include_spans: false,
            include_metadata: false,
        }
    }
}

impl Default for PortableWriteOptions {
    fn default() -> Self {
        Self::all()
    }
}

/// Header-level facts about an artifact, obtainable without decoding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableInfo {
    /// Format version stored in the header.
    pub format_version: u16,
    /// Raw feature flag word.
    pub feature_flags: u32,
    /// Number of sections declared in the directory.
    pub section_count: u32,
    /// Total artifact size declared in the header.
    pub total_size: u32,
    /// True when debug sections are present.
    pub has_debug_info: bool,
    /// True when the metadata section is present.
    pub has_metadata: bool,
    /// True when the program contains `HostAwait` instructions.
    pub uses_host_await: bool,
    /// True when the program was compiled with Rego v0 semantics.
    pub rego_v0: bool,
}
