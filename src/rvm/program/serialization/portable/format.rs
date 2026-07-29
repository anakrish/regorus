// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! On-the-wire constants for the **RVMP** portable execution artifact format.
//!
//! Everything in this module is part of the wire contract.  Values must never
//! be renumbered; new items are only ever appended.  See
//! `docs/rvm/portable-format.md` for the normative specification.

/// File magic: `RVMP` (Regorus Virtual Machine, Portable).
///
/// Deliberately distinct from the legacy `REGO` magic used by
/// [`Program::serialize_binary`](crate::rvm::Program::serialize_binary) so the
/// two artifact families can never be confused.
pub const MAGIC: [u8; 4] = *b"RVMP";

/// Current portable format version produced by this crate.
pub const FORMAT_VERSION: u16 = 1;

/// Minimum format version this crate can decode.
pub const MIN_FORMAT_VERSION: u16 = 1;

/// Size of the fixed file header in bytes.
pub const HEADER_SIZE: usize = 32;

/// Size of a single section directory entry in bytes.
pub const DIRECTORY_ENTRY_SIZE: usize = 16;

/// Byte alignment applied to the start of every section.
pub const SECTION_ALIGNMENT: usize = 8;

/// Size of one encoded instruction word in bytes.
pub const INSTRUCTION_WORD_SIZE: usize = 8;

/// Size of one encoded span record in bytes.
pub const SPAN_RECORD_SIZE: usize = 16;

/// Sentinel stored in a span record's `source_index` to mean "no span".
pub const SPAN_ABSENT: u32 = u32::MAX;

// ── Section identifiers ──────────────────────────────────────────────────────
//
// Ids below 16 are execution-critical: a decoder that cannot understand them
// cannot run the program.  Ids from 16 upwards are optional (debug,
// provenance, recompilation aids) and may be dropped by a writer or skipped by
// a reader.

/// Scalar program header (entry point, window sizes, semantic flags).
pub const SECTION_PROGRAM_HEADER: u32 = 1;
/// Deduplicated UTF-8 string table shared by every other section.
pub const SECTION_STRINGS: u32 = 2;
/// Fixed-width instruction words.
pub const SECTION_INSTRUCTIONS: u32 = 3;
/// Instruction parameter side tables.
pub const SECTION_INSTRUCTION_PARAMS: u32 = 4;
/// Literal value table.
pub const SECTION_LITERALS: u32 = 5;
/// Builtin function declarations.
pub const SECTION_BUILTINS: u32 = 6;
/// Ordered entry point table.
pub const SECTION_ENTRY_POINTS: u32 = 7;
/// Rule metadata table.
pub const SECTION_RULES: u32 = 8;
/// Rule lookup tree.
pub const SECTION_RULE_TREE: u32 = 9;

/// Source files (optional; needed for diagnostics and recompilation).
pub const SECTION_SOURCES: u32 = 16;
/// Per-instruction spans (optional; debug only).
pub const SECTION_SPANS: u32 = 17;
/// Program metadata and annotations (optional).
pub const SECTION_METADATA: u32 = 18;

/// Section flag: the reader must fail if it does not understand this section.
pub const SECTION_FLAG_REQUIRED: u32 = 0x0000_0001;

/// Returns `true` when `id` names a section this build knows how to decode.
pub const fn is_known_section(id: u32) -> bool {
    matches!(
        id,
        SECTION_PROGRAM_HEADER
            | SECTION_STRINGS
            | SECTION_INSTRUCTIONS
            | SECTION_INSTRUCTION_PARAMS
            | SECTION_LITERALS
            | SECTION_BUILTINS
            | SECTION_ENTRY_POINTS
            | SECTION_RULES
            | SECTION_RULE_TREE
            | SECTION_SOURCES
            | SECTION_SPANS
            | SECTION_METADATA
    )
}

// ── Feature flags ────────────────────────────────────────────────────────────
//
// The low 16 bits are informational: a reader that does not recognise them
// must ignore them.  The high 16 bits are required: a reader that does not
// recognise them must refuse to load the artifact.

/// Informational: debug sections (sources and/or spans) are present.
pub const FEATURE_DEBUG_INFO: u32 = 1 << 0;
/// Informational: the metadata section is present.
pub const FEATURE_METADATA: u32 = 1 << 1;
/// Informational: the program contains `HostAwait` instructions.
pub const FEATURE_HOST_AWAIT: u32 = 1 << 2;
/// Informational: the program was compiled with Rego v0 semantics.
pub const FEATURE_REGO_V0: u32 = 1 << 3;

/// Mask covering the informational (ignorable) flag range.
pub const FEATURE_INFORMATIONAL_MASK: u32 = 0x0000_FFFF;
/// Mask covering the required (must-understand) flag range.
pub const FEATURE_REQUIRED_MASK: u32 = 0xFFFF_0000;

/// All required-range flags understood by this build (currently none).
pub const KNOWN_REQUIRED_FEATURES: u32 = 0;

// ── Program header flags ─────────────────────────────────────────────────────

/// Program was compiled with Rego v0 semantics.
pub const PROGRAM_FLAG_REGO_V0: u8 = 1 << 0;
/// Program requires runtime recursion checking.
pub const PROGRAM_FLAG_RUNTIME_RECURSION_CHECK: u8 = 1 << 1;
/// Program contains at least one `HostAwait` instruction.
pub const PROGRAM_FLAG_HOST_AWAIT: u8 = 1 << 2;

/// All program header flag bits defined by this version.
pub const PROGRAM_FLAGS_KNOWN: u8 =
    PROGRAM_FLAG_REGO_V0 | PROGRAM_FLAG_RUNTIME_RECURSION_CHECK | PROGRAM_FLAG_HOST_AWAIT;

// ── Opcodes ──────────────────────────────────────────────────────────────────
//
// Explicit, stable numbering.  These are NOT the Rust enum discriminants of
// `Instruction`: reordering the Rust enum must not change the wire format.

/// Stable wire opcodes for [`Instruction`](crate::rvm::Instruction).
pub mod opcode {
    pub const LOAD: u8 = 0x01;
    pub const LOAD_TRUE: u8 = 0x02;
    pub const LOAD_FALSE: u8 = 0x03;
    pub const LOAD_NULL: u8 = 0x04;
    pub const LOAD_BOOL: u8 = 0x05;
    pub const LOAD_DATA: u8 = 0x06;
    pub const LOAD_INPUT: u8 = 0x07;
    pub const LOAD_CONTEXT: u8 = 0x08;
    pub const LOAD_METADATA: u8 = 0x09;
    pub const MOVE: u8 = 0x0A;
    pub const ADD: u8 = 0x0B;
    pub const SUB: u8 = 0x0C;
    pub const MUL: u8 = 0x0D;
    pub const DIV: u8 = 0x0E;
    pub const MOD: u8 = 0x0F;
    pub const EQ: u8 = 0x10;
    pub const NE: u8 = 0x11;
    pub const LT: u8 = 0x12;
    pub const LE: u8 = 0x13;
    pub const GT: u8 = 0x14;
    pub const GE: u8 = 0x15;
    pub const AND: u8 = 0x16;
    pub const OR: u8 = 0x17;
    pub const NOT: u8 = 0x18;
    pub const BUILTIN_CALL: u8 = 0x19;
    pub const HOST_AWAIT: u8 = 0x1A;
    pub const FUNCTION_CALL: u8 = 0x1B;
    pub const RETURN: u8 = 0x1C;
    pub const OBJECT_SET: u8 = 0x1D;
    pub const OBJECT_CREATE: u8 = 0x1E;
    pub const INDEX: u8 = 0x1F;
    pub const INDEX_LITERAL: u8 = 0x20;
    pub const CHAINED_INDEX: u8 = 0x21;
    pub const ARRAY_NEW: u8 = 0x22;
    pub const ARRAY_PUSH: u8 = 0x23;
    pub const ARRAY_PUSH_DEFINED: u8 = 0x24;
    pub const ARRAY_CREATE: u8 = 0x25;
    pub const SET_NEW: u8 = 0x26;
    pub const SET_ADD: u8 = 0x27;
    pub const SET_CREATE: u8 = 0x28;
    pub const CONTAINS: u8 = 0x29;
    pub const COUNT: u8 = 0x2A;
    pub const ASSERT_EQ: u8 = 0x2B;
    pub const GUARD: u8 = 0x2C;
    pub const RETURN_UNDEFINED_IF_NOT_TRUE: u8 = 0x2D;
    pub const COALESCE_UNDEFINED_TO_NULL: u8 = 0x2E;
    pub const LOOP_START: u8 = 0x2F;
    pub const LOOP_NEXT: u8 = 0x30;
    pub const CALL_RULE: u8 = 0x31;
    pub const RULE_INIT: u8 = 0x32;
    pub const VIRTUAL_DATA_DOCUMENT_LOOKUP: u8 = 0x33;
    pub const DESTRUCTURING_SUCCESS: u8 = 0x34;
    pub const RULE_RETURN: u8 = 0x35;
    pub const HALT: u8 = 0x36;
    pub const COMPREHENSION_BEGIN: u8 = 0x37;
    pub const COMPREHENSION_YIELD: u8 = 0x38;
    pub const COMPREHENSION_END: u8 = 0x39;
    pub const POLICY_CONDITION: u8 = 0x3A;
    pub const LOGICAL_BLOCK_START: u8 = 0x3B;
    pub const ALL_OF_NEXT: u8 = 0x3C;
    pub const ANY_OF_NEXT: u8 = 0x3D;
    pub const LOGICAL_BLOCK_END: u8 = 0x3E;
}

// ── Enum sub-codes ───────────────────────────────────────────────────────────

/// Stable wire codes for `LoopMode`.
pub mod loop_mode {
    pub const ANY: u8 = 0;
    pub const EVERY: u8 = 1;
    pub const FOR_EACH: u8 = 2;
}

/// Stable wire codes for `ComprehensionMode`.
pub mod comprehension_mode {
    pub const SET: u8 = 0;
    pub const ARRAY: u8 = 1;
    pub const OBJECT: u8 = 2;
}

/// Stable wire codes for `GuardMode`.
pub mod guard_mode {
    pub const NOT: u8 = 0;
    pub const CONDITION: u8 = 1;
    pub const NOT_UNDEFINED: u8 = 2;
}

/// Stable wire codes for `LogicalBlockMode`.
pub mod logical_block_mode {
    pub const ALL_OF: u8 = 0;
    pub const ANY_OF: u8 = 1;
}

/// Stable wire codes for `RuleType`.
pub mod rule_type {
    pub const COMPLETE: u8 = 0;
    pub const PARTIAL_SET: u8 = 1;
    pub const PARTIAL_OBJECT: u8 = 2;
}

/// Stable wire codes for `LiteralOrRegister`.
pub mod path_component {
    pub const LITERAL: u8 = 0;
    pub const REGISTER: u8 = 1;
}

/// Stable wire codes for `PolicyOp`.
pub mod policy_op {
    pub const EQUALS: u16 = 0;
    pub const NOT_EQUALS: u16 = 1;
    pub const GREATER: u16 = 2;
    pub const GREATER_OR_EQUALS: u16 = 3;
    pub const LESS: u16 = 4;
    pub const LESS_OR_EQUALS: u16 = 5;
    pub const IN: u16 = 6;
    pub const NOT_IN: u16 = 7;
    pub const CONTAINS: u16 = 8;
    pub const NOT_CONTAINS: u16 = 9;
    pub const CONTAINS_KEY: u16 = 10;
    pub const NOT_CONTAINS_KEY: u16 = 11;
    pub const LIKE: u16 = 12;
    pub const NOT_LIKE: u16 = 13;
    pub const MATCH: u16 = 14;
    pub const NOT_MATCH: u16 = 15;
    pub const MATCH_INSENSITIVELY: u16 = 16;
    pub const NOT_MATCH_INSENSITIVELY: u16 = 17;
    pub const EXISTS: u16 = 18;
    pub const VALUE_CONDITION_GUARD: u16 = 19;
    pub const NOT: u16 = 20;
}

/// Stable wire tags for encoded [`Value`](crate::value::Value) nodes.
pub mod value_tag {
    /// `Value::Null`
    pub const NULL: u8 = 0x00;
    /// `Value::Bool(false)`
    pub const FALSE: u8 = 0x01;
    /// `Value::Bool(true)`
    pub const TRUE: u8 = 0x02;
    /// `Value::Undefined`
    pub const UNDEFINED: u8 = 0x03;
    /// Signed 64-bit integer, zig-zag LEB128.
    pub const INT: u8 = 0x10;
    /// Unsigned 64-bit integer, LEB128.
    pub const UINT: u8 = 0x11;
    /// IEEE-754 binary64, 8 bytes little-endian.
    pub const FLOAT: u8 = 0x12;
    /// Arbitrary-precision integer, decimal text via string table index.
    pub const BIGINT: u8 = 0x13;
    /// UTF-8 string via string table index.
    pub const STRING: u8 = 0x20;
    /// Ordered array of values.
    pub const ARRAY: u8 = 0x30;
    /// Set of values, written in `Value::Ord` order.
    pub const SET: u8 = 0x31;
    /// Object with arbitrary value keys, written in `Value::Ord` key order.
    pub const OBJECT: u8 = 0x32;
}

/// CRC-32 (IEEE 802.3, reflected, `0xEDB88320` polynomial) over `data`.
///
/// Implemented bit-by-bit so that no lookup table needs to be shipped or
/// agreed on between implementations.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let carry = crc & 1;
            crc = crc.wrapping_shr(1);
            if carry != 0 {
                crc ^= 0xEDB8_8320;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_vectors() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
    }

    #[test]
    fn section_ids_are_classified() {
        assert!(is_known_section(SECTION_PROGRAM_HEADER));
        assert!(is_known_section(SECTION_METADATA));
        assert!(!is_known_section(9999));
    }
}
