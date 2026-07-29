// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fixed-width instruction word codec.
//!
//! Every instruction occupies exactly eight bytes:
//!
//! ```text
//! offset 0  u8   opcode        (stable wire opcode, see `format::opcode`)
//! offset 1  u8   a             (register / sub-mode)
//! offset 2  u8   b             (register / sub-mode)
//! offset 3  u8   c             (register / flag)
//! offset 4  u16  imm0  LE      (literal index, params index, jump target)
//! offset 6  u16  imm1  LE      (secondary jump target)
//! ```
//!
//! A fixed stride means the instruction section is a flat array: a managed
//! reader can bulk-copy or reinterpret it, and random access to any program
//! counter is O(1) with a single bounds check.  Unused fields are written as
//! zero, which is what makes the encoding canonical.

use super::errors::{PortableError, PortableResult};
use super::format::{
    comprehension_mode, guard_mode, logical_block_mode, loop_mode, opcode, policy_op,
    INSTRUCTION_WORD_SIZE,
};
use crate::rvm::instructions::{
    ComprehensionMode, GuardMode, LogicalBlockMode, LoopMode, PolicyOp,
};
use crate::rvm::Instruction;

/// Decoded eight byte instruction word.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InstructionWord {
    /// Stable wire opcode.
    pub opcode: u8,
    /// First byte operand.
    pub a: u8,
    /// Second byte operand.
    pub b: u8,
    /// Third byte operand.
    pub c: u8,
    /// First 16-bit immediate.
    pub imm0: u16,
    /// Second 16-bit immediate.
    pub imm1: u16,
}

impl InstructionWord {
    /// Serialize the word to its little-endian byte form.
    pub const fn to_bytes(self) -> [u8; INSTRUCTION_WORD_SIZE] {
        let imm0 = self.imm0.to_le_bytes();
        let imm1 = self.imm1.to_le_bytes();
        [
            self.opcode,
            self.a,
            self.b,
            self.c,
            imm0[0],
            imm0[1],
            imm1[0],
            imm1[1],
        ]
    }

    /// Parse a word from its little-endian byte form.
    pub const fn from_bytes(bytes: [u8; INSTRUCTION_WORD_SIZE]) -> Self {
        Self {
            opcode: bytes[0],
            a: bytes[1],
            b: bytes[2],
            c: bytes[3],
            imm0: u16::from_le_bytes([bytes[4], bytes[5]]),
            imm1: u16::from_le_bytes([bytes[6], bytes[7]]),
        }
    }

    const fn op(opcode: u8) -> Self {
        Self {
            opcode,
            a: 0,
            b: 0,
            c: 0,
            imm0: 0,
            imm1: 0,
        }
    }

    const fn with_a(opcode: u8, a: u8) -> Self {
        Self {
            opcode,
            a,
            b: 0,
            c: 0,
            imm0: 0,
            imm1: 0,
        }
    }

    const fn with_ab(opcode: u8, a: u8, b: u8) -> Self {
        Self {
            opcode,
            a,
            b,
            c: 0,
            imm0: 0,
            imm1: 0,
        }
    }

    const fn with_abc(opcode: u8, a: u8, b: u8, c: u8) -> Self {
        Self {
            opcode,
            a,
            b,
            c,
            imm0: 0,
            imm1: 0,
        }
    }

    const fn with_imm(opcode: u8, imm0: u16) -> Self {
        Self {
            opcode,
            a: 0,
            b: 0,
            c: 0,
            imm0,
            imm1: 0,
        }
    }

    const fn with_a_imm(opcode: u8, a: u8, imm0: u16) -> Self {
        Self {
            opcode,
            a,
            b: 0,
            c: 0,
            imm0,
            imm1: 0,
        }
    }

    const fn with_ab_imm(opcode: u8, a: u8, b: u8, imm0: u16) -> Self {
        Self {
            opcode,
            a,
            b,
            c: 0,
            imm0,
            imm1: 0,
        }
    }
}

const fn loop_mode_code(mode: LoopMode) -> u8 {
    match mode {
        LoopMode::Any => loop_mode::ANY,
        LoopMode::Every => loop_mode::EVERY,
        LoopMode::ForEach => loop_mode::FOR_EACH,
    }
}

/// Map a wire code back to a [`LoopMode`].
pub fn loop_mode_from_code(code: u8) -> PortableResult<LoopMode> {
    match code {
        loop_mode::ANY => Ok(LoopMode::Any),
        loop_mode::EVERY => Ok(LoopMode::Every),
        loop_mode::FOR_EACH => Ok(LoopMode::ForEach),
        other => Err(PortableError::InvalidDiscriminant {
            kind: "LoopMode",
            value: u32::from(other),
        }),
    }
}

/// Map a [`LoopMode`] to its wire code.
pub const fn loop_mode_to_code(mode: LoopMode) -> u8 {
    loop_mode_code(mode)
}

/// Map a [`ComprehensionMode`] to its wire code.
pub const fn comprehension_mode_to_code(mode: &ComprehensionMode) -> u8 {
    match *mode {
        ComprehensionMode::Set => comprehension_mode::SET,
        ComprehensionMode::Array => comprehension_mode::ARRAY,
        ComprehensionMode::Object => comprehension_mode::OBJECT,
    }
}

/// Map a wire code back to a [`ComprehensionMode`].
pub fn comprehension_mode_from_code(code: u8) -> PortableResult<ComprehensionMode> {
    match code {
        comprehension_mode::SET => Ok(ComprehensionMode::Set),
        comprehension_mode::ARRAY => Ok(ComprehensionMode::Array),
        comprehension_mode::OBJECT => Ok(ComprehensionMode::Object),
        other => Err(PortableError::InvalidDiscriminant {
            kind: "ComprehensionMode",
            value: u32::from(other),
        }),
    }
}

const fn guard_mode_to_code(mode: GuardMode) -> u8 {
    match mode {
        GuardMode::Not => guard_mode::NOT,
        GuardMode::Condition => guard_mode::CONDITION,
        GuardMode::NotUndefined => guard_mode::NOT_UNDEFINED,
    }
}

fn guard_mode_from_code(code: u8) -> PortableResult<GuardMode> {
    match code {
        guard_mode::NOT => Ok(GuardMode::Not),
        guard_mode::CONDITION => Ok(GuardMode::Condition),
        guard_mode::NOT_UNDEFINED => Ok(GuardMode::NotUndefined),
        other => Err(PortableError::InvalidDiscriminant {
            kind: "GuardMode",
            value: u32::from(other),
        }),
    }
}

const fn logical_block_mode_to_code(mode: LogicalBlockMode) -> u8 {
    match mode {
        LogicalBlockMode::AllOf => logical_block_mode::ALL_OF,
        LogicalBlockMode::AnyOf => logical_block_mode::ANY_OF,
    }
}

fn logical_block_mode_from_code(code: u8) -> PortableResult<LogicalBlockMode> {
    match code {
        logical_block_mode::ALL_OF => Ok(LogicalBlockMode::AllOf),
        logical_block_mode::ANY_OF => Ok(LogicalBlockMode::AnyOf),
        other => Err(PortableError::InvalidDiscriminant {
            kind: "LogicalBlockMode",
            value: u32::from(other),
        }),
    }
}

const fn policy_op_to_code(op: PolicyOp) -> u16 {
    match op {
        PolicyOp::Equals => policy_op::EQUALS,
        PolicyOp::NotEquals => policy_op::NOT_EQUALS,
        PolicyOp::Greater => policy_op::GREATER,
        PolicyOp::GreaterOrEquals => policy_op::GREATER_OR_EQUALS,
        PolicyOp::Less => policy_op::LESS,
        PolicyOp::LessOrEquals => policy_op::LESS_OR_EQUALS,
        PolicyOp::In => policy_op::IN,
        PolicyOp::NotIn => policy_op::NOT_IN,
        PolicyOp::Contains => policy_op::CONTAINS,
        PolicyOp::NotContains => policy_op::NOT_CONTAINS,
        PolicyOp::ContainsKey => policy_op::CONTAINS_KEY,
        PolicyOp::NotContainsKey => policy_op::NOT_CONTAINS_KEY,
        PolicyOp::Like => policy_op::LIKE,
        PolicyOp::NotLike => policy_op::NOT_LIKE,
        PolicyOp::Match => policy_op::MATCH,
        PolicyOp::NotMatch => policy_op::NOT_MATCH,
        PolicyOp::MatchInsensitively => policy_op::MATCH_INSENSITIVELY,
        PolicyOp::NotMatchInsensitively => policy_op::NOT_MATCH_INSENSITIVELY,
        PolicyOp::Exists => policy_op::EXISTS,
        PolicyOp::ValueConditionGuard => policy_op::VALUE_CONDITION_GUARD,
        PolicyOp::Not => policy_op::NOT,
    }
}

fn policy_op_from_code(code: u16) -> PortableResult<PolicyOp> {
    match code {
        policy_op::EQUALS => Ok(PolicyOp::Equals),
        policy_op::NOT_EQUALS => Ok(PolicyOp::NotEquals),
        policy_op::GREATER => Ok(PolicyOp::Greater),
        policy_op::GREATER_OR_EQUALS => Ok(PolicyOp::GreaterOrEquals),
        policy_op::LESS => Ok(PolicyOp::Less),
        policy_op::LESS_OR_EQUALS => Ok(PolicyOp::LessOrEquals),
        policy_op::IN => Ok(PolicyOp::In),
        policy_op::NOT_IN => Ok(PolicyOp::NotIn),
        policy_op::CONTAINS => Ok(PolicyOp::Contains),
        policy_op::NOT_CONTAINS => Ok(PolicyOp::NotContains),
        policy_op::CONTAINS_KEY => Ok(PolicyOp::ContainsKey),
        policy_op::NOT_CONTAINS_KEY => Ok(PolicyOp::NotContainsKey),
        policy_op::LIKE => Ok(PolicyOp::Like),
        policy_op::NOT_LIKE => Ok(PolicyOp::NotLike),
        policy_op::MATCH => Ok(PolicyOp::Match),
        policy_op::NOT_MATCH => Ok(PolicyOp::NotMatch),
        policy_op::MATCH_INSENSITIVELY => Ok(PolicyOp::MatchInsensitively),
        policy_op::NOT_MATCH_INSENSITIVELY => Ok(PolicyOp::NotMatchInsensitively),
        policy_op::EXISTS => Ok(PolicyOp::Exists),
        policy_op::VALUE_CONDITION_GUARD => Ok(PolicyOp::ValueConditionGuard),
        policy_op::NOT => Ok(PolicyOp::Not),
        other => Err(PortableError::InvalidDiscriminant {
            kind: "PolicyOp",
            value: u32::from(other),
        }),
    }
}

/// Convert an [`Instruction`] into its portable word form.
pub const fn encode_instruction(instruction: Instruction) -> InstructionWord {
    match instruction {
        Instruction::Load { dest, literal_idx } => {
            InstructionWord::with_a_imm(opcode::LOAD, dest, literal_idx)
        }
        Instruction::LoadTrue { dest } => InstructionWord::with_a(opcode::LOAD_TRUE, dest),
        Instruction::LoadFalse { dest } => InstructionWord::with_a(opcode::LOAD_FALSE, dest),
        Instruction::LoadNull { dest } => InstructionWord::with_a(opcode::LOAD_NULL, dest),
        Instruction::LoadBool { dest, value } => {
            InstructionWord::with_ab(opcode::LOAD_BOOL, dest, if value { 1 } else { 0 })
        }
        Instruction::LoadData { dest } => InstructionWord::with_a(opcode::LOAD_DATA, dest),
        Instruction::LoadInput { dest } => InstructionWord::with_a(opcode::LOAD_INPUT, dest),
        Instruction::LoadContext { dest } => InstructionWord::with_a(opcode::LOAD_CONTEXT, dest),
        Instruction::LoadMetadata { dest } => InstructionWord::with_a(opcode::LOAD_METADATA, dest),
        Instruction::Move { dest, src } => InstructionWord::with_ab(opcode::MOVE, dest, src),
        Instruction::Add { dest, left, right } => {
            InstructionWord::with_abc(opcode::ADD, dest, left, right)
        }
        Instruction::Sub { dest, left, right } => {
            InstructionWord::with_abc(opcode::SUB, dest, left, right)
        }
        Instruction::Mul { dest, left, right } => {
            InstructionWord::with_abc(opcode::MUL, dest, left, right)
        }
        Instruction::Div { dest, left, right } => {
            InstructionWord::with_abc(opcode::DIV, dest, left, right)
        }
        Instruction::Mod { dest, left, right } => {
            InstructionWord::with_abc(opcode::MOD, dest, left, right)
        }
        Instruction::Eq { dest, left, right } => {
            InstructionWord::with_abc(opcode::EQ, dest, left, right)
        }
        Instruction::Ne { dest, left, right } => {
            InstructionWord::with_abc(opcode::NE, dest, left, right)
        }
        Instruction::Lt { dest, left, right } => {
            InstructionWord::with_abc(opcode::LT, dest, left, right)
        }
        Instruction::Le { dest, left, right } => {
            InstructionWord::with_abc(opcode::LE, dest, left, right)
        }
        Instruction::Gt { dest, left, right } => {
            InstructionWord::with_abc(opcode::GT, dest, left, right)
        }
        Instruction::Ge { dest, left, right } => {
            InstructionWord::with_abc(opcode::GE, dest, left, right)
        }
        Instruction::And { dest, left, right } => {
            InstructionWord::with_abc(opcode::AND, dest, left, right)
        }
        Instruction::Or { dest, left, right } => {
            InstructionWord::with_abc(opcode::OR, dest, left, right)
        }
        Instruction::Not { dest, operand } => InstructionWord::with_ab(opcode::NOT, dest, operand),
        Instruction::BuiltinCall { params_index } => {
            InstructionWord::with_imm(opcode::BUILTIN_CALL, params_index)
        }
        Instruction::HostAwait { dest, arg, id } => {
            InstructionWord::with_abc(opcode::HOST_AWAIT, dest, arg, id)
        }
        Instruction::FunctionCall { params_index } => {
            InstructionWord::with_imm(opcode::FUNCTION_CALL, params_index)
        }
        Instruction::Return { value } => InstructionWord::with_a(opcode::RETURN, value),
        Instruction::ObjectSet { obj, key, value } => {
            InstructionWord::with_abc(opcode::OBJECT_SET, obj, key, value)
        }
        Instruction::ObjectCreate { params_index } => {
            InstructionWord::with_imm(opcode::OBJECT_CREATE, params_index)
        }
        Instruction::Index {
            dest,
            container,
            key,
        } => InstructionWord::with_abc(opcode::INDEX, dest, container, key),
        Instruction::IndexLiteral {
            dest,
            container,
            literal_idx,
        } => InstructionWord::with_ab_imm(opcode::INDEX_LITERAL, dest, container, literal_idx),
        Instruction::ChainedIndex { params_index } => {
            InstructionWord::with_imm(opcode::CHAINED_INDEX, params_index)
        }
        Instruction::ArrayNew { dest } => InstructionWord::with_a(opcode::ARRAY_NEW, dest),
        Instruction::ArrayPush { arr, value } => {
            InstructionWord::with_ab(opcode::ARRAY_PUSH, arr, value)
        }
        Instruction::ArrayPushDefined { arr, value } => {
            InstructionWord::with_ab(opcode::ARRAY_PUSH_DEFINED, arr, value)
        }
        Instruction::ArrayCreate { params_index } => {
            InstructionWord::with_imm(opcode::ARRAY_CREATE, params_index)
        }
        Instruction::SetNew { dest } => InstructionWord::with_a(opcode::SET_NEW, dest),
        Instruction::SetAdd { set, value } => InstructionWord::with_ab(opcode::SET_ADD, set, value),
        Instruction::SetCreate { params_index } => {
            InstructionWord::with_imm(opcode::SET_CREATE, params_index)
        }
        Instruction::Contains {
            dest,
            collection,
            value,
        } => InstructionWord::with_abc(opcode::CONTAINS, dest, collection, value),
        Instruction::Count { dest, collection } => {
            InstructionWord::with_ab(opcode::COUNT, dest, collection)
        }
        Instruction::AssertEq { left, right } => {
            InstructionWord::with_ab(opcode::ASSERT_EQ, left, right)
        }
        Instruction::Guard { register, mode } => {
            InstructionWord::with_ab(opcode::GUARD, register, guard_mode_to_code(mode))
        }
        Instruction::ReturnUndefinedIfNotTrue { condition } => {
            InstructionWord::with_a(opcode::RETURN_UNDEFINED_IF_NOT_TRUE, condition)
        }
        Instruction::CoalesceUndefinedToNull { register } => {
            InstructionWord::with_a(opcode::COALESCE_UNDEFINED_TO_NULL, register)
        }
        Instruction::LoopStart { params_index } => {
            InstructionWord::with_imm(opcode::LOOP_START, params_index)
        }
        Instruction::LoopNext {
            body_start,
            loop_end,
        } => InstructionWord {
            opcode: opcode::LOOP_NEXT,
            a: 0,
            b: 0,
            c: 0,
            imm0: body_start,
            imm1: loop_end,
        },
        Instruction::CallRule { dest, rule_index } => {
            InstructionWord::with_a_imm(opcode::CALL_RULE, dest, rule_index)
        }
        Instruction::RuleInit {
            result_reg,
            rule_index,
        } => InstructionWord::with_a_imm(opcode::RULE_INIT, result_reg, rule_index),
        Instruction::VirtualDataDocumentLookup { params_index } => {
            InstructionWord::with_imm(opcode::VIRTUAL_DATA_DOCUMENT_LOOKUP, params_index)
        }
        Instruction::DestructuringSuccess {} => InstructionWord::op(opcode::DESTRUCTURING_SUCCESS),
        Instruction::RuleReturn {} => InstructionWord::op(opcode::RULE_RETURN),
        Instruction::Halt {} => InstructionWord::op(opcode::HALT),
        Instruction::ComprehensionBegin { params_index } => {
            InstructionWord::with_imm(opcode::COMPREHENSION_BEGIN, params_index)
        }
        Instruction::ComprehensionYield { value_reg, key_reg } => match key_reg {
            Some(key) => InstructionWord::with_abc(opcode::COMPREHENSION_YIELD, value_reg, key, 1),
            None => InstructionWord::with_abc(opcode::COMPREHENSION_YIELD, value_reg, 0, 0),
        },
        Instruction::ComprehensionEnd {} => InstructionWord::op(opcode::COMPREHENSION_END),
        Instruction::PolicyCondition {
            dest,
            left,
            right,
            op,
        } => InstructionWord {
            opcode: opcode::POLICY_CONDITION,
            a: dest,
            b: left,
            c: right,
            imm0: policy_op_to_code(op),
            imm1: 0,
        },
        Instruction::LogicalBlockStart {
            mode,
            result,
            end_pc,
        } => InstructionWord::with_ab_imm(
            opcode::LOGICAL_BLOCK_START,
            logical_block_mode_to_code(mode),
            result,
            end_pc,
        ),
        Instruction::AllOfNext {
            check,
            result,
            end_pc,
        } => InstructionWord::with_ab_imm(opcode::ALL_OF_NEXT, check, result, end_pc),
        Instruction::AnyOfNext {
            check,
            result,
            end_pc,
        } => InstructionWord::with_ab_imm(opcode::ANY_OF_NEXT, check, result, end_pc),
        Instruction::LogicalBlockEnd { mode, result } => InstructionWord::with_ab(
            opcode::LOGICAL_BLOCK_END,
            logical_block_mode_to_code(mode),
            result,
        ),
    }
}

/// Convert a portable word back into an [`Instruction`].
///
/// `index` is only used to build a precise error message.
pub fn decode_instruction(word: InstructionWord, index: usize) -> PortableResult<Instruction> {
    let instruction = match word.opcode {
        opcode::LOAD => Instruction::Load {
            dest: word.a,
            literal_idx: word.imm0,
        },
        opcode::LOAD_TRUE => Instruction::LoadTrue { dest: word.a },
        opcode::LOAD_FALSE => Instruction::LoadFalse { dest: word.a },
        opcode::LOAD_NULL => Instruction::LoadNull { dest: word.a },
        opcode::LOAD_BOOL => Instruction::LoadBool {
            dest: word.a,
            value: word.b != 0,
        },
        opcode::LOAD_DATA => Instruction::LoadData { dest: word.a },
        opcode::LOAD_INPUT => Instruction::LoadInput { dest: word.a },
        opcode::LOAD_CONTEXT => Instruction::LoadContext { dest: word.a },
        opcode::LOAD_METADATA => Instruction::LoadMetadata { dest: word.a },
        opcode::MOVE => Instruction::Move {
            dest: word.a,
            src: word.b,
        },
        opcode::ADD => Instruction::Add {
            dest: word.a,
            left: word.b,
            right: word.c,
        },
        opcode::SUB => Instruction::Sub {
            dest: word.a,
            left: word.b,
            right: word.c,
        },
        opcode::MUL => Instruction::Mul {
            dest: word.a,
            left: word.b,
            right: word.c,
        },
        opcode::DIV => Instruction::Div {
            dest: word.a,
            left: word.b,
            right: word.c,
        },
        opcode::MOD => Instruction::Mod {
            dest: word.a,
            left: word.b,
            right: word.c,
        },
        opcode::EQ => Instruction::Eq {
            dest: word.a,
            left: word.b,
            right: word.c,
        },
        opcode::NE => Instruction::Ne {
            dest: word.a,
            left: word.b,
            right: word.c,
        },
        opcode::LT => Instruction::Lt {
            dest: word.a,
            left: word.b,
            right: word.c,
        },
        opcode::LE => Instruction::Le {
            dest: word.a,
            left: word.b,
            right: word.c,
        },
        opcode::GT => Instruction::Gt {
            dest: word.a,
            left: word.b,
            right: word.c,
        },
        opcode::GE => Instruction::Ge {
            dest: word.a,
            left: word.b,
            right: word.c,
        },
        opcode::AND => Instruction::And {
            dest: word.a,
            left: word.b,
            right: word.c,
        },
        opcode::OR => Instruction::Or {
            dest: word.a,
            left: word.b,
            right: word.c,
        },
        opcode::NOT => Instruction::Not {
            dest: word.a,
            operand: word.b,
        },
        opcode::BUILTIN_CALL => Instruction::BuiltinCall {
            params_index: word.imm0,
        },
        opcode::HOST_AWAIT => Instruction::HostAwait {
            dest: word.a,
            arg: word.b,
            id: word.c,
        },
        opcode::FUNCTION_CALL => Instruction::FunctionCall {
            params_index: word.imm0,
        },
        opcode::RETURN => Instruction::Return { value: word.a },
        opcode::OBJECT_SET => Instruction::ObjectSet {
            obj: word.a,
            key: word.b,
            value: word.c,
        },
        opcode::OBJECT_CREATE => Instruction::ObjectCreate {
            params_index: word.imm0,
        },
        opcode::INDEX => Instruction::Index {
            dest: word.a,
            container: word.b,
            key: word.c,
        },
        opcode::INDEX_LITERAL => Instruction::IndexLiteral {
            dest: word.a,
            container: word.b,
            literal_idx: word.imm0,
        },
        opcode::CHAINED_INDEX => Instruction::ChainedIndex {
            params_index: word.imm0,
        },
        opcode::ARRAY_NEW => Instruction::ArrayNew { dest: word.a },
        opcode::ARRAY_PUSH => Instruction::ArrayPush {
            arr: word.a,
            value: word.b,
        },
        opcode::ARRAY_PUSH_DEFINED => Instruction::ArrayPushDefined {
            arr: word.a,
            value: word.b,
        },
        opcode::ARRAY_CREATE => Instruction::ArrayCreate {
            params_index: word.imm0,
        },
        opcode::SET_NEW => Instruction::SetNew { dest: word.a },
        opcode::SET_ADD => Instruction::SetAdd {
            set: word.a,
            value: word.b,
        },
        opcode::SET_CREATE => Instruction::SetCreate {
            params_index: word.imm0,
        },
        opcode::CONTAINS => Instruction::Contains {
            dest: word.a,
            collection: word.b,
            value: word.c,
        },
        opcode::COUNT => Instruction::Count {
            dest: word.a,
            collection: word.b,
        },
        opcode::ASSERT_EQ => Instruction::AssertEq {
            left: word.a,
            right: word.b,
        },
        opcode::GUARD => Instruction::Guard {
            register: word.a,
            mode: guard_mode_from_code(word.b)?,
        },
        opcode::RETURN_UNDEFINED_IF_NOT_TRUE => {
            Instruction::ReturnUndefinedIfNotTrue { condition: word.a }
        }
        opcode::COALESCE_UNDEFINED_TO_NULL => {
            Instruction::CoalesceUndefinedToNull { register: word.a }
        }
        opcode::LOOP_START => Instruction::LoopStart {
            params_index: word.imm0,
        },
        opcode::LOOP_NEXT => Instruction::LoopNext {
            body_start: word.imm0,
            loop_end: word.imm1,
        },
        opcode::CALL_RULE => Instruction::CallRule {
            dest: word.a,
            rule_index: word.imm0,
        },
        opcode::RULE_INIT => Instruction::RuleInit {
            result_reg: word.a,
            rule_index: word.imm0,
        },
        opcode::VIRTUAL_DATA_DOCUMENT_LOOKUP => Instruction::VirtualDataDocumentLookup {
            params_index: word.imm0,
        },
        opcode::DESTRUCTURING_SUCCESS => Instruction::DestructuringSuccess {},
        opcode::RULE_RETURN => Instruction::RuleReturn {},
        opcode::HALT => Instruction::Halt {},
        opcode::COMPREHENSION_BEGIN => Instruction::ComprehensionBegin {
            params_index: word.imm0,
        },
        opcode::COMPREHENSION_YIELD => Instruction::ComprehensionYield {
            value_reg: word.a,
            key_reg: (word.c != 0).then_some(word.b),
        },
        opcode::COMPREHENSION_END => Instruction::ComprehensionEnd {},
        opcode::POLICY_CONDITION => Instruction::PolicyCondition {
            dest: word.a,
            left: word.b,
            right: word.c,
            op: policy_op_from_code(word.imm0)?,
        },
        opcode::LOGICAL_BLOCK_START => Instruction::LogicalBlockStart {
            mode: logical_block_mode_from_code(word.a)?,
            result: word.b,
            end_pc: word.imm0,
        },
        opcode::ALL_OF_NEXT => Instruction::AllOfNext {
            check: word.a,
            result: word.b,
            end_pc: word.imm0,
        },
        opcode::ANY_OF_NEXT => Instruction::AnyOfNext {
            check: word.a,
            result: word.b,
            end_pc: word.imm0,
        },
        opcode::LOGICAL_BLOCK_END => Instruction::LogicalBlockEnd {
            mode: logical_block_mode_from_code(word.a)?,
            result: word.b,
        },
        other => {
            return Err(PortableError::UnknownOpcode {
                opcode: other,
                index,
            })
        }
    };
    Ok(instruction)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn sample_instructions() -> Vec<Instruction> {
        alloc::vec![
            Instruction::Load {
                dest: 3,
                literal_idx: 900
            },
            Instruction::LoadTrue { dest: 1 },
            Instruction::LoadFalse { dest: 2 },
            Instruction::LoadNull { dest: 3 },
            Instruction::LoadBool {
                dest: 4,
                value: true
            },
            Instruction::LoadBool {
                dest: 4,
                value: false
            },
            Instruction::LoadData { dest: 5 },
            Instruction::LoadInput { dest: 6 },
            Instruction::LoadContext { dest: 7 },
            Instruction::LoadMetadata { dest: 8 },
            Instruction::Move { dest: 1, src: 2 },
            Instruction::Add {
                dest: 1,
                left: 2,
                right: 3
            },
            Instruction::Sub {
                dest: 1,
                left: 2,
                right: 3
            },
            Instruction::Mul {
                dest: 1,
                left: 2,
                right: 3
            },
            Instruction::Div {
                dest: 1,
                left: 2,
                right: 3
            },
            Instruction::Mod {
                dest: 1,
                left: 2,
                right: 3
            },
            Instruction::Eq {
                dest: 1,
                left: 2,
                right: 3
            },
            Instruction::Ne {
                dest: 1,
                left: 2,
                right: 3
            },
            Instruction::Lt {
                dest: 1,
                left: 2,
                right: 3
            },
            Instruction::Le {
                dest: 1,
                left: 2,
                right: 3
            },
            Instruction::Gt {
                dest: 1,
                left: 2,
                right: 3
            },
            Instruction::Ge {
                dest: 1,
                left: 2,
                right: 3
            },
            Instruction::And {
                dest: 1,
                left: 2,
                right: 3
            },
            Instruction::Or {
                dest: 1,
                left: 2,
                right: 3
            },
            Instruction::Not {
                dest: 1,
                operand: 2
            },
            Instruction::BuiltinCall { params_index: 12 },
            Instruction::HostAwait {
                dest: 1,
                arg: 2,
                id: 3
            },
            Instruction::FunctionCall { params_index: 5 },
            Instruction::Return { value: 9 },
            Instruction::ObjectSet {
                obj: 1,
                key: 2,
                value: 3
            },
            Instruction::ObjectCreate { params_index: 7 },
            Instruction::Index {
                dest: 1,
                container: 2,
                key: 3
            },
            Instruction::IndexLiteral {
                dest: 1,
                container: 2,
                literal_idx: 4000
            },
            Instruction::ChainedIndex { params_index: 8 },
            Instruction::ArrayNew { dest: 1 },
            Instruction::ArrayPush { arr: 1, value: 2 },
            Instruction::ArrayPushDefined { arr: 1, value: 2 },
            Instruction::ArrayCreate { params_index: 2 },
            Instruction::SetNew { dest: 1 },
            Instruction::SetAdd { set: 1, value: 2 },
            Instruction::SetCreate { params_index: 3 },
            Instruction::Contains {
                dest: 1,
                collection: 2,
                value: 3
            },
            Instruction::Count {
                dest: 1,
                collection: 2
            },
            Instruction::AssertEq { left: 1, right: 2 },
            Instruction::Guard {
                register: 1,
                mode: GuardMode::Not
            },
            Instruction::Guard {
                register: 1,
                mode: GuardMode::Condition
            },
            Instruction::Guard {
                register: 1,
                mode: GuardMode::NotUndefined
            },
            Instruction::ReturnUndefinedIfNotTrue { condition: 4 },
            Instruction::CoalesceUndefinedToNull { register: 4 },
            Instruction::LoopStart { params_index: 6 },
            Instruction::LoopNext {
                body_start: 10,
                loop_end: 20
            },
            Instruction::CallRule {
                dest: 1,
                rule_index: 42
            },
            Instruction::RuleInit {
                result_reg: 1,
                rule_index: 42
            },
            Instruction::VirtualDataDocumentLookup { params_index: 9 },
            Instruction::DestructuringSuccess {},
            Instruction::RuleReturn {},
            Instruction::Halt {},
            Instruction::ComprehensionBegin { params_index: 3 },
            Instruction::ComprehensionYield {
                value_reg: 1,
                key_reg: None
            },
            Instruction::ComprehensionYield {
                value_reg: 1,
                key_reg: Some(0)
            },
            Instruction::ComprehensionYield {
                value_reg: 1,
                key_reg: Some(5)
            },
            Instruction::ComprehensionEnd {},
            Instruction::PolicyCondition {
                dest: 1,
                left: 2,
                right: 3,
                op: PolicyOp::Equals
            },
            Instruction::PolicyCondition {
                dest: 1,
                left: 2,
                right: 3,
                op: PolicyOp::Not
            },
            Instruction::LogicalBlockStart {
                mode: LogicalBlockMode::AllOf,
                result: 2,
                end_pc: 44
            },
            Instruction::LogicalBlockStart {
                mode: LogicalBlockMode::AnyOf,
                result: 2,
                end_pc: 44
            },
            Instruction::AllOfNext {
                check: 1,
                result: 2,
                end_pc: 44
            },
            Instruction::AnyOfNext {
                check: 1,
                result: 2,
                end_pc: 44
            },
            Instruction::LogicalBlockEnd {
                mode: LogicalBlockMode::AllOf,
                result: 2
            },
            Instruction::LogicalBlockEnd {
                mode: LogicalBlockMode::AnyOf,
                result: 2
            },
        ]
    }

    #[test]
    fn every_instruction_round_trips() {
        for instruction in sample_instructions() {
            let word = encode_instruction(instruction);
            let bytes = word.to_bytes();
            let restored = InstructionWord::from_bytes(bytes);
            assert_eq!(word, restored);
            let decoded = decode_instruction(restored, 0).unwrap();
            let re_encoded = encode_instruction(decoded);
            assert_eq!(
                word, re_encoded,
                "instruction did not survive round-trip: {:?}",
                instruction
            );
        }
    }

    #[test]
    fn opcodes_are_unique() {
        let mut seen = alloc::collections::BTreeSet::new();
        for instruction in sample_instructions() {
            seen.insert(encode_instruction(instruction).opcode);
        }
        // 62 distinct opcodes are exercised by the sample set.
        assert_eq!(seen.len(), 62);
    }

    #[test]
    fn unknown_opcode_rejected() {
        let word = InstructionWord {
            opcode: 0xFE,
            ..InstructionWord::default()
        };
        assert!(matches!(
            decode_instruction(word, 7),
            Err(PortableError::UnknownOpcode {
                opcode: 0xFE,
                index: 7
            })
        ));
    }

    #[test]
    fn invalid_guard_mode_rejected() {
        let word = InstructionWord {
            opcode: opcode::GUARD,
            a: 1,
            b: 9,
            ..InstructionWord::default()
        };
        assert!(matches!(
            decode_instruction(word, 0),
            Err(PortableError::InvalidDiscriminant { .. })
        ));
    }
}
