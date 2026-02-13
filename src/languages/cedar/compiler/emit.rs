// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::error::{CompilerError, Result};
use super::Compiler;
use crate::rvm::instructions::BuiltinCallParams;
use crate::rvm::program::{BuiltinInfo, BuiltinKind, SpanInfo};
use crate::rvm::Instruction;
use crate::Value;
use alloc::string::String;

impl Compiler {
    pub(super) fn get_input_register(&mut self) -> Result<u8> {
        if let Some(reg) = self.input_reg {
            return Ok(reg);
        }
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::LoadInput { dest });
        self.input_reg = Some(dest);
        Ok(dest)
    }

    pub(super) fn get_entities_register(&mut self) -> Result<u8> {
        if let Some(reg) = self.entities_reg {
            return Ok(reg);
        }
        let input = self.get_input_register()?;
        let literal_idx = self.add_literal(Value::from("entities"));
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::IndexLiteral {
            dest,
            container: input,
            literal_idx,
        });
        self.entities_reg = Some(dest);
        Ok(dest)
    }

    pub(super) fn get_principal_register(&mut self) -> Result<u8> {
        if let Some(reg) = self.principal_reg {
            return Ok(reg);
        }
        let input = self.get_input_register()?;
        let literal_idx = self.add_literal(Value::from("principal"));
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::IndexLiteral {
            dest,
            container: input,
            literal_idx,
        });
        self.principal_reg = Some(dest);
        Ok(dest)
    }

    pub(super) fn get_action_register(&mut self) -> Result<u8> {
        if let Some(reg) = self.action_reg {
            return Ok(reg);
        }
        let input = self.get_input_register()?;
        let literal_idx = self.add_literal(Value::from("action"));
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::IndexLiteral {
            dest,
            container: input,
            literal_idx,
        });
        self.action_reg = Some(dest);
        Ok(dest)
    }

    pub(super) fn get_resource_register(&mut self) -> Result<u8> {
        if let Some(reg) = self.resource_reg {
            return Ok(reg);
        }
        let input = self.get_input_register()?;
        let literal_idx = self.add_literal(Value::from("resource"));
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::IndexLiteral {
            dest,
            container: input,
            literal_idx,
        });
        self.resource_reg = Some(dest);
        Ok(dest)
    }

    pub(super) fn get_context_register(&mut self) -> Result<u8> {
        if let Some(reg) = self.context_reg {
            return Ok(reg);
        }
        let input = self.get_input_register()?;
        let literal_idx = self.add_literal(Value::from("context"));
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::IndexLiteral {
            dest,
            container: input,
            literal_idx,
        });
        self.context_reg = Some(dest);
        Ok(dest)
    }

    pub(super) fn emit_cedar_in(&mut self, entity_reg: u8, target_reg: u8) -> Result<u8> {
        let entities = self.get_entities_register()?;
        self.emit_ctx_builtin("cedar.in", &[entity_reg, target_reg, entities])
    }

    pub(super) fn emit_cedar_in_set(&mut self, entity_reg: u8, target_reg: u8) -> Result<u8> {
        let entities = self.get_entities_register()?;
        self.emit_ctx_builtin("cedar.in_set", &[entity_reg, target_reg, entities])
    }

    pub(super) fn emit_cedar_has(&mut self, entity_reg: u8, attr_reg: u8) -> Result<u8> {
        let entities = self.get_entities_register()?;
        self.emit_ctx_builtin("cedar.has", &[entity_reg, attr_reg, entities])
    }

    pub(super) fn emit_cedar_attr(&mut self, entity_reg: u8, attr_reg: u8) -> Result<u8> {
        let entities = self.get_entities_register()?;
        self.emit_ctx_builtin("cedar.attr", &[entity_reg, attr_reg, entities])
    }

    pub(super) fn emit_cedar_like(&mut self, left_reg: u8, right_reg: u8) -> Result<u8> {
        self.emit_ctx_builtin("cedar.like", &[left_reg, right_reg])
    }

    pub(super) fn emit_cedar_is(&mut self, entity_reg: u8, type_reg: u8) -> Result<u8> {
        self.emit_ctx_builtin("cedar.is", &[entity_reg, type_reg])
    }

    pub(super) fn emit_ctx_builtin(&mut self, name: &str, args: &[u8]) -> Result<u8> {
        let builtin_index = self.get_builtin_index(name, BuiltinKind::Contexted)?;
        let dest = self.alloc_register()?;
        self.emit_builtin_call(dest, builtin_index, args);
        Ok(dest)
    }

    pub(super) fn emit_to_number(&mut self, value_reg: u8) -> Result<u8> {
        let builtin_index = self.get_builtin_index("to_number", BuiltinKind::Standard)?;
        let dest = self.alloc_register()?;
        self.emit_builtin_call(dest, builtin_index, &[value_reg]);
        Ok(dest)
    }

    pub(super) fn emit_builtin_call(&mut self, dest: u8, builtin_index: u16, args: &[u8]) {
        let mut args_array = [0_u8; 8];
        for (idx, arg) in args.iter().enumerate() {
            if let Some(slot) = args_array.get_mut(idx) {
                *slot = *arg;
            }
        }

        let params = BuiltinCallParams {
            dest,
            builtin_index,
            num_args: u8::try_from(args.len()).unwrap_or(u8::MAX),
            args: args_array,
        };
        let params_index = self
            .program
            .instruction_data
            .add_builtin_call_params(params);
        self.emit_instruction(Instruction::BuiltinCall { params_index });
    }

    pub(super) fn emit_assert_not_undefined(&mut self, register: u8) {
        self.emit_instruction(Instruction::AssertNotUndefined { register });
    }

    pub(super) fn emit_index_literal(&mut self, container: u8, key: Value) -> Result<u8> {
        let literal_idx = self.add_literal(key);
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::IndexLiteral {
            dest,
            container,
            literal_idx,
        });
        Ok(dest)
    }

    pub(super) fn emit_load_bool(&mut self, value: bool) -> Result<u8> {
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::LoadBool { dest, value });
        Ok(dest)
    }

    pub(super) fn emit_load_literal(&mut self, value: Value) -> Result<u8> {
        let literal_idx = self.add_literal(value);
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::Load { dest, literal_idx });
        Ok(dest)
    }

    pub(super) fn emit_not(&mut self, operand: u8) -> Result<u8> {
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::Not { dest, operand });
        Ok(dest)
    }

    pub(super) fn emit_and(&mut self, left: u8, right: u8) -> Result<u8> {
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::And { dest, left, right });
        Ok(dest)
    }

    pub(super) fn emit_or(&mut self, left: u8, right: u8) -> Result<u8> {
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::Or { dest, left, right });
        Ok(dest)
    }

    pub(super) fn emit_eq(&mut self, left: u8, right: u8) -> Result<u8> {
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::Eq { dest, left, right });
        Ok(dest)
    }

    pub(super) fn emit_ne(&mut self, left: u8, right: u8) -> Result<u8> {
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::Ne { dest, left, right });
        Ok(dest)
    }

    pub(super) fn emit_lt(&mut self, left: u8, right: u8) -> Result<u8> {
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::Lt { dest, left, right });
        Ok(dest)
    }

    pub(super) fn emit_le(&mut self, left: u8, right: u8) -> Result<u8> {
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::Le { dest, left, right });
        Ok(dest)
    }

    pub(super) fn emit_gt(&mut self, left: u8, right: u8) -> Result<u8> {
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::Gt { dest, left, right });
        Ok(dest)
    }

    pub(super) fn emit_ge(&mut self, left: u8, right: u8) -> Result<u8> {
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::Ge { dest, left, right });
        Ok(dest)
    }

    pub(super) fn emit_add(&mut self, left: u8, right: u8) -> Result<u8> {
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::Add { dest, left, right });
        Ok(dest)
    }

    pub(super) fn emit_sub(&mut self, left: u8, right: u8) -> Result<u8> {
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::Sub { dest, left, right });
        Ok(dest)
    }

    pub(super) fn emit_mul(&mut self, left: u8, right: u8) -> Result<u8> {
        let dest = self.alloc_register()?;
        self.emit_instruction(Instruction::Mul { dest, left, right });
        Ok(dest)
    }

    pub(super) fn add_literal(&mut self, value: Value) -> u16 {
        let index = self.program.add_literal(value);
        u16::try_from(index).unwrap_or(u16::MAX)
    }

    pub(super) fn get_builtin_index(&mut self, name: &str, kind: BuiltinKind) -> Result<u16> {
        if let Some(index) = self.builtin_index_map.get(name).copied() {
            return Ok(index);
        }

        let num_args = match kind {
            BuiltinKind::Standard => {
                if let Some(builtin) = crate::builtins::BUILTINS.get(name) {
                    u16::from(builtin.1)
                } else {
                    return Err(CompilerError::UnknownBuiltin {
                        name: String::from(name),
                    }
                    .into());
                }
            }
            BuiltinKind::Contexted => {
                #[cfg(feature = "cedar")]
                {
                    if let Some(builtin) = crate::builtins::BUILTINS_CTX.get(name) {
                        u16::from(builtin.1)
                    } else {
                        return Err(CompilerError::UnknownContextedBuiltin {
                            name: String::from(name),
                        }
                        .into());
                    }
                }
                #[cfg(not(feature = "cedar"))]
                {
                    return Err(CompilerError::ContextedBuiltinRequiresCedar {
                        name: String::from(name),
                    }
                    .into());
                }
            }
        };

        let builtin_info = BuiltinInfo {
            name: String::from(name),
            num_args,
            kind,
        };
        let index = self.program.add_builtin_info(builtin_info);
        self.builtin_index_map.insert(String::from(name), index);
        Ok(index)
    }

    pub(super) fn emit_instruction(&mut self, instruction: Instruction) {
        let span_info = if let Some(span) = self.current_span.clone() {
            let source_index = self.get_or_create_source_index(&span.source);
            Some(SpanInfo::from_lexer_span(&span, source_index))
        } else {
            None
        };
        self.program.add_instruction(instruction, span_info);
    }
}
