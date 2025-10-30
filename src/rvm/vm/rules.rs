// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::rvm::instructions::FunctionCallParams;
use crate::rvm::program::{RuleInfo, RuleType};
use crate::value::Value;
use alloc::vec::Vec;
use core::mem;

use super::context::CallRuleContext;
use super::errors::{Result, VmError};
use super::machine::RegoVM;

impl RegoVM {
    pub(super) fn execute_rule_definitions_common(
        &mut self,
        rule_definitions: &[Vec<u32>],
        rule_info: &RuleInfo,
        function_call_params: Option<&FunctionCallParams>,
    ) -> Result<(Value, bool)> {
        let mut first_successful_result: Option<Value> = None;
        let mut rule_failed_due_to_inconsistency = false;
        let is_function_call = rule_info.function_info.is_some();
        let result_reg = rule_info.result_reg as usize;

        let num_registers = rule_info.num_registers as usize;
        let mut register_window = self.new_register_window();
        register_window.clear();
        register_window.reserve(num_registers);

        register_window.push(Value::Undefined);

        let num_retained_registers = match function_call_params {
            Some(params) => {
                for arg in params.args[0..params.num_args as usize].iter() {
                    register_window.push(self.registers[*arg as usize].clone());
                }
                params.num_args as usize + 1
            }
            _ => match rule_info.rule_type {
                RuleType::PartialSet | RuleType::PartialObject => 1,
                RuleType::Complete => 0,
            },
        };

        let mut old_registers = Vec::default();
        mem::swap(&mut old_registers, &mut self.registers);

        let mut old_loop_stack = Vec::default();
        mem::swap(&mut old_loop_stack, &mut self.loop_stack);

        let mut old_comprehension_stack = Vec::default();
        mem::swap(&mut old_comprehension_stack, &mut self.comprehension_stack);

        self.register_stack.push(old_registers);
        self.registers = register_window;

        'outer: for (def_idx, definition_bodies) in rule_definitions.iter().enumerate() {
            for (body_entry_point_idx, body_entry_point) in definition_bodies.iter().enumerate() {
                if let Some(ctx) = self.call_rule_stack.last_mut() {
                    ctx.current_body_index = body_entry_point_idx;
                    ctx.current_definition_index = def_idx;
                }

                self.registers
                    .resize(num_retained_registers, Value::Undefined);
                self.registers.resize(num_registers, Value::Undefined);

                if let Some(destructuring_entry_point) =
                    rule_info.destructuring_blocks.get(def_idx).and_then(|x| *x)
                {
                    match self.jump_to(destructuring_entry_point as usize) {
                        Ok(_result) => {}
                        Err(_e) => {
                            continue 'outer;
                        }
                    }
                }

                match self.jump_to(*body_entry_point as usize) {
                    Ok(_) => {
                        if matches!(rule_info.rule_type, RuleType::Complete) || is_function_call {
                            let current_result = self.registers[result_reg].clone();
                            if current_result != Value::Undefined {
                                if let Some(ref expected) = first_successful_result {
                                    if *expected != current_result {
                                        rule_failed_due_to_inconsistency = true;
                                        self.registers[result_reg] = Value::Undefined;
                                        break;
                                    }
                                } else {
                                    first_successful_result = Some(current_result.clone());
                                }
                            }
                        }
                    }
                    Err(_e) => {
                        continue;
                    }
                }
            }

            if rule_failed_due_to_inconsistency {
                break;
            }
        }

        let final_result = if rule_failed_due_to_inconsistency {
            Value::Undefined
        } else if let Some(successful_result) = first_successful_result {
            successful_result
        } else {
            self.registers[result_reg].clone()
        };

        if let Some(old_registers) = self.register_stack.pop() {
            let mut current_register_window = Vec::default();
            mem::swap(&mut current_register_window, &mut self.registers);
            self.return_register_window(current_register_window);

            self.registers = old_registers;
        }

        self.loop_stack = old_loop_stack;
        self.comprehension_stack = old_comprehension_stack;

        Ok((final_result, rule_failed_due_to_inconsistency))
    }

    pub(super) fn execute_call_rule_common(
        &mut self,
        dest: u8,
        rule_index: u16,
        function_call_params: Option<&FunctionCallParams>,
    ) -> Result<()> {
        let rule_idx = rule_index as usize;

        if rule_idx >= self.rule_cache.len() {
            return Err(VmError::RuleIndexOutOfBounds { index: rule_index });
        }

        let rule_info = self
            .program
            .rule_infos
            .get(rule_idx)
            .ok_or_else(|| VmError::RuleInfoMissing { index: rule_index })?
            .clone();

        let is_function_rule = rule_info.function_info.is_some();

        if !is_function_rule {
            let (computed, cached_result) = &self.rule_cache[rule_idx];
            if *computed {
                self.registers[dest as usize] = cached_result.clone();                return Ok(());
            }
        }

        let rule_type = rule_info.rule_type.clone();
        let rule_definitions = rule_info.definitions.clone();

        if rule_definitions.is_empty() {
            let result = Value::Undefined;
            if !is_function_rule {
                self.rule_cache[rule_idx] = (true, result.clone());
            }
            self.registers[dest as usize] = result;            return Ok(());
        }

        self.call_rule_stack.push(CallRuleContext {
            return_pc: self.pc,
            dest_reg: dest,
            result_reg: rule_info.result_reg,
            rule_index,
            rule_type: rule_type.clone(),
            current_definition_index: 0,
            current_body_index: 0,
        });

        let (final_result, rule_failed_due_to_inconsistency) = self
            .execute_rule_definitions_common(&rule_definitions, &rule_info, function_call_params)?;

        self.registers[dest as usize] = Value::Undefined;

        let call_context = self.call_rule_stack.pop().expect("Call stack underflow");
        self.pc = call_context.return_pc;

        let result_from_rule = if !rule_failed_due_to_inconsistency {
            final_result
        } else {
            Value::Undefined
        };

        self.registers[dest as usize] = result_from_rule.clone();

        if self.registers[dest as usize] == Value::Undefined && !rule_failed_due_to_inconsistency {
            match call_context.rule_type {
                RuleType::PartialSet => {
                    self.registers[dest as usize] = Value::new_set();
                }
                RuleType::PartialObject => {
                    self.registers[dest as usize] = Value::new_object();
                }
                RuleType::Complete => {
                    if let Some(rule_info) = self
                        .program
                        .rule_infos
                        .get(call_context.rule_index as usize)
                    {
                        if let Some(default_literal_index) = rule_info.default_literal_index {
                            if let Some(default_value) =
                                self.program.literals.get(default_literal_index as usize)
                            {
                                self.registers[dest as usize] = default_value.clone();
                            }
                        }
                    }
                }
            }
        }

        let final_result = self.registers[dest as usize].clone();
        if !is_function_rule {
            self.rule_cache[rule_idx] = (true, final_result);
        }
        Ok(())
    }

    pub(super) fn execute_call_rule(&mut self, dest: u8, rule_index: u16) -> Result<()> {
        self.execute_call_rule_common(dest, rule_index, None)
    }

    pub(super) fn execute_rule_init(&mut self, result_reg: u8, _rule_index: u16) -> Result<()> {
        let current_ctx = self
            .call_rule_stack
            .last_mut()
            .expect("Call stack underflow");
        current_ctx.result_reg = result_reg;
        match current_ctx.rule_type {
            RuleType::Complete => {
                self.registers[result_reg as usize] = Value::Undefined;
            }
            RuleType::PartialSet => {
                if current_ctx.current_definition_index == 0 && current_ctx.current_body_index == 0
                {
                    self.registers[result_reg as usize] = Value::new_set();
                }
            }
            RuleType::PartialObject => {
                if current_ctx.current_definition_index == 0 && current_ctx.current_body_index == 0
                {
                    self.registers[result_reg as usize] = Value::new_object();
                }
            }
        }
        Ok(())
    }

    pub(super) fn execute_rule_return(&mut self) -> Result<()> {
        Ok(())
    }
}
