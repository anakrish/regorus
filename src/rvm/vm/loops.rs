// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::rvm::instructions::LoopMode;
use crate::value::Value;

use super::context::{IterationState, LoopContext};
use super::errors::{Result, VmError};
use super::machine::RegoVM;

#[derive(Clone, Copy)]
pub(super) struct LoopParams {
    pub(super) collection: u8,
    pub(super) key_reg: u8,
    pub(super) value_reg: u8,
    pub(super) result_reg: u8,
    pub(super) body_start: u16,
    pub(super) loop_end: u16,
}

#[derive(Debug)]
enum LoopAction {
    ExitWithSuccess,
    ExitWithFailure,
    Continue,
}

impl RegoVM {
    pub(super) fn execute_loop_start(&mut self, mode: &LoopMode, params: LoopParams) -> Result<()> {
        let initial_result = match mode {
            LoopMode::Any | LoopMode::Every | LoopMode::ForEach => Value::Bool(false),
        };
        self.registers[params.result_reg as usize] = initial_result.clone();

        let collection_value = self.registers[params.collection as usize].clone();

        let iteration_state = match &collection_value {
            Value::Array(items) => {
                if items.is_empty() {
                    self.handle_empty_collection(mode, params.result_reg, params.loop_end)?;
                    return Ok(());
                }
                IterationState::Array {
                    items: items.clone(),
                    index: 0,
                }
            }
            Value::Object(obj) => {
                if obj.is_empty() {
                    self.handle_empty_collection(mode, params.result_reg, params.loop_end)?;
                    return Ok(());
                }
                IterationState::Object {
                    obj: obj.clone(),
                    current_key: None,
                    first_iteration: true,
                }
            }
            Value::Set(set) => {
                if set.is_empty() {
                    self.handle_empty_collection(mode, params.result_reg, params.loop_end)?;
                    return Ok(());
                }
                IterationState::Set {
                    items: set.clone(),
                    current_item: None,
                    first_iteration: true,
                }
            }
            _ => {
                self.handle_empty_collection(mode, params.result_reg, params.loop_end)?;
                return Ok(());
            }
        };

        let has_next =
            self.setup_next_iteration(&iteration_state, params.key_reg, params.value_reg)?;
        if !has_next {
            self.pc = params.loop_end as usize;
            return Ok(());
        }

        let loop_next_pc = params.loop_end - 1;

        let loop_context = LoopContext {
            mode: mode.clone(),
            iteration_state,
            key_reg: params.key_reg,
            value_reg: params.value_reg,
            result_reg: params.result_reg,
            body_start: params.body_start,
            loop_end: params.loop_end,
            loop_next_pc,
            success_count: 0,
            total_iterations: 0,
            current_iteration_failed: false,
        };

        self.loop_stack.push(loop_context);

        self.pc = params.body_start as usize - 1;

        Ok(())
    }

    pub(super) fn execute_loop_next(&mut self, _body_start: u16, _loop_end: u16) -> Result<()> {
        if let Some(mut loop_ctx) = self.loop_stack.pop() {
            let body_start = loop_ctx.body_start;
            let loop_end = loop_ctx.loop_end;

            loop_ctx.total_iterations += 1;

            let iteration_succeeded = self.check_iteration_success(&loop_ctx)?;

            if iteration_succeeded {
                loop_ctx.success_count += 1;
            }

            let action = self.determine_loop_action(&loop_ctx.mode, iteration_succeeded);

            match action {
                LoopAction::ExitWithSuccess => {
                    self.registers[loop_ctx.result_reg as usize] = Value::Bool(true);
                    self.pc = loop_end as usize - 1;
                    return Ok(());
                }
                LoopAction::ExitWithFailure => {
                    self.registers[loop_ctx.result_reg as usize] = Value::Bool(false);
                    self.pc = loop_end as usize - 1;
                    return Ok(());
                }
                LoopAction::Continue => {}
            }

            if let IterationState::Object {
                ref mut current_key,
                ..
            } = &mut loop_ctx.iteration_state
            {
                if loop_ctx.key_reg != loop_ctx.value_reg {
                    *current_key = Some(self.registers[loop_ctx.key_reg as usize].clone());
                }
            } else if let IterationState::Set {
                ref mut current_item,
                ..
            } = &mut loop_ctx.iteration_state
            {
                *current_item = Some(self.registers[loop_ctx.value_reg as usize].clone());
            }

            loop_ctx.iteration_state.advance();
            let has_next = self.setup_next_iteration(
                &loop_ctx.iteration_state,
                loop_ctx.key_reg,
                loop_ctx.value_reg,
            )?;

            if has_next {
                loop_ctx.current_iteration_failed = false;

                self.loop_stack.push(loop_ctx);
                self.pc = body_start as usize - 1;
            } else {
                let final_result = match loop_ctx.mode {
                    LoopMode::Any => Value::Bool(loop_ctx.success_count > 0),
                    LoopMode::Every => {
                        Value::Bool(loop_ctx.success_count == loop_ctx.total_iterations)
                    }
                    LoopMode::ForEach => Value::Bool(loop_ctx.success_count > 0),
                };

                self.registers[loop_ctx.result_reg as usize] = final_result;

                self.pc = loop_end as usize - 1;
            }

            Ok(())
        } else {
            self.pc = _loop_end as usize;
            Ok(())
        }
    }

    fn handle_empty_collection(
        &mut self,
        mode: &LoopMode,
        result_reg: u8,
        loop_end: u16,
    ) -> Result<()> {
        let result = match mode {
            LoopMode::Any => Value::Bool(false),
            LoopMode::Every => Value::Bool(true),
            LoopMode::ForEach => Value::Bool(false),
        };

        self.registers[result_reg as usize] = result;
        self.pc = (loop_end as usize).saturating_sub(1);
        Ok(())
    }

    pub(super) fn setup_next_iteration(
        &mut self,
        state: &IterationState,
        key_reg: u8,
        value_reg: u8,
    ) -> Result<bool> {
        match state {
            IterationState::Array { items, index } => {
                if *index < items.len() {
                    if key_reg != value_reg {
                        let key_value = Value::from(*index as f64);
                        self.registers[key_reg as usize] = key_value;
                    }
                    let item_value = items[*index].clone();
                    self.registers[value_reg as usize] = item_value;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            IterationState::Object {
                obj,
                current_key,
                first_iteration,
            } => {
                if *first_iteration {
                    if let Some((key, value)) = obj.iter().next() {
                        if key_reg != value_reg {
                            self.registers[key_reg as usize] = key.clone();
                        }
                        self.registers[value_reg as usize] = value.clone();
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                } else {
                    if let Some(ref current) = current_key {
                        let mut range_iter = obj.range((
                            core::ops::Bound::Excluded(current),
                            core::ops::Bound::Unbounded,
                        ));
                        if let Some((key, value)) = range_iter.next() {
                            if key_reg != value_reg {
                                self.registers[key_reg as usize] = key.clone();
                            }
                            self.registers[value_reg as usize] = value.clone();
                            Ok(true)
                        } else {
                            Ok(false)
                        }
                    } else {
                        Ok(false)
                    }
                }
            }
            IterationState::Set {
                items,
                current_item,
                first_iteration,
            } => {
                if *first_iteration {
                    if let Some(item) = items.iter().next() {
                        if key_reg != value_reg {
                            self.registers[key_reg as usize] = item.clone();
                        }
                        self.registers[value_reg as usize] = item.clone();
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                } else {
                    if let Some(ref current) = current_item {
                        let mut range_iter = items.range((
                            core::ops::Bound::Excluded(current),
                            core::ops::Bound::Unbounded,
                        ));
                        if let Some(item) = range_iter.next() {
                            if key_reg != value_reg {
                                self.registers[key_reg as usize] = item.clone();
                            }
                            self.registers[value_reg as usize] = item.clone();
                            Ok(true)
                        } else {
                            Ok(false)
                        }
                    } else {
                        Ok(false)
                    }
                }
            }
        }
    }

    fn check_iteration_success(&self, loop_ctx: &LoopContext) -> Result<bool> {
        Ok(!loop_ctx.current_iteration_failed)
    }

    fn determine_loop_action(&self, mode: &LoopMode, success: bool) -> LoopAction {
        match (mode, success) {
            (LoopMode::Any, true) => LoopAction::ExitWithSuccess,
            (LoopMode::Every, false) => LoopAction::ExitWithFailure,
            (LoopMode::ForEach, _) => LoopAction::Continue,
            _ => LoopAction::Continue,
        }
    }

    pub(super) fn handle_condition(&mut self, condition_passed: bool) -> Result<()> {
        if condition_passed {
            return Ok(());
        }

        if !self.loop_stack.is_empty() {
            let (loop_mode, loop_next_pc, loop_end, result_reg) = {
                let loop_ctx = self.loop_stack.last().unwrap();
                (
                    loop_ctx.mode.clone(),
                    loop_ctx.loop_next_pc,
                    loop_ctx.loop_end,
                    loop_ctx.result_reg,
                )
            };

            match loop_mode {
                LoopMode::Any => {
                    if let Some(loop_ctx_mut) = self.loop_stack.last_mut() {
                        loop_ctx_mut.current_iteration_failed = true;
                    }

                    self.pc = loop_next_pc as usize - 1;
                }
                LoopMode::Every => {
                    self.loop_stack.pop();
                    self.pc = loop_end as usize - 1;
                    self.registers[result_reg as usize] = Value::Bool(false);
                }
                _ => {
                    if let Some(loop_ctx_mut) = self.loop_stack.last_mut() {
                        loop_ctx_mut.current_iteration_failed = true;
                    }
                    self.pc = loop_next_pc as usize - 1;
                }
            }
        } else {
            return Err(VmError::AssertionFailed);
        }

        Ok(())
    }
}
