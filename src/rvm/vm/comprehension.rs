// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::rvm::instructions::{ComprehensionBeginParams, ComprehensionMode};
use crate::value::Value;
use crate::Rc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use super::context::{ComprehensionContext, IterationState};
use super::errors::{Result, VmError};
use super::machine::RegoVM;

impl RegoVM {
    pub(super) fn execute_comprehension_begin(
        &mut self,
        params: &ComprehensionBeginParams,
    ) -> Result<()> {
        let initial_result = match params.mode {
            ComprehensionMode::Set => Value::new_set(),
            ComprehensionMode::Array => Value::new_array(),
            ComprehensionMode::Object => Value::Object(Rc::new(BTreeMap::new())),
        };
        self.registers[params.result_reg as usize] = initial_result.clone();

        let auto_iterate = params.collection_reg != params.result_reg;
        let iteration_state = if auto_iterate {
            let source_value = self.registers[params.collection_reg as usize].clone();
            match source_value {
                Value::Array(items) => {
                    if items.is_empty() {
                        None
                    } else {
                        Some(IterationState::Array { items, index: 0 })
                    }
                }
                Value::Object(obj) => {
                    if obj.is_empty() {
                        None
                    } else {
                        Some(IterationState::Object {
                            obj,
                            current_key: None,
                            first_iteration: true,
                        })
                    }
                }
                Value::Set(set) => {
                    if set.is_empty() {
                        None
                    } else {
                        Some(IterationState::Set {
                            items: set,
                            current_item: None,
                            first_iteration: true,
                        })
                    }
                }
                Value::Undefined => None,
                Value::Null => None,
                _ => None,
            }
        } else {
            None
        };

        let mut has_iteration = false;
        if let Some(state) = iteration_state.as_ref() {
            has_iteration = self.setup_next_iteration(state, params.key_reg, params.value_reg)?;
        }

        let mut comprehension_context = ComprehensionContext {
            mode: params.mode.clone(),
            result_reg: params.result_reg,
            key_reg: params.key_reg,
            value_reg: params.value_reg,
            body_start: params.body_start,
            comprehension_end: params.comprehension_end,
            iteration_state,
        };

        if auto_iterate {
            if has_iteration {
                self.pc = params.body_start as usize - 1;
            } else {
                comprehension_context.iteration_state = None;
                self.pc = params.comprehension_end as usize - 1;
            }
        }

        self.comprehension_stack.push(comprehension_context);

        Ok(())
    }

    pub(super) fn execute_comprehension_yield(
        &mut self,
        value_reg: u8,
        key_reg: Option<u8>,
    ) -> Result<()> {
        let mut comprehension_context = if let Some(context) = self.comprehension_stack.pop() {
            context
        } else {
            return Err(VmError::InvalidIteration {
                value: Value::String(Arc::from("No active comprehension")),
            });
        };

        let value_to_add = self.registers[value_reg as usize].clone();
        let key_value = if let Some(key_reg) = key_reg {
            let key = self.registers[key_reg as usize].clone();
            Some(key)
        } else if matches!(comprehension_context.mode, ComprehensionMode::Object) {
            let key = self.registers[comprehension_context.key_reg as usize].clone();
            Some(key)
        } else {
            None
        };

        let result_reg = comprehension_context.result_reg as usize;
        let current_result = self.registers[result_reg].clone();
        let mode = comprehension_context.mode.clone();

        let updated_result = match (mode, current_result) {
            (ComprehensionMode::Set, Value::Set(set)) => {
                let mut new_set = set.as_ref().clone();
                new_set.insert(value_to_add);
                Value::Set(crate::Rc::new(new_set))
            }
            (ComprehensionMode::Array, Value::Array(arr)) => {
                let mut new_arr = arr.as_ref().to_vec();
                new_arr.push(value_to_add);
                Value::Array(crate::Rc::new(new_arr))
            }
            (ComprehensionMode::Object, Value::Object(obj)) => {
                if let Some(key) = key_value {
                    let mut new_obj = obj.as_ref().clone();
                    new_obj.insert(key, value_to_add);
                    Value::Object(crate::Rc::new(new_obj))
                } else {
                    self.comprehension_stack.push(comprehension_context);
                    return Err(VmError::InvalidIteration {
                        value: Value::String(Arc::from("Object comprehension requires key")),
                    });
                }
            }
            (_mode, other) => {
                self.comprehension_stack.push(comprehension_context);
                return Err(VmError::InvalidIteration { value: other });
            }
        };

        self.registers[result_reg] = updated_result;

        if let Some(iter_state) = comprehension_context.iteration_state.as_mut() {
            match iter_state {
                IterationState::Object { current_key, .. } => {
                    let tracked_key =
                        if comprehension_context.key_reg != comprehension_context.value_reg {
                            self.registers[comprehension_context.key_reg as usize].clone()
                        } else {
                            self.registers[comprehension_context.value_reg as usize].clone()
                        };
                    *current_key = Some(tracked_key);
                }
                IterationState::Set { current_item, .. } => {
                    *current_item =
                        Some(self.registers[comprehension_context.value_reg as usize].clone());
                }
                IterationState::Array { .. } => {}
            }

            iter_state.advance();
            let has_next = self.setup_next_iteration(
                iter_state,
                comprehension_context.key_reg,
                comprehension_context.value_reg,
            )?;

            if has_next {
                self.pc = comprehension_context.body_start as usize - 1;
            } else {
                comprehension_context.iteration_state = None;
                self.pc = comprehension_context.comprehension_end as usize - 1;
            }
        }

        self.comprehension_stack.push(comprehension_context);

        Ok(())
    }

    pub(super) fn execute_comprehension_end(&mut self) -> Result<()> {
        if let Some(_context) = self.comprehension_stack.pop() {
            Ok(())
        } else {
            Err(VmError::InvalidIteration {
                value: Value::String(Arc::from("No active comprehension context")),
            })
        }
    }
}
