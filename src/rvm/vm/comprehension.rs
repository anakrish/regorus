// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::rvm::instructions::{ComprehensionBeginParams, ComprehensionMode};
use crate::value::Value;
use crate::Rc;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::context::{ComprehensionContext, IterationState};
use super::errors::{Result, VmError};
use super::execution_model::{ExecutionFrame, ExecutionMode, FrameKind};
use super::machine::RegoVM;

impl RegoVM {
    pub(super) fn execute_comprehension_begin(
        &mut self,
        params: &ComprehensionBeginParams,
    ) -> Result<()> {
        match self.execution_mode {
            ExecutionMode::RunToCompletion => {
                self.execute_comprehension_begin_run_to_completion(params)
            }
            ExecutionMode::Suspendable => self.execute_comprehension_begin_suspendable(params),
        }
    }

    fn execute_comprehension_begin_run_to_completion(
        &mut self,
        params: &ComprehensionBeginParams,
    ) -> Result<()> {
        let initial_result = match params.mode {
            ComprehensionMode::Set => Value::new_set(),
            ComprehensionMode::Array => Value::new_array(),
            ComprehensionMode::Object => Value::Object(Rc::new(BTreeMap::new())),
        };
        self.set_register(params.result_reg, initial_result.clone())?;

        let auto_iterate = params.collection_reg != params.result_reg;
        let iteration_state = if auto_iterate {
            let source_value = self.get_register(params.collection_reg)?.clone();
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

        let has_iteration = if let Some(state) = iteration_state.as_ref() {
            self.setup_next_iteration(state, params.key_reg, params.value_reg)?
        } else {
            false
        };

        let resume_pc = if auto_iterate {
            usize::from(params.comprehension_end)
        } else {
            usize::from(params.comprehension_end.saturating_sub(1))
        };

        let mut comprehension_context = ComprehensionContext {
            mode: params.mode.clone(),
            result_reg: params.result_reg,
            key_reg: params.key_reg,
            value_reg: params.value_reg,
            body_start: params.body_start,
            comprehension_end: params.comprehension_end,
            iteration_state,
            resume_pc,
            #[cfg(feature = "explanations")]
            witness: super::context::WitnessState {
                finalized_block_start: self.causality.finalized_block_len(),
                ..Default::default()
            },
        };

        if auto_iterate {
            if has_iteration {
                self.pc = usize::from(params.body_start).saturating_sub(1);
            } else {
                comprehension_context.iteration_state = None;
                self.pc = usize::from(params.comprehension_end).saturating_sub(1);
            }
        }

        self.comprehension_stack.push(comprehension_context);

        Ok(())
    }

    fn execute_comprehension_begin_suspendable(
        &mut self,
        params: &ComprehensionBeginParams,
    ) -> Result<()> {
        let initial_result = match params.mode {
            ComprehensionMode::Set => Value::new_set(),
            ComprehensionMode::Array => Value::new_array(),
            ComprehensionMode::Object => Value::Object(Rc::new(BTreeMap::new())),
        };
        self.set_register(params.result_reg, initial_result.clone())?;

        let auto_iterate = params.collection_reg != params.result_reg;
        let iteration_state = if auto_iterate {
            let source_value = self.get_register(params.collection_reg)?.clone();
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

        let has_iteration = if let Some(state) = iteration_state.as_ref() {
            self.setup_next_iteration(state, params.key_reg, params.value_reg)?
        } else {
            false
        };

        let resume_pc = if auto_iterate {
            usize::from(params.comprehension_end)
        } else {
            usize::from(params.comprehension_end.saturating_sub(1))
        };

        let mut comprehension_context = ComprehensionContext {
            mode: params.mode.clone(),
            result_reg: params.result_reg,
            key_reg: params.key_reg,
            value_reg: params.value_reg,
            body_start: params.body_start,
            comprehension_end: params.comprehension_end,
            iteration_state,
            resume_pc,
            #[cfg(feature = "explanations")]
            witness: super::context::WitnessState {
                finalized_block_start: self.causality.finalized_block_len(),
                ..Default::default()
            },
        };

        let next_pc = if auto_iterate {
            if has_iteration {
                usize::from(params.body_start)
            } else {
                comprehension_context.iteration_state = None;
                usize::from(params.comprehension_end)
            }
        } else {
            self.pc.saturating_add(1)
        };

        let return_pc = comprehension_context.resume_pc;

        let frame = ExecutionFrame::new(
            next_pc,
            FrameKind::Comprehension {
                return_pc,
                context: comprehension_context,
            },
        );
        self.execution_stack.push(frame);

        Ok(())
    }

    pub(super) fn execute_comprehension_yield(
        &mut self,
        value_reg: u8,
        key_reg: Option<u8>,
    ) -> Result<()> {
        match self.execution_mode {
            ExecutionMode::RunToCompletion => {
                self.execute_comprehension_yield_run_to_completion(value_reg, key_reg)
            }
            ExecutionMode::Suspendable => {
                self.execute_comprehension_yield_suspendable(value_reg, key_reg)
            }
        }
    }

    fn execute_comprehension_yield_run_to_completion(
        &mut self,
        value_reg: u8,
        key_reg: Option<u8>,
    ) -> Result<()> {
        let mut comprehension_context = if let Some(context) = self.comprehension_stack.pop() {
            context
        } else {
            return Err(VmError::InvalidIteration {
                value: Value::String(Arc::from("No active comprehension")),
                pc: self.pc,
            });
        };

        let value_to_add = self.get_register(value_reg)?.clone();
        let key_value = if let Some(key_reg) = key_reg {
            Some(self.get_register(key_reg)?.clone())
        } else if matches!(comprehension_context.mode, ComprehensionMode::Object) {
            Some(self.get_register(comprehension_context.key_reg)?.clone())
        } else {
            None
        };

        let result_reg = comprehension_context.result_reg;
        // Take ownership so Rc refcount stays at 1 and make_mut mutates in-place.
        let mut current_result = self.take_register(result_reg)?;

        match (&comprehension_context.mode, &mut current_result) {
            (&ComprehensionMode::Set, &mut Value::Set(ref mut set)) => {
                crate::Rc::make_mut(set).insert(value_to_add);
            }
            (&ComprehensionMode::Array, &mut Value::Array(ref mut arr)) => {
                crate::Rc::make_mut(arr).push(value_to_add);
            }
            (&ComprehensionMode::Object, &mut Value::Object(ref mut obj)) => {
                if let Some(key) = key_value.clone() {
                    crate::Rc::make_mut(obj).insert(key, value_to_add);
                } else {
                    self.set_register(result_reg, current_result)?;
                    self.comprehension_stack.push(comprehension_context);
                    return Err(VmError::InvalidIteration {
                        value: Value::String(Arc::from("Object comprehension requires key")),
                        pc: self.pc,
                    });
                }
            }
            (_mode, other) => {
                let offending = core::mem::replace(other, Value::Undefined);
                self.set_register(result_reg, current_result)?;
                self.comprehension_stack.push(comprehension_context);
                return Err(VmError::InvalidIteration {
                    value: offending,
                    pc: self.pc,
                });
            }
        }

        self.set_register(result_reg, current_result)?;

        #[cfg(feature = "explanations")]
        {
            comprehension_context.witness.yield_count =
                comprehension_context.witness.yield_count.saturating_add(1);
            comprehension_context.witness.iteration_count = comprehension_context
                .witness
                .iteration_count
                .saturating_add(1);
            if comprehension_context.witness.sample_value.is_none() {
                comprehension_context.witness.sample_key = key_value.clone();
                comprehension_context.witness.sample_value =
                    Some(self.get_register(value_reg)?.clone());
            }
            // Capture passing iteration snapshot (first success only).
            if comprehension_context.witness.passing_iteration.is_none() {
                comprehension_context.witness.passing_iteration =
                    Some(self.make_loop_iteration_snapshot(
                        comprehension_context.key_reg,
                        comprehension_context.value_reg,
                    )?);
                let indices = self.capture_iteration_event_indices(
                    comprehension_context.witness.finalized_block_start,
                );
                if !indices.is_empty() {
                    comprehension_context.witness.passing_event_indices = Some(indices);
                }
            } else {
                // Still finalize the block to keep finalized_block_start consistent.
                let _ = self.capture_iteration_event_indices(
                    comprehension_context.witness.finalized_block_start,
                );
            }
        }

        if let Some(iter_state) = comprehension_context.iteration_state.as_mut() {
            match *iter_state {
                IterationState::Object {
                    ref mut current_key,
                    ..
                } => {
                    let tracked_key =
                        if comprehension_context.key_reg != comprehension_context.value_reg {
                            self.get_register(comprehension_context.key_reg)?.clone()
                        } else {
                            self.get_register(comprehension_context.value_reg)?.clone()
                        };
                    *current_key = Some(tracked_key);
                }
                IterationState::Set {
                    ref mut current_item,
                    ..
                } => {
                    *current_item =
                        Some(self.get_register(comprehension_context.value_reg)?.clone());
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
                self.pc = usize::from(comprehension_context.body_start).saturating_sub(1);
            } else {
                comprehension_context.iteration_state = None;
                self.pc = usize::from(comprehension_context.comprehension_end).saturating_sub(1);
            }
        }

        self.comprehension_stack.push(comprehension_context);

        Ok(())
    }

    fn execute_comprehension_yield_suspendable(
        &mut self,
        value_reg: u8,
        key_reg: Option<u8>,
    ) -> Result<()> {
        let comprehension_index = (0..self.execution_stack.len())
            .rev()
            .find(|&idx| {
                self.execution_stack
                    .get(idx)
                    .is_some_and(|frame| matches!(frame.kind, FrameKind::Comprehension { .. }))
            })
            .ok_or(VmError::InvalidIteration {
                value: Value::String(Arc::from("No active comprehension")),
                pc: self.pc,
            })?;

        let (
            value_to_add,
            key_value,
            mode,
            result_reg_idx,
            key_reg_idx,
            value_reg_idx,
            iteration_key,
            iteration_value,
        ) = {
            let frame =
                self.execution_stack
                    .get(comprehension_index)
                    .ok_or(VmError::InvalidIteration {
                        value: Value::String(Arc::from("No active comprehension")),
                        pc: self.pc,
                    })?;

            if let FrameKind::Comprehension { ref context, .. } = frame.kind {
                let value_to_add = self.get_register(value_reg)?.clone();
                let key_value = if let Some(key_reg) = key_reg {
                    Some(self.get_register(key_reg)?.clone())
                } else if matches!(context.mode, ComprehensionMode::Object) {
                    Some(self.get_register(context.key_reg)?.clone())
                } else {
                    None
                };

                let result_reg_idx = context.result_reg;
                let mode = context.mode.clone();
                let iteration_key = self.get_register(context.key_reg)?.clone();
                let iteration_value = self.get_register(context.value_reg)?.clone();

                (
                    value_to_add,
                    key_value,
                    mode,
                    result_reg_idx,
                    context.key_reg,
                    context.value_reg,
                    iteration_key,
                    iteration_value,
                )
            } else {
                return Err(VmError::InvalidIteration {
                    value: Value::String(Arc::from("No active comprehension")),
                    pc: self.pc,
                });
            }
        };

        // Take ownership so Rc refcount stays at 1 and make_mut mutates in-place.
        let mut current_result = self.take_register(result_reg_idx)?;

        match (&mode, &mut current_result) {
            (&ComprehensionMode::Set, &mut Value::Set(ref mut set)) => {
                crate::Rc::make_mut(set).insert(value_to_add);
            }
            (&ComprehensionMode::Array, &mut Value::Array(ref mut arr)) => {
                crate::Rc::make_mut(arr).push(value_to_add);
            }
            (&ComprehensionMode::Object, &mut Value::Object(ref mut obj)) => {
                if let Some(ref key) = key_value {
                    crate::Rc::make_mut(obj).insert(key.clone(), value_to_add);
                } else {
                    self.set_register(result_reg_idx, current_result)?;
                    return Err(VmError::InvalidIteration {
                        value: Value::String(Arc::from("Object comprehension requires key")),
                        pc: self.pc,
                    });
                }
            }
            (_mode, other) => {
                let offending = core::mem::replace(other, Value::Undefined);
                self.set_register(result_reg_idx, current_result)?;
                return Err(VmError::InvalidIteration {
                    value: offending,
                    pc: self.pc,
                });
            }
        }

        let (iteration_state_snapshot, body_start, comprehension_end) = {
            let frame = self.execution_stack.get_mut(comprehension_index).ok_or(
                VmError::InvalidIteration {
                    value: Value::String(Arc::from("No active comprehension")),
                    pc: self.pc,
                },
            )?;

            if let &mut FrameKind::Comprehension {
                ref mut context, ..
            } = &mut frame.kind
            {
                if let Some(iter_state) = context.iteration_state.as_mut() {
                    match *iter_state {
                        IterationState::Object {
                            ref mut current_key,
                            ..
                        } => {
                            let tracked_key = if context.key_reg != context.value_reg {
                                iteration_key.clone()
                            } else {
                                iteration_value.clone()
                            };
                            *current_key = Some(tracked_key);
                        }
                        IterationState::Set {
                            ref mut current_item,
                            ..
                        } => {
                            *current_item = Some(iteration_value.clone());
                        }
                        IterationState::Array { .. } => {}
                    }

                    iter_state.advance();
                }

                (
                    context.iteration_state.clone(),
                    context.body_start,
                    context.comprehension_end,
                )
            } else {
                return Err(VmError::InvalidIteration {
                    value: Value::String(Arc::from("No active comprehension")),
                    pc: self.pc,
                });
            }
        };

        self.set_register(result_reg_idx, current_result)?;

        #[cfg(feature = "explanations")]
        {
            let sample_value = self.get_register(value_reg_idx)?.clone();

            // Read witness state from context before taking &mut self for snapshots.
            let (finalized_block_start, needs_passing) = {
                let frame = self.execution_stack.get(comprehension_index);
                frame.map_or((0, false), |frame| {
                    if let FrameKind::Comprehension { ref context, .. } = frame.kind {
                        (
                            context.witness.finalized_block_start,
                            context.witness.passing_iteration.is_none(),
                        )
                    } else {
                        (0, false)
                    }
                })
            };

            // Capture passing iteration snapshot before writing to context.
            let passing_snapshot = if needs_passing {
                Some(self.make_loop_iteration_snapshot(key_reg_idx, value_reg_idx)?)
            } else {
                None
            };
            let iteration_event_indices =
                self.capture_iteration_event_indices(finalized_block_start);

            if let Some(frame) = self.execution_stack.get_mut(comprehension_index) {
                if let FrameKind::Comprehension {
                    ref mut context, ..
                } = frame.kind
                {
                    context.witness.yield_count = context.witness.yield_count.saturating_add(1);
                    context.witness.iteration_count =
                        context.witness.iteration_count.saturating_add(1);
                    if context.witness.sample_value.is_none() {
                        context.witness.sample_key = key_value.clone();
                        context.witness.sample_value = Some(sample_value);
                    }
                    if let Some(snapshot) = passing_snapshot {
                        context.witness.passing_iteration = Some(snapshot);
                        if !iteration_event_indices.is_empty() {
                            context.witness.passing_event_indices = Some(iteration_event_indices);
                        }
                    }
                }
            }
        }

        if let Some(state) = iteration_state_snapshot.as_ref() {
            let has_next = self.setup_next_iteration(state, key_reg_idx, value_reg_idx)?;

            if has_next {
                if let Some(frame) = self.execution_stack.get_mut(comprehension_index) {
                    frame.pc = usize::from(body_start);
                    self.frame_pc_overridden = true;
                }
            } else if let Some(frame) = self.execution_stack.get_mut(comprehension_index) {
                if let &mut FrameKind::Comprehension {
                    ref mut context, ..
                } = &mut frame.kind
                {
                    context.iteration_state = None;
                }
                frame.pc = usize::from(comprehension_end);
                self.frame_pc_overridden = true;
            }
        }

        Ok(())
    }

    pub(super) fn execute_comprehension_end(&mut self) -> Result<()> {
        match self.execution_mode {
            ExecutionMode::RunToCompletion => self.execute_comprehension_end_run_to_completion(),
            ExecutionMode::Suspendable => self.execute_comprehension_end_suspendable(),
        }
    }

    pub(super) fn handle_comprehension_condition_failure_run_to_completion(
        &mut self,
    ) -> Result<bool> {
        if let Some(mut context) = self.comprehension_stack.pop() {
            self.advance_comprehension_after_failure(&mut context)?;
            self.comprehension_stack.push(context);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(super) fn handle_comprehension_condition_failure_suspendable(&mut self) -> Result<bool> {
        if let Some(mut frame) = self.execution_stack.pop() {
            let handled = if let &mut FrameKind::Comprehension {
                ref mut context, ..
            } = &mut frame.kind
            {
                self.advance_comprehension_after_failure(context)?;
                true
            } else {
                false
            };

            self.execution_stack.push(frame);
            if handled {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Record the comprehension's outcome as a condition event and store its
    /// index so the next condition can inline it (analogous to nested rule blocks).
    #[cfg(feature = "explanations")]
    fn record_comprehension_end_condition(&mut self, _result_reg: u8) -> Result<()> {
        self.record_current_instruction_condition(
            crate::explanations::ExplanationOutcome::Success,
        )?;
        Ok(())
    }

    fn advance_comprehension_after_failure(
        &mut self,
        context: &mut ComprehensionContext,
    ) -> Result<()> {
        if let Some(iter_state) = context.iteration_state.as_mut() {
            self.capture_comprehension_iteration_position(
                iter_state,
                context.key_reg,
                context.value_reg,
            )?;

            // Capture the failing iteration snapshot (first failure only).
            #[cfg(feature = "explanations")]
            {
                context.witness.iteration_count = context.witness.iteration_count.saturating_add(1);
                if context.witness.failing_iteration.is_none() {
                    context.witness.failing_iteration = Some(
                        self.make_loop_iteration_snapshot(context.key_reg, context.value_reg)?,
                    );
                    let indices =
                        self.capture_iteration_event_indices(context.witness.finalized_block_start);
                    if !indices.is_empty() {
                        context.witness.failing_event_indices = Some(indices);
                    }
                } else {
                    // Still finalize the block to keep finalized_block_start consistent.
                    let _ =
                        self.capture_iteration_event_indices(context.witness.finalized_block_start);
                }
            }

            iter_state.advance();
            let has_next =
                self.setup_next_iteration(iter_state, context.key_reg, context.value_reg)?;
            if has_next {
                self.pc = usize::from(context.body_start.saturating_sub(1));
            } else {
                context.iteration_state = None;
                self.pc = usize::from(context.comprehension_end.saturating_sub(1));
            }
        } else {
            self.pc = usize::from(context.comprehension_end.saturating_sub(1));
        }

        Ok(())
    }

    fn capture_comprehension_iteration_position(
        &mut self,
        iter_state: &mut IterationState,
        key_reg: u8,
        value_reg: u8,
    ) -> Result<()> {
        match *iter_state {
            IterationState::Object {
                ref mut current_key,
                ..
            } => {
                let tracked_key = if key_reg != value_reg {
                    self.get_register(key_reg)?.clone()
                } else {
                    self.get_register(value_reg)?.clone()
                };
                *current_key = Some(tracked_key);
            }
            IterationState::Set {
                ref mut current_item,
                ..
            } => {
                *current_item = Some(self.get_register(value_reg)?.clone());
            }
            IterationState::Array { .. } => {}
        }

        Ok(())
    }

    fn execute_comprehension_end_run_to_completion(&mut self) -> Result<()> {
        let context = self
            .comprehension_stack
            .pop()
            .ok_or(VmError::InvalidIteration {
                value: Value::String(Arc::from("No active comprehension context")),
                pc: self.pc,
            })?;
        #[cfg(not(feature = "explanations"))]
        let _ = &context;
        #[cfg(feature = "explanations")]
        {
            let sample_key = context
                .witness
                .sample_key
                .as_ref()
                .map(|v| self.causality.snapshot_value(v));
            let sample_value = context
                .witness
                .sample_value
                .as_ref()
                .map(|v| self.causality.snapshot_value(v));

            // If the comprehension didn't iterate on its own (non-auto-iterate),
            // adopt iteration data from the inner loop that ran inside the body.
            let (iteration_count, success_count, passing_iteration, failing_iteration) =
                if context.witness.iteration_count == 0 {
                    self.causality.last_loop_witness().map_or(
                        (Some(0), Some(0), None, None),
                        |inner| {
                            (
                                inner.iteration_count,
                                inner.success_count,
                                inner.passing_iteration.clone(),
                                inner.failing_iteration.clone(),
                            )
                        },
                    )
                } else {
                    (
                        Some(context.witness.iteration_count),
                        Some(context.witness.yield_count),
                        context.witness.passing_iteration.clone(),
                        context.witness.failing_iteration.clone(),
                    )
                };

            let witness = crate::causality::RawWitnessSnapshot {
                collection_path: None,
                iteration_count,
                success_count,
                yield_count: Some(context.witness.yield_count),
                condition_texts: Vec::new(),
                sample_key,
                sample_key_hint: None,
                sample_value,
                sample_value_hint: None,
                passing_iteration,
                failing_iteration,
            };
            self.causality
                .insert_comprehension_witness(context.result_reg, witness);
            self.record_comprehension_end_condition(context.result_reg)?;
        }
        Ok(())
    }

    fn execute_comprehension_end_suspendable(&mut self) -> Result<()> {
        let mut unwound_frames: Vec<ExecutionFrame> = Vec::new();

        loop {
            let frame = match self.execution_stack.pop() {
                Some(frame) => frame,
                None => {
                    // Restore any frames we already unwound before propagating the error.
                    while let Some(restored) = unwound_frames.pop() {
                        self.execution_stack.push(restored);
                    }
                    return Err(VmError::InvalidIteration {
                        value: Value::String(Arc::from("No active comprehension context")),
                        pc: self.pc,
                    });
                }
            };

            let ExecutionFrame {
                pc: frame_pc,
                kind: frame_kind,
            } = frame;

            match frame_kind {
                FrameKind::Comprehension {
                    return_pc: _,
                    context,
                } => {
                    #[cfg(feature = "explanations")]
                    {
                        let sample_key = context
                            .witness
                            .sample_key
                            .as_ref()
                            .map(|v| self.causality.snapshot_value(v));
                        let sample_value = context
                            .witness
                            .sample_value
                            .as_ref()
                            .map(|v| self.causality.snapshot_value(v));

                        // Adopt inner loop iteration data when comprehension
                        // didn't iterate itself.
                        let (iteration_count, success_count, passing_iteration, failing_iteration) =
                            if context.witness.iteration_count == 0 {
                                self.causality.last_loop_witness().map_or(
                                    (Some(0), Some(0), None, None),
                                    |inner| {
                                        (
                                            inner.iteration_count,
                                            inner.success_count,
                                            inner.passing_iteration.clone(),
                                            inner.failing_iteration.clone(),
                                        )
                                    },
                                )
                            } else {
                                (
                                    Some(context.witness.iteration_count),
                                    Some(context.witness.yield_count),
                                    context.witness.passing_iteration.clone(),
                                    context.witness.failing_iteration.clone(),
                                )
                            };

                        let witness = crate::causality::RawWitnessSnapshot {
                            collection_path: None,
                            iteration_count,
                            success_count,
                            yield_count: Some(context.witness.yield_count),
                            condition_texts: Vec::new(),
                            sample_key,
                            sample_key_hint: None,
                            sample_value,
                            sample_value_hint: None,
                            passing_iteration,
                            failing_iteration,
                        };
                        self.causality
                            .insert_comprehension_witness(context.result_reg, witness);
                        self.record_comprehension_end_condition(context.result_reg)?;
                    }
                    let raw_target = context.resume_pc;
                    let resume_pc = if raw_target <= self.pc {
                        self.pc.saturating_add(1)
                    } else if raw_target == self.pc.saturating_add(1) {
                        raw_target
                    } else {
                        raw_target.saturating_sub(1)
                    };
                    if let Some(parent) = self.execution_stack.last_mut() {
                        parent.pc = resume_pc;
                    }
                    while let Some(restored) = unwound_frames.pop() {
                        self.execution_stack.push(restored);
                    }
                    return Ok(());
                }
                FrameKind::Loop { return_pc, context } => {
                    if let Some(parent) = self.execution_stack.last_mut() {
                        parent.pc = return_pc;
                    }
                    // Keep the loop frame available so we can restore it if we discover a mismatch.
                    unwound_frames.push(ExecutionFrame::new(
                        frame_pc,
                        FrameKind::Loop { return_pc, context },
                    ));
                }
                other_kind => {
                    let message = format!(
                        "Mismatched comprehension frame: frame={:?} stack_depth={} unwound_loops={}",
                        &other_kind,
                        self.execution_stack.len(),
                        unwound_frames.len()
                    );
                    // Put the unexpected frame back on the stack along with any loops we unwound.
                    self.execution_stack
                        .push(ExecutionFrame::new(frame_pc, other_kind));
                    while let Some(restored) = unwound_frames.pop() {
                        self.execution_stack.push(restored);
                    }
                    return Err(VmError::InvalidIteration {
                        value: Value::String(Arc::from(message.into_boxed_str())),
                        pc: self.pc,
                    });
                }
            }
        }
    }
}
