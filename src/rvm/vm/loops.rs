// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::rvm::instructions::LoopMode;
use crate::value::Value;
#[cfg(feature = "explanations")]
use alloc::vec::Vec;

#[cfg(feature = "explanations")]
use super::context::LoopExplanationRecordSet;
use super::context::{IterationState, LoopContext};
use super::errors::{Result, VmError};
use super::execution_model::{ExecutionFrame, ExecutionMode, FrameKind};
use super::machine::RegoVM;

fn compute_body_resume_pc(loop_start_pc: usize, body_start: u16) -> usize {
    if body_start == 0 {
        return 0;
    }

    let candidate = usize::from(body_start.saturating_sub(1));
    if candidate == loop_start_pc {
        usize::from(body_start)
    } else {
        candidate
    }
}

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
    #[cfg(feature = "explanations")]
    fn bindings_from_records(
        records: &[crate::ExplanationRecord],
    ) -> Vec<crate::ExplanationBinding> {
        records
            .last()
            .map(|record| record.bindings.clone())
            .unwrap_or_default()
    }

    #[cfg(feature = "explanations")]
    fn make_loop_iteration_witness(
        &self,
        key_reg: u8,
        value_reg: u8,
        bindings: Vec<crate::ExplanationBinding>,
    ) -> Result<crate::explanations::RawConditionIterationWitness> {
        Ok(crate::explanations::RawConditionIterationWitness {
            sample_key: if key_reg != value_reg {
                Some(self.get_register(key_reg)?.clone())
            } else {
                None
            },
            sample_key_hint: None,
            sample_value: Some(self.get_register(value_reg)?.clone()),
            sample_value_hint: None,
            bindings,
        })
    }

    #[cfg(feature = "explanations")]
    fn capture_iteration_records(
        &mut self,
        block_record_start: usize,
    ) -> Vec<crate::ExplanationRecord> {
        let _ = self.finalize_current_block_records();
        let records = self
            .block_records
            .get(block_record_start..)
            .unwrap_or(&[])
            .to_vec();
        self.block_records.truncate(block_record_start);
        records
    }

    #[cfg(feature = "explanations")]
    fn insert_loop_summary_state(
        &mut self,
        result_reg: u8,
        mode: LoopMode,
        total_iterations: usize,
        success_count: usize,
        witness: &super::context::WitnessState,
    ) {
        self.loop_witnesses.insert(
            result_reg,
            crate::explanations::RawConditionEvaluationWitness {
                iteration_count: Some(u32::try_from(total_iterations).unwrap_or(u32::MAX)),
                success_count: Some(u32::try_from(success_count).unwrap_or(u32::MAX)),
                yield_count: None,
                condition_texts: Vec::new(),
                sample_key: witness.sample_key.clone(),
                sample_key_hint: None,
                sample_value: witness.sample_value.clone(),
                sample_value_hint: None,
                passing_iteration: witness.passing_iteration.clone(),
                failing_iteration: witness.failing_iteration.clone(),
            },
        );
        self.loop_records.insert(
            result_reg,
            LoopExplanationRecordSet {
                passing: witness.passing_records.clone(),
                failing: witness.failing_records.clone(),
            },
        );

        if matches!(mode, LoopMode::Any) && success_count == 0 {
            self.loop_records.entry(result_reg).or_default();
        }
    }

    pub(super) fn execute_loop_start(&mut self, mode: &LoopMode, params: LoopParams) -> Result<()> {
        match self.execution_mode {
            ExecutionMode::RunToCompletion => {
                self.execute_loop_start_run_to_completion(mode, params)
            }
            ExecutionMode::Suspendable => self.execute_loop_start_suspendable(mode, params),
        }
    }

    pub(super) fn execute_loop_next(&mut self, body_start: u16, loop_end: u16) -> Result<()> {
        match self.execution_mode {
            ExecutionMode::RunToCompletion => {
                self.execute_loop_next_run_to_completion(body_start, loop_end)
            }
            ExecutionMode::Suspendable => self.execute_loop_next_suspendable(body_start, loop_end),
        }
    }

    pub(super) fn handle_condition(&mut self, condition_passed: bool) -> Result<()> {
        match self.execution_mode {
            ExecutionMode::RunToCompletion => {
                self.handle_condition_run_to_completion(condition_passed)
            }
            ExecutionMode::Suspendable => self.handle_condition_suspendable(condition_passed),
        }
    }

    fn execute_loop_start_run_to_completion(
        &mut self,
        mode: &LoopMode,
        params: LoopParams,
    ) -> Result<()> {
        let initial_result = match *mode {
            LoopMode::Any | LoopMode::Every | LoopMode::ForEach => Value::Bool(false),
        };
        self.set_register(params.result_reg, initial_result.clone())?;
        let collection_value = self.get_register(params.collection)?.clone();

        let iteration_state = match collection_value {
            Value::Array(ref items) => {
                if items.is_empty() {
                    self.handle_empty_collection(mode, params.result_reg, params.loop_end)?;
                    return Ok(());
                }
                IterationState::Array {
                    items: items.clone(),
                    index: 0,
                }
            }
            Value::Object(ref obj) => {
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
            Value::Set(ref set) => {
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
            self.pc = usize::from(params.loop_end);
            return Ok(());
        }

        let loop_next_pc = params.loop_end.saturating_sub(1);
        let body_resume_pc = compute_body_resume_pc(self.pc, params.body_start);

        let loop_context = LoopContext {
            mode: *mode,
            iteration_state,
            key_reg: params.key_reg,
            value_reg: params.value_reg,
            result_reg: params.result_reg,
            body_start: params.body_start,
            loop_end: params.loop_end,
            loop_next_pc,
            body_resume_pc,
            success_count: 0,
            total_iterations: 0,
            current_iteration_failed: false,
            #[cfg(feature = "explanations")]
            witness: super::context::WitnessState {
                block_record_start: self.block_records.len(),
                ..Default::default()
            },
        };

        self.loop_stack.push(loop_context);

        self.pc = usize::from(params.body_start.saturating_sub(1));

        Ok(())
    }

    fn execute_loop_next_run_to_completion(
        &mut self,
        _body_start: u16,
        loop_end: u16,
    ) -> Result<()> {
        if let Some(mut loop_ctx) = self.loop_stack.pop() {
            let body_start = loop_ctx.body_start;
            let loop_end_local = loop_ctx.loop_end;

            loop_ctx.total_iterations = loop_ctx.total_iterations.saturating_add(1);

            let iteration_succeeded = Self::check_iteration_success(&loop_ctx)?;

            #[cfg(feature = "explanations")]
            let iteration_records =
                self.capture_iteration_records(loop_ctx.witness.block_record_start);

            if iteration_succeeded {
                loop_ctx.success_count = loop_ctx.success_count.saturating_add(1);
            }

            #[cfg(feature = "explanations")]
            {
                let bindings = Self::bindings_from_records(&iteration_records);
                let witness = self.make_loop_iteration_witness(
                    loop_ctx.key_reg,
                    loop_ctx.value_reg,
                    bindings,
                )?;
                if loop_ctx.witness.sample_value.is_none() {
                    loop_ctx.witness.sample_key = witness.sample_key.clone();
                    loop_ctx.witness.sample_value = witness.sample_value.clone();
                }
                if iteration_succeeded {
                    if loop_ctx.witness.passing_iteration.is_none() {
                        loop_ctx.witness.passing_iteration = Some(witness);
                    }
                    if loop_ctx.witness.passing_records.is_none() && !iteration_records.is_empty() {
                        loop_ctx.witness.passing_records = Some(iteration_records.clone());
                    }
                } else {
                    if loop_ctx.witness.failing_iteration.is_none() {
                        loop_ctx.witness.failing_iteration = Some(witness);
                    }
                    if loop_ctx.witness.failing_records.is_none() && !iteration_records.is_empty() {
                        loop_ctx.witness.failing_records = Some(iteration_records.clone());
                    }
                }
            }

            let action = Self::determine_loop_action(&loop_ctx.mode, iteration_succeeded);

            match action {
                LoopAction::ExitWithSuccess => {
                    #[cfg(feature = "explanations")]
                    self.insert_loop_summary_state(
                        loop_ctx.result_reg,
                        loop_ctx.mode,
                        loop_ctx.total_iterations,
                        loop_ctx.success_count,
                        &loop_ctx.witness,
                    );
                    self.set_register(loop_ctx.result_reg, Value::Bool(true))?;
                    self.pc = usize::from(loop_end_local.saturating_sub(1));
                    return Ok(());
                }
                LoopAction::ExitWithFailure => {
                    #[cfg(feature = "explanations")]
                    self.insert_loop_summary_state(
                        loop_ctx.result_reg,
                        loop_ctx.mode,
                        loop_ctx.total_iterations,
                        loop_ctx.success_count,
                        &loop_ctx.witness,
                    );
                    self.set_register(loop_ctx.result_reg, Value::Bool(false))?;
                    self.pc = usize::from(loop_end_local.saturating_sub(1));
                    return Ok(());
                }
                LoopAction::Continue => {}
            }

            if let &mut IterationState::Object {
                ref mut current_key,
                ..
            } = &mut loop_ctx.iteration_state
            {
                if loop_ctx.key_reg != loop_ctx.value_reg {
                    *current_key = Some(self.get_register(loop_ctx.key_reg)?.clone());
                }
            } else if let &mut IterationState::Set {
                ref mut current_item,
                ..
            } = &mut loop_ctx.iteration_state
            {
                *current_item = Some(self.get_register(loop_ctx.value_reg)?.clone());
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
                self.pc = usize::from(body_start.saturating_sub(1));
            } else {
                let final_result = match loop_ctx.mode {
                    LoopMode::Any => Value::Bool(loop_ctx.success_count > 0),
                    LoopMode::Every => {
                        Value::Bool(loop_ctx.success_count == loop_ctx.total_iterations)
                    }
                    LoopMode::ForEach => Value::Bool(loop_ctx.success_count > 0),
                };

                #[cfg(feature = "explanations")]
                self.insert_loop_summary_state(
                    loop_ctx.result_reg,
                    loop_ctx.mode,
                    loop_ctx.total_iterations,
                    loop_ctx.success_count,
                    &loop_ctx.witness,
                );

                self.set_register(loop_ctx.result_reg, final_result)?;

                self.pc = usize::from(loop_end_local.saturating_sub(1));
            }

            Ok(())
        } else {
            self.pc = usize::from(loop_end);
            Ok(())
        }
    }

    fn execute_loop_start_suspendable(
        &mut self,
        mode: &LoopMode,
        params: LoopParams,
    ) -> Result<()> {
        let initial_result = match *mode {
            LoopMode::Any | LoopMode::Every | LoopMode::ForEach => Value::Bool(false),
        };
        self.set_register(params.result_reg, initial_result.clone())?;

        let collection_value = self.get_register(params.collection)?.clone();

        let iteration_state = match collection_value {
            Value::Array(ref items) => {
                if items.is_empty() {
                    self.handle_empty_collection(mode, params.result_reg, params.loop_end)?;
                    return Ok(());
                }
                IterationState::Array {
                    items: items.clone(),
                    index: 0,
                }
            }
            Value::Object(ref obj) => {
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
            Value::Set(ref set) => {
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
            self.pc = usize::from(params.loop_end);
            return Ok(());
        }

        let loop_next_pc = params.loop_end.saturating_sub(1);
        let body_resume_pc = compute_body_resume_pc(self.pc, params.body_start);

        let loop_context = LoopContext {
            mode: *mode,
            iteration_state,
            key_reg: params.key_reg,
            value_reg: params.value_reg,
            result_reg: params.result_reg,
            body_start: params.body_start,
            loop_end: params.loop_end,
            loop_next_pc,
            body_resume_pc,
            success_count: 0,
            total_iterations: 0,
            current_iteration_failed: false,
            #[cfg(feature = "explanations")]
            witness: super::context::WitnessState {
                block_record_start: self.block_records.len(),
                ..Default::default()
            },
        };

        let frame = ExecutionFrame::new(
            usize::from(params.body_start),
            FrameKind::Loop {
                return_pc: usize::from(params.loop_end),
                context: loop_context,
            },
        );
        self.execution_stack.push(frame);

        Ok(())
    }

    fn execute_loop_next_suspendable(&mut self, body_start: u16, loop_end: u16) -> Result<()> {
        if !matches!(
            self.execution_stack.last(),
            Some(ExecutionFrame {
                kind: FrameKind::Loop { .. },
                ..
            })
        ) {
            if let Some(frame) = self.execution_stack.last_mut() {
                // Advance past the offending instruction so we do not repeatedly
                // resume at the same LoopNext when the owning loop frame has
                // already been popped (for example after a manual comprehension
                // finalizes in suspendable mode).
                let mut target_pc = usize::from(loop_end);
                if target_pc <= self.pc {
                    target_pc = self.pc.saturating_add(1);
                }
                frame.pc = target_pc;
                self.frame_pc_overridden = true;
            }
            return Ok(());
        }

        let (resume_pc, result_reg, loop_mode, iteration_succeeded) = {
            let frame = self
                .execution_stack
                .last_mut()
                .ok_or(VmError::AssertionFailed { pc: self.pc })?;
            match &mut frame.kind {
                &mut FrameKind::Loop {
                    ref return_pc,
                    ref mut context,
                } => {
                    context.total_iterations = context.total_iterations.saturating_add(1);
                    let succeeded = !context.current_iteration_failed;
                    if succeeded {
                        context.success_count = context.success_count.saturating_add(1);
                    }

                    (*return_pc, context.result_reg, context.mode, succeeded)
                }
                _ => return Err(VmError::AssertionFailed { pc: self.pc }),
            }
        };

        #[cfg(feature = "explanations")]
        {
            let block_record_start = self
                .execution_stack
                .last()
                .and_then(|frame| match frame.kind {
                    FrameKind::Loop { ref context, .. } => Some(context.witness.block_record_start),
                    _ => None,
                })
                .ok_or(VmError::AssertionFailed { pc: self.pc })?;
            let iteration_records = self.capture_iteration_records(block_record_start);
            let (key_reg, value_reg) = self
                .execution_stack
                .last()
                .and_then(|frame| match frame.kind {
                    FrameKind::Loop { ref context, .. } => {
                        Some((context.key_reg, context.value_reg))
                    }
                    _ => None,
                })
                .ok_or(VmError::AssertionFailed { pc: self.pc })?;
            let bindings = Self::bindings_from_records(&iteration_records);
            let witness = self.make_loop_iteration_witness(key_reg, value_reg, bindings)?;
            if let Some(frame) = self.execution_stack.last_mut() {
                if let FrameKind::Loop {
                    ref mut context, ..
                } = frame.kind
                {
                    if context.witness.sample_value.is_none() {
                        context.witness.sample_key = witness.sample_key.clone();
                        context.witness.sample_value = witness.sample_value.clone();
                    }
                    if iteration_succeeded {
                        if context.witness.passing_iteration.is_none() {
                            context.witness.passing_iteration = Some(witness);
                        }
                        if context.witness.passing_records.is_none()
                            && !iteration_records.is_empty()
                        {
                            context.witness.passing_records = Some(iteration_records.clone());
                        }
                    } else {
                        if context.witness.failing_iteration.is_none() {
                            context.witness.failing_iteration = Some(witness);
                        }
                        if context.witness.failing_records.is_none()
                            && !iteration_records.is_empty()
                        {
                            context.witness.failing_records = Some(iteration_records.clone());
                        }
                    }
                }
            }
        }

        let action = Self::determine_loop_action(&loop_mode, iteration_succeeded);

        match action {
            LoopAction::ExitWithSuccess => {
                #[cfg(feature = "explanations")]
                if let Some((total_iterations, success_count, witness)) =
                    self.execution_stack.last().and_then(|frame| {
                        if let FrameKind::Loop { ref context, .. } = frame.kind {
                            Some((
                                context.total_iterations,
                                context.success_count,
                                context.witness.clone(),
                            ))
                        } else {
                            None
                        }
                    })
                {
                    self.insert_loop_summary_state(
                        result_reg,
                        loop_mode,
                        total_iterations,
                        success_count,
                        &witness,
                    );
                }
                self.set_register(result_reg, Value::Bool(true))?;
                let completed_frame = self
                    .execution_stack
                    .pop()
                    .ok_or(VmError::AssertionFailed { pc: self.pc })?;
                if let Some(parent) = self.execution_stack.last_mut() {
                    parent.pc = resume_pc;
                    self.frame_pc_overridden = true;
                }
                drop(completed_frame);
                Ok(())
            }
            LoopAction::ExitWithFailure => {
                #[cfg(feature = "explanations")]
                if let Some((total_iterations, success_count, witness)) =
                    self.execution_stack.last().and_then(|frame| {
                        if let FrameKind::Loop { ref context, .. } = frame.kind {
                            Some((
                                context.total_iterations,
                                context.success_count,
                                context.witness.clone(),
                            ))
                        } else {
                            None
                        }
                    })
                {
                    self.insert_loop_summary_state(
                        result_reg,
                        loop_mode,
                        total_iterations,
                        success_count,
                        &witness,
                    );
                }
                self.set_register(result_reg, Value::Bool(false))?;
                let completed_frame = self
                    .execution_stack
                    .pop()
                    .ok_or(VmError::AssertionFailed { pc: self.pc })?;
                if let Some(parent) = self.execution_stack.last_mut() {
                    parent.pc = resume_pc;
                    self.frame_pc_overridden = true;
                }
                drop(completed_frame);
                Ok(())
            }
            LoopAction::Continue => {
                let (mode, success_count, total_iterations, key_reg, value_reg, iteration_state) = {
                    let (mode, success_count, total_iterations, key_reg, value_reg) = {
                        let frame = self
                            .execution_stack
                            .last()
                            .ok_or(VmError::AssertionFailed { pc: self.pc })?;
                        match frame.kind {
                            FrameKind::Loop { ref context, .. } => (
                                context.mode,
                                context.success_count,
                                context.total_iterations,
                                context.key_reg,
                                context.value_reg,
                            ),
                            _ => return Err(VmError::AssertionFailed { pc: self.pc }),
                        }
                    };

                    let key_value = if key_reg != value_reg {
                        Some(self.get_register(key_reg)?.clone())
                    } else {
                        None
                    };
                    let value_value = self.get_register(value_reg)?.clone();

                    let frame = self
                        .execution_stack
                        .last_mut()
                        .ok_or(VmError::AssertionFailed { pc: self.pc })?;
                    match &mut frame.kind {
                        &mut FrameKind::Loop {
                            ref mut context, ..
                        } => {
                            if let &mut IterationState::Object {
                                ref mut current_key,
                                ..
                            } = &mut context.iteration_state
                            {
                                if context.key_reg != context.value_reg {
                                    *current_key = key_value;
                                }
                            } else if let &mut IterationState::Set {
                                ref mut current_item,
                                ..
                            } = &mut context.iteration_state
                            {
                                *current_item = Some(value_value.clone());
                            }

                            context.iteration_state.advance();
                            context.current_iteration_failed = false;

                            (
                                mode,
                                success_count,
                                total_iterations,
                                key_reg,
                                value_reg,
                                context.iteration_state.clone(),
                            )
                        }
                        _ => return Err(VmError::AssertionFailed { pc: self.pc }),
                    }
                };

                let has_next = self.setup_next_iteration(&iteration_state, key_reg, value_reg)?;

                if has_next {
                    if let Some(frame) = self.execution_stack.last_mut() {
                        if let FrameKind::Loop { ref context, .. } = frame.kind {
                            frame.pc = context.body_resume_pc;
                        } else {
                            frame.pc = usize::from(body_start);
                        }
                        self.frame_pc_overridden = true;
                    }
                    Ok(())
                } else {
                    let final_result = match mode {
                        LoopMode::Any => Value::Bool(success_count > 0),
                        LoopMode::Every => Value::Bool(success_count == total_iterations),
                        LoopMode::ForEach => Value::Bool(success_count > 0),
                    };

                    #[cfg(feature = "explanations")]
                    if let Some(witness) = self.execution_stack.last().and_then(|frame| {
                        if let FrameKind::Loop { ref context, .. } = frame.kind {
                            Some(context.witness.clone())
                        } else {
                            None
                        }
                    }) {
                        self.insert_loop_summary_state(
                            result_reg,
                            mode,
                            total_iterations,
                            success_count,
                            &witness,
                        );
                    }

                    self.set_register(result_reg, final_result)?;

                    let completed_frame = self
                        .execution_stack
                        .pop()
                        .ok_or(VmError::AssertionFailed { pc: self.pc })?;
                    if let Some(parent) = self.execution_stack.last_mut() {
                        parent.pc = resume_pc;
                        self.frame_pc_overridden = true;
                    }
                    drop(completed_frame);

                    Ok(())
                }
            }
        }
    }

    fn handle_empty_collection(
        &mut self,
        mode: &LoopMode,
        result_reg: u8,
        loop_end: u16,
    ) -> Result<()> {
        let result = match *mode {
            LoopMode::Any => Value::Bool(false),
            LoopMode::Every => Value::Bool(true),
            LoopMode::ForEach => Value::Bool(false),
        };

        #[cfg(feature = "explanations")]
        self.insert_loop_summary_state(
            result_reg,
            *mode,
            0,
            0,
            &super::context::WitnessState::default(),
        );

        self.set_register(result_reg, result)?;
        self.pc = usize::from(loop_end).saturating_sub(1);
        Ok(())
    }

    pub(super) fn setup_next_iteration(
        &mut self,
        state: &IterationState,
        key_reg: u8,
        value_reg: u8,
    ) -> Result<bool> {
        match *state {
            IterationState::Array {
                ref items,
                ref index,
            } => {
                if *index < items.len() {
                    if key_reg != value_reg {
                        let key_value = Value::from(*index);
                        self.set_register(key_reg, key_value)?;
                    }
                    if let Some(item_value) = items.get(*index).cloned() {
                        self.set_register(value_reg, item_value)?;
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                } else {
                    Ok(false)
                }
            }
            IterationState::Object {
                ref obj,
                ref current_key,
                ref first_iteration,
            } => {
                if *first_iteration {
                    if let Some((key, value)) = obj.iter().next() {
                        if key_reg != value_reg {
                            self.set_register(key_reg, key.clone())?;
                        }
                        self.set_register(value_reg, value.clone())?;
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                } else if let Some(ref current) = *current_key {
                    let mut range_iter = obj.range((
                        core::ops::Bound::Excluded(current),
                        core::ops::Bound::Unbounded,
                    ));
                    if let Some((key, value)) = range_iter.next() {
                        if key_reg != value_reg {
                            self.set_register(key_reg, key.clone())?;
                        }
                        self.set_register(value_reg, value.clone())?;
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                } else {
                    Ok(false)
                }
            }
            IterationState::Set {
                ref items,
                ref current_item,
                ref first_iteration,
            } => {
                if *first_iteration {
                    if let Some(item) = items.iter().next() {
                        if key_reg != value_reg {
                            self.set_register(key_reg, item.clone())?;
                        }
                        self.set_register(value_reg, item.clone())?;
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                } else if let Some(ref current) = *current_item {
                    let mut range_iter = items.range((
                        core::ops::Bound::Excluded(current),
                        core::ops::Bound::Unbounded,
                    ));
                    if let Some(item) = range_iter.next() {
                        if key_reg != value_reg {
                            self.set_register(key_reg, item.clone())?;
                        }
                        self.set_register(value_reg, item.clone())?;
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

    const fn check_iteration_success(loop_ctx: &LoopContext) -> Result<bool> {
        Ok(!loop_ctx.current_iteration_failed)
    }

    const fn determine_loop_action(mode: &LoopMode, success: bool) -> LoopAction {
        match (mode, success) {
            (&LoopMode::Any, true) => LoopAction::ExitWithSuccess,
            (&LoopMode::Every, false) => LoopAction::ExitWithFailure,
            (&LoopMode::ForEach, _) => LoopAction::Continue,
            _ => LoopAction::Continue,
        }
    }

    fn handle_condition_run_to_completion(&mut self, condition_passed: bool) -> Result<()> {
        if condition_passed {
            return Ok(());
        }

        if !self.loop_stack.is_empty() {
            let (loop_mode, loop_next_pc, loop_end, result_reg) = {
                let loop_ctx = self
                    .loop_stack
                    .last()
                    .ok_or(VmError::AssertionFailed { pc: self.pc })?;
                (
                    loop_ctx.mode,
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

                    self.pc = usize::from(loop_next_pc.saturating_sub(1));
                }
                LoopMode::Every => {
                    #[cfg(feature = "explanations")]
                    if let Some((key_reg, value_reg)) = self.loop_stack.last().and_then(|ctx| {
                        ctx.witness
                            .sample_value
                            .is_none()
                            .then_some((ctx.key_reg, ctx.value_reg))
                    }) {
                        let sample_key = if key_reg != value_reg {
                            Some(self.get_register(key_reg)?.clone())
                        } else {
                            None
                        };
                        let sample_value = self.get_register(value_reg)?.clone();
                        if let Some(loop_ctx_mut) = self.loop_stack.last_mut() {
                            loop_ctx_mut.witness.sample_key = sample_key;
                            loop_ctx_mut.witness.sample_value = Some(sample_value);
                        }
                    }
                    #[cfg(feature = "explanations")]
                    if let Some(block_record_start) = self
                        .loop_stack
                        .last()
                        .map(|ctx| ctx.witness.block_record_start)
                    {
                        let iteration_records = self.capture_iteration_records(block_record_start);
                        if let Some((key_reg, value_reg)) = self
                            .loop_stack
                            .last()
                            .map(|ctx| (ctx.key_reg, ctx.value_reg))
                        {
                            let bindings = Self::bindings_from_records(&iteration_records);
                            let witness =
                                self.make_loop_iteration_witness(key_reg, value_reg, bindings)?;
                            if let Some(loop_ctx_mut) = self.loop_stack.last_mut() {
                                if loop_ctx_mut.witness.sample_value.is_none() {
                                    loop_ctx_mut.witness.sample_key = witness.sample_key.clone();
                                    loop_ctx_mut.witness.sample_value =
                                        witness.sample_value.clone();
                                }
                                if loop_ctx_mut.witness.failing_iteration.is_none() {
                                    loop_ctx_mut.witness.failing_iteration = Some(witness);
                                }
                                if loop_ctx_mut.witness.failing_records.is_none()
                                    && !iteration_records.is_empty()
                                {
                                    loop_ctx_mut.witness.failing_records =
                                        Some(iteration_records.clone());
                                }
                            }
                        }
                    }

                    #[cfg(feature = "explanations")]
                    if let Some((total_iterations, success_count, witness)) =
                        self.loop_stack.last().map(|loop_ctx| {
                            (
                                loop_ctx.total_iterations.saturating_add(1),
                                loop_ctx.success_count,
                                loop_ctx.witness.clone(),
                            )
                        })
                    {
                        self.insert_loop_summary_state(
                            result_reg,
                            LoopMode::Every,
                            total_iterations,
                            success_count,
                            &witness,
                        );
                    }

                    self.loop_stack.pop();
                    self.pc = usize::from(loop_end.saturating_sub(1));
                    self.set_register(result_reg, Value::Bool(false))?;
                }
                _ => {
                    if let Some(loop_ctx_mut) = self.loop_stack.last_mut() {
                        loop_ctx_mut.current_iteration_failed = true;
                    }
                    self.pc = usize::from(loop_next_pc.saturating_sub(1));
                }
            }
        } else if self.handle_comprehension_condition_failure_run_to_completion()? {
            // handled by comprehension context
        } else {
            return Err(VmError::AssertionFailed { pc: self.pc });
        }

        Ok(())
    }

    fn handle_condition_suspendable(&mut self, condition_passed: bool) -> Result<()> {
        if condition_passed {
            return Ok(());
        }

        if let Some(&ExecutionFrame {
            kind: FrameKind::Loop { .. },
            ..
        }) = self.execution_stack.last()
        {
            let (mode, resume_pc, loop_next_pc, result_reg) = {
                let frame = self
                    .execution_stack
                    .last_mut()
                    .ok_or(VmError::AssertionFailed { pc: self.pc })?;
                match &mut frame.kind {
                    &mut FrameKind::Loop {
                        ref return_pc,
                        ref mut context,
                    } => (
                        context.mode,
                        *return_pc,
                        context.loop_next_pc,
                        context.result_reg,
                    ),
                    _ => return Err(VmError::AssertionFailed { pc: self.pc }),
                }
            };

            match mode {
                LoopMode::Any | LoopMode::ForEach => {
                    if let Some(&mut ExecutionFrame {
                        kind:
                            FrameKind::Loop {
                                context: ref mut ctx,
                                ..
                            },
                        ..
                    }) = self.execution_stack.last_mut()
                    {
                        ctx.current_iteration_failed = true;
                        self.pc = usize::from(loop_next_pc.saturating_sub(1));
                    }
                    Ok(())
                }
                LoopMode::Every => {
                    #[cfg(feature = "explanations")]
                    let sample_regs = self.execution_stack.last().and_then(|frame| {
                        if let FrameKind::Loop {
                            context: ref ctx, ..
                        } = frame.kind
                        {
                            ctx.witness
                                .sample_value
                                .is_none()
                                .then_some((ctx.key_reg, ctx.value_reg))
                        } else {
                            None
                        }
                    });
                    #[cfg(feature = "explanations")]
                    let sample_key = if let Some((key_reg, value_reg)) = sample_regs {
                        if key_reg != value_reg {
                            Some(self.get_register(key_reg)?.clone())
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    #[cfg(feature = "explanations")]
                    let sample_value = if let Some((_, value_reg)) = sample_regs {
                        Some(self.get_register(value_reg)?.clone())
                    } else {
                        None
                    };

                    if let Some(&mut ExecutionFrame {
                        kind:
                            FrameKind::Loop {
                                context: ref mut ctx,
                                ..
                            },
                        ..
                    }) = self.execution_stack.last_mut()
                    {
                        ctx.current_iteration_failed = true;
                        #[cfg(feature = "explanations")]
                        if ctx.witness.sample_value.is_none() {
                            ctx.witness.sample_key = sample_key;
                            ctx.witness.sample_value = sample_value;
                        }
                    }

                    #[cfg(feature = "explanations")]
                    {
                        let block_record_start = self
                            .execution_stack
                            .last()
                            .and_then(|frame| {
                                if let FrameKind::Loop { ref context, .. } = frame.kind {
                                    Some(context.witness.block_record_start)
                                } else {
                                    None
                                }
                            })
                            .ok_or(VmError::AssertionFailed { pc: self.pc })?;
                        let iteration_records = self.capture_iteration_records(block_record_start);
                        let (key_reg, value_reg) = self
                            .execution_stack
                            .last()
                            .and_then(|frame| {
                                if let FrameKind::Loop { ref context, .. } = frame.kind {
                                    Some((context.key_reg, context.value_reg))
                                } else {
                                    None
                                }
                            })
                            .ok_or(VmError::AssertionFailed { pc: self.pc })?;
                        let bindings = Self::bindings_from_records(&iteration_records);
                        let witness =
                            self.make_loop_iteration_witness(key_reg, value_reg, bindings)?;
                        if let Some(&mut ExecutionFrame {
                            kind:
                                FrameKind::Loop {
                                    context: ref mut ctx,
                                    ..
                                },
                            ..
                        }) = self.execution_stack.last_mut()
                        {
                            if ctx.witness.failing_iteration.is_none() {
                                ctx.witness.failing_iteration = Some(witness);
                            }
                            if ctx.witness.failing_records.is_none()
                                && !iteration_records.is_empty()
                            {
                                ctx.witness.failing_records = Some(iteration_records.clone());
                            }
                        }
                    }

                    self.set_register(result_reg, Value::Bool(false))?;
                    #[cfg(feature = "explanations")]
                    if let Some((total_iterations, success_count, witness)) =
                        self.execution_stack.last().and_then(|frame| {
                            if let FrameKind::Loop { ref context, .. } = frame.kind {
                                Some((
                                    context.total_iterations.saturating_add(1),
                                    context.success_count,
                                    context.witness.clone(),
                                ))
                            } else {
                                None
                            }
                        })
                    {
                        self.insert_loop_summary_state(
                            result_reg,
                            LoopMode::Every,
                            total_iterations,
                            success_count,
                            &witness,
                        );
                    }
                    let completed_frame = self
                        .execution_stack
                        .pop()
                        .ok_or(VmError::AssertionFailed { pc: self.pc })?;
                    if let Some(parent) = self.execution_stack.last_mut() {
                        parent.pc = resume_pc;
                        self.frame_pc_overridden = true;
                    }
                    drop(completed_frame);
                    Ok(())
                }
            }
        } else if self.handle_comprehension_condition_failure_suspendable()? {
            Ok(())
        } else {
            Err(VmError::AssertionFailed { pc: self.pc })
        }
    }
}
