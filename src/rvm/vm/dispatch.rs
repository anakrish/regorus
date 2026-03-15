// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::rvm::instructions::{Instruction, LiteralOrRegister};
use crate::rvm::program::Program;
use crate::value::Value;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::mem;

use super::errors::{Result, VmError};
use super::execution_model::{ExecutionMode, SuspendReason};
use super::loops::LoopParams;
use super::machine::RegoVM;

pub(super) enum InstructionOutcome {
    Continue,
    Return(Value),
    Break,
    Suspend { reason: SuspendReason },
}

impl RegoVM {
    #[cfg(feature = "explanations")]
    const fn capture_all_contributing_conditions(&self) -> bool {
        matches!(
            self.explanation_settings.condition_mode,
            crate::ExplanationConditionMode::AllContributing
        )
    }

    #[cfg(feature = "explanations")]
    const fn invert_explanation_outcome(
        outcome: crate::explanations::ExplanationOutcome,
    ) -> crate::explanations::ExplanationOutcome {
        match outcome {
            crate::explanations::ExplanationOutcome::Success => {
                crate::explanations::ExplanationOutcome::Failure
            }
            crate::explanations::ExplanationOutcome::Failure => {
                crate::explanations::ExplanationOutcome::Success
            }
        }
    }

    /// Check whether the instruction immediately before `self.pc` is a
    /// `CallRule` (or `Not` wrapping a `CallRule`) whose dest matches
    /// `condition`, i.e. the assert is checking the result of a nested rule.
    /// If so, return true so the caller can inline the nested rule's block
    /// indices into the current block.
    #[cfg(feature = "explanations")]
    fn is_nested_rule_condition(
        &self,
        condition: u8,
        outcome: crate::explanations::ExplanationOutcome,
    ) -> bool {
        let Some(prev_pc) = self.pc.checked_sub(1) else {
            return false;
        };
        let Some(prev_instr) = self.program.instructions.get(prev_pc) else {
            return false;
        };
        match *prev_instr {
            Instruction::CallRule { dest, .. } if dest == condition => {
                // Nested rule outcome must match
                if let Some(last_idx) = self.causality.last_rule_block_indices().last() {
                    if let Some(event) = self
                        .causality
                        .events_ref()
                        .get(usize::try_from(*last_idx).unwrap_or(usize::MAX))
                    {
                        let event_passed = matches!(
                            event.kind,
                            crate::causality::CausalEventKind::Condition { passed: true, .. }
                        );
                        let expected_passed =
                            outcome == crate::explanations::ExplanationOutcome::Success;
                        return event_passed == expected_passed;
                    }
                }
                false
            }
            Instruction::Not { dest, operand } if dest == condition => {
                // Check for Not(CallRule)
                if let Some(prev2_pc) = self.pc.checked_sub(2) {
                    if let Some(&Instruction::CallRule {
                        dest: nested_dest, ..
                    }) = self.program.instructions.get(prev2_pc)
                    {
                        if nested_dest == operand {
                            let inverted = Self::invert_explanation_outcome(outcome);
                            if let Some(last_idx) = self.causality.last_rule_block_indices().last()
                            {
                                if let Some(event) = self
                                    .causality
                                    .events_ref()
                                    .get(usize::try_from(*last_idx).unwrap_or(usize::MAX))
                                {
                                    let event_passed = matches!(
                                        event.kind,
                                        crate::causality::CausalEventKind::Condition {
                                            passed: true,
                                            ..
                                        }
                                    );
                                    let expected_passed = inverted
                                        == crate::explanations::ExplanationOutcome::Success;
                                    return event_passed == expected_passed;
                                }
                            }
                        }
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// Build a `RawConditionSnapshot` from an `InstructionConditionProbe`.
    /// Values are captured as indices into the capture's value table (Rc-bump).
    #[cfg(feature = "explanations")]
    fn snapshot_condition_probe(
        &mut self,
        probe: &crate::rvm::program::InstructionConditionProbe,
    ) -> Option<crate::causality::RawConditionSnapshot> {
        use crate::causality::{RawConditionSnapshot, RawWitnessSnapshot};

        let snapshot = match *probe {
            crate::rvm::program::InstructionConditionProbe::Comparison {
                operator,
                actual_register,
                expected_register,
                ref actual_hint,
                ref expected_hint,
            } => {
                let actual_val = self.get_register(actual_register).ok()?.clone();
                let expected_val = self.get_register(expected_register).ok()?.clone();
                let actual_idx = self.causality.snapshot_value(&actual_val);
                let expected_idx = self.causality.snapshot_value(&expected_val);
                RawConditionSnapshot {
                    kind: crate::ConditionEvaluationKind::Comparison,
                    operator: Some(operator),
                    actual: Some(actual_idx),
                    actual_hint: actual_hint.clone(),
                    actual_path: self.provenance.get(actual_register).cloned(),
                    expected: Some(expected_idx),
                    expected_hint: expected_hint.clone(),
                    expected_path: self.provenance.get(expected_register).cloned(),
                    witness: None,
                }
            }
            crate::rvm::program::InstructionConditionProbe::Membership {
                operator,
                actual_register,
                expected_register,
                ref actual_hint,
                ref expected_hint,
            } => {
                let actual_val = self.get_register(actual_register).ok()?.clone();
                let actual_idx = self.causality.snapshot_value(&actual_val);
                let expected_idx = expected_register.and_then(|reg| {
                    let val = self.get_register(reg).ok()?.clone();
                    Some(self.causality.snapshot_value(&val))
                });
                let expected_path =
                    expected_register.and_then(|reg| self.provenance.get(reg).cloned());
                RawConditionSnapshot {
                    kind: crate::ConditionEvaluationKind::Membership,
                    operator: Some(operator),
                    actual: Some(actual_idx),
                    actual_hint: actual_hint.clone(),
                    actual_path: self.provenance.get(actual_register).cloned(),
                    expected: expected_idx,
                    expected_hint: expected_hint.clone(),
                    expected_path,
                    witness: None,
                }
            }
            crate::rvm::program::InstructionConditionProbe::Truthiness { register, ref hint } => {
                let value = self.get_register(register).ok()?.clone();
                let operator = match value {
                    Value::Bool(false) | Value::Null | Value::Undefined => {
                        crate::ConditionOperator::Falsy
                    }
                    _ => crate::ConditionOperator::Truthy,
                };
                let actual_idx = self.causality.snapshot_value(&value);
                RawConditionSnapshot {
                    kind: crate::ConditionEvaluationKind::Truthiness,
                    operator: Some(operator),
                    actual: Some(actual_idx),
                    actual_hint: hint.clone(),
                    actual_path: self.provenance.get(register).cloned(),
                    expected: None,
                    expected_hint: None,
                    expected_path: None,
                    witness: None,
                }
            }
            crate::rvm::program::InstructionConditionProbe::Builtin {
                operator,
                actual_register,
                expected_register,
                ref actual_hint,
                ref expected_hint,
            } => {
                let actual_val = self.get_register(actual_register).ok()?.clone();
                let actual_idx = self.causality.snapshot_value(&actual_val);
                let expected_idx = expected_register.and_then(|reg| {
                    let val = self.get_register(reg).ok()?.clone();
                    Some(self.causality.snapshot_value(&val))
                });
                let expected_path =
                    expected_register.and_then(|reg| self.provenance.get(reg).cloned());
                RawConditionSnapshot {
                    kind: crate::ConditionEvaluationKind::Builtin,
                    operator: Some(operator),
                    actual: Some(actual_idx),
                    actual_hint: actual_hint.clone(),
                    actual_path: self.provenance.get(actual_register).cloned(),
                    expected: expected_idx,
                    expected_hint: expected_hint.clone(),
                    expected_path,
                    witness: None,
                }
            }
            crate::rvm::program::InstructionConditionProbe::Loop {
                result_register,
                operator,
                ref condition_texts,
            } => {
                let actual_val = self.get_register(result_register).ok()?.clone();
                let mut witness = self.causality.loop_witness(result_register).cloned();
                let actual_idx = self.causality.snapshot_value(&actual_val);
                if let Some(ref mut w) = witness {
                    w.condition_texts = condition_texts.clone();
                } else if !condition_texts.is_empty() {
                    witness = Some(RawWitnessSnapshot {
                        collection_path: None,
                        iteration_count: None,
                        success_count: None,
                        yield_count: None,
                        condition_texts: condition_texts.clone(),
                        sample_key: None,
                        sample_key_hint: None,
                        sample_value: None,
                        sample_value_hint: None,
                        passing_iteration: None,
                        failing_iteration: None,
                    });
                }
                let collection_path = witness.as_ref().and_then(|w| w.collection_path.clone());
                RawConditionSnapshot {
                    kind: crate::ConditionEvaluationKind::Quantifier,
                    operator,
                    actual: Some(actual_idx),
                    actual_hint: None,
                    actual_path: collection_path,
                    expected: None,
                    expected_hint: None,
                    expected_path: None,
                    witness,
                }
            }
            crate::rvm::program::InstructionConditionProbe::Comprehension {
                result_register,
                ref condition_texts,
            } => {
                let actual_val = self.get_register(result_register).ok()?.clone();
                let mut comp_witness = self
                    .causality
                    .comprehension_witness(result_register)
                    .cloned();
                let actual_idx = self.causality.snapshot_value(&actual_val);
                // Inject condition_texts from the compile-time probe.
                if let Some(ref mut w) = comp_witness {
                    if w.condition_texts.is_empty() && !condition_texts.is_empty() {
                        w.condition_texts = condition_texts.clone();
                    }
                } else if !condition_texts.is_empty() {
                    comp_witness = Some(RawWitnessSnapshot {
                        collection_path: None,
                        iteration_count: None,
                        success_count: None,
                        yield_count: None,
                        condition_texts: condition_texts.clone(),
                        sample_key: None,
                        sample_key_hint: None,
                        sample_value: None,
                        sample_value_hint: None,
                        passing_iteration: None,
                        failing_iteration: None,
                    });
                }
                RawConditionSnapshot {
                    kind: crate::ConditionEvaluationKind::Comprehension,
                    operator: None,
                    actual: Some(actual_idx),
                    actual_hint: None,
                    actual_path: None,
                    expected: None,
                    expected_hint: None,
                    expected_path: None,
                    witness: comp_witness,
                }
            }
        };

        Some(snapshot)
    }

    /// Record a condition evaluation event into the causality capture.
    /// This replaces `record_current_instruction_condition` with thin event recording.
    #[cfg(feature = "explanations")]
    pub(super) fn record_current_instruction_condition(
        &mut self,
        outcome: crate::explanations::ExplanationOutcome,
    ) -> Result<()> {
        if !self.causality.is_enabled() {
            return Ok(());
        }

        let metadata = match self
            .program
            .instruction_explanations
            .get(self.pc)
            .cloned()
            .flatten()
        {
            Some(metadata) => metadata,
            None => return Ok(()),
        };

        let passed = outcome == crate::explanations::ExplanationOutcome::Success;
        let pc = u32::try_from(self.pc).unwrap_or(u32::MAX);

        // Handle loop probes: inline loop event ranges
        if let Some(result_register) = metadata.probe.as_ref().and_then(|probe| match probe {
            &crate::rvm::program::InstructionConditionProbe::Loop {
                result_register, ..
            } => Some(result_register),
            _ => None,
        }) {
            // Get loop event ranges for passing/failing iterations
            let loop_indices: Vec<u32> = self
                .causality
                .loop_event_range_indices(result_register, passed);

            // Snapshot bindings and condition probe.
            // Pass an empty binding list: the quantifier condition represents the
            // loop as a whole.  Per-iteration bindings are already captured in
            // the individual iteration condition events, and snapshotting here
            // would record the *last* iteration's register values, which would
            // overwrite the correct per-iteration bindings in the output.
            let (bindings_start, bindings_end) =
                self.causality
                    .snapshot_bindings(&[], &self.registers, &self.provenance);
            let snapshot = metadata
                .probe
                .as_ref()
                .and_then(|probe| self.snapshot_condition_probe(probe));

            let event_idx = self.causality.record_condition(
                pc,
                passed,
                None,
                None,
                bindings_start,
                bindings_end,
                snapshot,
            );

            // Build the block: loop iteration records + this condition
            let mut block_indices = loop_indices;
            block_indices.push(event_idx);
            self.causality
                .replace_current_block_conditions(block_indices);

            // Attach the quantifier to every emission produced during this loop.
            let loop_emission_keys = self.causality.pop_loop_emission_scope();
            if !loop_emission_keys.is_empty() {
                self.causality
                    .append_condition_to_emissions(event_idx, &loop_emission_keys);
                // Clear the current block to prevent the quantifier from leaking
                // into a later unrelated emission (e.g. via a Move instruction).
                self.causality.replace_current_block_conditions(Vec::new());
            }

            return Ok(());
        }

        // Handle comprehension end probes: record event and store index for
        // the next condition to inline.  Only applies to ComprehensionEnd
        // instructions; AssertCondition with a comprehension probe follows
        // the normal condition path below.
        if matches!(
            self.program.instructions.get(self.pc),
            Some(Instruction::ComprehensionEnd {})
        ) {
            if let Some(_result_register) = metadata.probe.as_ref().and_then(|probe| match probe {
                &crate::rvm::program::InstructionConditionProbe::Comprehension {
                    result_register,
                    ..
                } => Some(result_register),
                _ => None,
            }) {
                let (bindings_start, bindings_end) =
                    self.causality
                        .snapshot_bindings(&[], &self.registers, &self.provenance);
                let snapshot = metadata
                    .probe
                    .as_ref()
                    .and_then(|probe| self.snapshot_condition_probe(probe));
                let (actual_idx, expected_idx) = snapshot
                    .as_ref()
                    .map(|s| (s.actual, s.expected))
                    .unwrap_or((None, None));

                let event_idx = self.causality.record_condition(
                    pc,
                    passed,
                    actual_idx,
                    expected_idx,
                    bindings_start,
                    bindings_end,
                    snapshot,
                );

                // Store as last-rule-block so the next condition inlines it.
                let mut indices = self.causality.take_last_rule_block_indices();
                indices.push(event_idx);
                self.causality.set_last_rule_block_indices(indices);
                return Ok(());
            }
        }

        // Handle nested rule calls
        if let Some(&Instruction::AssertCondition { condition }) =
            self.program.instructions.get(self.pc)
        {
            if self.is_nested_rule_condition(condition, outcome) {
                let nested_indices = self.causality.take_last_rule_block_indices();
                if self.capture_all_contributing_conditions() {
                    // Keep existing + add nested
                    for idx in &nested_indices {
                        self.causality.push_current_block_condition(*idx);
                    }
                } else {
                    self.causality
                        .replace_current_block_conditions(nested_indices);
                }
                return Ok(());
            }
        }

        // Normal condition: snapshot values and bindings, record event
        let (bindings_start, bindings_end) =
            self.causality
                .snapshot_bindings(&metadata.bindings, &self.registers, &self.provenance);
        let snapshot = metadata
            .probe
            .as_ref()
            .and_then(|probe| self.snapshot_condition_probe(probe));

        // Snapshot actual/expected from the probe for the event
        let (actual_idx, expected_idx) = snapshot
            .as_ref()
            .map(|s| (s.actual, s.expected))
            .unwrap_or((None, None));

        let event_idx = self.causality.record_condition(
            pc,
            passed,
            actual_idx,
            expected_idx,
            bindings_start,
            bindings_end,
            snapshot,
        );

        // If a recent CallRule left block indices (e.g. count(violation) == 0
        // wraps a CallRule result through a BuiltinCall), inline those conditions
        // so the helper rule's explanations flow into this block.
        let nested_indices = self.causality.take_last_rule_block_indices();

        if self.capture_all_contributing_conditions() {
            for idx in &nested_indices {
                self.causality.push_current_block_condition(*idx);
            }
            self.causality.push_current_block_condition(event_idx);
        } else {
            let mut block = nested_indices;
            block.push(event_idx);
            self.causality.replace_current_block_conditions(block);
        }

        Ok(())
    }

    #[cfg(feature = "explanations")]
    pub(super) fn finalize_current_block(&mut self) -> Vec<u32> {
        self.causality.finalize_current_block()
    }

    #[cfg(feature = "explanations")]
    pub(super) fn snapshot_latest_block(&mut self, explanation_key: Value) {
        self.causality.snapshot_latest_block(explanation_key);
    }

    #[cfg(feature = "explanations")]
    pub(super) fn snapshot_all_blocks(&mut self, explanation_key: Value) {
        self.causality.snapshot_all_blocks(explanation_key);
    }

    pub(super) fn execute_instruction(
        &mut self,
        program: &Program,
        instruction: Instruction,
    ) -> Result<InstructionOutcome> {
        self.memory_check()?;
        self.execute_load_and_move(program, instruction)
    }

    fn execute_load_and_move(
        &mut self,
        program: &Program,
        instruction: Instruction,
    ) -> Result<InstructionOutcome> {
        use Instruction::*;
        match instruction {
            Load { dest, literal_idx } => {
                if let Some(value) = program.literals.get(usize::from(literal_idx)) {
                    self.set_register(dest, value.clone())?;
                    #[cfg(feature = "explanations")]
                    self.provenance.clear_reg(dest);
                    Ok(InstructionOutcome::Continue)
                } else {
                    Err(VmError::LiteralIndexOutOfBounds {
                        index: literal_idx,
                        pc: self.pc,
                    })
                }
            }
            LoadTrue { dest } => {
                self.set_register(dest, Value::Bool(true))?;
                #[cfg(feature = "explanations")]
                self.provenance.clear_reg(dest);
                Ok(InstructionOutcome::Continue)
            }
            LoadFalse { dest } => {
                self.set_register(dest, Value::Bool(false))?;
                #[cfg(feature = "explanations")]
                self.provenance.clear_reg(dest);
                Ok(InstructionOutcome::Continue)
            }
            LoadNull { dest } => {
                self.set_register(dest, Value::Null)?;
                #[cfg(feature = "explanations")]
                self.provenance.clear_reg(dest);
                Ok(InstructionOutcome::Continue)
            }
            LoadBool { dest, value } => {
                self.set_register(dest, Value::Bool(value))?;
                #[cfg(feature = "explanations")]
                self.provenance.clear_reg(dest);
                Ok(InstructionOutcome::Continue)
            }
            LoadData { dest } => {
                self.set_register(dest, self.data.clone())?;
                #[cfg(feature = "explanations")]
                self.provenance.set_root(dest, "data");
                Ok(InstructionOutcome::Continue)
            }
            LoadInput { dest } => {
                self.set_register(dest, self.input.clone())?;
                #[cfg(feature = "explanations")]
                self.provenance.set_root(dest, "input");
                Ok(InstructionOutcome::Continue)
            }
            Move { dest, src } => {
                let value = self.get_register(src)?.clone();
                self.set_register(dest, value)?;
                #[cfg(feature = "explanations")]
                self.provenance.copy(dest, src);
                #[cfg(feature = "explanations")]
                self.snapshot_latest_block(self.get_register(dest)?.clone());
                Ok(InstructionOutcome::Continue)
            }
            other => self.execute_arithmetic_instruction(program, other),
        }
    }

    fn execute_arithmetic_instruction(
        &mut self,
        program: &Program,
        instruction: Instruction,
    ) -> Result<InstructionOutcome> {
        use Instruction::*;
        match instruction {
            Add { dest, left, right } => {
                let a = self.get_register(left)?;
                let b = self.get_register(right)?;

                if a == &Value::Undefined || b == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
                    #[cfg(feature = "explanations")]
                    self.provenance.clear_reg(dest);
                    return Ok(InstructionOutcome::Continue);
                }

                let result = self.add_values(a, b)?;
                self.set_register(dest, result)?;
                #[cfg(feature = "explanations")]
                self.provenance.clear_reg(dest);
                Ok(InstructionOutcome::Continue)
            }
            Sub { dest, left, right } => {
                let a = self.get_register(left)?;
                let b = self.get_register(right)?;

                if a == &Value::Undefined || b == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
                    #[cfg(feature = "explanations")]
                    self.provenance.clear_reg(dest);
                    return Ok(InstructionOutcome::Continue);
                }

                let result = self.sub_values(a, b)?;
                self.set_register(dest, result)?;
                #[cfg(feature = "explanations")]
                self.provenance.clear_reg(dest);
                Ok(InstructionOutcome::Continue)
            }
            Mul { dest, left, right } => {
                let a = self.get_register(left)?;
                let b = self.get_register(right)?;

                if a == &Value::Undefined || b == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
                    #[cfg(feature = "explanations")]
                    self.provenance.clear_reg(dest);
                    return Ok(InstructionOutcome::Continue);
                }

                let result = self.mul_values(a, b)?;
                self.set_register(dest, result)?;
                #[cfg(feature = "explanations")]
                self.provenance.clear_reg(dest);
                Ok(InstructionOutcome::Continue)
            }
            Div { dest, left, right } => {
                let a = self.get_register(left)?;
                let b = self.get_register(right)?;

                if a == &Value::Undefined || b == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
                    #[cfg(feature = "explanations")]
                    self.provenance.clear_reg(dest);
                    return Ok(InstructionOutcome::Continue);
                }

                let result = self.div_values(a, b)?;
                self.set_register(dest, result)?;
                #[cfg(feature = "explanations")]
                self.provenance.clear_reg(dest);
                Ok(InstructionOutcome::Continue)
            }
            Mod { dest, left, right } => {
                let a = self.get_register(left)?;
                let b = self.get_register(right)?;

                if a == &Value::Undefined || b == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
                    #[cfg(feature = "explanations")]
                    self.provenance.clear_reg(dest);
                    return Ok(InstructionOutcome::Continue);
                }

                let result = self.mod_values(a, b)?;
                self.set_register(dest, result)?;
                #[cfg(feature = "explanations")]
                self.provenance.clear_reg(dest);
                Ok(InstructionOutcome::Continue)
            }
            other => self.execute_comparison_instruction(program, other),
        }
    }

    fn execute_comparison_instruction(
        &mut self,
        program: &Program,
        instruction: Instruction,
    ) -> Result<InstructionOutcome> {
        use Instruction::*;
        match instruction {
            Eq { dest, left, right } => {
                let a = self.get_register(left)?;
                let b = self.get_register(right)?;

                if a == &Value::Undefined || b == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
                    #[cfg(feature = "explanations")]
                    self.provenance.clear_reg(dest);
                    return Ok(InstructionOutcome::Continue);
                }

                self.set_register(dest, Value::Bool(a == b))?;
                #[cfg(feature = "explanations")]
                self.provenance.clear_reg(dest);
                Ok(InstructionOutcome::Continue)
            }
            Ne { dest, left, right } => {
                let a = self.get_register(left)?;
                let b = self.get_register(right)?;

                if a == &Value::Undefined || b == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
                    #[cfg(feature = "explanations")]
                    self.provenance.clear_reg(dest);
                    return Ok(InstructionOutcome::Continue);
                }

                self.set_register(dest, Value::Bool(a != b))?;
                #[cfg(feature = "explanations")]
                self.provenance.clear_reg(dest);
                Ok(InstructionOutcome::Continue)
            }
            Lt { dest, left, right } => {
                let a = self.get_register(left)?;
                let b = self.get_register(right)?;

                if a == &Value::Undefined || b == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
                    #[cfg(feature = "explanations")]
                    self.provenance.clear_reg(dest);
                    return Ok(InstructionOutcome::Continue);
                }

                if self.strict_builtin_errors && mem::discriminant(a) != mem::discriminant(b) {
                    return Err(VmError::ArithmeticError {
                        message: alloc::format!(
                            "#undefined: cannot compare values of different types (left={a:?}, right={b:?})"
                        ),
                        pc: self.pc,
                    });
                }

                self.set_register(dest, Value::Bool(a < b))?;
                #[cfg(feature = "explanations")]
                self.provenance.clear_reg(dest);
                Ok(InstructionOutcome::Continue)
            }
            Le { dest, left, right } => {
                let a = self.get_register(left)?;
                let b = self.get_register(right)?;

                if a == &Value::Undefined || b == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
                    #[cfg(feature = "explanations")]
                    self.provenance.clear_reg(dest);
                    return Ok(InstructionOutcome::Continue);
                }

                if self.strict_builtin_errors && mem::discriminant(a) != mem::discriminant(b) {
                    return Err(VmError::ArithmeticError {
                        message: alloc::format!(
                            "#undefined: cannot compare values of different types (left={a:?}, right={b:?})"
                        ),
                        pc: self.pc,
                    });
                }

                self.set_register(dest, Value::Bool(a <= b))?;
                #[cfg(feature = "explanations")]
                self.provenance.clear_reg(dest);
                Ok(InstructionOutcome::Continue)
            }
            Gt { dest, left, right } => {
                let a = self.get_register(left)?;
                let b = self.get_register(right)?;

                if a == &Value::Undefined || b == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
                    #[cfg(feature = "explanations")]
                    self.provenance.clear_reg(dest);
                    return Ok(InstructionOutcome::Continue);
                }

                if self.strict_builtin_errors && mem::discriminant(a) != mem::discriminant(b) {
                    return Err(VmError::ArithmeticError {
                        message: alloc::format!(
                            "#undefined: cannot compare values of different types (left={a:?}, right={b:?})"
                        ),
                        pc: self.pc,
                    });
                }

                self.set_register(dest, Value::Bool(a > b))?;
                #[cfg(feature = "explanations")]
                self.provenance.clear_reg(dest);
                Ok(InstructionOutcome::Continue)
            }
            Ge { dest, left, right } => {
                let a = self.get_register(left)?;
                let b = self.get_register(right)?;

                if a == &Value::Undefined || b == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
                    #[cfg(feature = "explanations")]
                    self.provenance.clear_reg(dest);
                    return Ok(InstructionOutcome::Continue);
                }

                if self.strict_builtin_errors && mem::discriminant(a) != mem::discriminant(b) {
                    return Err(VmError::ArithmeticError {
                        message: alloc::format!(
                            "#undefined: cannot compare values of different types (left={a:?}, right={b:?})"
                        ),
                        pc: self.pc,
                    });
                }

                self.set_register(dest, Value::Bool(a >= b))?;
                #[cfg(feature = "explanations")]
                self.provenance.clear_reg(dest);
                Ok(InstructionOutcome::Continue)
            }
            And { dest, left, right } => {
                let left_value = self.get_register(left)?;
                let right_value = self.get_register(right)?;

                if left_value == &Value::Undefined || right_value == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
                    #[cfg(feature = "explanations")]
                    self.provenance.clear_reg(dest);
                    return Ok(InstructionOutcome::Continue);
                }

                match (self.to_bool(left_value), self.to_bool(right_value)) {
                    (Some(a), Some(b)) => {
                        self.set_register(dest, Value::Bool(a && b))?;
                        #[cfg(feature = "explanations")]
                        self.provenance.clear_reg(dest);
                        Ok(InstructionOutcome::Continue)
                    }
                    _ => Err(VmError::ArithmeticError {
                        message: alloc::format!(
                            "#undefined: logical AND expects booleans (left={left_value:?}, right={right_value:?})"
                        ),
                        pc: self.pc,
                    }),
                }
            }
            Or { dest, left, right } => {
                let left_value = self.get_register(left)?;
                let right_value = self.get_register(right)?;

                if left_value == &Value::Undefined || right_value == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
                    #[cfg(feature = "explanations")]
                    self.provenance.clear_reg(dest);
                    return Ok(InstructionOutcome::Continue);
                }

                match (self.to_bool(left_value), self.to_bool(right_value)) {
                    (Some(a), Some(b)) => {
                        self.set_register(dest, Value::Bool(a || b))?;
                        #[cfg(feature = "explanations")]
                        self.provenance.clear_reg(dest);
                        Ok(InstructionOutcome::Continue)
                    }
                    _ => Err(VmError::ArithmeticError {
                        message: alloc::format!(
                            "#undefined: logical OR expects booleans (left={left_value:?}, right={right_value:?})"
                        ),
                        pc: self.pc,
                    }),
                }
            }
            Not { dest, operand } => {
                let operand_value = self.get_register(operand)?;

                if operand_value == &Value::Undefined {
                    // In Rego, `not expr` succeeds when `expr` has no results.
                    // When the operand evaluates to undefined we should treat it as
                    // a successful negation instead of propagating undefined.
                    self.set_register(dest, Value::Bool(true))?;
                    #[cfg(feature = "explanations")]
                    self.provenance.clear_reg(dest);
                    return Ok(InstructionOutcome::Continue);
                }

                if let Some(value) = self.to_bool(operand_value) {
                    self.set_register(dest, Value::Bool(!value))?;
                    #[cfg(feature = "explanations")]
                    self.provenance.clear_reg(dest);
                    Ok(InstructionOutcome::Continue)
                } else {
                    Err(VmError::ArithmeticError {
                        message: alloc::format!(
                            "#undefined: logical NOT expects a boolean (operand={operand_value:?})"
                        ),
                        pc: self.pc,
                    })
                }
            }
            AssertCondition { condition } => {
                let value = self.get_register(condition)?;

                let condition_result = match *value {
                    Value::Bool(b) => b,
                    Value::Undefined => false,
                    _ => true,
                };

                #[cfg(feature = "explanations")]
                self.record_current_instruction_condition(if condition_result {
                    crate::explanations::ExplanationOutcome::Success
                } else {
                    crate::explanations::ExplanationOutcome::Failure
                })?;

                #[cfg(feature = "explanations")]
                if !condition_result {
                    let _ = self.finalize_current_block();
                }

                self.handle_condition(condition_result)?;
                Ok(InstructionOutcome::Continue)
            }
            AssertNotUndefined { register } => {
                let value = self.get_register(register)?;

                let is_undefined = matches!(value, Value::Undefined);
                #[cfg(feature = "explanations")]
                self.record_current_instruction_condition(if is_undefined {
                    crate::explanations::ExplanationOutcome::Failure
                } else {
                    crate::explanations::ExplanationOutcome::Success
                })?;

                #[cfg(feature = "explanations")]
                if is_undefined {
                    let _ = self.finalize_current_block();
                }
                self.handle_condition(!is_undefined)?;
                Ok(InstructionOutcome::Continue)
            }
            other => self.execute_call_instruction(program, other),
        }
    }

    fn execute_call_instruction(
        &mut self,
        program: &Program,
        instruction: Instruction,
    ) -> Result<InstructionOutcome> {
        use Instruction::*;
        match instruction {
            BuiltinCall { params_index } => {
                self.execute_builtin_call(params_index)?;
                Ok(InstructionOutcome::Continue)
            }
            HostAwait { dest, arg, id } => {
                let argument = self.get_register(arg)?.clone();
                let identifier = self
                    .registers
                    .get(usize::from(id))
                    .cloned()
                    .unwrap_or(Value::Undefined);
                match self.execution_mode {
                    ExecutionMode::RunToCompletion => {
                        let response = self.next_host_await_response(&identifier, dest)?;
                        self.set_register(dest, response)?;
                        #[cfg(feature = "explanations")]
                        self.provenance.clear_reg(dest);
                        Ok(InstructionOutcome::Continue)
                    }
                    ExecutionMode::Suspendable => Ok(InstructionOutcome::Suspend {
                        reason: SuspendReason::HostAwait {
                            dest,
                            argument,
                            identifier,
                        },
                    }),
                }
            }
            FunctionCall { params_index } => {
                self.execute_function_call(params_index)?;
                Ok(InstructionOutcome::Continue)
            }
            Return { value } => {
                let result = self.get_register(value)?.clone();
                #[cfg(feature = "explanations")]
                if !matches!(result, Value::Array(_) | Value::Set(_) | Value::Object(_)) {
                    self.snapshot_all_blocks(result.clone());
                }
                Ok(InstructionOutcome::Return(result))
            }
            CallRule { dest, rule_index } => {
                self.execute_call_rule(dest, rule_index)?;
                Ok(InstructionOutcome::Continue)
            }
            RuleInit {
                result_reg,
                rule_index,
            } => {
                self.execute_rule_init(result_reg, rule_index)?;
                Ok(InstructionOutcome::Continue)
            }
            DestructuringSuccess {} => Ok(InstructionOutcome::Break),
            RuleReturn {} => {
                self.execute_rule_return()?;
                Ok(InstructionOutcome::Break)
            }
            other => self.execute_collection_instruction(program, other),
        }
    }

    fn execute_collection_instruction(
        &mut self,
        program: &Program,
        instruction: Instruction,
    ) -> Result<InstructionOutcome> {
        use Instruction::*;
        match instruction {
            ObjectSet { obj, key, value } => {
                let key_value = self.get_register(key)?.clone();
                let value_value = self.get_register(value)?.clone();

                // Take ownership so Rc refcount stays at 1 and make_mut is a no-op.
                let mut obj_value = self.take_register(obj)?;

                if let Ok(obj_mut) = obj_value.as_object_mut() {
                    obj_mut.insert(key_value, value_value);
                    self.set_register(obj, obj_value)?;
                } else {
                    let offending = obj_value.clone();
                    self.set_register(obj, obj_value)?;
                    return Err(VmError::RegisterNotObject {
                        register: obj,
                        value: offending,
                        pc: self.pc,
                    });
                }
                #[cfg(feature = "explanations")]
                self.snapshot_latest_block(self.get_register(key)?.clone());
                Ok(InstructionOutcome::Continue)
            }
            ObjectCreate { params_index } => {
                let params = program
                    .instruction_data
                    .get_object_create_params(params_index)
                    .ok_or(VmError::InvalidObjectCreateParams {
                        index: params_index,
                        pc: self.pc,
                        available: program.instruction_data.object_create_params.len(),
                    })?;

                let mut any_undefined = false;

                for &(_, value_reg) in params.literal_key_field_pairs() {
                    if matches!(self.get_register(value_reg)?, Value::Undefined) {
                        any_undefined = true;
                        break;
                    }
                }

                if !any_undefined {
                    for &(key_reg, value_reg) in params.field_pairs() {
                        if matches!(self.get_register(key_reg)?, Value::Undefined)
                            || matches!(self.get_register(value_reg)?, Value::Undefined)
                        {
                            any_undefined = true;
                            break;
                        }
                    }
                }

                if any_undefined {
                    self.set_register(params.dest, Value::Undefined)?;
                } else {
                    let mut obj_value = program
                        .literals
                        .get(usize::from(params.template_literal_idx))
                        .ok_or(VmError::InvalidTemplateLiteralIndex {
                            index: params.template_literal_idx,
                            pc: self.pc,
                            available: program.literals.len(),
                        })?
                        .clone();

                    if let Ok(obj_mut) = obj_value.as_object_mut() {
                        let mut literal_updates = params.literal_key_field_pairs().iter();
                        let mut current_literal_update = literal_updates.next();

                        for (key, value) in obj_mut.iter_mut() {
                            if let Some(&(literal_idx, value_reg)) = current_literal_update {
                                if let Some(literal_key) =
                                    program.literals.get(usize::from(literal_idx))
                                {
                                    if key == literal_key {
                                        *value = self.get_register(value_reg)?.clone();
                                        current_literal_update = literal_updates.next();
                                    }
                                }
                            } else {
                                break;
                            }
                        }

                        while let Some(&(literal_idx, value_reg)) = current_literal_update {
                            if let Some(key_value) = program.literals.get(usize::from(literal_idx))
                            {
                                let value_value = self.get_register(value_reg)?.clone();
                                obj_mut.insert(key_value.clone(), value_value);
                            }
                            current_literal_update = literal_updates.next();
                        }

                        for &(key_reg, value_reg) in params.field_pairs() {
                            let key_value = self.get_register(key_reg)?.clone();
                            let value_value = self.get_register(value_reg)?.clone();
                            obj_mut.insert(key_value, value_value);
                        }
                    } else {
                        return Err(VmError::ObjectCreateInvalidTemplate {
                            template: obj_value,
                            pc: self.pc,
                        });
                    }

                    self.set_register(params.dest, obj_value)?;
                }
                #[cfg(feature = "explanations")]
                self.provenance.clear_reg(params.dest);
                Ok(InstructionOutcome::Continue)
            }
            Index {
                dest,
                container,
                key,
            } => {
                let key_value = self.get_register(key)?;
                let container_value = self.get_register(container)?;
                let result = container_value[key_value].clone();
                #[cfg(feature = "explanations")]
                let key_clone = key_value.clone();
                self.set_register(dest, result)?;
                #[cfg(feature = "explanations")]
                self.provenance.append_index(dest, container, &key_clone);
                Ok(InstructionOutcome::Continue)
            }
            IndexLiteral {
                dest,
                container,
                literal_idx,
            } => {
                let container_value = self.get_register(container)?;

                if let Some(key_value) = program.literals.get(usize::from(literal_idx)) {
                    let result = container_value[key_value].clone();
                    self.set_register(dest, result)?;
                    #[cfg(feature = "explanations")]
                    {
                        if let Ok(field) = key_value.as_string() {
                            self.provenance
                                .append_field(dest, container, field.as_ref());
                        } else {
                            self.provenance.append_index(dest, container, key_value);
                        }
                    }
                    Ok(InstructionOutcome::Continue)
                } else {
                    Err(VmError::LiteralIndexOutOfBounds {
                        index: literal_idx,
                        pc: self.pc,
                    })
                }
            }
            ArrayNew { dest } => {
                let empty_array = Value::Array(crate::Rc::new(Vec::new()));
                self.set_register(dest, empty_array)?;
                #[cfg(feature = "explanations")]
                self.provenance.clear_reg(dest);
                Ok(InstructionOutcome::Continue)
            }
            ArrayPush { arr, value } => {
                let value_to_push = self.get_register(value)?.clone();

                // Take ownership so Rc refcount stays at 1 and make_mut is a no-op.
                let mut arr_value = self.take_register(arr)?;

                if let Ok(arr_mut) = arr_value.as_array_mut() {
                    arr_mut.push(value_to_push);
                    self.set_register(arr, arr_value)?;
                } else {
                    let offending = arr_value.clone();
                    self.set_register(arr, arr_value)?;
                    return Err(VmError::RegisterNotArray {
                        register: arr,
                        value: offending,
                        pc: self.pc,
                    });
                }
                Ok(InstructionOutcome::Continue)
            }
            ArrayCreate { params_index } => {
                if let Some(params) = program
                    .instruction_data
                    .get_array_create_params(params_index)
                {
                    let mut any_undefined = false;
                    for &reg in params.element_registers() {
                        if matches!(self.get_register(reg)?, Value::Undefined) {
                            any_undefined = true;
                            break;
                        }
                    }

                    if any_undefined {
                        self.set_register(params.dest, Value::Undefined)?;
                    } else {
                        let elements: Vec<Value> = params
                            .element_registers()
                            .iter()
                            .map(|&reg| self.get_register(reg).cloned())
                            .collect::<Result<Vec<_>>>()?;

                        let array_value = Value::Array(crate::Rc::new(elements));
                        self.set_register(params.dest, array_value)?;
                    }
                    #[cfg(feature = "explanations")]
                    self.provenance.clear_reg(params.dest);
                    Ok(InstructionOutcome::Continue)
                } else {
                    Err(VmError::InvalidArrayCreateParams {
                        index: params_index,
                        pc: self.pc,
                        available: program.instruction_data.array_create_params.len(),
                    })
                }
            }
            SetNew { dest } => {
                let empty_set = Value::Set(crate::Rc::new(BTreeSet::new()));
                self.set_register(dest, empty_set)?;
                #[cfg(feature = "explanations")]
                self.provenance.clear_reg(dest);
                Ok(InstructionOutcome::Continue)
            }
            SetAdd { set, value } => {
                let value_to_add = self.get_register(value)?.clone();

                // Take ownership so Rc refcount stays at 1 and make_mut is a no-op.
                let mut set_value = self.take_register(set)?;

                if let Ok(set_mut) = set_value.as_set_mut() {
                    set_mut.insert(value_to_add);
                    self.set_register(set, set_value)?;
                } else {
                    let offending = set_value.clone();
                    self.set_register(set, set_value)?;
                    return Err(VmError::RegisterNotSet {
                        register: set,
                        value: offending,
                        pc: self.pc,
                    });
                }
                #[cfg(feature = "explanations")]
                self.snapshot_latest_block(self.get_register(value)?.clone());
                Ok(InstructionOutcome::Continue)
            }
            SetCreate { params_index } => {
                if let Some(params) = program.instruction_data.get_set_create_params(params_index) {
                    let mut any_undefined = false;
                    for &reg in params.element_registers() {
                        if matches!(self.get_register(reg)?, Value::Undefined) {
                            any_undefined = true;
                            break;
                        }
                    }

                    if any_undefined {
                        self.set_register(params.dest, Value::Undefined)?;
                    } else {
                        let mut set = BTreeSet::new();
                        for &reg in params.element_registers() {
                            set.insert(self.get_register(reg)?.clone());
                        }

                        let set_value = Value::Set(crate::Rc::new(set));
                        self.set_register(params.dest, set_value)?;
                    }
                    #[cfg(feature = "explanations")]
                    self.provenance.clear_reg(params.dest);
                    Ok(InstructionOutcome::Continue)
                } else {
                    Err(VmError::InvalidSetCreateParams {
                        index: params_index,
                        pc: self.pc,
                        available: program.instruction_data.set_create_params.len(),
                    })
                }
            }
            Contains {
                dest,
                collection,
                value,
            } => {
                let value_to_check = self.get_register(value)?;
                let collection_value = self.get_register(collection)?;

                let result = match *collection_value {
                    Value::Set(ref set_elements) => {
                        Value::Bool(set_elements.contains(value_to_check))
                    }
                    Value::Array(ref array_items) => {
                        Value::Bool(array_items.contains(value_to_check))
                    }
                    Value::Object(ref object_fields) => Value::Bool(
                        object_fields.contains_key(value_to_check)
                            || object_fields.values().any(|v| v == value_to_check),
                    ),
                    _ => Value::Bool(false),
                };

                self.set_register(dest, result)?;
                #[cfg(feature = "explanations")]
                self.provenance.clear_reg(dest);
                Ok(InstructionOutcome::Continue)
            }
            Count { dest, collection } => {
                let collection_value = self.get_register(collection)?;

                let result = match *collection_value {
                    Value::Array(ref array_items) => Value::from(array_items.len()),
                    Value::Object(ref object_fields) => Value::from(object_fields.len()),
                    Value::Set(ref set_elements) => Value::from(set_elements.len()),
                    _ => Value::Undefined,
                };

                self.set_register(dest, result)?;
                #[cfg(feature = "explanations")]
                self.provenance.clear_reg(dest);
                Ok(InstructionOutcome::Continue)
            }
            other => self.execute_loop_instruction(program, other),
        }
    }

    fn execute_loop_instruction(
        &mut self,
        program: &Program,
        instruction: Instruction,
    ) -> Result<InstructionOutcome> {
        use Instruction::*;
        match instruction {
            LoopStart { params_index } => {
                let loop_params_len = program.instruction_data.loop_params.len();

                let loop_params = program
                    .instruction_data
                    .get_loop_params(params_index)
                    .ok_or(VmError::InvalidLoopParams {
                        index: params_index,
                        pc: self.pc,
                        available: loop_params_len,
                    })?;
                let mode = loop_params.mode;
                let params = LoopParams {
                    collection: loop_params.collection,
                    key_reg: loop_params.key_reg,
                    value_reg: loop_params.value_reg,
                    result_reg: loop_params.result_reg,
                    body_start: loop_params.body_start,
                    loop_end: loop_params.loop_end,
                };
                self.execute_loop_start(&mode, params)?;
                Ok(InstructionOutcome::Continue)
            }
            LoopNext {
                body_start,
                loop_end,
            } => {
                self.execute_loop_next(body_start, loop_end)?;
                Ok(InstructionOutcome::Continue)
            }
            Halt {} => {
                let result = self.get_register(0)?.clone();
                Ok(InstructionOutcome::Return(result))
            }
            other => self.execute_virtual_instruction(program, other),
        }
    }

    fn execute_virtual_instruction(
        &mut self,
        program: &Program,
        instruction: Instruction,
    ) -> Result<InstructionOutcome> {
        use Instruction::*;
        match instruction {
            ChainedIndex { params_index } => {
                let params = program
                    .instruction_data
                    .get_chained_index_params(params_index)
                    .ok_or(VmError::InvalidChainedIndexParams {
                        index: params_index,
                        pc: self.pc,
                        available: program.instruction_data.chained_index_params.len(),
                    })?;

                let mut current_value = self.get_register(params.root)?.clone();

                #[cfg(feature = "explanations")]
                // Start provenance from root, then extend per component
                self.provenance.copy(params.dest, params.root);

                for component in &params.path_components {
                    let key_value = match *component {
                        LiteralOrRegister::Literal(idx) => program
                            .literals
                            .get(usize::from(idx))
                            .ok_or(VmError::LiteralIndexOutOfBounds {
                                index: idx,
                                pc: self.pc,
                            })?
                            .clone(),
                        LiteralOrRegister::Register(reg) => self.get_register(reg)?.clone(),
                    };

                    current_value = current_value[&key_value].clone();

                    #[cfg(feature = "explanations")]
                    {
                        if let Ok(field) = key_value.as_string() {
                            self.provenance
                                .append_field(params.dest, params.dest, field.as_ref());
                        } else {
                            self.provenance
                                .append_index(params.dest, params.dest, &key_value);
                        }
                    }

                    if current_value == Value::Undefined {
                        break;
                    }
                }

                self.set_register(params.dest, current_value)?;
                Ok(InstructionOutcome::Continue)
            }
            VirtualDataDocumentLookup { params_index } => {
                self.execute_virtual_data_document_lookup(params_index)?;
                Ok(InstructionOutcome::Continue)
            }
            ComprehensionBegin { params_index } => {
                let params = program
                    .instruction_data
                    .get_comprehension_begin_params(params_index)
                    .ok_or(VmError::InvalidComprehensionBeginParams {
                        index: params_index,
                        pc: self.pc,
                        available: program.instruction_data.comprehension_begin_params.len(),
                    })?
                    .clone();
                self.execute_comprehension_begin(&params)?;
                Ok(InstructionOutcome::Continue)
            }
            ComprehensionYield { value_reg, key_reg } => {
                self.execute_comprehension_yield(value_reg, key_reg)?;
                Ok(InstructionOutcome::Continue)
            }
            ComprehensionEnd {} => {
                self.execute_comprehension_end()?;
                Ok(InstructionOutcome::Continue)
            }
            unexpected => Err(VmError::UnhandledInstruction {
                instruction: alloc::format!("{:?}", unexpected),
                pc: self.pc,
            }),
        }
    }
}
