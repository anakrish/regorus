// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::rvm::instructions::{Instruction, LiteralOrRegister};
use crate::rvm::program::Program;
use crate::value::Value;
use alloc::collections::BTreeSet;
#[cfg(feature = "explanations")]
use alloc::string::ToString as _;
#[cfg(feature = "explanations")]
use alloc::vec;
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

    #[cfg(feature = "explanations")]
    fn nested_rule_explanation_records_for_assert(
        &self,
        condition: u8,
        outcome: crate::explanations::ExplanationOutcome,
    ) -> Option<Vec<crate::ExplanationRecord>> {
        let expected_outcome = match *self.program.instructions.get(self.pc.checked_sub(1)?)? {
            Instruction::CallRule { dest, .. } if dest == condition => outcome,
            Instruction::Not { dest, operand } if dest == condition => {
                match *self.program.instructions.get(self.pc.checked_sub(2)?)? {
                    Instruction::CallRule {
                        dest: nested_dest, ..
                    } if nested_dest == operand => Self::invert_explanation_outcome(outcome),
                    _ => return None,
                }
            }
            _ => return None,
        };

        let nested_record = self.last_rule_block_records.last()?.clone();
        if nested_record.outcome != expected_outcome {
            return None;
        }

        if self.capture_all_contributing_conditions() {
            Some(self.last_rule_block_records.clone())
        } else {
            Some(vec![nested_record])
        }
    }

    #[cfg(feature = "explanations")]
    fn resolve_condition_probe(
        &self,
        probe: &crate::rvm::program::InstructionConditionProbe,
    ) -> Option<crate::ConditionEvaluation> {
        let raw = match *probe {
            crate::rvm::program::InstructionConditionProbe::Comparison {
                operator,
                actual_register,
                expected_register,
                ref actual_hint,
                ref expected_hint,
            } => crate::explanations::RawConditionEvaluation {
                kind: crate::ConditionEvaluationKind::Comparison,
                operator: Some(operator),
                actual_value: Some(self.get_register(actual_register).ok()?.clone()),
                actual_hint: actual_hint.clone(),
                expected_value: Some(self.get_register(expected_register).ok()?.clone()),
                expected_hint: expected_hint.clone(),
                witness: None,
            },
            crate::rvm::program::InstructionConditionProbe::Membership {
                operator,
                actual_register,
                expected_register,
                ref actual_hint,
                ref expected_hint,
            } => crate::explanations::RawConditionEvaluation {
                kind: crate::ConditionEvaluationKind::Membership,
                operator: Some(operator),
                actual_value: Some(self.get_register(actual_register).ok()?.clone()),
                actual_hint: actual_hint.clone(),
                expected_value: expected_register
                    .and_then(|register| self.get_register(register).ok().cloned()),
                expected_hint: expected_hint.clone(),
                witness: None,
            },
            crate::rvm::program::InstructionConditionProbe::Truthiness { register, ref hint } => {
                let value = self.get_register(register).ok()?.clone();
                crate::explanations::RawConditionEvaluation {
                    kind: crate::ConditionEvaluationKind::Truthiness,
                    operator: Some(match value {
                        Value::Bool(false) | Value::Null | Value::Undefined => {
                            crate::ConditionOperator::Falsy
                        }
                        _ => crate::ConditionOperator::Truthy,
                    }),
                    actual_value: Some(value),
                    actual_hint: hint.clone(),
                    expected_value: None,
                    expected_hint: None,
                    witness: None,
                }
            }
            crate::rvm::program::InstructionConditionProbe::Builtin {
                operator,
                actual_register,
                expected_register,
                ref actual_hint,
                ref expected_hint,
            } => crate::explanations::RawConditionEvaluation {
                kind: crate::ConditionEvaluationKind::Builtin,
                operator: Some(operator),
                actual_value: Some(self.get_register(actual_register).ok()?.clone()),
                actual_hint: actual_hint.clone(),
                expected_value: expected_register
                    .and_then(|register| self.get_register(register).ok().cloned()),
                expected_hint: expected_hint.clone(),
                witness: None,
            },
            crate::rvm::program::InstructionConditionProbe::Loop {
                result_register,
                operator,
                ref condition_texts,
            } => {
                let mut witness = self.loop_witnesses.get(&result_register).cloned();
                if let Some(ref mut witness) = witness {
                    witness.condition_texts = condition_texts.clone();
                } else if !condition_texts.is_empty() {
                    witness = Some(crate::explanations::RawConditionEvaluationWitness {
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

                crate::explanations::RawConditionEvaluation {
                    kind: crate::ConditionEvaluationKind::Quantifier,
                    operator,
                    actual_value: Some(self.get_register(result_register).ok()?.clone()),
                    actual_hint: None,
                    expected_value: None,
                    expected_hint: None,
                    witness,
                }
            }
            crate::rvm::program::InstructionConditionProbe::Comprehension { result_register } => {
                crate::explanations::RawConditionEvaluation {
                    kind: crate::ConditionEvaluationKind::Comprehension,
                    operator: None,
                    actual_value: Some(self.get_register(result_register).ok()?.clone()),
                    actual_hint: None,
                    expected_value: None,
                    expected_hint: None,
                    witness: self.comprehension_witnesses.get(&result_register).cloned(),
                }
            }
        };

        Some(raw.sanitize(&self.explanation_settings))
    }

    #[cfg(feature = "explanations")]
    fn make_current_instruction_record(
        &self,
        metadata: crate::rvm::program::InstructionExplanationInfo,
        outcome: crate::explanations::ExplanationOutcome,
    ) -> crate::ExplanationRecord {
        let evaluation = metadata
            .probe
            .as_ref()
            .and_then(|probe| self.resolve_condition_probe(probe));

        let location = self
            .program
            .instruction_spans
            .get(self.pc)
            .and_then(|span| span.as_ref())
            .map(|span| crate::SourceLocation {
                file: span
                    .get_source_name(&self.program.sources)
                    .unwrap_or_default()
                    .to_string()
                    .into(),
                row: u32::try_from(span.line).unwrap_or(u32::MAX),
                col: u32::try_from(span.column).unwrap_or(u32::MAX),
            })
            .unwrap_or(crate::SourceLocation {
                file: "".into(),
                row: 0,
                col: 0,
            });

        let bindings = metadata
            .bindings
            .into_iter()
            .filter_map(|binding| {
                self.get_register(binding.register)
                    .ok()
                    .filter(|value| **value != Value::Undefined)
                    .map(|value| {
                        crate::explanations::sanitize_explanation_binding(
                            &binding.name,
                            value,
                            &self.explanation_settings,
                        )
                    })
            })
            .collect::<Vec<_>>();

        crate::ExplanationRecord {
            outcome,
            location,
            text: metadata.text.into(),
            evaluation,
            bindings,
        }
    }

    #[cfg(feature = "explanations")]
    fn record_current_instruction_condition(
        &mut self,
        outcome: crate::explanations::ExplanationOutcome,
    ) -> Result<()> {
        if self.explanations.is_none() {
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

        if let Some(result_register) = metadata.probe.as_ref().and_then(|probe| match probe {
            &crate::rvm::program::InstructionConditionProbe::Loop {
                result_register, ..
            } => Some(result_register),
            _ => None,
        }) {
            let mut records = self
                .loop_records
                .get(&result_register)
                .map(|record_set| match outcome {
                    crate::explanations::ExplanationOutcome::Success => {
                        record_set.passing.clone().unwrap_or_default()
                    }
                    crate::explanations::ExplanationOutcome::Failure => record_set
                        .failing
                        .clone()
                        .or_else(|| record_set.passing.clone())
                        .unwrap_or_default(),
                })
                .unwrap_or_default();
            records.push(self.make_current_instruction_record(metadata, outcome));
            self.current_block_records = records;
            return Ok(());
        }

        if let Some(&Instruction::AssertCondition { condition }) =
            self.program.instructions.get(self.pc)
        {
            if let Some(nested_records) =
                self.nested_rule_explanation_records_for_assert(condition, outcome)
            {
                if self.capture_all_contributing_conditions() {
                    self.current_block_records.extend(nested_records);
                } else {
                    self.current_block_records = nested_records;
                }
                return Ok(());
            }
        }

        let record = self.make_current_instruction_record(metadata, outcome);

        if self.capture_all_contributing_conditions() {
            self.current_block_records.push(record);
        } else {
            self.current_block_records.clear();
            self.current_block_records.push(record);
        }

        Ok(())
    }

    #[cfg(feature = "explanations")]
    pub(super) fn finalize_current_block_records(&mut self) -> Vec<crate::ExplanationRecord> {
        if self.current_block_records.is_empty() {
            return Vec::new();
        }

        let records = mem::take(&mut self.current_block_records);
        self.block_records.extend(records.iter().cloned());
        records
    }

    #[cfg(feature = "explanations")]
    pub(super) fn snapshot_latest_block(&mut self, explanation_key: Value) {
        let latest_block = self.finalize_current_block_records();
        if !latest_block.is_empty() {
            if let Some(explanations) = self.explanations.as_mut() {
                explanations
                    .entry(explanation_key)
                    .or_default()
                    .extend(latest_block);
            }
        }
    }

    #[cfg(feature = "explanations")]
    pub(super) fn snapshot_all_blocks(&mut self, explanation_key: Value) {
        let _ = self.finalize_current_block_records();
        if let Some(explanations) = self.explanations.as_mut() {
            explanations.insert(explanation_key, self.block_records.clone());
        }
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
                Ok(InstructionOutcome::Continue)
            }
            LoadFalse { dest } => {
                self.set_register(dest, Value::Bool(false))?;
                Ok(InstructionOutcome::Continue)
            }
            LoadNull { dest } => {
                self.set_register(dest, Value::Null)?;
                Ok(InstructionOutcome::Continue)
            }
            LoadBool { dest, value } => {
                self.set_register(dest, Value::Bool(value))?;
                Ok(InstructionOutcome::Continue)
            }
            LoadData { dest } => {
                self.set_register(dest, self.data.clone())?;
                Ok(InstructionOutcome::Continue)
            }
            LoadInput { dest } => {
                self.set_register(dest, self.input.clone())?;
                Ok(InstructionOutcome::Continue)
            }
            Move { dest, src } => {
                let value = self.get_register(src)?.clone();
                self.set_register(dest, value)?;
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
                    return Ok(InstructionOutcome::Continue);
                }

                let result = self.add_values(a, b)?;
                self.set_register(dest, result)?;
                Ok(InstructionOutcome::Continue)
            }
            Sub { dest, left, right } => {
                let a = self.get_register(left)?;
                let b = self.get_register(right)?;

                if a == &Value::Undefined || b == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
                    return Ok(InstructionOutcome::Continue);
                }

                let result = self.sub_values(a, b)?;
                self.set_register(dest, result)?;
                Ok(InstructionOutcome::Continue)
            }
            Mul { dest, left, right } => {
                let a = self.get_register(left)?;
                let b = self.get_register(right)?;

                if a == &Value::Undefined || b == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
                    return Ok(InstructionOutcome::Continue);
                }

                let result = self.mul_values(a, b)?;
                self.set_register(dest, result)?;
                Ok(InstructionOutcome::Continue)
            }
            Div { dest, left, right } => {
                let a = self.get_register(left)?;
                let b = self.get_register(right)?;

                if a == &Value::Undefined || b == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
                    return Ok(InstructionOutcome::Continue);
                }

                let result = self.div_values(a, b)?;
                self.set_register(dest, result)?;
                Ok(InstructionOutcome::Continue)
            }
            Mod { dest, left, right } => {
                let a = self.get_register(left)?;
                let b = self.get_register(right)?;

                if a == &Value::Undefined || b == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
                    return Ok(InstructionOutcome::Continue);
                }

                let result = self.mod_values(a, b)?;
                self.set_register(dest, result)?;
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
                    return Ok(InstructionOutcome::Continue);
                }

                self.set_register(dest, Value::Bool(a == b))?;
                Ok(InstructionOutcome::Continue)
            }
            Ne { dest, left, right } => {
                let a = self.get_register(left)?;
                let b = self.get_register(right)?;

                if a == &Value::Undefined || b == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
                    return Ok(InstructionOutcome::Continue);
                }

                self.set_register(dest, Value::Bool(a != b))?;
                Ok(InstructionOutcome::Continue)
            }
            Lt { dest, left, right } => {
                let a = self.get_register(left)?;
                let b = self.get_register(right)?;

                if a == &Value::Undefined || b == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
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
                Ok(InstructionOutcome::Continue)
            }
            Le { dest, left, right } => {
                let a = self.get_register(left)?;
                let b = self.get_register(right)?;

                if a == &Value::Undefined || b == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
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
                Ok(InstructionOutcome::Continue)
            }
            Gt { dest, left, right } => {
                let a = self.get_register(left)?;
                let b = self.get_register(right)?;

                if a == &Value::Undefined || b == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
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
                Ok(InstructionOutcome::Continue)
            }
            Ge { dest, left, right } => {
                let a = self.get_register(left)?;
                let b = self.get_register(right)?;

                if a == &Value::Undefined || b == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
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
                Ok(InstructionOutcome::Continue)
            }
            And { dest, left, right } => {
                let left_value = self.get_register(left)?;
                let right_value = self.get_register(right)?;

                if left_value == &Value::Undefined || right_value == &Value::Undefined {
                    self.set_register(dest, Value::Undefined)?;
                    return Ok(InstructionOutcome::Continue);
                }

                match (self.to_bool(left_value), self.to_bool(right_value)) {
                    (Some(a), Some(b)) => {
                        self.set_register(dest, Value::Bool(a && b))?;
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
                    return Ok(InstructionOutcome::Continue);
                }

                match (self.to_bool(left_value), self.to_bool(right_value)) {
                    (Some(a), Some(b)) => {
                        self.set_register(dest, Value::Bool(a || b))?;
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
                    return Ok(InstructionOutcome::Continue);
                }

                if let Some(value) = self.to_bool(operand_value) {
                    self.set_register(dest, Value::Bool(!value))?;
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
                    let _ = self.finalize_current_block_records();
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
                    let _ = self.finalize_current_block_records();
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

                let mut obj_value = self.get_register(obj)?.clone();

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
                self.set_register(dest, result)?;
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
                Ok(InstructionOutcome::Continue)
            }
            ArrayPush { arr, value } => {
                let value_to_push = self.get_register(value)?.clone();

                let mut arr_value = self.get_register(arr)?.clone();

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
                Ok(InstructionOutcome::Continue)
            }
            SetAdd { set, value } => {
                let value_to_add = self.get_register(value)?.clone();

                let mut set_value = self.get_register(set)?.clone();

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
