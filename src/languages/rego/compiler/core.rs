// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::as_conversions,
    clippy::unused_trait_names
)]

use super::{CompilationContext, Compiler, CompilerError, Register, Result, Scope};
#[cfg(feature = "explanations")]
use crate::ast::Expr;
use crate::ast::ExprRef;
use crate::builtins;
use crate::compiler::destructuring_planner::plans::BindingPlan;
use crate::lexer::Span;
use crate::rvm::program::{BuiltinInfo, SpanInfo};
#[cfg(feature = "explanations")]
use crate::rvm::program::{
    ExplanationBindingInfo, InstructionConditionProbe, InstructionExplanationInfo,
};
use crate::rvm::Instruction;
use crate::Value;
#[cfg(feature = "explanations")]
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};

impl<'a> Compiler<'a> {
    /// Check if a function path is a builtin function (similar to interpreter's is_builtin)
    pub(super) fn is_builtin(&self, path: &str) -> bool {
        path == "print" || builtins::BUILTINS.contains_key(path)
    }

    /// Check if a function path is a user-defined function rule
    pub(super) fn is_user_defined_function(&self, rule_path: &str) -> bool {
        self.policy.inner.rules.contains_key(rule_path)
    }

    /// Get builtin index for a builtin function
    pub(super) fn get_builtin_index(&mut self, builtin_name: &str) -> Result<u16> {
        if !self.is_builtin(builtin_name) {
            return Err(CompilerError::NotBuiltinFunction {
                name: builtin_name.to_string(),
            }
            .into());
        }

        // Check if we already have an index for this builtin
        if let Some(&index) = self.builtin_index_map.get(builtin_name) {
            return Ok(index);
        }

        // Get the builtin function info to determine number of arguments
        let num_args = if builtin_name == "print" {
            2 // Special case for print
        } else if let Some(builtin_fcn) = builtins::BUILTINS.get(builtin_name) {
            builtin_fcn.1 as u16 // Second element is the number of arguments
        } else {
            return Err(CompilerError::UnknownBuiltinFunction {
                name: builtin_name.to_string(),
            }
            .into());
        };

        // Create builtin info and add it to the program
        let builtin_info = BuiltinInfo {
            name: builtin_name.to_string(),
            num_args,
        };
        let index = self.program.add_builtin_info(builtin_info);

        // Store in our mapping
        self.builtin_index_map
            .insert(builtin_name.to_string(), index);

        Ok(index)
    }

    pub fn alloc_register(&mut self) -> Register {
        // Assert that we don't exceed 256 registers (u8::MAX + 1)
        assert!(
            self.register_counter < 255,
            "Register overflow: attempted to allocate register {}, but maximum is 255. \
			 Consider using register windowing or spill handling.",
            self.register_counter
        );

        let reg = self.register_counter;
        self.register_counter += 1;

        reg
    }

    /// Add a literal value to the literal table, returning its index
    pub fn add_literal(&mut self, value: Value) -> u16 {
        // Check if literal already exists to avoid duplication
        // TODO: Optimize lookup
        for (idx, existing) in self.program.literals.iter().enumerate() {
            if existing == &value {
                return idx as u16;
            }
        }

        let idx = self.program.literals.len() as u16;
        self.program.literals.push(value);
        idx
    }

    /// Push a new variable scope (like the interpreter)
    pub fn push_scope(&mut self) {
        self.scopes.push(Scope::default());
    }

    /// Pop the current variable scope (like the interpreter)
    pub fn pop_scope(&mut self) {
        if self.scopes.len() > 1 {
            self.scopes.pop();
        }
    }

    /// Reset input/data registers for a new rule definition
    /// This ensures input and data are loaded only once per rule definition
    pub fn reset_rule_definition_registers(&mut self) {
        self.current_input_register = None;
        self.current_data_register = None;
    }

    /// Push a new compilation context onto the context stack
    pub fn push_context(&mut self, context: CompilationContext) {
        self.context_stack.push(context);
    }

    /// Pop the current compilation context from the context stack
    pub fn pop_context(&mut self) -> Option<CompilationContext> {
        // Don't pop the last context (default RegularRule)
        if self.context_stack.len() > 1 {
            self.context_stack.pop()
        } else {
            None
        }
    }

    /// Get the current scope mutably
    fn current_scope_mut(&mut self) -> &mut Scope {
        self.scopes.last_mut().expect("No active scope")
    }

    /// Add a variable to the current scope (like interpreter's add_variable)
    pub fn add_variable(&mut self, var_name: &str, register: Register) {
        if var_name != "_" {
            // Don't store anonymous variables
            self.current_scope_mut()
                .bound_vars
                .insert(var_name.to_string(), register);
        }
    }

    /// Returns true when a variable is already bound in the innermost scope
    pub fn is_var_bound_in_current_scope(&self, var_name: &str) -> bool {
        self.scopes
            .last()
            .map(|scope| scope.bound_vars.contains_key(var_name))
            .unwrap_or(false)
    }

    /// Look up a variable in all scopes starting from innermost (like interpreter's lookup_local_var)
    pub fn lookup_local_var(&self, var_name: &str) -> Option<Register> {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.bound_vars.get(var_name).copied())
    }

    pub fn add_unbound_variable(&mut self, var_name: &str) {
        self.current_scope_mut()
            .unbound_vars
            .insert(var_name.to_string());
    }

    pub fn is_unbound_var(&self, var_name: &str) -> bool {
        self.lookup_local_var(var_name).is_none()
            && self
                .scopes
                .iter()
                .rev()
                .any(|scope| scope.unbound_vars.contains(var_name))
    }

    pub fn bind_unbound_variable(&mut self, var_name: &str) {
        self.current_scope_mut().unbound_vars.remove(var_name);
    }

    pub(super) fn store_variable(&mut self, var_name: String, register: Register) {
        self.add_variable(&var_name, register);
    }

    /// Look up a variable register (backward compatibility)
    pub(super) fn lookup_variable(&self, var_name: &str) -> Option<Register> {
        self.lookup_local_var(var_name)
    }

    pub(super) fn get_binding_plan_for_expr(&self, expr: &ExprRef) -> Result<Option<BindingPlan>> {
        let module_idx = self.current_module_index;
        let expr_idx = expr.as_ref().eidx();
        self.policy
            .inner
            .loop_hoisting_table
            .get_expr_binding_plan(module_idx, expr_idx)
            .map_err(|err| {
                CompilerError::General {
                    message: format!("loop hoisting table out of bounds: {err}"),
                }
                .at(expr.span())
            })
            .map(|plan: Option<&BindingPlan>| plan.cloned())
    }

    pub(super) fn expect_binding_plan_for_expr(
        &self,
        expr: &ExprRef,
        context: &str,
    ) -> Result<BindingPlan> {
        self.get_binding_plan_for_expr(expr)?.ok_or_else(|| {
            CompilerError::MissingBindingPlan {
                context: context.to_string(),
            }
            .at(expr.span())
        })
    }

    pub(super) fn resolve_variable(&mut self, var_name: &str, span: &Span) -> Result<Register> {
        match var_name {
            "input" => {
                if let Some(register) = self.current_input_register {
                    return Ok(register);
                }

                let dest = self.alloc_register();
                self.emit_instruction(Instruction::LoadInput { dest }, span);
                self.current_input_register = Some(dest);
                return Ok(dest);
            }
            "data" => {
                if let Some(register) = self.current_data_register {
                    return Ok(register);
                }

                let dest = self.alloc_register();
                self.emit_instruction(Instruction::LoadData { dest }, span);
                self.current_data_register = Some(dest);
                return Ok(dest);
            }
            _ => {}
        }

        if let Some(var_reg) = self.lookup_variable(var_name) {
            return Ok(var_reg);
        }

        let rule_path = format!("{}.{}", &self.current_package, var_name);
        let rule_index = self.get_or_assign_rule_index(&rule_path)?;
        let dest = self.alloc_register();

        self.emit_instruction(Instruction::CallRule { dest, rule_index }, span);
        Ok(dest)
    }

    pub fn emit_instruction(&mut self, instruction: Instruction, span: &Span) {
        self.program.instructions.push(instruction);
        #[cfg(feature = "explanations")]
        self.program.instruction_explanations.push(None);

        let source_path = span.source.get_path().to_string();
        let source_index = self.get_or_create_source_index(&source_path);

        self.spans
            .push(SpanInfo::from_lexer_span(span, source_index));
    }

    fn get_or_create_source_index(&mut self, source_path: &str) -> usize {
        if let Some(&index) = self.source_to_index.get(source_path) {
            index
        } else {
            let index = self.source_to_index.len();
            self.source_to_index.insert(source_path.to_string(), index);
            index
        }
    }

    #[cfg(feature = "explanations")]
    fn expr_redaction_hint(expr: &ExprRef) -> Option<String> {
        match *expr.as_ref() {
            Expr::Var {
                value: Value::String(ref name),
                ..
            } => Some(name.as_ref().to_string()),
            Expr::RefDot { ref field, .. } => Some(field.0.text().to_string()),
            Expr::RefBrack { ref index, .. } => match *index.as_ref() {
                Expr::String {
                    value: Value::String(ref name),
                    ..
                } => Some(name.as_ref().to_string()),
                _ => None,
            },
            _ => None,
        }
    }

    #[cfg(feature = "explanations")]
    fn make_builtin_probe(
        &self,
        expr: &ExprRef,
        params_index: u16,
    ) -> Option<InstructionConditionProbe> {
        let Expr::Call { ref params, .. } = *expr.as_ref() else {
            return None;
        };
        let params_info = self
            .program
            .instruction_data
            .get_builtin_call_params(params_index)?;
        let builtin = self
            .program
            .builtin_info_table
            .get(usize::from(params_info.builtin_index))?;
        let mapping = match builtin.name.as_str() {
            "contains" if params_info.arg_count() >= 2 => {
                Some((crate::ConditionOperator::Contains, 0_usize, Some(1_usize)))
            }
            "startswith" if params_info.arg_count() >= 2 => {
                Some((crate::ConditionOperator::StartsWith, 0_usize, Some(1_usize)))
            }
            "endswith" if params_info.arg_count() >= 2 => {
                Some((crate::ConditionOperator::EndsWith, 0_usize, Some(1_usize)))
            }
            "regex.match" if params_info.arg_count() >= 2 => {
                Some((crate::ConditionOperator::RegexMatch, 1_usize, Some(0_usize)))
            }
            "glob.match" if params_info.arg_count() >= 3 => {
                Some((crate::ConditionOperator::GlobMatch, 2_usize, Some(0_usize)))
            }
            "is_array" if params_info.arg_count() >= 1 => {
                Some((crate::ConditionOperator::IsArray, 0_usize, None))
            }
            "is_boolean" if params_info.arg_count() >= 1 => {
                Some((crate::ConditionOperator::IsBoolean, 0_usize, None))
            }
            "is_null" if params_info.arg_count() >= 1 => {
                Some((crate::ConditionOperator::IsNull, 0_usize, None))
            }
            "is_number" if params_info.arg_count() >= 1 => {
                Some((crate::ConditionOperator::IsNumber, 0_usize, None))
            }
            "is_object" if params_info.arg_count() >= 1 => {
                Some((crate::ConditionOperator::IsObject, 0_usize, None))
            }
            "is_set" if params_info.arg_count() >= 1 => {
                Some((crate::ConditionOperator::IsSet, 0_usize, None))
            }
            "is_string" if params_info.arg_count() >= 1 => {
                Some((crate::ConditionOperator::IsString, 0_usize, None))
            }
            _ => None,
        }?;

        let (operator, actual_index, expected_index) = mapping;
        Some(InstructionConditionProbe::Builtin {
            operator,
            actual_register: *params_info.arg_registers().get(actual_index)?,
            expected_register: expected_index
                .and_then(|index| params_info.arg_registers().get(index).copied()),
            actual_hint: params.get(actual_index).and_then(Self::expr_redaction_hint),
            expected_hint: expected_index.and_then(|index| {
                params
                    .get(actual_index)
                    .and_then(Self::expr_redaction_hint)
                    .or_else(|| params.get(index).and_then(Self::expr_redaction_hint))
            }),
        })
    }

    #[cfg(feature = "explanations")]
    fn make_condition_probe(
        &self,
        expr: &ExprRef,
        result_register: Register,
    ) -> Option<InstructionConditionProbe> {
        let previous_instruction = self.program.instructions.iter().rev().nth(1).copied();

        match previous_instruction {
            _ if matches!(
                expr.as_ref(),
                Expr::ArrayCompr { .. } | Expr::SetCompr { .. } | Expr::ObjectCompr { .. }
            ) =>
            {
                Some(InstructionConditionProbe::Comprehension {
                    result_register,
                    condition_texts: alloc::vec::Vec::new(),
                })
            }
            Some(Instruction::Eq { dest, left, right }) if dest == result_register => {
                let Expr::BoolExpr {
                    ref lhs, ref rhs, ..
                } = *expr.as_ref()
                else {
                    return None;
                };
                Some(InstructionConditionProbe::Comparison {
                    operator: crate::ConditionOperator::Equals,
                    actual_register: left,
                    expected_register: right,
                    actual_hint: Self::expr_redaction_hint(lhs),
                    expected_hint: Self::expr_redaction_hint(lhs)
                        .or_else(|| Self::expr_redaction_hint(rhs)),
                })
            }
            Some(Instruction::Ne { dest, left, right }) if dest == result_register => {
                let Expr::BoolExpr {
                    ref lhs, ref rhs, ..
                } = *expr.as_ref()
                else {
                    return None;
                };
                Some(InstructionConditionProbe::Comparison {
                    operator: crate::ConditionOperator::NotEquals,
                    actual_register: left,
                    expected_register: right,
                    actual_hint: Self::expr_redaction_hint(lhs),
                    expected_hint: Self::expr_redaction_hint(lhs)
                        .or_else(|| Self::expr_redaction_hint(rhs)),
                })
            }
            Some(Instruction::Lt { dest, left, right }) if dest == result_register => {
                let Expr::BoolExpr {
                    ref lhs, ref rhs, ..
                } = *expr.as_ref()
                else {
                    return None;
                };
                Some(InstructionConditionProbe::Comparison {
                    operator: crate::ConditionOperator::LessThan,
                    actual_register: left,
                    expected_register: right,
                    actual_hint: Self::expr_redaction_hint(lhs),
                    expected_hint: Self::expr_redaction_hint(lhs)
                        .or_else(|| Self::expr_redaction_hint(rhs)),
                })
            }
            Some(Instruction::Le { dest, left, right }) if dest == result_register => {
                let Expr::BoolExpr {
                    ref lhs, ref rhs, ..
                } = *expr.as_ref()
                else {
                    return None;
                };
                Some(InstructionConditionProbe::Comparison {
                    operator: crate::ConditionOperator::LessThanOrEquals,
                    actual_register: left,
                    expected_register: right,
                    actual_hint: Self::expr_redaction_hint(lhs),
                    expected_hint: Self::expr_redaction_hint(lhs)
                        .or_else(|| Self::expr_redaction_hint(rhs)),
                })
            }
            Some(Instruction::Gt { dest, left, right }) if dest == result_register => {
                let Expr::BoolExpr {
                    ref lhs, ref rhs, ..
                } = *expr.as_ref()
                else {
                    return None;
                };
                Some(InstructionConditionProbe::Comparison {
                    operator: crate::ConditionOperator::GreaterThan,
                    actual_register: left,
                    expected_register: right,
                    actual_hint: Self::expr_redaction_hint(lhs),
                    expected_hint: Self::expr_redaction_hint(lhs)
                        .or_else(|| Self::expr_redaction_hint(rhs)),
                })
            }
            Some(Instruction::Ge { dest, left, right }) if dest == result_register => {
                let Expr::BoolExpr {
                    ref lhs, ref rhs, ..
                } = *expr.as_ref()
                else {
                    return None;
                };
                Some(InstructionConditionProbe::Comparison {
                    operator: crate::ConditionOperator::GreaterThanOrEquals,
                    actual_register: left,
                    expected_register: right,
                    actual_hint: Self::expr_redaction_hint(lhs),
                    expected_hint: Self::expr_redaction_hint(lhs)
                        .or_else(|| Self::expr_redaction_hint(rhs)),
                })
            }
            Some(Instruction::Contains {
                dest,
                collection,
                value,
            }) if dest == result_register => Some(InstructionConditionProbe::Membership {
                operator: crate::ConditionOperator::In,
                actual_register: value,
                expected_register: Some(collection),
                actual_hint: match *expr.as_ref() {
                    Expr::Membership {
                        value: ref member_expr,
                        ..
                    } => Self::expr_redaction_hint(member_expr),
                    _ => None,
                },
                expected_hint: match *expr.as_ref() {
                    Expr::Membership {
                        collection: ref collection_expr,
                        ..
                    } => Self::expr_redaction_hint(collection_expr),
                    _ => None,
                },
            }),
            Some(Instruction::BuiltinCall { params_index }) => {
                self.make_builtin_probe(expr, params_index)
            }
            _ => Some(InstructionConditionProbe::Truthiness {
                register: result_register,
                hint: Self::expr_redaction_hint(expr),
            }),
        }
    }

    #[cfg(feature = "explanations")]
    pub(super) fn attach_explanation_to_last_instruction(
        &mut self,
        text: &str,
        expr: &ExprRef,
        result_register: Register,
    ) {
        let bindings = self
            .scopes
            .iter()
            .fold(
                BTreeMap::<String, Register>::new(),
                |mut visible_bindings, scope| {
                    for (name, register) in &scope.bound_vars {
                        if name != "_" {
                            visible_bindings.insert(name.clone(), *register);
                        }
                    }
                    visible_bindings
                },
            )
            .into_iter()
            .map(|(name, register)| ExplanationBindingInfo { name, register })
            .collect();

        let probe = self.make_condition_probe(expr, result_register);
        if let Some(slot) = self.program.instruction_explanations.last_mut() {
            *slot = Some(InstructionExplanationInfo {
                text: text.to_string(),
                bindings,
                probe,
            });
        }
    }

    #[cfg(feature = "explanations")]
    pub(super) fn attach_explanation_probe_to_last_instruction(
        &mut self,
        text: &str,
        probe: Option<InstructionConditionProbe>,
    ) {
        let bindings = self
            .scopes
            .iter()
            .fold(
                BTreeMap::<String, Register>::new(),
                |mut visible_bindings, scope| {
                    for (name, register) in &scope.bound_vars {
                        if name != "_" {
                            visible_bindings.insert(name.clone(), *register);
                        }
                    }
                    visible_bindings
                },
            )
            .into_iter()
            .map(|(name, register)| ExplanationBindingInfo { name, register })
            .collect();

        if let Some(slot) = self.program.instruction_explanations.last_mut() {
            *slot = Some(InstructionExplanationInfo {
                text: text.to_string(),
                bindings,
                probe,
            });
        }
    }
}
