// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Constraint / condition / LHS compilation.

use alloc::string::String;
use alloc::vec::Vec;

use anyhow::{anyhow, Result};

use crate::languages::azure_policy::ast::{Condition, Constraint, FieldKind, Lhs, OperatorKind};
use crate::rvm::instructions::{LoopMode, LoopStartParams};
use crate::rvm::Instruction;

use super::utils::{split_count_wildcard_path, split_path_without_wildcards};
use super::Compiler;

impl Compiler {
    pub(super) fn compile_constraint(&mut self, constraint: &Constraint) -> Result<u8> {
        match constraint {
            Constraint::AllOf { span, constraints } => {
                let mut regs = Vec::with_capacity(constraints.len());
                for child in constraints {
                    regs.push(self.compile_constraint(child)?);
                }
                self.emit_builtin_call("azure.policy.logic_all", &regs, span)
            }
            Constraint::AnyOf { span, constraints } => {
                let mut regs = Vec::with_capacity(constraints.len());
                for child in constraints {
                    regs.push(self.compile_constraint(child)?);
                }
                self.emit_builtin_call("azure.policy.logic_any", &regs, span)
            }
            Constraint::Not { span, constraint } => {
                let inner = self.compile_constraint(constraint)?;
                self.emit_builtin_call("azure.policy.logic_not", &[inner], span)
            }
            Constraint::Condition(condition) => self.compile_condition(condition),
        }
    }

    pub(super) fn compile_condition(&mut self, condition: &Condition) -> Result<u8> {
        // Implicit allOf: field with [*] outside count → every element must match.
        if let Some(field_path) = self.has_unbound_wildcard_field(&condition.lhs)? {
            return self.compile_condition_wildcard_allof(&field_path, condition);
        }

        if condition.operator.kind == OperatorKind::Exists {
            return self.compile_exists_condition(condition);
        }

        let lhs = self.compile_lhs(&condition.lhs, &condition.span)?;
        let rhs = self.compile_value_or_expr(&condition.rhs, &condition.span)?;
        let builtin = Self::operator_builtin_name(&condition.operator.kind);

        self.emit_builtin_call(builtin, &[lhs, rhs], &condition.operator.span)
    }

    fn compile_exists_condition(&mut self, condition: &Condition) -> Result<u8> {
        let lhs = self.compile_lhs(&condition.lhs, &condition.span)?;
        let rhs = self.compile_value_or_expr(&condition.rhs, &condition.span)?;

        self.emit_builtin_call(
            "azure.policy.op.exists",
            &[lhs, rhs],
            &condition.operator.span,
        )
    }

    pub(super) fn compile_lhs(&mut self, lhs: &Lhs, span: &crate::lexer::Span) -> Result<u8> {
        match lhs {
            Lhs::Field(field) => self.compile_field_kind(&field.kind, &field.span),
            Lhs::Value { value, .. } => self.compile_value_or_expr(value, span),
            Lhs::Count(count_node) => self.compile_count(count_node),
        }
    }

    // -- implicit allOf for [*] fields outside count -----------------------

    /// Map an [`OperatorKind`] to its RVM builtin function name.
    fn operator_builtin_name(kind: &OperatorKind) -> &'static str {
        match kind {
            OperatorKind::Equals => "azure.policy.op.equals",
            OperatorKind::NotEquals => "azure.policy.op.not_equals",
            OperatorKind::Greater => "azure.policy.op.greater",
            OperatorKind::GreaterOrEquals => "azure.policy.op.greater_or_equals",
            OperatorKind::Less => "azure.policy.op.less",
            OperatorKind::LessOrEquals => "azure.policy.op.less_or_equals",
            OperatorKind::In => "azure.policy.op.in",
            OperatorKind::NotIn => "azure.policy.op.not_in",
            OperatorKind::Contains => "azure.policy.op.contains",
            OperatorKind::NotContains => "azure.policy.op.not_contains",
            OperatorKind::ContainsKey => "azure.policy.op.contains_key",
            OperatorKind::NotContainsKey => "azure.policy.op.not_contains_key",
            OperatorKind::Like => "azure.policy.op.like",
            OperatorKind::NotLike => "azure.policy.op.not_like",
            OperatorKind::Match => "azure.policy.op.match",
            OperatorKind::NotMatch => "azure.policy.op.not_match",
            OperatorKind::MatchInsensitively => "azure.policy.op.match_insensitively",
            OperatorKind::NotMatchInsensitively => "azure.policy.op.not_match_insensitively",
            OperatorKind::Exists => "azure.policy.op.exists",
        }
    }

    /// Check whether a condition's LHS is a field with an unbound `[*]`
    /// wildcard (i.e., not inside a count loop that covers this path).
    /// Returns the resolved field path if so.
    fn has_unbound_wildcard_field(&self, lhs: &Lhs) -> Result<Option<String>> {
        let field = match lhs {
            Lhs::Field(field_node) => field_node,
            _ => return Ok(None),
        };

        let path = match &field.kind {
            FieldKind::Alias(alias) => match self.alias_map.get(&alias.to_lowercase()) {
                Some(s) => s.clone(),
                None => alias.clone(),
            },
            _ => return Ok(None),
        };

        if !path.contains("[*]") {
            return Ok(None);
        }

        if self.resolve_count_binding(&path)?.is_some() {
            return Ok(None);
        }

        Ok(Some(path))
    }

    /// Compile a condition where the field LHS contains `[*]` outside a
    /// count loop.
    ///
    /// Azure Policy applies implicit *allOf* semantics: every array element
    /// must satisfy the operator condition.  An empty or missing array
    /// evaluates to `true` (vacuous truth).
    ///
    /// This emits a `LoopMode::Every` loop that applies `AssertCondition`
    /// per element, so the first failing element short-circuits to `false`.
    fn compile_condition_wildcard_allof(
        &mut self,
        field_path: &str,
        condition: &Condition,
    ) -> Result<u8> {
        let span = &condition.span;

        // Compile RHS once, outside the loop.
        let rhs_reg = self.compile_value_or_expr(&condition.rhs, span)?;
        let builtin = Self::operator_builtin_name(&condition.operator.kind);

        self.compile_allof_loop_inner(None, field_path, builtin, rhs_reg, condition)
    }

    /// Recursive helper: emit one `Every` loop per `[*]` in the path.
    ///
    /// * `base_reg` — if `Some`, index from this register (recursive calls
    ///   inside a loop body); if `None`, index from `input.resource`.
    /// * `remaining_path` — portion of the field path still to process
    ///   (must contain at least one `[*]`).
    /// * `operator_builtin` — the RVM builtin name for the operator.
    /// * `rhs_reg` — the pre-compiled right-hand operand register.
    fn compile_allof_loop_inner(
        &mut self,
        base_reg: Option<u8>,
        remaining_path: &str,
        operator_builtin: &str,
        rhs_reg: u8,
        condition: &Condition,
    ) -> Result<u8> {
        let (prefix, suffix) = split_count_wildcard_path(remaining_path)?;
        let span = &condition.span;

        // Navigate to the collection (the array before [*]).
        let collection_reg = match base_reg {
            Some(base) if prefix.is_empty() => base,
            Some(base) => {
                let parts = split_path_without_wildcards(&prefix)?;
                let refs = parts.iter().map(String::as_str).collect::<Vec<_>>();
                self.emit_chained_index_literal_path(base, &refs, span)?
            }
            None if prefix.is_empty() => self.compile_resource_root(span)?,
            None => self.compile_resource_path_value(&prefix, span)?,
        };

        // Every loop — empty/missing collection → true (vacuous truth).
        let key_reg = self.alloc_register()?;
        let current_reg = self.alloc_register()?;
        let loop_result_reg = self.alloc_register()?;

        let params_index = self.program.add_loop_params(LoopStartParams {
            mode: LoopMode::Every,
            collection: collection_reg,
            key_reg,
            value_reg: current_reg,
            result_reg: loop_result_reg,
            body_start: 0,
            loop_end: 0,
        });

        self.emit(Instruction::LoopStart { params_index }, span);

        let body_start = u16::try_from(self.program.instructions.len())
            .map_err(|_| anyhow!("instruction index overflow"))?;

        match suffix {
            Some(ref s) if s.contains("[*]") => {
                // Nested wildcard — recurse for an inner Every loop.
                let inner_result = self.compile_allof_loop_inner(
                    Some(current_reg),
                    s,
                    operator_builtin,
                    rhs_reg,
                    condition,
                )?;
                self.emit(
                    Instruction::AssertCondition {
                        condition: inner_result,
                    },
                    span,
                );
            }
            _ => {
                // Leaf: extract element value, compare, and assert.
                let element_reg = match &suffix {
                    Some(s) => {
                        let parts = split_path_without_wildcards(s)?;
                        let refs = parts.iter().map(String::as_str).collect::<Vec<_>>();
                        self.emit_chained_index_literal_path(current_reg, &refs, span)?
                    }
                    None => current_reg,
                };

                // Missing sub-field → null (same as compile_field_kind).
                self.emit_coalesce_undefined_to_null(element_reg, span);

                let cmp_reg = self.emit_builtin_call(
                    operator_builtin,
                    &[element_reg, rhs_reg],
                    &condition.operator.span,
                )?;

                self.emit(Instruction::AssertCondition { condition: cmp_reg }, span);
            }
        }

        self.emit(
            Instruction::LoopNext {
                body_start,
                loop_end: 0,
            },
            span,
        );

        let loop_end = u16::try_from(self.program.instructions.len())
            .map_err(|_| anyhow!("instruction index overflow"))?;

        self.program.update_loop_params(params_index, |params| {
            params.body_start = body_start;
            params.loop_end = loop_end;
        });

        if let Some(Instruction::LoopNext { loop_end: le, .. }) =
            self.program.instructions.last_mut()
        {
            *le = loop_end;
        }

        Ok(loop_result_reg)
    }
}
