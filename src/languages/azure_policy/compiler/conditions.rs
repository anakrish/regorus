// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Constraint / condition / LHS compilation.

use alloc::string::String;
use alloc::vec::Vec;

use anyhow::{anyhow, Result};

#[allow(unused_imports)]
use crate::languages::azure_policy::ast::CountNode;
use crate::languages::azure_policy::ast::{Condition, Constraint, FieldKind, Lhs, OperatorKind};
use crate::rvm::instructions::{LoopMode, LoopStartParams};
use crate::rvm::Instruction;

use super::utils::{split_count_wildcard_path, split_path_without_wildcards};
use super::Compiler;

impl Compiler {
    pub(super) fn compile_constraint(&mut self, constraint: &Constraint) -> Result<u8> {
        match constraint {
            Constraint::AllOf { span, constraints } => self.compile_allof(constraints, span),
            Constraint::AnyOf { span, constraints } => self.compile_anyof(constraints, span),
            Constraint::Not { span, constraint } => {
                let inner = self.compile_constraint(constraint)?;
                self.emit_coalesce_undefined_to_null(inner, span);
                let dest = self.alloc_register()?;
                self.emit(
                    Instruction::PolicyNot {
                        dest,
                        operand: inner,
                    },
                    span,
                );
                Ok(dest)
            }
            Constraint::Condition(condition) => self.compile_condition(condition),
        }
    }

    // -- allOf with short-circuit ------------------------------------------

    fn compile_allof(
        &mut self,
        constraints: &[Constraint],
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        let result_reg = self.alloc_register()?;

        // Track which instruction indices need end_pc patching.
        let mut patch_pcs = Vec::with_capacity(constraints.len().saturating_add(1));

        // Emit AllOfStart — end_pc is a placeholder, patched after all children.
        patch_pcs.push(self.current_pc()?);
        self.emit(
            Instruction::AllOfStart {
                result: result_reg,
                end_pc: 0,
            },
            span,
        );

        for child in constraints {
            let child_reg = self.compile_constraint(child)?;
            self.emit_coalesce_undefined_to_null(child_reg, span);
            // AllOfNext — end_pc is a placeholder.
            patch_pcs.push(self.current_pc()?);
            self.emit(
                Instruction::AllOfNext {
                    check: child_reg,
                    result: result_reg,
                    end_pc: 0,
                },
                span,
            );
        }

        // AllOfEnd — all children passed → set result to true.
        let end_pc = self.current_pc()?;
        self.emit(Instruction::AllOfEnd { result: result_reg }, span);

        // Patch AllOfStart and AllOfNext instructions with the final end_pc.
        self.patch_end_pc(&patch_pcs, end_pc);

        Ok(result_reg)
    }

    // -- anyOf with short-circuit ------------------------------------------

    fn compile_anyof(
        &mut self,
        constraints: &[Constraint],
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        let result_reg = self.alloc_register()?;

        // Track which instruction indices need end_pc patching.
        let mut patch_pcs = Vec::with_capacity(constraints.len().saturating_add(1));

        // Emit AnyOfStart — end_pc is a placeholder, patched after all children.
        patch_pcs.push(self.current_pc()?);
        self.emit(
            Instruction::AnyOfStart {
                result: result_reg,
                end_pc: 0,
            },
            span,
        );

        for child in constraints {
            let child_reg = self.compile_constraint(child)?;
            self.emit_coalesce_undefined_to_null(child_reg, span);
            // AnyOfNext — end_pc is a placeholder.
            patch_pcs.push(self.current_pc()?);
            self.emit(
                Instruction::AnyOfNext {
                    check: child_reg,
                    result: result_reg,
                    end_pc: 0,
                },
                span,
            );
        }

        // AnyOfEnd — no child matched → result stays false.
        let end_pc = self.current_pc()?;
        self.emit(Instruction::AnyOfEnd {}, span);

        // Patch AnyOfStart and AnyOfNext instructions with the final end_pc.
        self.patch_end_pc(&patch_pcs, end_pc);

        Ok(result_reg)
    }

    // -- operator condition compilation ------------------------------------

    pub(super) fn compile_condition(&mut self, condition: &Condition) -> Result<u8> {
        // Record resource type hints from `{ "field": "type", "equals"/"in": ... }` patterns.
        self.record_resource_type_from_condition(condition);

        // Implicit allOf: field with [*] outside count → every element must match.
        if let Some(field_path) = self.has_unbound_wildcard_field(&condition.lhs)? {
            return self.compile_condition_wildcard_allof(&field_path, condition);
        }

        // Count existence optimization: compile `count > 0`, `count == 0`,
        // etc. as a `LoopMode::Any` loop that exits on the first match.
        if let Lhs::Count(count_node) = &condition.lhs {
            if let Some(result) = self.try_compile_count_as_any(count_node, condition)? {
                return Ok(result);
            }
        }

        let lhs = self.compile_lhs(&condition.lhs, &condition.span)?;
        let rhs = self.compile_value_or_expr(&condition.rhs, &condition.span)?;
        self.emit_policy_operator(&condition.operator.kind, lhs, rhs, &condition.operator.span)
    }

    pub(super) fn compile_lhs(&mut self, lhs: &Lhs, span: &crate::lexer::Span) -> Result<u8> {
        match lhs {
            Lhs::Field(field) => self.compile_field_kind(&field.kind, &field.span),
            Lhs::Value { value, .. } => self.compile_value_or_expr(value, span),
            Lhs::Count(count_node) => self.compile_count(count_node),
        }
    }

    /// Emit a native policy operator instruction for the given operator kind.
    fn emit_policy_operator(
        &mut self,
        kind: &OperatorKind,
        left: u8,
        right: u8,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        self.record_operator(kind);
        let dest = self.alloc_register()?;
        let instruction = match kind {
            OperatorKind::Equals => Instruction::PolicyEquals { dest, left, right },
            OperatorKind::NotEquals => Instruction::PolicyNotEquals { dest, left, right },
            OperatorKind::Greater => Instruction::PolicyGreater { dest, left, right },
            OperatorKind::GreaterOrEquals => {
                Instruction::PolicyGreaterOrEquals { dest, left, right }
            }
            OperatorKind::Less => Instruction::PolicyLess { dest, left, right },
            OperatorKind::LessOrEquals => Instruction::PolicyLessOrEquals { dest, left, right },
            OperatorKind::In => Instruction::PolicyIn { dest, left, right },
            OperatorKind::NotIn => Instruction::PolicyNotIn { dest, left, right },
            OperatorKind::Contains => Instruction::PolicyContains { dest, left, right },
            OperatorKind::NotContains => Instruction::PolicyNotContains { dest, left, right },
            OperatorKind::ContainsKey => Instruction::PolicyContainsKey { dest, left, right },
            OperatorKind::NotContainsKey => Instruction::PolicyNotContainsKey { dest, left, right },
            OperatorKind::Like => Instruction::PolicyLike { dest, left, right },
            OperatorKind::NotLike => Instruction::PolicyNotLike { dest, left, right },
            OperatorKind::Match => Instruction::PolicyMatch { dest, left, right },
            OperatorKind::NotMatch => Instruction::PolicyNotMatch { dest, left, right },
            OperatorKind::MatchInsensitively => {
                Instruction::PolicyMatchInsensitively { dest, left, right }
            }
            OperatorKind::NotMatchInsensitively => {
                Instruction::PolicyNotMatchInsensitively { dest, left, right }
            }
            OperatorKind::Exists => Instruction::PolicyExists { dest, left, right },
        };
        self.emit(instruction, span);
        Ok(dest)
    }

    // -- implicit allOf for [*] fields outside count -----------------------

    /// Check whether a condition's LHS is a field with an unbound `[*]`
    /// wildcard (i.e., not inside a count loop that covers this path).
    /// Returns the resolved field path if so.
    fn has_unbound_wildcard_field(&self, lhs: &Lhs) -> Result<Option<String>> {
        let field = match lhs {
            Lhs::Field(field_node) => field_node,
            _ => return Ok(None),
        };

        let path = match &field.kind {
            FieldKind::Alias(alias) => self.resolve_alias_path(alias)?,
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

        self.compile_allof_loop_inner(None, field_path, rhs_reg, condition)
    }

    /// Recursive helper: emit one `Every` loop per `[*]` in the path.
    ///
    /// * `base_reg` — if `Some`, index from this register (recursive calls
    ///   inside a loop body); if `None`, index from `input.resource`.
    /// * `remaining_path` — portion of the field path still to process
    ///   (must contain at least one `[*]`).
    /// * `rhs_reg` — the pre-compiled right-hand operand register.
    fn compile_allof_loop_inner(
        &mut self,
        base_reg: Option<u8>,
        remaining_path: &str,
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
                let inner_result =
                    self.compile_allof_loop_inner(Some(current_reg), s, rhs_reg, condition)?;
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

                let cmp_reg = self.emit_policy_operator(
                    &condition.operator.kind,
                    element_reg,
                    rhs_reg,
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
