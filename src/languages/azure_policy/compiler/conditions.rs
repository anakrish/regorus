// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Constraint / condition / LHS compilation.

use alloc::string::String;
use alloc::string::ToString as _;
use alloc::vec::Vec;

use anyhow::{anyhow, Result};

#[allow(unused_imports)]
use crate::languages::azure_policy::ast::CountNode;
use crate::languages::azure_policy::ast::{Condition, Constraint, FieldKind, Lhs, OperatorKind};
use crate::rvm::instructions::{GuardMode, LogicalBlockMode, LoopMode, LoopStartParams, PolicyOp};
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
                    Instruction::PolicyCondition {
                        dest,
                        left: inner,
                        right: 0,
                        op: PolicyOp::Not,
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

        // Emit LogicalBlockStart(AllOf) — end_pc is a placeholder, patched after all children.
        patch_pcs.push(self.current_pc()?);
        self.emit(
            Instruction::LogicalBlockStart {
                mode: LogicalBlockMode::AllOf,
                result: result_reg,
                end_pc: 0,
            },
            span,
        );

        for child in constraints {
            // Save register counter before compiling child — child's
            // intermediate registers are dead after AllOfNext reads the
            // result, so we reclaim them for the next sibling.
            let saved_counter = self.register_counter;
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
            // Reclaim child's intermediate registers.
            self.restore_register_counter(saved_counter);
        }

        // LogicalBlockEnd(AllOf) — all children passed → set result to true.
        let end_pc = self.current_pc()?;
        self.emit(
            Instruction::LogicalBlockEnd {
                mode: LogicalBlockMode::AllOf,
                result: result_reg,
            },
            span,
        );

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

        // Emit LogicalBlockStart(AnyOf) — end_pc is a placeholder, patched after all children.
        patch_pcs.push(self.current_pc()?);
        self.emit(
            Instruction::LogicalBlockStart {
                mode: LogicalBlockMode::AnyOf,
                result: result_reg,
                end_pc: 0,
            },
            span,
        );

        for child in constraints {
            // Save register counter before compiling child — child's
            // intermediate registers are dead after AnyOfNext reads the
            // result, so we reclaim them for the next sibling.
            let saved_counter = self.register_counter;
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
            // Reclaim child's intermediate registers.
            self.restore_register_counter(saved_counter);
        }

        // LogicalBlockEnd(AnyOf) — no child matched → result stays false.
        let end_pc = self.current_pc()?;
        self.emit(
            Instruction::LogicalBlockEnd {
                mode: LogicalBlockMode::AnyOf,
                result: result_reg,
            },
            span,
        );

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

        // Inner unbound [*] within count where clause: the outer [*] is
        // bound by count, but the inner [*] still needs implicit allOf.
        // Example: `properties.ParentArray[*].NestedArray[*].Prop` inside
        // a count iterating over `ParentArray[*]`.
        if let Some((binding, inner_path)) =
            self.has_inner_unbound_wildcard_field(&condition.lhs)?
        {
            let span = &condition.span;
            let rhs_reg = self.compile_value_or_expr(&condition.rhs, span)?;
            return self.compile_allof_loop_inner(
                Some(binding.current_reg),
                &inner_path,
                rhs_reg,
                condition,
            );
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
        let op_result = self.emit_policy_operator(
            &condition.operator.kind,
            lhs,
            rhs,
            &condition.operator.span,
        )?;

        // For `value:` conditions, guard against undefined LHS.
        //
        // When the ARM template expression in a `value:` condition resolves to
        // Undefined (because an intermediate property in a dot-chain doesn't
        // exist), the condition must evaluate to `false` regardless of the
        // operator.  This differs from `field:` conditions where each operator
        // has its own undefined semantics (e.g. `notEquals` returns true when
        // the field is absent).
        //
        // The guard is emitted for ALL value conditions.  For operators that
        // already return false on Undefined (equals, greater, etc.) it is a
        // harmless no-op.  For "negated" operators (notEquals, notContains,
        // etc.) it corrects their behaviour.
        if matches!(condition.lhs, Lhs::Value { .. }) {
            let guarded = self.alloc_register()?;
            self.emit(
                Instruction::PolicyCondition {
                    dest: guarded,
                    left: lhs,
                    right: op_result,
                    op: PolicyOp::ValueConditionGuard,
                },
                &condition.span,
            );
            return Ok(guarded);
        }

        Ok(op_result)
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
        let op = match kind {
            OperatorKind::Equals => PolicyOp::Equals,
            OperatorKind::NotEquals => PolicyOp::NotEquals,
            OperatorKind::Greater => PolicyOp::Greater,
            OperatorKind::GreaterOrEquals => PolicyOp::GreaterOrEquals,
            OperatorKind::Less => PolicyOp::Less,
            OperatorKind::LessOrEquals => PolicyOp::LessOrEquals,
            OperatorKind::In => PolicyOp::In,
            OperatorKind::NotIn => PolicyOp::NotIn,
            OperatorKind::Contains => PolicyOp::Contains,
            OperatorKind::NotContains => PolicyOp::NotContains,
            OperatorKind::ContainsKey => PolicyOp::ContainsKey,
            OperatorKind::NotContainsKey => PolicyOp::NotContainsKey,
            OperatorKind::Like => PolicyOp::Like,
            OperatorKind::NotLike => PolicyOp::NotLike,
            OperatorKind::Match => PolicyOp::Match,
            OperatorKind::NotMatch => PolicyOp::NotMatch,
            OperatorKind::MatchInsensitively => PolicyOp::MatchInsensitively,
            OperatorKind::NotMatchInsensitively => PolicyOp::NotMatchInsensitively,
            OperatorKind::Exists => PolicyOp::Exists,
        };
        let instruction = Instruction::PolicyCondition {
            dest,
            left,
            right,
            op,
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

    /// Check whether a condition's LHS has an inner unbound `[*]` that lives
    /// *inside* an active count binding.
    ///
    /// For example, `properties.ParentArray[*].NestedArray[*].Prop` inside a
    /// count over `ParentArray[*]` — the outer `[*]` is bound by count, but
    /// the inner `NestedArray[*]` is unbound and needs implicit allOf.
    ///
    /// Returns `(CountBinding, inner_suffix)` where `inner_suffix` is the
    /// path *after* the bound `prefix[*].` (e.g. `nestedarray[*].prop`).
    fn has_inner_unbound_wildcard_field(
        &self,
        lhs: &Lhs,
    ) -> Result<Option<(super::CountBinding, String)>> {
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

        let binding = match self.resolve_count_binding(&path)? {
            Some(b) => b,
            None => return Ok(None),
        };

        if let Some(prefix) = &binding.field_wildcard_prefix {
            // The count binding covers `prefix[*]`.
            // bound_len covers "prefix[*]." (including the trailing dot).
            let bound_len = prefix.len() + 4; // len("prefix") + len("[*].")
            if path.len() > bound_len {
                let remainder = &path[bound_len..];
                if remainder.contains("[*]") {
                    return Ok(Some((binding, remainder.to_string())));
                }
            }
        }

        Ok(None)
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
                    Instruction::Guard {
                        register: inner_result,
                        mode: GuardMode::Condition,
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

                // NOTE: No coalesce here. Undefined / Null distinction is
                // preserved so that policy operators handle missing sub-fields
                // correctly.

                let cmp_reg = self.emit_policy_operator(
                    &condition.operator.kind,
                    element_reg,
                    rhs_reg,
                    &condition.operator.span,
                )?;

                self.emit(
                    Instruction::Guard {
                        register: cmp_reg,
                        mode: GuardMode::Condition,
                    },
                    span,
                );
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
