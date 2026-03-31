// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `count` / `count.where` compilation and count-binding resolution.

use alloc::format;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

use anyhow::{anyhow, bail, Result};

use crate::languages::azure_policy::ast::{
    Condition, Constraint, CountNode, FieldKind, JsonValue, OperatorKind, ValueOrExpr,
};
use crate::rvm::instructions::{GuardMode, LoopMode, LoopStartParams, PolicyOp};
use crate::rvm::Instruction;
use crate::Value;

use super::utils::{split_count_wildcard_path, split_path_without_wildcards};
use super::{Compiler, CountBinding};

impl Compiler {
    pub(super) fn compile_count(&mut self, count_node: &CountNode) -> Result<u8> {
        self.observed_uses_count = true;
        match count_node {
            CountNode::Value {
                span,
                value,
                name,
                where_,
            } => {
                let collection_reg = self.compile_value_or_expr(value, span)?;
                self.compile_count_loop(
                    collection_reg,
                    name.as_ref().map(|n| n.name.clone()),
                    None,
                    where_.as_deref(),
                    span,
                )
            }
            CountNode::Field {
                span,
                field,
                where_,
            } => {
                let field_path = self.extract_field_count_path(field)?;
                let (_prefix, suffix) = split_count_wildcard_path(&field_path)?;

                // Multi-level wildcard (e.g. `A[*].B[*]`) → emit nested loops.
                // If an outer count binding covers part of the path, start
                // from the bound element instead of the resource root.
                if suffix.as_ref().is_some_and(|s| s.contains("[*]")) {
                    if let Some(binding) = self.resolve_count_binding(&field_path)? {
                        if let Some(outer_prefix) = &binding.field_wildcard_prefix {
                            let strip_len = outer_prefix.len() + 4; // prefix + "[*]."
                            if field_path.len() > strip_len {
                                let inner_path = &field_path[strip_len..];
                                return self.compile_count_nested(
                                    Some(binding.current_reg),
                                    inner_path,
                                    where_.as_deref(),
                                    outer_prefix,
                                    span,
                                );
                            }
                        }
                    }
                    return self.compile_count_nested(
                        None,
                        &field_path,
                        where_.as_deref(),
                        "",
                        span,
                    );
                }

                // Single wildcard → existing path via resolve + single count loop.
                let (collection_reg, prefix) = self.resolve_count_field_collection(field, span)?;
                self.compile_count_loop(collection_reg, None, Some(prefix), where_.as_deref(), span)
            }
        }
    }

    /// Resolve the collection register and wildcard prefix for a field-based
    /// count node, handling nested count bindings.
    fn resolve_count_field_collection(
        &mut self,
        field: &crate::languages::azure_policy::ast::FieldNode,
        span: &crate::lexer::Span,
    ) -> Result<(u8, String)> {
        let field_path = self.extract_field_count_path(field)?;
        let (collection_prefix, suffix) = split_count_wildcard_path(&field_path)?;

        // Check if this field path is relative to an outer count binding.
        if let Some(binding) = self.resolve_count_binding(&field_path)? {
            if let Some(outer_prefix) = &binding.field_wildcard_prefix {
                let strip_len = outer_prefix.len() + 4; // prefix + "[*]."
                if field_path.len() > strip_len {
                    let inner_path = &field_path[strip_len..];
                    let (inner_collection, _) = split_count_wildcard_path(inner_path)?;
                    let parts = split_path_without_wildcards(&inner_collection)?;
                    let refs = parts.iter().map(String::as_str).collect::<Vec<_>>();
                    let collection_reg =
                        self.emit_chained_index_literal_path(binding.current_reg, &refs, span)?;
                    let inner_prefix = format!("{}[*].{}", outer_prefix, inner_collection);
                    return Ok((collection_reg, inner_prefix));
                }
            }
        }

        // Multi-level wildcard: now handled by compile_count_nested in compile_count.
        // (Single-wildcard paths fall through to here.)
        if suffix.as_ref().is_some_and(|s| s.contains("[*]")) {
            bail!(
                "multi-wildcard path should have been handled before resolve_count_field_collection: {}",
                field_path
            );
        }

        let collection_reg = self.compile_resource_path_value(&collection_prefix, span)?;
        Ok((collection_reg, collection_prefix))
    }

    /// Compile a multi-wildcard count path as nested loops.
    ///
    /// Each intermediate `[*]` level emits a `ForEach` loop that accumulates
    /// the inner count.  The innermost `[*]` emits the real count loop with
    /// the where clause and binding.
    ///
    /// * `base_reg` — `None` for resource root, `Some` when inside an outer loop.
    /// * `remaining_path` — the portion of the field path still to process;
    ///   must contain at least one `[*]`.
    /// * `where_clause` — the optional where constraint (applied only at the
    ///   innermost level).
    /// * `accumulated_prefix` — the path prefix accumulated from outer levels,
    ///   used to build binding prefixes.
    fn compile_count_nested(
        &mut self,
        base_reg: Option<u8>,
        remaining_path: &str,
        where_clause: Option<&Constraint>,
        accumulated_prefix: &str,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        let (collection_part, suffix) = split_count_wildcard_path(remaining_path)?;
        let has_more_wildcards = suffix.as_ref().is_some_and(|s| s.contains("[*]"));

        // Build the binding prefix for this level.
        let binding_prefix = if accumulated_prefix.is_empty() {
            collection_part.clone()
        } else {
            format!("{}[*].{}", accumulated_prefix, collection_part)
        };

        // Lowercase the collection path to match normalized resource keys.
        let collection_lower = collection_part.to_lowercase();

        // Navigate to the collection.
        let collection_reg = match base_reg {
            Some(base) if collection_lower.is_empty() => base,
            Some(base) => {
                let parts = split_path_without_wildcards(&collection_lower)?;
                let refs = parts.iter().map(String::as_str).collect::<Vec<_>>();
                self.emit_chained_index_literal_path(base, &refs, span)?
            }
            None if collection_lower.is_empty() => self.compile_resource_root(span)?,
            None => self.compile_resource_path_value(&collection_lower, span)?,
        };

        if !has_more_wildcards {
            // Innermost wildcard → delegate to the regular count loop.
            // Optimization: if no where clause, just emit Count instruction.
            if where_clause.is_none() {
                let dest = self.alloc_register()?;
                self.emit(
                    Instruction::Count {
                        dest,
                        collection: collection_reg,
                    },
                    span,
                );
                return Ok(dest);
            }
            return self.compile_count_loop(
                collection_reg,
                None,
                Some(binding_prefix),
                where_clause,
                span,
            );
        }

        // Intermediate wildcard → ForEach loop that accumulates inner counts.
        let count_reg = self.load_literal(Value::from(0_i64), span)?;
        let key_reg = self.alloc_register()?;
        let current_reg = self.alloc_register()?;
        let loop_result_reg = self.alloc_register()?;

        let params_index = self.program.add_loop_params(LoopStartParams {
            mode: LoopMode::ForEach,
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

        // Push binding for this level so inner where-clause field references
        // can resolve through this wildcard level.
        self.count_bindings.push(CountBinding {
            name: None,
            field_wildcard_prefix: Some(binding_prefix.clone()),
            current_reg,
        });

        // Recurse for the inner level(s).
        let suffix_ref = suffix
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("suffix should be Some for nested count"))?;
        let inner_count = self.compile_count_nested(
            Some(current_reg),
            suffix_ref,
            where_clause,
            &binding_prefix,
            span,
        )?;

        // Accumulate inner count into outer count.
        self.emit(
            Instruction::Add {
                dest: count_reg,
                left: count_reg,
                right: inner_count,
            },
            span,
        );

        self.count_bindings.pop();

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

        Ok(count_reg)
    }

    /// Compile a multi-wildcard count path as nested `Any` loops for the
    /// `count > 0` / `count == 0` existence-pattern optimization.
    ///
    /// Each intermediate `[*]` level emits an `Any` loop whose body is the
    /// next level.  The innermost `[*]` emits `compile_count_any_loop` with
    /// the where clause.  If `exists` is false the result is negated.
    fn compile_count_nested_any(
        &mut self,
        base_reg: Option<u8>,
        remaining_path: &str,
        where_clause: &Constraint,
        accumulated_prefix: &str,
        exists: bool,
        span: &crate::lexer::Span,
    ) -> Result<Option<u8>> {
        let (collection_part, suffix) = split_count_wildcard_path(remaining_path)?;
        let has_more_wildcards = suffix.as_ref().is_some_and(|s| s.contains("[*]"));

        let binding_prefix = if accumulated_prefix.is_empty() {
            collection_part.clone()
        } else {
            format!("{}[*].{}", accumulated_prefix, collection_part)
        };

        // Lowercase the collection path to match normalized resource keys.
        let collection_lower = collection_part.to_lowercase();

        // Navigate to the collection.
        let collection_reg = match base_reg {
            Some(base) if collection_lower.is_empty() => base,
            Some(base) => {
                let parts = split_path_without_wildcards(&collection_lower)?;
                let refs = parts.iter().map(String::as_str).collect::<Vec<_>>();
                self.emit_chained_index_literal_path(base, &refs, span)?
            }
            None if collection_lower.is_empty() => self.compile_resource_root(span)?,
            None => self.compile_resource_path_value(&collection_lower, span)?,
        };

        if !has_more_wildcards {
            // Innermost wildcard → regular Any loop.
            let any_result = self.compile_count_any_loop(
                collection_reg,
                None,
                Some(binding_prefix),
                where_clause,
                span,
            )?;
            return if exists {
                Ok(Some(any_result))
            } else {
                let dest = self.alloc_register()?;
                self.emit(
                    Instruction::PolicyCondition {
                        dest,
                        left: any_result,
                        right: 0,
                        op: PolicyOp::Not,
                    },
                    span,
                );
                Ok(Some(dest))
            };
        }

        // Intermediate wildcard → Any loop wrapping inner nested Any.
        let key_reg = self.alloc_register()?;
        let current_reg = self.alloc_register()?;
        let result_reg = self.alloc_register()?;

        let params_index = self.program.add_loop_params(LoopStartParams {
            mode: LoopMode::Any,
            collection: collection_reg,
            key_reg,
            value_reg: current_reg,
            result_reg,
            body_start: 0,
            loop_end: 0,
        });

        self.emit(Instruction::LoopStart { params_index }, span);

        let body_start = u16::try_from(self.program.instructions.len())
            .map_err(|_| anyhow!("instruction index overflow"))?;

        // Push binding for this level.
        self.count_bindings.push(CountBinding {
            name: None,
            field_wildcard_prefix: Some(binding_prefix.clone()),
            current_reg,
        });

        // Recurse — the inner call returns Some(result_reg) with the final
        // negation already applied at the innermost level.  For the outer
        // Any loop, we need "any inner satisfies" so we pass `exists = true`
        // here and handle the overall negation at the end.
        let suffix_ref = suffix
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("suffix should be Some for nested any"))?;
        let inner = self
            .compile_count_nested_any(
                Some(current_reg),
                suffix_ref,
                where_clause,
                &binding_prefix,
                /* exists */ true,
                span,
            )?
            .ok_or_else(|| anyhow::anyhow!("nested any should always return Some"))?;

        // The outer Any body succeeds when the inner Any returned true.
        self.emit(
            Instruction::Guard {
                register: inner,
                mode: GuardMode::Condition,
            },
            span,
        );

        self.count_bindings.pop();

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

        // If !exists (count == 0), negate the Any result.
        if exists {
            Ok(Some(result_reg))
        } else {
            let dest = self.alloc_register()?;
            self.emit(
                Instruction::PolicyCondition {
                    dest,
                    left: result_reg,
                    right: 0,
                    op: PolicyOp::Not,
                },
                span,
            );
            Ok(Some(dest))
        }
    }

    fn extract_field_count_path(
        &self,
        field: &crate::languages::azure_policy::ast::FieldNode,
    ) -> Result<String> {
        match &field.kind {
            FieldKind::Type => Ok("type".to_string()),
            FieldKind::Id => Ok("id".to_string()),
            FieldKind::Kind => Ok("kind".to_string()),
            FieldKind::Name => Ok("name".to_string()),
            FieldKind::Location => Ok("location".to_string()),
            FieldKind::FullName => Ok("fullName".to_string()),
            FieldKind::IdentityType => Ok("identity.type".to_string()),
            FieldKind::IdentityField(subpath) => {
                Ok(format!("identity.{}", subpath.to_ascii_lowercase()))
            }
            FieldKind::ApiVersion => Ok("apiVersion".to_string()),
            FieldKind::Tags => Ok("tags".to_string()),
            FieldKind::Tag(tag) => Ok(format!("tags.{}", tag)),
            FieldKind::Alias(path) => self.resolve_alias_path(path),
            FieldKind::Expr(_) => {
                bail!("count over expression field is not supported in core subset")
            }
        }
    }

    fn compile_count_loop(
        &mut self,
        collection_reg: u8,
        binding_name: Option<String>,
        field_wildcard_prefix: Option<String>,
        where_constraint: Option<&Constraint>,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        let count_reg = self.load_literal(Value::from(0_i64), span)?;
        // Hoist the increment constant above the loop.
        let one_reg = self.load_literal(Value::from(1_i64), span)?;
        let key_reg = self.alloc_register()?;
        let current_reg = self.alloc_register()?;
        let loop_result_reg = self.alloc_register()?;

        let params_index = self.program.add_loop_params(LoopStartParams {
            mode: LoopMode::ForEach,
            collection: collection_reg,
            key_reg,
            value_reg: current_reg,
            result_reg: loop_result_reg,
            body_start: 0,
            loop_end: 0,
        });

        self.emit(Instruction::LoopStart { params_index }, span);

        let body_start_u16 = u16::try_from(self.program.instructions.len())
            .map_err(|_| anyhow!("instruction index overflow"))?;

        self.count_bindings.push(CountBinding {
            name: binding_name,
            field_wildcard_prefix,
            current_reg,
        });

        // Compile where clause body (if present) as a conditional increment.
        if let Some(where_clause) = where_constraint {
            let where_reg = self.compile_constraint(where_clause)?;
            self.emit(
                Instruction::Guard {
                    register: where_reg,
                    mode: GuardMode::Condition,
                },
                span,
            );
        }

        self.emit(
            Instruction::Add {
                dest: count_reg,
                left: count_reg,
                right: one_reg,
            },
            span,
        );

        self.count_bindings.pop();

        self.emit(
            Instruction::LoopNext {
                body_start: body_start_u16,
                loop_end: 0,
            },
            span,
        );

        let loop_end_u16 = u16::try_from(self.program.instructions.len())
            .map_err(|_| anyhow!("instruction index overflow"))?;

        self.program.update_loop_params(params_index, |params| {
            params.body_start = body_start_u16;
            params.loop_end = loop_end_u16;
        });

        if let Some(Instruction::LoopNext { loop_end, .. }) = self.program.instructions.last_mut() {
            *loop_end = loop_end_u16;
        }

        Ok(count_reg)
    }

    // -- count existence optimization (Any mode) ---------------------------

    /// Try to compile a count condition as a `LoopMode::Any` loop when the
    /// operator + RHS form an existence check (e.g., `count > 0`).
    ///
    /// Returns `Some(result_reg)` if optimized, `None` to fall back to the
    /// generic count + compare path.
    pub(super) fn try_compile_count_as_any(
        &mut self,
        count_node: &CountNode,
        condition: &Condition,
    ) -> Result<Option<u8>> {
        // Extract the where clause — without one, the Count-instruction fast
        // path in compile_count_loop already handles all operators.
        let where_constraint = match count_node {
            CountNode::Field {
                where_: Some(w), ..
            }
            | CountNode::Value {
                where_: Some(w), ..
            } => w.as_ref(),
            _ => return Ok(None),
        };

        // Determine whether the operator+RHS is an existence pattern.
        let exists = match Self::classify_existence_pattern(condition) {
            Some(e) => e,
            None => return Ok(None),
        };

        self.observed_uses_count = true;

        // Resolve collection and compile as Any loop.
        let any_result = match count_node {
            CountNode::Value {
                span, value, name, ..
            } => {
                let collection_reg = self.compile_value_or_expr(value, span)?;
                self.compile_count_any_loop(
                    collection_reg,
                    name.as_ref().map(|n| n.name.clone()),
                    None,
                    where_constraint,
                    span,
                )?
            }
            CountNode::Field { span, field, .. } => {
                // Multi-wildcard field paths use nested Any loops.
                // Resolve outer bindings so we start from the bound element.
                let field_path = self.extract_field_count_path(field)?;
                let (_, suffix) = split_count_wildcard_path(&field_path)?;
                if suffix.as_ref().is_some_and(|s| s.contains("[*]")) {
                    if let Some(binding) = self.resolve_count_binding(&field_path)? {
                        if let Some(outer_prefix) = &binding.field_wildcard_prefix {
                            let strip_len = outer_prefix.len() + 4;
                            if field_path.len() > strip_len {
                                let inner_path = &field_path[strip_len..];
                                return self.compile_count_nested_any(
                                    Some(binding.current_reg),
                                    inner_path,
                                    where_constraint,
                                    outer_prefix,
                                    exists,
                                    span,
                                );
                            }
                        }
                    }
                    return self.compile_count_nested_any(
                        None,
                        &field_path,
                        where_constraint,
                        "",
                        exists,
                        span,
                    );
                }

                let (collection_reg, prefix) = self.resolve_count_field_collection(field, span)?;
                self.compile_count_any_loop(
                    collection_reg,
                    None,
                    Some(prefix),
                    where_constraint,
                    span,
                )?
            }
        };

        if exists {
            Ok(Some(any_result))
        } else {
            let dest = self.alloc_register()?;
            self.emit(
                Instruction::PolicyCondition {
                    dest,
                    left: any_result,
                    right: 0,
                    op: PolicyOp::Not,
                },
                &condition.span,
            );
            Ok(Some(dest))
        }
    }

    /// Check whether a count condition's operator + RHS form an existence
    /// pattern.  Returns `Some(true)` for "at least one" semantics,
    /// `Some(false)` for "none" semantics, or `None` if not applicable.
    fn classify_existence_pattern(condition: &Condition) -> Option<bool> {
        let n = match &condition.rhs {
            ValueOrExpr::Value(JsonValue::Number(_, s)) => s.parse::<i64>().ok()?,
            _ => return None,
        };
        match (&condition.operator.kind, n) {
            (OperatorKind::Greater, 0)
            | (OperatorKind::GreaterOrEquals, 1)
            | (OperatorKind::NotEquals, 0) => Some(true),
            (OperatorKind::Equals, 0)
            | (OperatorKind::Less, 1)
            | (OperatorKind::LessOrEquals, 0) => Some(false),
            _ => None,
        }
    }

    /// Compile a count's where clause as a `LoopMode::Any` loop.
    ///
    /// The result register is `true` if any element satisfies the where
    /// constraint, `false` otherwise.  The loop exits on the first match.
    fn compile_count_any_loop(
        &mut self,
        collection_reg: u8,
        binding_name: Option<String>,
        field_wildcard_prefix: Option<String>,
        where_constraint: &Constraint,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        let key_reg = self.alloc_register()?;
        let current_reg = self.alloc_register()?;
        let result_reg = self.alloc_register()?;

        let params_index = self.program.add_loop_params(LoopStartParams {
            mode: LoopMode::Any,
            collection: collection_reg,
            key_reg,
            value_reg: current_reg,
            result_reg,
            body_start: 0,
            loop_end: 0,
        });

        self.emit(Instruction::LoopStart { params_index }, span);

        let body_start = u16::try_from(self.program.instructions.len())
            .map_err(|_| anyhow!("instruction index overflow"))?;

        self.count_bindings.push(CountBinding {
            name: binding_name,
            field_wildcard_prefix,
            current_reg,
        });

        let where_reg = self.compile_constraint(where_constraint)?;
        self.emit(
            Instruction::Guard {
                register: where_reg,
                mode: GuardMode::Condition,
            },
            span,
        );

        self.count_bindings.pop();

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

        Ok(result_reg)
    }

    pub(super) fn resolve_count_binding(&self, field_path: &str) -> Result<Option<CountBinding>> {
        for binding in self.count_bindings.iter().rev() {
            if let Some(name) = &binding.name {
                if field_path == name {
                    return Ok(Some(binding.clone()));
                }
            }

            if let Some(prefix) = &binding.field_wildcard_prefix {
                let wildcard_prefix = format!("{}[*]", prefix);
                if field_path == prefix
                    || field_path.starts_with(&(prefix.clone() + "."))
                    || field_path == wildcard_prefix
                    || field_path.starts_with(&(wildcard_prefix + "."))
                {
                    return Ok(Some(binding.clone()));
                }
            }
        }

        Ok(None)
    }

    pub(super) fn compile_from_binding(
        &mut self,
        binding: &CountBinding,
        field_path: &str,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        if let Some(name) = &binding.name {
            if field_path == name {
                let dest = self.alloc_register()?;
                self.emit(
                    Instruction::Move {
                        dest,
                        src: binding.current_reg,
                    },
                    span,
                );
                return Ok(dest);
            }
        }

        if let Some(prefix) = &binding.field_wildcard_prefix {
            let wildcard_prefix = format!("{}[*]", prefix);

            if field_path == prefix || field_path == wildcard_prefix {
                let dest = self.alloc_register()?;
                self.emit(
                    Instruction::Move {
                        dest,
                        src: binding.current_reg,
                    },
                    span,
                );
                return Ok(dest);
            }

            if field_path.starts_with(&(prefix.clone() + ".")) {
                let suffix = &field_path[prefix.len().saturating_add(1)..];
                return self.compile_suffix_from_binding(binding.current_reg, suffix, span);
            }

            if field_path.starts_with(&(format!("{}[*].", prefix))) {
                let suffix = &field_path[prefix.len().saturating_add(4)..];
                return self.compile_suffix_from_binding(binding.current_reg, suffix, span);
            }
        }

        bail!(
            "invalid current count binding for field path '{}'",
            field_path
        )
    }

    /// Compile a suffix path from a binding's current register.
    ///
    /// If the suffix contains `[*]` (from a nested count context), only the
    /// portion before the first `[*]` is used for navigation.  The inner
    /// count's loop will handle the iteration.
    fn compile_suffix_from_binding(
        &mut self,
        base_reg: u8,
        suffix: &str,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        // Strip any trailing [*] or [*].suffix — we only navigate to the
        // array itself; the count loop iterates its elements.
        let nav_path = if let Some(idx) = suffix.find("[*]") {
            &suffix[..idx]
        } else {
            suffix
        };
        // Lowercase to match normalizer-lowercased keys.
        let nav_path = nav_path.to_lowercase();
        let parts = split_path_without_wildcards(&nav_path)?;
        let refs = parts.iter().map(String::as_str).collect::<Vec<_>>();
        self.emit_chained_index_literal_path(base_reg, &refs, span)
    }

    pub(super) fn compile_current_reference(
        &mut self,
        key: &str,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        let resolve_for_key = |compiler: &mut Self, candidate: &str| -> Result<Option<u8>> {
            for binding in compiler.count_bindings.iter().rev() {
                if let Some(name) = &binding.name {
                    if candidate == name {
                        let current_reg = binding.current_reg;
                        let dest = compiler.alloc_register()?;
                        compiler.emit(
                            Instruction::Move {
                                dest,
                                src: current_reg,
                            },
                            span,
                        );
                        return Ok(Some(dest));
                    }

                    if candidate.starts_with(&(name.clone() + ".")) {
                        let suffix = &candidate[name.len().saturating_add(1)..];
                        let parts = split_path_without_wildcards(suffix)?;
                        let refs = parts.iter().map(String::as_str).collect::<Vec<_>>();
                        return compiler
                            .emit_chained_index_literal_path(binding.current_reg, &refs, span)
                            .map(Some);
                    }
                }

                if let Some(prefix) = &binding.field_wildcard_prefix {
                    if candidate == prefix || candidate == format!("{}[*]", prefix) {
                        let current_reg = binding.current_reg;
                        let dest = compiler.alloc_register()?;
                        compiler.emit(
                            Instruction::Move {
                                dest,
                                src: current_reg,
                            },
                            span,
                        );
                        return Ok(Some(dest));
                    }

                    if candidate.starts_with(&(prefix.clone() + "[*].")) {
                        let suffix = &candidate[prefix.len().saturating_add(4)..];
                        return compiler
                            .compile_suffix_from_binding(binding.current_reg, suffix, span)
                            .map(Some);
                    }
                }
            }

            Ok(None)
        };

        if let Some(result) = resolve_for_key(self, key)? {
            return Ok(result);
        }

        let normalized_key = self
            .resolve_alias_path(key)
            .unwrap_or_else(|_| key.to_string());
        if normalized_key != key {
            if let Some(result) = resolve_for_key(self, &normalized_key)? {
                return Ok(result);
            }
        }

        bail!(span.error(&format!(
            "current('{}') is used outside an active count scope",
            key
        )))
    }
}
