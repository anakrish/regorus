// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Field-kind and resource-path compilation.

use alloc::format;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

use anyhow::{anyhow, bail, Result};

use crate::languages::azure_policy::ast::{Expr, ExprLiteral, FieldKind};
use crate::rvm::instructions::{LoopMode, LoopStartParams};
use crate::rvm::Instruction;

use super::utils::{split_count_wildcard_path, split_path_without_wildcards};
use super::Compiler;

impl Compiler {
    pub(super) fn compile_field_kind(
        &mut self,
        kind: &FieldKind,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        let reg = match kind {
            FieldKind::Type => {
                self.record_field_kind("type");
                self.compile_resource_path_value("type", span)?
            }
            FieldKind::Id => {
                self.record_field_kind("id");
                self.compile_resource_path_value("id", span)?
            }
            FieldKind::Kind => {
                self.record_field_kind("kind");
                self.compile_resource_path_value("kind", span)?
            }
            FieldKind::Name => {
                self.record_field_kind("name");
                self.compile_resource_path_value("name", span)?
            }
            FieldKind::Location => {
                self.record_field_kind("location");
                self.compile_resource_path_value("location", span)?
            }
            FieldKind::FullName => {
                self.record_field_kind("fullName");
                self.compile_resource_path_value("fullName", span)?
            }
            FieldKind::Tags => {
                self.record_field_kind("tags");
                self.compile_resource_path_value("tags", span)?
            }
            FieldKind::IdentityType => {
                self.record_field_kind("identity.type");
                self.compile_resource_path_value("identity.type", span)?
            }
            FieldKind::IdentityField(ref subpath) => {
                let path = format!("identity.{}", subpath.to_ascii_lowercase());
                self.record_field_kind(&path);
                self.compile_resource_path_value(&path, span)?
            }
            FieldKind::ApiVersion => {
                self.record_field_kind("apiVersion");
                self.compile_resource_path_value("apiVersion", span)?
            }
            FieldKind::Tag(tag) => {
                self.record_field_kind("tags");
                self.record_tag_name(tag);
                // Lowercase tag name to match normalizer's lowercased keys.
                // ARM tag names are case-insensitive and ASCII-only.
                self.compile_resource_path_value(
                    &format!("tags.{}", tag.to_ascii_lowercase()),
                    span,
                )?
            }
            FieldKind::Alias(path) => {
                self.record_alias(path);
                let short = self.resolve_alias_path(path)?;
                self.compile_field_path_expression(&short, span)?
            }
            FieldKind::Expr(expr) => self.compile_dynamic_field_expr(expr, span)?,
        };
        // Azure Policy: missing field → null (prevents RVM undefined-propagation
        // from short-circuiting subsequent builtin calls).
        self.emit_coalesce_undefined_to_null(reg, span);
        Ok(reg)
    }

    /// Compile a dynamic field expression (`FieldKind::Expr`).
    ///
    /// Two patterns are supported:
    ///
    /// 1. **`if(cond, 'alias_A', 'alias_B')`** — both aliases are resolved at
    ///    compile time and the correct field value is selected at runtime via
    ///    `azure.policy.if`.
    ///
    /// 2. **`concat('tags…', …)`** — produces a short tag path (e.g.
    ///    `tags.env`) that is resolved at runtime via `resolve_field`.
    ///
    /// Any other dynamic pattern is rejected at compile time because full
    /// alias paths cannot be resolved at runtime against the normalized
    /// resource structure.
    fn compile_dynamic_field_expr(&mut self, expr: &Expr, span: &crate::lexer::Span) -> Result<u8> {
        if let Expr::Call { func, args, .. } = expr {
            if let Expr::Ident { name, .. } = func.as_ref() {
                if name.eq_ignore_ascii_case("if") && args.len() == 3 {
                    if let (
                        Expr::Literal {
                            value: ExprLiteral::String(alias_a),
                            ..
                        },
                        Expr::Literal {
                            value: ExprLiteral::String(alias_b),
                            ..
                        },
                    ) = (&args[1], &args[2])
                    {
                        // Record alias observations for metadata.
                        self.record_alias(alias_a);
                        self.record_alias(alias_b);

                        // Resolve both aliases at compile time.
                        let short_a = self.resolve_alias_path(alias_a)?;
                        let short_b = self.resolve_alias_path(alias_b)?;

                        // Compile the condition expression.
                        let cond_reg = self.compile_expr(&args[0])?;

                        // Compile both branch field lookups (ChainedIndex).
                        let then_reg = self.compile_field_path_expression(&short_a, span)?;
                        self.emit_coalesce_undefined_to_null(then_reg, span);

                        let else_reg = self.compile_field_path_expression(&short_b, span)?;
                        self.emit_coalesce_undefined_to_null(else_reg, span);

                        // Select the correct branch at runtime.
                        return self.emit_builtin_call(
                            "azure.policy.if",
                            &[cond_reg, then_reg, else_reg],
                            span,
                        );
                    }
                }
            }
        }

        // Handle concat() that produces a tag path, e.g.:
        //   concat('tags.', parameters('tagName'))
        //   concat('tags[', parameters('tagName'), ']')
        // These produce short paths like "tags.env" that resolve_field handles.
        if let Expr::Call { func, args, .. } = expr {
            if let Expr::Ident { name, .. } = func.as_ref() {
                if name.eq_ignore_ascii_case("concat") && !args.is_empty() {
                    if let Expr::Literal {
                        value: ExprLiteral::String(first),
                        ..
                    } = &args[0]
                    {
                        if first.starts_with("tags") {
                            self.observed_has_dynamic_fields = true;
                            let path_reg = self.compile_expr(expr)?;
                            let resource_reg = self.compile_resource_root(span)?;
                            return self.emit_builtin_call(
                                "azure.policy.resolve_field",
                                &[resource_reg, path_reg],
                                span,
                            );
                        }
                    }
                }
            }
        }

        bail!(
            "unsupported dynamic field expression; only \
             `if(cond, 'alias', 'alias')` and `concat('tags...', ...)` \
             patterns are supported"
        );
    }

    pub(super) fn compile_field_path_expression(
        &mut self,
        field_path: &str,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        if let Some(binding) = self.resolve_count_binding(field_path)? {
            return self.compile_from_binding(&binding, field_path, span);
        }
        if field_path.contains("[*]") {
            return self.compile_field_wildcard_collect(field_path, span);
        }
        self.compile_resource_path_value(field_path, span)
    }

    pub(super) fn compile_resource_path_value(
        &mut self,
        field_path: &str,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        // The normalizer lowercases all object keys (including tag names,
        // which are case-insensitive in Azure).  Alias-resolved paths are
        // already lowercase; this covers built-in field names like
        // `fullName` → `fullname`, `apiVersion` → `apiversion`, and tag
        // names like `tags.Created By` → `tags.created by`.
        let field_path_lower = field_path.to_lowercase();
        let field_path = field_path_lower.as_str();

        // When resource_override_reg is set (e.g., inside existenceCondition),
        // resolve fields against the override register directly instead of
        // input.resource.
        if let Some(override_reg) = self.resource_override_reg {
            let parts = split_path_without_wildcards(field_path)?;
            let refs = parts.iter().map(String::as_str).collect::<Vec<_>>();
            return self.emit_chained_index_literal_path(override_reg, &refs, span);
        }

        let input_reg = self.load_input(span)?;

        let mut path = Vec::new();
        path.push("resource".to_string());
        for part in split_path_without_wildcards(field_path)? {
            path.push(part);
        }

        let refs = path.iter().map(String::as_str).collect::<Vec<_>>();
        self.emit_chained_index_literal_path(input_reg, &refs, span)
    }

    pub(super) fn compile_resource_root(&mut self, span: &crate::lexer::Span) -> Result<u8> {
        if let Some(override_reg) = self.resource_override_reg {
            return Ok(override_reg);
        }
        let input_reg = self.load_input(span)?;
        self.emit_chained_index_literal_path(input_reg, &["resource"], span)
    }

    // -- wildcard collection (`field('path[*].prop')` → array) -------------

    /// Compile a field path containing `[*]` into an instruction sequence that
    /// collects all matching values into an array.
    ///
    /// For example, `field('properties.ipRules[*].value')` produces an array
    /// of each element's `value` field.
    /// directly into the same result array.
    ///
    /// When the underlying array is missing (undefined), the `ForEach` loop
    /// iterates zero times and an empty array is returned.
    pub(super) fn compile_field_wildcard_collect(
        &mut self,
        field_path: &str,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        let result_reg = self.alloc_register()?;
        self.emit(Instruction::ArrayNew { dest: result_reg }, span);
        self.compile_wildcard_collect_inner(None, field_path, result_reg, span)?;
        Ok(result_reg)
    }

    /// Recursive helper: emit a `ForEach` loop for the first `[*]` found in
    /// `remaining_path`, then either push the leaf value or recurse for the
    /// next `[*]`.
    ///
    /// * `base_reg` — if `Some`, index from this register instead of from
    ///   `input.resource` (used on recursive calls inside a loop body).
    /// * `remaining_path` — the portion of the field path still to process;
    ///   must contain at least one `[*]`.
    /// * `result_reg` — the outermost result array register; every leaf value
    ///   is pushed here.
    fn compile_wildcard_collect_inner(
        &mut self,
        base_reg: Option<u8>,
        remaining_path: &str,
        result_reg: u8,
        span: &crate::lexer::Span,
    ) -> Result<()> {
        let (prefix, suffix) = split_count_wildcard_path(remaining_path)?;

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

        // Set up a ForEach loop over the collection.
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

        // Loop body: extract value and push (or recurse for nested [*]).
        match suffix {
            Some(ref s) if s.contains("[*]") => {
                // Nested wildcard — recurse to emit an inner loop that also
                // pushes into result_reg (flat-map semantics).
                self.compile_wildcard_collect_inner(Some(current_reg), s, result_reg, span)?;
            }
            Some(ref s) => {
                // Simple suffix: chain-index into the current element.
                let parts = split_path_without_wildcards(s)?;
                let refs = parts.iter().map(String::as_str).collect::<Vec<_>>();
                let val_reg = self.emit_chained_index_literal_path(current_reg, &refs, span)?;
                // Use ArrayPushDefined to skip absent nested properties,
                // matching Azure Policy's field() collection semantics.
                self.emit(
                    Instruction::ArrayPushDefined {
                        arr: result_reg,
                        value: val_reg,
                    },
                    span,
                );
            }
            None => {
                // No suffix: push the element itself.
                self.emit(
                    Instruction::ArrayPushDefined {
                        arr: result_reg,
                        value: current_reg,
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

        Ok(())
    }
}
