// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `count` / `count.where` compilation and count-binding resolution.

use alloc::format;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

use anyhow::{anyhow, bail, Result};

use crate::languages::azure_policy::ast::{Constraint, CountNode, FieldKind};
use crate::rvm::instructions::{LoopMode, LoopStartParams};
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
                let (collection_prefix, _suffix) = split_count_wildcard_path(&field_path)?;

                // Check if this field path is relative to an outer count binding.
                // For nested counts like `rules[*].targets[*]` inside a `rules[*]`
                // loop, the collection should come from the outer loop's current
                // element, not from `input.resource`.
                if let Some(binding) = self.resolve_count_binding(&field_path)? {
                    if let Some(outer_prefix) = &binding.field_wildcard_prefix {
                        // Strip the outer prefix + `[*].` to get the inner path.
                        // e.g., "rules[*].targets[*]" → strip "rules[*]." → "targets[*]"
                        let strip_len = outer_prefix.len() + 4; // len of prefix + "[*]."
                        if field_path.len() > strip_len {
                            let inner_path = &field_path[strip_len..];
                            let (inner_collection, _inner_suffix) =
                                split_count_wildcard_path(inner_path)?;
                            let parts = split_path_without_wildcards(&inner_collection)?;
                            let refs = parts.iter().map(String::as_str).collect::<Vec<_>>();
                            let collection_reg = self.emit_chained_index_literal_path(
                                binding.current_reg,
                                &refs,
                                span,
                            )?;
                            // The inner binding's wildcard prefix covers the full
                            // path up to the inner `[*]`.
                            let inner_prefix = format!("{}[*].{}", outer_prefix, inner_collection);
                            return self.compile_count_loop(
                                collection_reg,
                                None,
                                Some(inner_prefix),
                                where_.as_deref(),
                                span,
                            );
                        }
                    }
                }

                // Top-level count: collection from input.resource.
                let collection_reg = self.compile_resource_path_value(&collection_prefix, span)?;

                self.compile_count_loop(
                    collection_reg,
                    None,
                    Some(collection_prefix),
                    where_.as_deref(),
                    span,
                )
            }
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
        let key_reg = self.alloc_register()?;
        let current_reg = self.alloc_register()?;
        let loop_result_reg = self.alloc_register()?;

        let loop_start_index = self.program.instructions.len();
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

        if let Some(where_constraint) = where_constraint {
            let where_reg = self.compile_constraint(where_constraint)?;
            self.emit(
                Instruction::AssertCondition {
                    condition: where_reg,
                },
                span,
            );
        }

        let one_reg = self.load_literal(Value::from(1_i64), span)?;
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

        let _ = loop_start_index;
        Ok(count_reg)
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
        let parts = split_path_without_wildcards(nav_path)?;
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
