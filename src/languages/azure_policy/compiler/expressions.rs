// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Template-expression and call-expression compilation.

use alloc::vec::Vec;

use anyhow::{anyhow, bail, Result};

use crate::languages::azure_policy::ast::{Expr, ExprLiteral, ValueOrExpr};
use crate::rvm::Instruction;
use crate::Value;

use super::utils::{extract_string_literal, json_value_to_runtime};
use super::Compiler;

impl Compiler {
    pub(super) fn compile_value_or_expr(
        &mut self,
        voe: &ValueOrExpr,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        match voe {
            ValueOrExpr::Value(value) => self.compile_json_value(value, span),
            ValueOrExpr::Expr { expr, .. } => self.compile_expr(expr),
        }
    }

    pub(super) fn compile_json_value(
        &mut self,
        value: &crate::languages::azure_policy::ast::JsonValue,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        let runtime_value = json_value_to_runtime(value)?;
        self.load_literal(runtime_value, span)
    }

    pub(super) fn compile_expr(&mut self, expr: &Expr) -> Result<u8> {
        match expr {
            Expr::Literal { span, value } => {
                let v = match value {
                    ExprLiteral::Number(n) => Value::from(
                        n.parse::<f64>()
                            .map_err(|_| anyhow!("invalid number literal {}", n))?,
                    ),
                    ExprLiteral::String(s) => Value::from(s.clone()),
                    ExprLiteral::Bool(b) => Value::Bool(*b),
                };
                self.load_literal(v, span)
            }
            Expr::Ident { name, span } => {
                // The lexer may produce `true`/`false`/`null` as identifiers.
                match name.to_lowercase().as_str() {
                    "true" => self.load_literal(Value::Bool(true), span),
                    "false" => self.load_literal(Value::Bool(false), span),
                    "null" => self.load_literal(Value::Null, span),
                    _ => bail!(span.error(&alloc::format!(
                        "unsupported bare identifier in template expression: {}",
                        name
                    ))),
                }
            }
            Expr::Call { span, func, args } => self.compile_call_expr(span, func, args),
            Expr::Dot {
                span,
                object,
                field,
                ..
            } => {
                let object_reg = self.compile_expr(object)?;
                let dest = self.alloc_register()?;
                let literal_idx = self.add_literal_u16(Value::from(field.clone()))?;
                self.emit(
                    Instruction::IndexLiteral {
                        dest,
                        container: object_reg,
                        literal_idx,
                    },
                    span,
                );
                Ok(dest)
            }
            Expr::Index {
                span,
                object,
                index,
            } => {
                let object_reg = self.compile_expr(object)?;
                let index_reg = self.compile_expr(index)?;
                let dest = self.alloc_register()?;
                self.emit(
                    Instruction::Index {
                        dest,
                        container: object_reg,
                        key: index_reg,
                    },
                    span,
                );
                Ok(dest)
            }
        }
    }

    pub(super) fn compile_call_expr(
        &mut self,
        span: &crate::lexer::Span,
        func: &Expr,
        args: &[Expr],
    ) -> Result<u8> {
        let Expr::Ident { name, .. } = func else {
            bail!(span.error("unsupported dynamic function expression"));
        };

        let function_name = name.to_lowercase();

        match function_name.as_str() {
            "parameters" => {
                let Some(first_arg) = args.first() else {
                    bail!(span.error("parameters() requires one argument"));
                };
                let param_name = extract_string_literal(first_arg)?;
                let input_reg = self.load_input(span)?;
                let params_reg =
                    self.emit_chained_index_literal_path(input_reg, &["parameters"], span)?;
                let defaults_reg = if let Some(ref defaults) = self.parameter_defaults {
                    self.load_literal(defaults.clone(), span)?
                } else {
                    self.load_literal(Value::new_object(), span)?
                };
                let name_reg = self.load_literal(Value::from(param_name), span)?;
                self.emit_builtin_call(
                    "azure.policy.get_parameter",
                    &[params_reg, defaults_reg, name_reg],
                    span,
                )
            }
            "field" => {
                let Some(first_arg) = args.first() else {
                    bail!(span.error("field() requires one argument"));
                };
                let field_path = extract_string_literal(first_arg)?;
                let reg = self.compile_field_path_expression(&field_path, span)?;
                // Azure Policy: missing field → null.  Without this, the RVM's
                // undefined-propagation would short-circuit any subsequent
                // builtin calls (e.g. `empty(field('missing'))` → Undefined
                // instead of true).
                self.emit_coalesce_undefined_to_null(reg, span);
                Ok(reg)
            }
            "current" => {
                match args.first() {
                    Some(first_arg) => {
                        let key = extract_string_literal(first_arg)?;
                        self.compile_current_reference(&key, span)
                    }
                    None => {
                        // Zero-arg current() — innermost count binding.
                        let binding = self.count_bindings.last().ok_or_else(|| {
                            anyhow::anyhow!(
                                "{}",
                                span.error("current() used outside a count scope")
                            )
                        })?;
                        let current_reg = binding.current_reg;
                        let dest = self.alloc_register()?;
                        self.emit(
                            crate::rvm::Instruction::Move {
                                dest,
                                src: current_reg,
                            },
                            span,
                        );
                        Ok(dest)
                    }
                }
            }
            "resourcegroup" => {
                let ctx_reg = self.load_context(span)?;
                self.emit_chained_index_literal_path(ctx_reg, &["resourceGroup"], span)
            }
            "subscription" => {
                let ctx_reg = self.load_context(span)?;
                self.emit_chained_index_literal_path(ctx_reg, &["subscription"], span)
            }
            "requestcontext" => {
                let ctx_reg = self.load_context(span)?;
                self.emit_chained_index_literal_path(ctx_reg, &["requestContext"], span)
            }
            "policy" => {
                let ctx_reg = self.load_context(span)?;
                self.emit_chained_index_literal_path(ctx_reg, &["policy"], span)
            }
            "utcnow" => {
                // utcNow() returns the current UTC timestamp from context.
                // Optional format parameter is ignored — we always use ISO 8601.
                let ctx_reg = self.load_context(span)?;
                self.emit_chained_index_literal_path(ctx_reg, &["utcNow"], span)
            }
            "concat" | "if" | "and" | "not" | "tolower" | "toupper" | "replace" | "substring"
            | "length" | "add" | "equals" | "greaterorequals" | "lessorequals" | "contains" => self
                .compile_arm_template_function(&function_name, span, args)?
                .ok_or_else(|| anyhow!("{}", span.error("unreachable"))),

            // ── ARM template functions (dispatched to template_dispatch.rs) ──
            other => {
                if let Some(dest) = self.compile_arm_template_function(other, span, args)? {
                    Ok(dest)
                } else {
                    bail!(span.error(&alloc::format!("unsupported template function '{}'", other)))
                }
            }
        }
    }

    pub(super) fn compile_call_args(&mut self, args: &[Expr]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(args.len());
        for arg in args {
            out.push(self.compile_expr(arg)?);
        }
        Ok(out)
    }
}
