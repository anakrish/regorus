// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::error::{CompilerError, Result};
use crate::languages::cedar::ast::*;
use crate::Value;
use alloc::string::String;
use alloc::vec::Vec;

use super::helpers::{path_to_name, path_to_string};
use super::Compiler;

impl Compiler {
    pub(super) fn compile_expr(&mut self, expr: &Expr) -> Result<u8> {
        self.with_span(expr.span(), |this| match *expr {
            Expr::Bool { ref value, .. } => Ok(this.emit_load_literal(value.clone())?),
            Expr::Str { ref value, .. } => Ok(this.emit_load_literal(value.clone())?),
            Expr::Number { ref value, .. } => Ok(this.emit_load_literal(value.clone())?),
            Expr::Ident { ref name, .. } => Ok(this.emit_load_literal(name.clone())?),
            Expr::Var { ref name, .. } => name.as_string().map_or_else(
                |_| Err(CompilerError::InvalidVariable.into()),
                |name| match name.as_ref() {
                    "principal" => this.get_principal_register(),
                    "action" => this.get_action_register(),
                    "resource" => this.get_resource_register(),
                    "context" => this.get_context_register(),
                    _ => Err(CompilerError::UnsupportedVariable {
                        name: String::from(name.as_ref()),
                    }
                    .into()),
                },
            ),
            Expr::Entity { ref path, .. } => Ok(this.emit_load_literal(path_to_string(path)?)?),
            Expr::List { ref exprs, .. } => this.compile_list(exprs),
            Expr::Unary {
                ref expr, ref op, ..
            } => {
                let inner = this.compile_expr(expr)?;
                match *op {
                    UnaryOp::Not => Ok(this.emit_not(inner)?),
                    UnaryOp::Minus => {
                        let zero = this.emit_load_literal(Value::from(0_u64))?;
                        Ok(this.emit_sub(zero, inner)?)
                    }
                }
            }
            Expr::Bin {
                ref left,
                ref right,
                ref op,
                ..
            } => {
                let left_reg = this.compile_expr(left)?;
                let right_is_list = matches!(**right, Expr::List { .. });
                let right_reg = this.compile_expr(right)?;
                match *op {
                    BinOp::Or => Ok(this.emit_or(left_reg, right_reg)?),
                    BinOp::And => Ok(this.emit_and(left_reg, right_reg)?),
                    BinOp::Less => Ok(this.emit_lt(left_reg, right_reg)?),
                    BinOp::LessEqual => Ok(this.emit_le(left_reg, right_reg)?),
                    BinOp::Greater => Ok(this.emit_gt(left_reg, right_reg)?),
                    BinOp::GreaterEqual => Ok(this.emit_ge(left_reg, right_reg)?),
                    BinOp::NotEqual => Ok(this.emit_ne(left_reg, right_reg)?),
                    BinOp::Equal => Ok(this.emit_eq(left_reg, right_reg)?),
                    BinOp::Add => Ok(this.emit_add(left_reg, right_reg)?),
                    BinOp::Sub => Ok(this.emit_sub(left_reg, right_reg)?),
                    BinOp::Mul => Ok(this.emit_mul(left_reg, right_reg)?),
                    BinOp::Has => this.emit_cedar_has(left_reg, right_reg),
                    BinOp::Like => this.emit_cedar_like(left_reg, right_reg),
                    BinOp::In => {
                        if right_is_list {
                            this.emit_cedar_in_set(left_reg, right_reg)
                        } else {
                            this.emit_cedar_in(left_reg, right_reg)
                        }
                    }
                }
            }
            Expr::IsIn {
                ref left,
                ref path,
                ref in_expr,
                ..
            } => {
                let left_reg = this.compile_expr(left)?;
                let type_reg = this.emit_load_literal(path_to_string(path)?)?;
                let is_reg = this.emit_cedar_is(left_reg, type_reg)?;
                if let Some(in_expr) = in_expr.as_ref() {
                    let in_value_reg = this.compile_expr(in_expr)?;
                    let in_check = this.emit_cedar_in(left_reg, in_value_reg)?;
                    Ok(this.emit_and(is_reg, in_check)?)
                } else {
                    Ok(is_reg)
                }
            }
            Expr::Member {
                ref expr,
                ref access,
                ..
            } => {
                let mut current = this.compile_expr(expr)?;
                if access.is_empty() {
                    return Ok(current);
                }

                let mut access_iter = access.iter();
                let Some(first) = access_iter.next() else {
                    return Ok(current);
                };

                match *first {
                    Access::Field { ref field, .. } => {
                        let field_reg = this.emit_load_literal(field.clone())?;
                        current = this.emit_cedar_attr(current, field_reg)?;
                    }
                    Access::Call { .. } => {
                        return Err(CompilerError::MemberCallUnsupported.into());
                    }
                }

                for access_item in access_iter {
                    match *access_item {
                        Access::Field { ref field, .. } => {
                            current = this.emit_index_literal(current, field.clone())?;
                        }
                        Access::Call { .. } => {
                            return Err(CompilerError::MemberCallUnsupported.into());
                        }
                    }
                }

                this.emit_assert_not_undefined(current);
                Ok(current)
            }
            Expr::ExtFcnCall {
                ref path, ref args, ..
            } => {
                let name = path_to_name(path)?;
                let mut arg_regs = Vec::new();
                for arg in args {
                    arg_regs.push(this.compile_expr(arg)?);
                }
                let builtin_index =
                    this.get_builtin_index(&name, crate::rvm::program::BuiltinKind::Standard)?;
                let dest = this.alloc_register()?;
                this.emit_builtin_call(dest, builtin_index, &arg_regs);
                Ok(dest)
            }
            Expr::If { .. } => Err(CompilerError::IfUnsupported.into()),
        })
    }

    fn compile_list(&mut self, exprs: &[Expr]) -> Result<u8> {
        let mut element_regs = Vec::new();
        for expr in exprs {
            element_regs.push(self.compile_expr(expr)?);
        }

        let dest = self.alloc_register()?;
        let params = crate::rvm::instructions::ArrayCreateParams {
            dest,
            elements: element_regs,
        };
        let params_index = self
            .program
            .instruction_data
            .add_array_create_params(params);
        self.emit_instruction(crate::rvm::Instruction::ArrayCreate { params_index });
        Ok(dest)
    }

    pub(super) fn compile_entity(&mut self, entity: &Entity) -> Result<u8> {
        let value = path_to_string(&entity.path)?;
        self.emit_load_literal(value)
    }

    pub(super) fn compile_entity_list(&mut self, entities: &[Entity]) -> Result<u8> {
        let mut elements = Vec::new();
        for entity in entities {
            let value = path_to_string(&entity.path)?;
            elements.push(self.emit_load_literal(value)?);
        }

        let dest = self.alloc_register()?;
        let params = crate::rvm::instructions::ArrayCreateParams { dest, elements };
        let params_index = self
            .program
            .instruction_data
            .add_array_create_params(params);
        self.emit_instruction(crate::rvm::Instruction::ArrayCreate { params_index });
        Ok(dest)
    }
}
