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
        match *expr {
            Expr::Bool { ref value, .. } => Ok(self.emit_load_literal(value.clone())?),
            Expr::Str { ref value, .. } => Ok(self.emit_load_literal(value.clone())?),
            Expr::Number { ref value, .. } => Ok(self.emit_load_literal(value.clone())?),
            Expr::Ident { ref name, .. } => Ok(self.emit_load_literal(name.clone())?),
            Expr::Var { ref name, .. } => name.as_string().map_or_else(
                |_| Err(CompilerError::InvalidVariable.into()),
                |name| match name.as_ref() {
                    "principal" => self.get_principal_register(),
                    "action" => self.get_action_register(),
                    "resource" => self.get_resource_register(),
                    "context" => self.get_context_register(),
                    _ => Err(CompilerError::UnsupportedVariable {
                        name: String::from(name.as_ref()),
                    }
                    .into()),
                },
            ),
            Expr::Entity { ref path, .. } => Ok(self.emit_load_literal(path_to_string(path)?)?),
            Expr::List { ref exprs, .. } => self.compile_list(exprs),
            Expr::Unary {
                ref expr, ref op, ..
            } => {
                let inner = self.compile_expr(expr)?;
                match *op {
                    UnaryOp::Not => Ok(self.emit_not(inner)?),
                    UnaryOp::Minus => {
                        let zero = self.emit_load_literal(Value::from(0_u64))?;
                        Ok(self.emit_sub(zero, inner)?)
                    }
                }
            }
            Expr::Bin {
                ref left,
                ref right,
                ref op,
                ..
            } => {
                let left_reg = self.compile_expr(left)?;
                let right_is_list = matches!(**right, Expr::List { .. });
                let right_reg = self.compile_expr(right)?;
                match *op {
                    BinOp::Or => Ok(self.emit_or(left_reg, right_reg)?),
                    BinOp::And => Ok(self.emit_and(left_reg, right_reg)?),
                    BinOp::Less => Ok(self.emit_lt(left_reg, right_reg)?),
                    BinOp::LessEqual => Ok(self.emit_le(left_reg, right_reg)?),
                    BinOp::Greater => Ok(self.emit_gt(left_reg, right_reg)?),
                    BinOp::GreaterEqual => Ok(self.emit_ge(left_reg, right_reg)?),
                    BinOp::NotEqual => Ok(self.emit_ne(left_reg, right_reg)?),
                    BinOp::Equal => Ok(self.emit_eq(left_reg, right_reg)?),
                    BinOp::Add => Ok(self.emit_add(left_reg, right_reg)?),
                    BinOp::Sub => Ok(self.emit_sub(left_reg, right_reg)?),
                    BinOp::Mul => Ok(self.emit_mul(left_reg, right_reg)?),
                    BinOp::Has => self.emit_cedar_has(left_reg, right_reg),
                    BinOp::Like => self.emit_cedar_like(left_reg, right_reg),
                    BinOp::In => {
                        if right_is_list {
                            self.emit_cedar_in_set(left_reg, right_reg)
                        } else {
                            self.emit_cedar_in(left_reg, right_reg)
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
                let left_reg = self.compile_expr(left)?;
                let type_reg = self.emit_load_literal(path_to_string(path)?)?;
                let is_reg = self.emit_cedar_is(left_reg, type_reg)?;
                if let Some(in_expr) = in_expr.as_ref() {
                    let in_value_reg = self.compile_expr(in_expr)?;
                    let in_check = self.emit_cedar_in(left_reg, in_value_reg)?;
                    Ok(self.emit_and(is_reg, in_check)?)
                } else {
                    Ok(is_reg)
                }
            }
            Expr::Member {
                ref expr,
                ref access,
                ..
            } => {
                let mut current = self.compile_expr(expr)?;
                if access.is_empty() {
                    return Ok(current);
                }

                let mut access_iter = access.iter();
                let Some(first) = access_iter.next() else {
                    return Ok(current);
                };

                match *first {
                    Access::Field { ref field, .. } => {
                        let field_reg = self.emit_load_literal(field.clone())?;
                        current = self.emit_cedar_attr(current, field_reg)?;
                    }
                    Access::Call { .. } => {
                        return Err(CompilerError::MemberCallUnsupported.into());
                    }
                }

                for access_item in access_iter {
                    match *access_item {
                        Access::Field { ref field, .. } => {
                            current = self.emit_index_literal(current, field.clone())?;
                        }
                        Access::Call { .. } => {
                            return Err(CompilerError::MemberCallUnsupported.into());
                        }
                    }
                }

                self.emit_assert_not_undefined(current);
                Ok(current)
            }
            Expr::ExtFcnCall {
                ref path, ref args, ..
            } => {
                let name = path_to_name(path)?;
                let mut arg_regs = Vec::new();
                for arg in args {
                    arg_regs.push(self.compile_expr(arg)?);
                }
                let builtin_index =
                    self.get_builtin_index(&name, crate::rvm::program::BuiltinKind::Standard)?;
                let dest = self.alloc_register()?;
                self.emit_builtin_call(dest, builtin_index, &arg_regs);
                Ok(dest)
            }
            Expr::If { .. } => Err(CompilerError::IfUnsupported.into()),
        }
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
