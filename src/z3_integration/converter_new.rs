// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Rego to Z3 Converter
//!
//! This module provides conversion functionality from Rego AST to Z3 logical formulas
//! for policy verification and analysis.

use crate::ast::*;
use anyhow::{anyhow, Result};
use std::collections::BTreeMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use z3::{
    ast::{Bool, Dynamic, Int, Real},
    FuncDecl, Sort,
};

/// Converts Rego expressions and policies to Z3 logical formulas
pub struct RegoToZ3Converter {
    variables: BTreeMap<String, Int>,
    bool_variables: BTreeMap<String, Bool>,
    functions: BTreeMap<String, FuncDecl>,
}

impl RegoToZ3Converter {
    pub fn new() -> Self {
        Self {
            variables: BTreeMap::new(),
            bool_variables: BTreeMap::new(),
            functions: BTreeMap::new(),
        }
    }

    /// Convert a Rego module to Z3 constraints
    pub fn convert_module(&mut self, module: &Module) -> Result<Vec<Bool>> {
        let mut constraints = Vec::new();

        for rule in &module.policy {
            let rule_constraints = self.convert_rule(rule)?;
            constraints.extend(rule_constraints);
        }

        Ok(constraints)
    }

    /// Convert a Rego rule to Z3 constraints
    pub fn convert_rule(&mut self, rule: &Ref<Rule>) -> Result<Vec<Bool>> {
        match rule.as_ref() {
            Rule::Spec { head, bodies, .. } => {
                let mut constraints = Vec::new();

                if bodies.is_empty() {
                    // Fact - always true
                    constraints.push(Bool::from_bool(true));
                } else {
                    // Rule with body
                    for body in bodies {
                        let body_constraint = self.convert_rule_body(body)?;
                        let head_constraint = self.convert_rule_head(head)?;
                        
                        // If body is true, then head is true
                        let implication = Bool::and(&[&body_constraint.not(), &head_constraint]);
                        constraints.push(implication);
                    }
                }

                Ok(constraints)
            }
            _ => {
                // Unknown rule type - treat as true
                Ok(vec![Bool::from_bool(true)])
            }
        }
    }

    fn convert_rule_body(&mut self, body: &RuleBody) -> Result<Bool> {
        let mut constraints = Vec::new();

        for stmt in &body.stmts {
            let stmt_constraint = self.convert_literal_stmt(stmt)?;
            constraints.push(stmt_constraint);
        }

        Ok(Bool::and(&constraints.iter().collect::<Vec<_>>()))
    }

    fn convert_rule_head(&mut self, head: &RuleHead) -> Result<Bool> {
        match head {
            RuleHead::Compr { .. } => {
                // Complex comprehension - approximate as true for now
                Ok(Bool::from_bool(true))
            }
            RuleHead::Set { .. } => {
                // Set head - approximate as true for now  
                Ok(Bool::from_bool(true))
            }
            RuleHead::Func { name, args, assign, .. } => {
                if let Some(assign) = assign {
                    let var = self.get_or_create_bool_variable(&format!("func_{}", name));
                    let assign_constraint = self.convert_assignment(assign)?;
                    Ok(Bool::and(&[&var, &assign_constraint]))
                } else {
                    // Function without assignment
                    let var = self.get_or_create_bool_variable(&format!("func_{}", name));
                    Ok(var)
                }
            }
        }
    }

    fn convert_literal_stmt(&mut self, stmt: &LiteralStmt) -> Result<Bool> {
        match stmt {
            LiteralStmt::Expr { expr, .. } => {
                self.convert_expr_to_bool(expr)
            }
            LiteralStmt::NotExpr { expr, .. } => {
                let expr_constraint = self.convert_expr_to_bool(expr)?;
                Ok(expr_constraint.not())
            }
            LiteralStmt::SomeVars { .. } => {
                // Some variable declaration - treat as true
                Ok(Bool::from_bool(true))
            }
            LiteralStmt::SomeIn { .. } => {
                // Some in expression - treat as true for now
                Ok(Bool::from_bool(true))
            }
        }
    }

    fn convert_assignment(&mut self, assign: &RuleAssign) -> Result<Bool> {
        // For now, treat assignments as true
        // TODO: Implement proper assignment constraint generation
        Ok(Bool::from_bool(true))
    }

    pub fn convert_expr_to_z3(&mut self, expr: &Ref<Expr>) -> Result<Dynamic> {
        match expr.as_ref() {
            Expr::Number(n) => {
                match n {
                    Number::Int(int_val) => {
                        Ok(Int::from_i64(*int_val).into())
                    }
                    Number::Float(float_val) => {
                        // Convert float to rational
                        Ok(Real::from_real((float_val * 1000000.0) as i32, 1000000).into())
                    }
                }
            }
            Expr::String(s) => {
                // Convert string to hash for comparison
                let mut hasher = DefaultHasher::new();
                s.hash(&mut hasher);
                let hash = hasher.finish() as i64;
                Ok(Int::from_i64(hash).into())
            }
            Expr::Bool(b) => Ok(Bool::from_bool(*b).into()),
            Expr::Null => {
                // Represent null as a special value
                Ok(Int::from_i64(-1).into())
            }
            Expr::Array(arr) => {
                // Convert array to hash for now
                let mut hasher = DefaultHasher::new();
                arr.len().hash(&mut hasher);
                let hash = hasher.finish() as i64;
                Ok(Int::from_i64(hash).into())
            }
            Expr::Object(obj) => {
                // Convert object to hash for now
                let mut hasher = DefaultHasher::new();
                obj.len().hash(&mut hasher);
                let hash = hasher.finish() as i64;
                Ok(Int::from_i64(hash).into())
            }
            Expr::Set(set) => {
                // Convert set to hash for now
                let mut hasher = DefaultHasher::new();
                set.len().hash(&mut hasher);
                let hash = hasher.finish() as i64;
                Ok(Int::from_i64(hash).into())
            }
            Expr::RefDot { refr, field, .. } => {
                // Handle field access - for now return hash
                let mut hasher = DefaultHasher::new();
                field.hash(&mut hasher);
                let hash = hasher.finish() as i64;
                Ok(Int::from_i64(hash).into())
            }
            Expr::Var(var) => {
                let var_z3 = self.get_or_create_variable(&var.0);
                Ok(var_z3.into())
            }
            Expr::Call { fcn, args, .. } => {
                match fcn.as_ref() {
                    Expr::Var(func_name) => {
                        // Create or get function declaration
                        let func_key = format!("{}_{}", func_name.0, args.len());
                        if !self.functions.contains_key(&func_key) {
                            let arg_sorts: Vec<Sort> = args.iter().map(|_| Sort::int()).collect();
                            let return_sort = Sort::bool();
                            
                            let func_decl = FuncDecl::new(
                                func_name.0.clone(),
                                &arg_sorts.iter().collect::<Vec<_>>(),
                                &return_sort
                            );
                            self.functions.insert(func_key.clone(), func_decl);
                        }
                        
                        let func_decl = &self.functions[&func_key];
                        let z3_args: Result<Vec<Dynamic>> = args.iter()
                            .map(|arg| self.convert_expr_to_z3(arg))
                            .collect();
                        let z3_args = z3_args?;
                        let bool_app = func_decl.apply(&z3_args.iter().collect::<Vec<_>>());
                        Ok(bool_app)
                    }
                    _ => {
                        // Unsupported function call
                        Ok(Bool::from_bool(true).into())
                    }
                }
            }
            Expr::UnaryExpr { op, expr: operand, .. } => {
                match op {
                    UnaryOp::Len => {
                        // Return length as integer
                        Ok(Int::from_i64(1).into()) // Placeholder
                    }
                    _ => {
                        Ok(Bool::from_bool(true).into())
                    }
                }
            }
            Expr::BinExpr { op, lhs, rhs, .. } => {
                let lhs_z3 = self.convert_expr_to_z3(lhs)?;
                let rhs_z3 = self.convert_expr_to_z3(rhs)?;
                
                match op {
                    BinOp::Eq => {
                        let eq_result = lhs_z3._eq(&rhs_z3);
                        Ok(eq_result.into())
                    }
                    BinOp::Ne => {
                        let ne_result = lhs_z3._eq(&rhs_z3).not();
                        Ok(ne_result.into())
                    }
                    _ => {
                        // Other operations - approximate as true
                        Ok(Bool::from_bool(true).into())
                    }
                }
            }
            Expr::ArithExpr { op, lhs, rhs, .. } => {
                // Handle arithmetic operations
                Ok(Int::from_i64(0).into()) // Placeholder
            }
            Expr::Membership { key, value, .. } => {
                // Handle membership test (in operator)
                Ok(Bool::from_bool(true).into()) // Placeholder
            }
            _ => {
                // Default case for unhandled expressions
                Ok(Bool::from_bool(true).into())
            }
        }
    }

    fn convert_expr_to_bool(&mut self, expr: &Ref<Expr>) -> Result<Bool> {
        match expr.as_ref() {
            Expr::Bool(b) => Ok(Bool::from_bool(*b)),
            _ => {
                // Convert other expressions to bool by checking if they're "truthy"
                Ok(Bool::from_bool(true))
            }
        }
    }

    fn get_or_create_variable(&mut self, name: &str) -> Int {
        if let Some(var) = self.variables.get(name) {
            var.clone()
        } else {
            let var = Int::new_const(name);
            self.variables.insert(name.to_string(), var.clone());
            var
        }
    }

    fn get_or_create_bool_variable(&mut self, name: &str) -> Bool {
        if let Some(var) = self.bool_variables.get(name) {
            var.clone()
        } else {
            let var = Bool::new_const(name);
            self.bool_variables.insert(name.to_string(), var.clone());
            var
        }
    }

    fn create_disjunction(&self, exprs: &[Bool]) -> Bool {
        if exprs.is_empty() {
            Bool::from_bool(false)
        } else {
            Bool::or(&exprs.iter().collect::<Vec<_>>())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_converter_creation() {
        let _converter = RegoToZ3Converter::new();
        // Basic test to ensure converter can be created
    }
}
