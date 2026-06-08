// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Rego to Z3 Converter
//!
//! This module provides conversion functionality from Rego AST to Z3 logical formulas
//! for policy verification and analysis.

use crate::ast::*;
use crate::value::Value;
use anyhow::{Result, anyhow};
use alloc::{
    vec,
    vec::Vec,
    string::{String, ToString},
    collections::BTreeMap,
    format,
};
use z3::{ast::{Bool, String as Z3String, Int, Dynamic, Ast}, SatResult, Solver};

/// Converts Rego expressions and policies to Z3 logical formulas
pub struct RegoToZ3Converter {
    variables: BTreeMap<String, Dynamic>,
}

impl RegoToZ3Converter {
    pub fn new() -> Self {
        Self {
            variables: BTreeMap::new(),
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
            Rule::Spec { bodies, .. } => {
                let mut rule_constraints = Vec::new();
                
                for body in bodies {
                    let body_constraint = self.convert_rule_body(body)?;
                    rule_constraints.push(body_constraint);
                }
                
                Ok(rule_constraints)
            }
            Rule::Default { .. } => {
                // Default rules are always true
                Ok(vec![Bool::from_bool(true)])
            }
        }
    }

    /// Convert a rule body to Z3 constraint
    fn convert_rule_body(&mut self, body: &RuleBody) -> Result<Bool> {
        let mut conditions = Vec::new();
        
        for stmt in &body.query.stmts {
            let condition = self.convert_statement(stmt)?;
            conditions.push(condition);
        }
        
        if conditions.is_empty() {
            Ok(Bool::from_bool(true))
        } else if conditions.len() == 1 {
            Ok(conditions.into_iter().next().unwrap())
        } else {
            // All conditions must be true (AND)
            Ok(Bool::and(&conditions.iter().collect::<Vec<_>>()))
        }
    }

    /// Convert a statement to Z3 constraint
    fn convert_statement(&mut self, stmt: &LiteralStmt) -> Result<Bool> {
        match &stmt.literal {
            Literal::Expr { expr, .. } => {
                self.convert_expr_to_bool(expr)
            }
            Literal::NotExpr { expr, .. } => {
                let inner = self.convert_expr_to_bool(expr)?;
                Ok(inner.not())
            }
            _ => {
                // For other types (assignments, etc.), assume they're always satisfiable
                Ok(Bool::from_bool(true))
            }
        }
    }

    /// Convert expression to Z3 boolean
    fn convert_expr_to_bool(&mut self, expr: &Ref<Expr>) -> Result<Bool> {
        match expr.as_ref() {
            Expr::BoolExpr { op, lhs, rhs, .. } => {
                self.convert_bool_expr(op, lhs, rhs)
            }
            Expr::Bool { value, .. } => {
                if let Value::Bool(b) = value {
                    Ok(Bool::from_bool(*b))
                } else {
                    Ok(Bool::from_bool(false))
                }
            }
            Expr::Membership { value, collection, .. } => {
                self.convert_membership(value, collection)
            }
            Expr::UnaryExpr { expr, .. } => {
                // Assume this is negation
                let inner = self.convert_expr_to_bool(expr)?;
                Ok(inner.not())
            }
            _ => {
                // For unsupported expressions, assume they can be satisfied
                Ok(Bool::from_bool(true))
            }
        }
    }

    /// Convert boolean expression
    fn convert_bool_expr(&mut self, op: &BoolOp, lhs: &Ref<Expr>, rhs: &Ref<Expr>) -> Result<Bool> {
        match op {
            BoolOp::Eq => {
                let left = self.convert_expr_to_z3(lhs)?;
                let right = self.convert_expr_to_z3(rhs)?;
                Ok(left._eq(&right))
            }
            BoolOp::Ne => {
                let left = self.convert_expr_to_z3(lhs)?;
                let right = self.convert_expr_to_z3(rhs)?;
                Ok(left._eq(&right).not())
            }
            BoolOp::Lt => {
                let left = self.convert_expr_to_int(lhs)?;
                let right = self.convert_expr_to_int(rhs)?;
                Ok(left.lt(&right))
            }
            BoolOp::Le => {
                let left = self.convert_expr_to_int(lhs)?;
                let right = self.convert_expr_to_int(rhs)?;
                Ok(left.le(&right))
            }
            BoolOp::Gt => {
                let left = self.convert_expr_to_int(lhs)?;
                let right = self.convert_expr_to_int(rhs)?;
                Ok(left.gt(&right))
            }
            BoolOp::Ge => {
                let left = self.convert_expr_to_int(lhs)?;
                let right = self.convert_expr_to_int(rhs)?;
                Ok(left.ge(&right))
            }
        }
    }

    /// Convert membership expression (input.field in ["value1", "value2"])
    fn convert_membership(&mut self, value: &Ref<Expr>, collection: &Ref<Expr>) -> Result<Bool> {
        let var = self.convert_expr_to_z3(value)?;
        
        if let Expr::Array { items, .. } = collection.as_ref() {
            let mut options = Vec::new();
            
            for item in items {
                let item_value = self.convert_expr_to_z3(item)?;
                options.push(var._eq(&item_value));
            }
            
            if options.is_empty() {
                Ok(Bool::from_bool(false))
            } else if options.len() == 1 {
                Ok(options.into_iter().next().unwrap())
            } else {
                // Any of the options can be true (OR)
                Ok(Bool::or(&options.iter().collect::<Vec<_>>()))
            }
        } else {
            // Non-array collection - assume it's satisfiable
            Ok(Bool::from_bool(true))
        }
    }

    /// Convert expression to Z3 dynamic type
    pub fn convert_expr_to_z3(&mut self, expr: &Ref<Expr>) -> Result<Dynamic> {
        match expr.as_ref() {
            Expr::String { value, .. } => {
                if let Value::String(s) = value {
                    // Create a string constant (literal value) - keep using new_const for now
                    Ok(Z3String::new_const(s.as_ref()).into())
                } else {
                    Ok(Z3String::new_const("").into())
                }
            }
            Expr::Number { value, .. } => {
                if let Value::Number(n) = value {
                    // Convert to integer for simplicity
                    let int_val = n.as_i64().unwrap_or(0);
                    Ok(Int::from_i64(int_val).into())
                } else {
                    Ok(Int::from_i64(0).into())
                }
            }
            Expr::Bool { value, .. } => {
                if let Value::Bool(b) = value {
                    Ok(Bool::from_bool(*b).into())
                } else {
                    Ok(Bool::from_bool(false).into())
                }
            }
            Expr::Var { value, .. } => {
                let var_name = if let Value::String(s) = value {
                    s.to_string()
                } else {
                    "unknown_var".to_string()
                };
                
                if let Some(existing_var) = self.variables.get(&var_name) {
                    Ok(existing_var.clone())
                } else {
                    // Create new string variable (most common case for input fields)
                    let var = Z3String::new_const(var_name.as_str());
                    let dynamic_var: Dynamic = var.into();
                    self.variables.insert(var_name, dynamic_var.clone());
                    Ok(dynamic_var)
                }
            }
            Expr::RefDot { refr, field, .. } => {
                let base = self.extract_variable_name(refr);
                let var_name = if let Value::String(field_name) = &field.1 {
                    format!("{}.{}", base, field_name.as_ref())
                } else {
                    base
                };
                
                if let Some(existing_var) = self.variables.get(&var_name) {
                    Ok(existing_var.clone())
                } else {
                    // Don't create the variable here - let the context determine the type
                    // This allows Z3 to infer whether it should be string, int, etc.
                    // For now, default to string but mark it as untyped
                    let var = Z3String::new_const(var_name.as_str());
                    let dynamic_var: Dynamic = var.into();
                    self.variables.insert(var_name, dynamic_var.clone());
                    Ok(dynamic_var)
                }
            }
            Expr::RefBrack { refr, index, .. } => {
                let base = self.extract_variable_name(refr);
                let var_name = if let Expr::String { value, .. } = index.as_ref() {
                    if let Value::String(index_name) = value {
                        format!("{}.{}", base, index_name.as_ref())
                    } else {
                        base
                    }
                } else {
                    base
                };
                
                if let Some(existing_var) = self.variables.get(&var_name) {
                    Ok(existing_var.clone())
                } else {
                    let var = Z3String::new_const(var_name.as_str());
                    let dynamic_var: Dynamic = var.into();
                    self.variables.insert(var_name, dynamic_var.clone());
                    Ok(dynamic_var)
                }
            }
            _ => {
                // For unsupported expressions, create a fresh variable
                let var_name = format!("expr_{}", self.variables.len());
                let var = Z3String::new_const(var_name.as_str());
                let dynamic_var: Dynamic = var.into();
                self.variables.insert(var_name, dynamic_var.clone());
                Ok(dynamic_var)
            }
        }
    }

    /// Convert expression to Z3 integer
    fn convert_expr_to_int(&mut self, expr: &Ref<Expr>) -> Result<Int> {
        match expr.as_ref() {
            Expr::Number { value, .. } => {
                if let Value::Number(n) = value {
                    let int_val = n.as_i64().unwrap_or(0);
                    Ok(Int::from_i64(int_val))
                } else {
                    Ok(Int::from_i64(0))
                }
            }
            Expr::Var { .. } | Expr::RefDot { .. } | Expr::RefBrack { .. } => {
                let var_name = self.extract_variable_name(expr);
                
                if let Some(existing_var) = self.variables.get(&var_name) {
                    // Try to convert existing variable to int
                    if let Some(int_var) = existing_var.as_int() {
                        Ok(int_var)
                    } else {
                        // Create new int variable
                        let int_var = Int::new_const(var_name.as_str());
                        self.variables.insert(var_name, int_var.clone().into());
                        Ok(int_var)
                    }
                } else {
                    // Create new int variable
                    let int_var = Int::new_const(var_name.as_str());
                    self.variables.insert(var_name, int_var.clone().into());
                    Ok(int_var)
                }
            }
            _ => {
                Err(anyhow!("Cannot convert expression to integer"))
            }
        }
    }

    /// Extract variable name from expression
    fn extract_variable_name(&self, expr: &Ref<Expr>) -> String {
        match expr.as_ref() {
            Expr::Var { value, .. } => {
                if let Value::String(s) = value {
                    s.to_string()
                } else {
                    "unknown_var".to_string()
                }
            }
            Expr::RefDot { refr, field, .. } => {
                let base = self.extract_variable_name(refr);
                if let Value::String(field_name) = &field.1 {
                    format!("{}.{}", base, field_name.as_ref())
                } else {
                    base
                }
            }
            Expr::RefBrack { refr, index, .. } => {
                let base = self.extract_variable_name(refr);
                if let Expr::String { value, .. } = index.as_ref() {
                    if let Value::String(index_name) = value {
                        format!("{}.{}", base, index_name.as_ref())
                    } else {
                        base
                    }
                } else {
                    base
                }
            }
            _ => "unknown_var".to_string(),
        }
    }

    /// Check if two sets of constraints can be satisfied simultaneously
    pub fn check_constraints_satisfiable(&self, constraints1: &[Bool], constraints2: &[Bool]) -> Result<bool> {
        let solver = Solver::new();
        
        // Add all constraints from both sets
        for constraint in constraints1.iter().chain(constraints2.iter()) {
            solver.assert(constraint);
        }
        
        match solver.check() {
            SatResult::Sat => Ok(true),
            SatResult::Unsat => Ok(false),
            SatResult::Unknown => Ok(true), // Be conservative
        }
    }

    /// Find a model that satisfies both constraint sets (for conflict examples)
    pub fn find_satisfying_model(&self, constraints1: &[Bool], constraints2: &[Bool]) -> Result<Option<String>> {
        let solver = Solver::new();
        
        // Add all constraints
        for constraint in constraints1.iter().chain(constraints2.iter()) {
            solver.assert(constraint);
        }
        
        match solver.check() {
            SatResult::Sat => {
                if let Some(model) = solver.get_model() {
                    // Convert model to properly structured JSON
                    use serde_json::{Map, Value as JsonValue};
                    let mut json_obj = Map::new();
                    
                    for (var_name, var) in &self.variables {
                        if let Some(value) = model.eval(var, true) {
                            let value_str = value.to_string();
                            
                            // Clean up Z3 value string - remove extra quotes if present
                            let final_value = if value_str.starts_with("\"") && value_str.ends_with("\"") && value_str.len() > 2 {
                                value_str[1..value_str.len()-1].to_string()
                            } else {
                                value_str
                            };
                            
                            // Convert flat variable name to nested JSON structure
                            if var_name.starts_with("input.") {
                                let path = &var_name[6..]; // Remove "input." prefix
                                self.set_nested_json_value(&mut json_obj, path, JsonValue::String(final_value));
                            }
                        }
                    }
                    
                    // Convert to JSON string
                    let json_value = JsonValue::Object(json_obj);
                    match serde_json::to_string(&json_value) {
                        Ok(json_str) => Ok(Some(json_str)),
                        Err(_) => Ok(Some("{}".to_string())), // Fallback to empty object
                    }
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }
    
    /// Helper method to set nested JSON values from dot-separated paths
    fn set_nested_json_value(&self, obj: &mut serde_json::Map<String, serde_json::Value>, path: &str, value: serde_json::Value) {
        let parts: Vec<&str> = path.split('.').collect();
        
        fn set_recursive(
            obj: &mut serde_json::Map<String, serde_json::Value>,
            parts: &[&str],
            value: serde_json::Value,
        ) {
            if parts.is_empty() {
                return;
            }
            
            if parts.len() == 1 {
                // Last part - set the value
                obj.insert(parts[0].to_string(), value);
            } else {
                // Intermediate part - ensure nested object exists
                let entry = obj.entry(parts[0].to_string()).or_insert_with(|| {
                    serde_json::Value::Object(serde_json::Map::new())
                });
                
                if let serde_json::Value::Object(nested_obj) = entry {
                    set_recursive(nested_obj, &parts[1..], value);
                }
            }
        }
        
        set_recursive(obj, &parts, value);
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
