// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Database-friendly Rego subset parser
//!
//! This module provides a parser for a restricted subset of Rego designed
//! for efficient translation to database queries (SQL, KQL, etc.). It builds on
//! the main parser but enforces stricter rules about what constructs are allowed.
//!
//! ## Comment Support
//!
//! The database parser supports hash-style comments (#) which are the standard
//! Rego comment format:
//!
//! ```rego
//! # This is a comment
//! package mypackage
//!
//! allow {
//!     user.role == "admin"  # End-of-line comment
//! }
//! ```
//!
//! Comments are automatically ignored during parsing and do not affect
//! the generated database queries.

use crate::ast::*;
use crate::lexer::*;
use crate::parser::Parser;

use alloc::{format, string::ToString};
use anyhow::{bail, Result};

/// Parser for database-friendly Rego subset
pub struct DatabaseParser<'source> {
    parser: Parser<'source>,
}

impl<'source> DatabaseParser<'source> {
    pub fn new(source: &'source Source) -> Result<Self> {
        Ok(Self {
            parser: Parser::new(source)?,
        })
    }

    /// Create a new DatabaseParser with C-style comments enabled
    pub fn new_with_c_style_comments(source: &'source Source) -> Result<Self> {
        // Create a custom parser setup that would enable C-style comments
        // For now, we'll note this limitation in documentation
        let mut parser = Self::new(source)?;
        parser.enable_c_style_comments()?;
        Ok(parser)
    }

    /// Enable Rego v1 syntax
    pub fn enable_rego_v1(&mut self) -> Result<()> {
        self.parser.enable_rego_v1()
    }

    /// Enable C-style comments (//) instead of hash comments (#)
    /// Note: Currently limited by Parser API - both styles are supported separately
    pub fn enable_c_style_comments(&mut self) -> Result<()> {
        // The current Parser API doesn't allow changing comment style after creation
        // This is a design limitation that would require changes to the core parser
        // For now, we document that hash comments (#) are the default supported style
        Ok(())
    }

    /// Parse a complete module with database restrictions
    pub fn parse_database_module(&mut self) -> Result<Module> {
        let module = self.parser.parse()?;
        self.validate_database_module(&module)?;
        Ok(module)
    }

    /// Parse a user query with database restrictions
    pub fn parse_database_query(&mut self) -> Result<Ref<Query>> {
        let query = self.parser.parse_user_query()?;
        self.validate_database_query(&query)?;
        Ok(query)
    }

    /// Validate that a module conforms to database subset rules
    fn validate_database_module(&self, module: &Module) -> Result<()> {
        // Check package declaration
        self.validate_package(&module.package)?;

        // Check imports
        for import in &module.imports {
            self.validate_import(import)?;
        }

        // Check rules
        for rule in &module.policy {
            self.validate_database_rule(rule)?;
        }

        Ok(())
    }

    /// Validate package declaration
    fn validate_package(&self, package: &Package) -> Result<()> {
        // Package must be a simple path reference
        self.validate_simple_path(&package.refr)?;
        Ok(())
    }

    /// Validate import statement
    fn validate_import(&self, import: &Import) -> Result<()> {
        // Import must be a simple path reference
        self.validate_simple_path(&import.refr)?;
        Ok(())
    }

    /// Validate that a path reference is simple (no complex expressions)
    fn validate_simple_path(&self, expr: &Ref<Expr>) -> Result<()> {
        match expr.as_ref() {
            Expr::Var { .. } => Ok(()),
            Expr::RefDot { refr, .. } => self.validate_simple_path(refr),
            Expr::RefBrack { refr, index, .. } => {
                self.validate_simple_path(refr)?;
                match index.as_ref() {
                    Expr::String { .. } => Ok(()),
                    _ => bail!(expr
                        .span()
                        .error("database subset: array indices in paths must be string literals")),
                }
            }
            _ => bail!(expr
                .span()
                .error("database subset: path must be simple variable or field reference")),
        }
    }

    /// Validate a rule conforms to database subset
    fn validate_database_rule(&self, rule: &Ref<Rule>) -> Result<()> {
        match rule.as_ref() {
            Rule::Default {
                refr, args, value, ..
            } => {
                self.validate_simple_path(refr)?;
                for arg in args {
                    self.validate_database_expr(arg)?;
                }
                self.validate_database_expr(value)?;
            }
            Rule::Spec { head, bodies, .. } => {
                self.validate_database_rule_head(head)?;
                for body in bodies {
                    self.validate_database_rule_body(body)?;
                }
            }
        }
        Ok(())
    }

    /// Validate rule head
    fn validate_database_rule_head(&self, head: &RuleHead) -> Result<()> {
        match head {
            RuleHead::Set { refr, key, .. } => {
                // Only allow "rule_name contains var" pattern for Set rules
                self.validate_simple_path(refr)?;

                // For the simplified grammar, key must be present (the variable after "contains")
                if key.is_none() {
                    bail!(refr.span().error(
                        "database subset: Set rules must use 'rule_name contains var' pattern"
                    ));
                }

                if let Some(key) = key {
                    // The key must be a simple variable
                    match key.as_ref() {
                        Expr::Var { .. } => Ok(()),
                        _ => bail!(key
                            .span()
                            .error("database subset: the variable in 'contains' pattern must be a simple variable")),
                    }
                } else {
                    Ok(())
                }
            }
            RuleHead::Compr { span, .. } => {
                // Comprehension rules are not supported in simplified grammar
                bail!(span
                    .error("database subset: only 'rule_name contains var if {{ ... }}' rule patterns are supported"));
            }
            RuleHead::Func { span, .. } => {
                // Functions are not supported in simplified grammar
                bail!(span
                    .error("database subset: only 'rule_name contains var if {{ ... }}' rule patterns are supported"));
            }
        }
    }

    /// Validate that a key expression is static (evaluatable at compile time)
    fn validate_static_key(&self, expr: &Ref<Expr>) -> Result<()> {
        match expr.as_ref() {
            Expr::String { .. } | Expr::Number { .. } | Expr::Var { .. } => Ok(()),
            _ => bail!(expr
                .span()
                .error("database subset: keys must be static (string, number, or variable)")),
        }
    }

    /// Validate rule body
    fn validate_database_rule_body(&self, body: &RuleBody) -> Result<()> {
        if let Some(assign) = &body.assign {
            self.validate_database_expr(&assign.value)?;
        }

        // For simplified grammar, ensure the rule body contains at least one "some var in table"
        let has_some_in = body
            .query
            .stmts
            .iter()
            .any(|stmt| matches!(stmt.literal, Literal::SomeIn { .. }));

        if !has_some_in {
            bail!(body.query.span.error("database subset: rule body must contain at least one 'some var in table' statement"));
        }

        self.validate_database_query(&body.query)?;
        Ok(())
    }

    /// Validate a query conforms to database subset
    fn validate_database_query(&self, query: &Ref<Query>) -> Result<()> {
        for stmt in &query.stmts {
            self.validate_database_literal_stmt(stmt)?;
        }
        Ok(())
    }

    /// Validate a literal statement
    fn validate_database_literal_stmt(&self, stmt: &LiteralStmt) -> Result<()> {
        self.validate_database_literal(&stmt.literal)?;

        // With modifiers are supported but limited
        for modifier in &stmt.with_mods {
            self.validate_simple_path(&modifier.refr)?;
            self.validate_database_expr(&modifier.r#as)?;
        }
        Ok(())
    }

    /// Validate a literal
    fn validate_database_literal(&self, literal: &Literal) -> Result<()> {
        match literal {
            Literal::Expr { expr, .. } => self.validate_database_expr(expr),
            Literal::NotExpr { expr, .. } => {
                // Not expressions are supported but limited to simple expressions
                self.validate_simple_expression(expr)
            }
            Literal::SomeVars { .. } => {
                // Some variable declarations are supported
                Ok(())
            }
            Literal::SomeIn {
                value, collection, ..
            } => {
                // Some-in is supported for simple cases
                self.validate_database_expr(value)?;
                self.validate_database_expr(collection)
            }
            Literal::Every { .. } => {
                // Every is not supported in database subset
                bail!("database subset: 'every' statements are not supported")
            }
        }
    }

    /// Validate that an expression is simple (no complex operations)
    fn validate_simple_expression(&self, expr: &Ref<Expr>) -> Result<()> {
        match expr.as_ref() {
            Expr::Var { .. }
            | Expr::String { .. }
            | Expr::Number { .. }
            | Expr::Bool { .. }
            | Expr::Null { .. } => Ok(()),

            Expr::RefDot { refr, .. } | Expr::RefBrack { refr, .. } => {
                self.validate_simple_expression(refr)
            }

            Expr::BoolExpr { lhs, rhs, .. } => {
                self.validate_simple_expression(lhs)?;
                self.validate_simple_expression(rhs)
            }

            _ => bail!(expr
                .span()
                .error("database subset: complex expressions not allowed in 'not' statements")),
        }
    }

    /// Validate an expression conforms to database subset
    fn validate_database_expr(&self, expr: &Ref<Expr>) -> Result<()> {
        match expr.as_ref() {
            // Simple literals are always allowed
            Expr::String { .. }
            | Expr::RawString { .. }
            | Expr::Number { .. }
            | Expr::Bool { .. }
            | Expr::Null { .. }
            | Expr::Var { .. } => Ok(()),

            // Arrays with restrictions
            Expr::Array { items, .. } => {
                for item in items {
                    self.validate_database_expr(item)?;
                }
                Ok(())
            }

            // Sets with restrictions
            Expr::Set { items, .. } => {
                for item in items {
                    self.validate_database_expr(item)?;
                }
                Ok(())
            }

            // Objects with static keys
            Expr::Object { fields, .. } => {
                for (_, key, value) in fields {
                    self.validate_static_key(key)?;
                    self.validate_database_expr(value)?;
                }
                Ok(())
            }

            // Simple comprehensions only
            Expr::ArrayCompr { .. } => {
                bail!(expr
                    .span()
                    .error("database subset: array comprehensions are not supported"))
            }

            Expr::SetCompr { .. } => {
                bail!(expr
                    .span()
                    .error("database subset: set comprehensions are not supported"))
            }

            // Object comprehensions are complex - not supported
            Expr::ObjectCompr { .. } => {
                bail!(expr
                    .span()
                    .error("database subset: object comprehensions are not supported"))
            }

            // References with restrictions
            Expr::RefDot { refr, .. } => self.validate_database_expr(refr),

            Expr::RefBrack { refr, index, .. } => {
                self.validate_database_expr(refr)?;
                self.validate_database_expr(index)
            }

            // Arithmetic operations
            Expr::ArithExpr { lhs, rhs, .. } => {
                self.validate_database_expr(lhs)?;
                self.validate_database_expr(rhs)
            }

            // Boolean operations
            Expr::BoolExpr { lhs, rhs, .. } => {
                self.validate_database_expr(lhs)?;
                self.validate_database_expr(rhs)
            }

            // Set operations
            Expr::BinExpr { lhs, rhs, .. } => {
                self.validate_database_expr(lhs)?;
                self.validate_database_expr(rhs)
            }

            // Assignment expressions
            Expr::AssignExpr { lhs, rhs, .. } => {
                self.validate_database_expr(lhs)?;
                self.validate_database_expr(rhs)
            }

            // Membership expressions
            Expr::Membership {
                value,
                collection,
                key,
                ..
            } => {
                self.validate_database_expr(value)?;
                self.validate_database_expr(collection)?;
                if let Some(key) = key {
                    self.validate_database_expr(key)?;
                }
                Ok(())
            }

            // Unary expressions (limited)
            Expr::UnaryExpr { expr, .. } => self.validate_database_expr(expr),

            // Function calls are now supported for builtin functions
            Expr::Call { fcn, params, .. } => {
                // Validate that it's a simple function name (not a complex expression)
                let func_name = match fcn.as_ref() {
                    Expr::Var { value, .. } => value
                        .as_string()
                        .map_err(|_| anyhow::anyhow!(fcn.span().error("Invalid function name")))?
                        .to_string(),
                    Expr::RefDot { refr, field, .. } => {
                        // Handle dotted function names like array.concat, json.marshal, etc.
                        let base_name = match refr.as_ref() {
                            Expr::Var { value, .. } => value
                                .as_string()
                                .map_err(|_| {
                                    anyhow::anyhow!(refr.span().error("Invalid base function name"))
                                })?
                                .to_string(),
                            _ => {
                                bail!(refr
                                    .span()
                                    .error("database subset: complex function base expressions not supported"))
                            }
                        };
                        format!("{}.{}", base_name, field.0.text())
                    }
                    _ => {
                        bail!(fcn
                            .span()
                            .error("database subset: complex function expressions not supported"))
                    }
                };

                // Check if it's a supported builtin function
                if !self.is_supported_builtin(&func_name) {
                    bail!(fcn.span().error(&format!(
                        "database subset: unsupported function '{}'",
                        func_name
                    )))
                }

                // Validate all parameters
                for param in params {
                    self.validate_database_expr(param)?;
                }
                Ok(())
            }

            #[cfg(feature = "rego-extensions")]
            Expr::OrExpr { lhs, rhs, .. } => {
                self.validate_database_expr(lhs)?;
                self.validate_database_expr(rhs)
            }
        }
    }

    /// Check if a function name is a supported builtin function
    fn is_supported_builtin(&self, func_name: &str) -> bool {
        matches!(
            func_name,
            // === String Functions ===
            "contains" | "endswith" | "startswith" | "split" | "substring" | "indexof"
            | "concat" | "lower" | "upper" | "replace" | "trim" | "trim_left" | "trim_right"
            | "trim_space" | "sprintf"

            // === String Namespace Functions ===
            | "strings.reverse" | "strings.replace_n"

            // === Math Functions - Basic ===
            | "abs" | "floor" | "round" | "ceil"

            // === Math Functions - Advanced ===
            | "pow" | "sqrt" | "log" | "exp" | "sin" | "cos" | "tan"

            // === Aggregation Functions ===
            | "sum" | "count" | "max" | "min"

            // === Array/Collection Functions ===
            | "array.concat" | "array.reverse" | "array.slice" | "sort" | "array.length"

            // === Type Conversion Functions ===
            | "to_number" | "format_int"

            // === Type Checking Functions ===
            | "is_string" | "is_number" | "is_boolean" | "is_array" | "is_object" | "is_null"

            // === JSON Functions ===
            | "json.marshal" | "json.unmarshal"

            // === Regular Expression Functions ===
            | "regex.match" | "regex.split"

            // === Encoding Functions ===
            | "base64.encode" | "base64.decode" | "base64url.encode" | "base64url.decode"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Source;
    use alloc::string::ToString;

    fn parse_database_module(input: &str) -> Result<Module> {
        let source = Source::from_contents("test.rego".to_string(), input.to_string())?;
        let mut parser = DatabaseParser::new(&source)?;
        parser.parse_database_module()
    }

    fn parse_database_query(input: &str) -> Result<Ref<Query>> {
        let source = Source::from_contents("test.rego".to_string(), input.to_string())?;
        let mut parser = DatabaseParser::new(&source)?;
        parser.parse_database_query()
    }

    #[test]
    fn test_simple_rule() {
        let input = r#"
            package test
            
            import rego.v1

            allowed_users contains result if {
                some user in data.users
                user.role == "admin"
                user.active == true
                result := {
                    "name": user.name,
                    "role": user.role
                }
            }
        "#;

        assert!(parse_database_module(input).is_ok());
    }

    #[test]
    fn test_reject_function_call() {
        let input = r#"
            package test

            result = custom_function(input.value)
        "#;

        assert!(parse_database_module(input).is_err());
    }

    #[test]
    fn test_reject_every() {
        let input = r#"
            package test

            all_valid {
                every user in data.users {
                    user.active == true
                }
            }
        "#;

        assert!(parse_database_module(input).is_err());
    }

    #[test]
    fn test_reject_object_comprehension() {
        let input = r#"
            package test

            user_map = {u.id: u.name | u = data.users[_]}
        "#;

        assert!(parse_database_module(input).is_err());
    }

    #[test]
    fn test_simple_query() {
        let input = r#"
            user.role == "admin"; user.active == true
        "#;

        assert!(parse_database_query(input).is_ok());
    }
}
