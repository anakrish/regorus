// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure RBAC policy parser
//!
//! This module provides functionality to parse Azure RBAC policies from JSON format
//! into the RBAC AST representation, including parsing of ABAC condition expressions.

use crate::lexer::{Lexer, Source, Token, TokenKind};
use crate::rbac::ast::*;
use crate::*;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde_json;

/// Error types for RBAC parsing
#[derive(Debug, Clone)]
pub enum RbacParseError {
    InvalidJson(String),
    MissingField(String),
    InvalidFieldType(String),
    UnsupportedCondition(String),
}

impl core::fmt::Display for RbacParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RbacParseError::InvalidJson(msg) => write!(f, "Invalid JSON: {}", msg),
            RbacParseError::MissingField(field) => write!(f, "Missing required field: {}", field),
            RbacParseError::InvalidFieldType(field) => write!(f, "Invalid field type: {}", field),
            RbacParseError::UnsupportedCondition(expr) => {
                write!(f, "Unsupported condition expression: {}", expr)
            }
        }
    }
}

/// RBAC policy parser
pub struct RbacParser;

impl RbacParser {
    /// Parse an RBAC policy from JSON string
    pub fn parse_policy(input: &str) -> Result<RbacPolicy, RbacParseError> {
        let json_value: serde_json::Value =
            serde_json::from_str(input).map_err(|e| RbacParseError::InvalidJson(e.to_string()))?;

        Self::parse_policy_from_json(&json_value, EmptySpan::default())
    }

    /// Parse RBAC policy from JSON value
    fn parse_policy_from_json(
        json: &serde_json::Value,
        span: EmptySpan,
    ) -> Result<RbacPolicy, RbacParseError> {
        let obj = json
            .as_object()
            .ok_or_else(|| RbacParseError::InvalidFieldType("root object".to_string()))?;

        // Extract version (default to "2.0" if not specified)
        let version = obj
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("2.0")
            .to_string();

        // Parse role definitions
        let role_definitions = if let Some(role_defs) = obj.get("roleDefinitions") {
            Self::parse_role_definitions(role_defs)?
        } else {
            Vec::new()
        };

        // Parse role assignments
        let role_assignments = if let Some(role_assigns) = obj.get("roleAssignments") {
            Self::parse_role_assignments(role_assigns)?
        } else {
            Vec::new()
        };

        Ok(RbacPolicy {
            span,
            version,
            role_definitions,
            role_assignments,
        })
    }

    /// Parse role definitions array
    fn parse_role_definitions(
        json: &serde_json::Value,
    ) -> Result<Vec<RoleDefinition>, RbacParseError> {
        let array = json
            .as_array()
            .ok_or_else(|| RbacParseError::InvalidFieldType("roleDefinitions".to_string()))?;

        array
            .iter()
            .map(|item| Self::parse_role_definition(item))
            .collect()
    }

    /// Parse a single role definition
    fn parse_role_definition(json: &serde_json::Value) -> Result<RoleDefinition, RbacParseError> {
        let obj = json
            .as_object()
            .ok_or_else(|| RbacParseError::InvalidFieldType("role definition".to_string()))?;

        let id = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RbacParseError::MissingField("id".to_string()))?
            .to_string();

        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RbacParseError::MissingField("name".to_string()))?
            .to_string();

        let description = obj
            .get("description")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let role_type = obj
            .get("type")
            .and_then(|v| v.as_str())
            .map(|s| match s {
                "BuiltInRole" => RoleType::BuiltInRole,
                _ => RoleType::CustomRole,
            })
            .unwrap_or(RoleType::CustomRole);

        let permissions = if let Some(perms) = obj.get("permissions") {
            Self::parse_permissions(perms)?
        } else {
            Vec::new()
        };

        let assignable_scopes = if let Some(scopes) = obj.get("assignableScopes") {
            Self::parse_string_array(scopes, "assignableScopes")?
        } else {
            Vec::new()
        };

        Ok(RoleDefinition {
            span: EmptySpan::default(),
            id,
            name,
            description,
            role_type,
            permissions,
            assignable_scopes,
        })
    }

    /// Parse permissions array
    fn parse_permissions(json: &serde_json::Value) -> Result<Vec<Permission>, RbacParseError> {
        let array = json
            .as_array()
            .ok_or_else(|| RbacParseError::InvalidFieldType("permissions".to_string()))?;

        array
            .iter()
            .map(|item| Self::parse_permission(item))
            .collect()
    }

    /// Parse a single permission
    fn parse_permission(json: &serde_json::Value) -> Result<Permission, RbacParseError> {
        let obj = json
            .as_object()
            .ok_or_else(|| RbacParseError::InvalidFieldType("permission".to_string()))?;

        let actions = if let Some(acts) = obj.get("actions") {
            Self::parse_string_array(acts, "actions")?
        } else {
            Vec::new()
        };

        let not_actions = if let Some(not_acts) = obj.get("notActions") {
            Self::parse_string_array(not_acts, "notActions")?
        } else {
            Vec::new()
        };

        let data_actions = if let Some(data_acts) = obj.get("dataActions") {
            Self::parse_string_array(data_acts, "dataActions")?
        } else {
            Vec::new()
        };

        let not_data_actions = if let Some(not_data_acts) = obj.get("notDataActions") {
            Self::parse_string_array(not_data_acts, "notDataActions")?
        } else {
            Vec::new()
        };

        Ok(Permission {
            span: EmptySpan::default(),
            actions,
            not_actions,
            data_actions,
            not_data_actions,
        })
    }

    /// Parse role assignments array
    fn parse_role_assignments(
        json: &serde_json::Value,
    ) -> Result<Vec<RoleAssignment>, RbacParseError> {
        let array = json
            .as_array()
            .ok_or_else(|| RbacParseError::InvalidFieldType("roleAssignments".to_string()))?;

        array
            .iter()
            .map(|item| Self::parse_role_assignment(item))
            .collect()
    }

    /// Parse a single role assignment
    fn parse_role_assignment(json: &serde_json::Value) -> Result<RoleAssignment, RbacParseError> {
        let obj = json
            .as_object()
            .ok_or_else(|| RbacParseError::InvalidFieldType("role assignment".to_string()))?;

        let id = obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RbacParseError::MissingField("id".to_string()))?
            .to_string();

        let principal_id = obj
            .get("principalId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RbacParseError::MissingField("principalId".to_string()))?
            .to_string();

        let principal_type = obj
            .get("principalType")
            .and_then(|v| v.as_str())
            .map(|s| match s {
                "User" => PrincipalType::User,
                "Group" => PrincipalType::Group,
                "ServicePrincipal" => PrincipalType::ServicePrincipal,
                "MSI" => PrincipalType::ManagedServiceIdentity,
                _ => PrincipalType::User,
            })
            .unwrap_or(PrincipalType::User);

        let role_definition_id = obj
            .get("roleDefinitionId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RbacParseError::MissingField("roleDefinitionId".to_string()))?
            .to_string();

        let scope = obj
            .get("scope")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RbacParseError::MissingField("scope".to_string()))?
            .to_string();

        let condition = if let Some(cond) = obj.get("condition") {
            if let Some(condition_str) = cond.as_str() {
                if !condition_str.is_empty() {
                    Some(ConditionExpression::new(
                        EmptySpan::default(),
                        condition_str.to_string(),
                    ))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let condition_version = obj
            .get("conditionVersion")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(RoleAssignment {
            span: EmptySpan::default(),
            id,
            principal_id,
            principal_type,
            role_definition_id,
            scope,
            condition,
            condition_version,
        })
    }

    /// Parse an array of strings
    fn parse_string_array(
        json: &serde_json::Value,
        field_name: &str,
    ) -> Result<Vec<String>, RbacParseError> {
        let array = json
            .as_array()
            .ok_or_else(|| RbacParseError::InvalidFieldType(field_name.to_string()))?;

        array
            .iter()
            .map(|item| {
                item.as_str()
                    .ok_or_else(|| RbacParseError::InvalidFieldType(format!("{} item", field_name)))
                    .map(|s| s.to_string())
            })
            .collect()
    }

    /// Parse a condition expression string into AST
    pub fn parse_condition_expression(
        condition_str: &str,
    ) -> Result<ConditionExpression, RbacParseError> {
        if condition_str.trim().is_empty() {
            return Err(RbacParseError::UnsupportedCondition(
                "Empty condition expression".to_string(),
            ));
        }

        let source = Source::from_contents("condition".to_string(), condition_str.to_string())
            .map_err(|e| RbacParseError::InvalidJson(e.to_string()))?;
        let parsed_expr = ConditionParser::parse(&source)?;

        Ok(ConditionExpression::with_parsed(
            EmptySpan::default(),
            condition_str.to_string(),
            parsed_expr,
        ))
    }
}

/// Condition expression parser
pub struct ConditionParser<'source> {
    lexer: Lexer<'source>,
    current: Token,
}

impl<'source> ConditionParser<'source> {
    /// Parse a condition expression from source
    pub fn parse(source: &'source Source) -> Result<ConditionExpr, RbacParseError> {
        let mut lexer = Lexer::new(source);
        lexer.set_enable_rbac_tokens(true);
        lexer.set_allow_single_quoted_strings(true);

        let current = lexer
            .next_token()
            .map_err(|e| RbacParseError::InvalidJson(e.to_string()))?;

        let mut parser = Self { lexer, current };
        parser.parse_or_expression()
    }

    /// Get current token text
    fn current_text(&self) -> &str {
        self.current.1.text()
    }

    /// Advance to next token
    fn advance(&mut self) -> Result<(), RbacParseError> {
        self.current = self
            .lexer
            .next_token()
            .map_err(|e| RbacParseError::InvalidJson(e.to_string()))?;
        Ok(())
    }

    /// Check if current token matches expected
    fn expect(&mut self, expected: TokenKind) -> Result<(), RbacParseError> {
        if self.current.0 != expected {
            return Err(RbacParseError::UnsupportedCondition(format!(
                "Expected {:?}, found {:?} at {}",
                expected,
                self.current.0,
                self.current_text()
            )));
        }
        self.advance()?;
        Ok(())
    }

    /// Parse OR expression (lowest precedence)
    fn parse_or_expression(&mut self) -> Result<ConditionExpr, RbacParseError> {
        let mut left = self.parse_and_expression()?;

        while self.current.0 == TokenKind::LogicalOr
            || (self.current.0 == TokenKind::Ident && self.current_text() == "OR")
        {
            self.advance()?;
            let right = self.parse_and_expression()?;
            left = ConditionExpr::Logical(LogicalExpression {
                span: EmptySpan,
                operator: LogicalOperator::Or,
                left: Box::new(left),
                right: Box::new(right),
            });
        }

        Ok(left)
    }

    /// Parse AND expression (higher precedence than OR)
    fn parse_and_expression(&mut self) -> Result<ConditionExpr, RbacParseError> {
        let mut left = self.parse_unary_expression()?;

        while self.current.0 == TokenKind::LogicalAnd
            || (self.current.0 == TokenKind::Ident && self.current_text() == "AND")
        {
            self.advance()?;
            let right = self.parse_unary_expression()?;
            left = ConditionExpr::Logical(LogicalExpression {
                span: EmptySpan,
                operator: LogicalOperator::And,
                left: Box::new(left),
                right: Box::new(right),
            });
        }

        Ok(left)
    }

    /// Parse unary expression (NOT, Exists)
    fn parse_unary_expression(&mut self) -> Result<ConditionExpr, RbacParseError> {
        if self.current.0 == TokenKind::Ident {
            let text = self.current_text();
            match text {
                "NOT" | "!" => {
                    self.advance()?;
                    let operand = self.parse_unary_expression()?;
                    return Ok(ConditionExpr::Unary(UnaryExpression {
                        span: EmptySpan,
                        operator: UnaryOperator::Not,
                        operand: Box::new(operand),
                    }));
                }
                "Exists" => {
                    self.advance()?;
                    let operand = self.parse_primary_expression()?;
                    return Ok(ConditionExpr::Unary(UnaryExpression {
                        span: EmptySpan,
                        operator: UnaryOperator::Exists,
                        operand: Box::new(operand),
                    }));
                }
                "NotExists" => {
                    self.advance()?;
                    let operand = self.parse_primary_expression()?;
                    return Ok(ConditionExpr::Unary(UnaryExpression {
                        span: EmptySpan,
                        operator: UnaryOperator::NotExists,
                        operand: Box::new(operand),
                    }));
                }
                _ => {}
            }
        }

        self.parse_comparison_expression()
    }

    /// Parse comparison/binary expression
    fn parse_comparison_expression(&mut self) -> Result<ConditionExpr, RbacParseError> {
        let left = self.parse_primary_expression()?;

        // Check for binary operator
        if self.current.0 == TokenKind::Ident {
            let op_text = self.current_text().to_string();

            // Check if this is a known operator
            if self.is_binary_operator(&op_text) {
                self.advance()?;
                let right = self.parse_primary_expression()?;
                return Ok(ConditionExpr::Binary(BinaryExpression {
                    span: EmptySpan,
                    operator: ConditionOperator { name: op_text },
                    left: Box::new(left),
                    right: Box::new(right),
                }));
            }
        }

        Ok(left)
    }

    /// Check if identifier is a binary operator
    fn is_binary_operator(&self, op: &str) -> bool {
        matches!(
            op,
            "StringEquals"
                | "StringNotEquals"
                | "StringEqualsIgnoreCase"
                | "StringNotEqualsIgnoreCase"
                | "StringLike"
                | "StringNotLike"
                | "StringStartsWith"
                | "StringNotStartsWith"
                | "StringEndsWith"
                | "StringNotEndsWith"
                | "StringContains"
                | "StringNotContains"
                | "StringMatches"
                | "StringNotMatches"
                | "NumericEquals"
                | "NumericNotEquals"
                | "NumericLessThan"
                | "NumericLessThanEquals"
                | "NumericGreaterThan"
                | "NumericGreaterThanEquals"
                | "NumericInRange"
                | "BoolEquals"
                | "BoolNotEquals"
                | "DateTimeEquals"
                | "DateTimeNotEquals"
                | "DateTimeGreaterThan"
                | "DateTimeGreaterThanEquals"
                | "DateTimeLessThan"
                | "DateTimeLessThanEquals"
                | "TimeOfDayEquals"
                | "TimeOfDayNotEquals"
                | "TimeOfDayGreaterThan"
                | "TimeOfDayGreaterThanEquals"
                | "TimeOfDayLessThan"
                | "TimeOfDayLessThanEquals"
                | "TimeOfDayInRange"
                | "GuidEquals"
                | "GuidNotEquals"
                | "IpMatch"
                | "IpNotMatch"
                | "IpInRange"
                | "ListContains"
                | "ListNotContains"
                | "ForAnyOfAnyValues"
                | "ForAllOfAnyValues"
                | "ForAnyOfAllValues"
                | "ForAllOfAllValues"
                | "ActionMatches"
                | "SubOperationMatches"
        )
    }

    /// Parse primary expression (literals, attribute refs, function calls, parentheses)
    fn parse_primary_expression(&mut self) -> Result<ConditionExpr, RbacParseError> {
        match self.current.0 {
            // Parenthesized expression
            TokenKind::Symbol if self.current_text() == "(" => {
                self.advance()?;
                let expr = self.parse_or_expression()?;
                self.expect_symbol(")")?;
                Ok(expr)
            }

            // Attribute reference (@Source[...])
            TokenKind::At => self.parse_attribute_reference(),

            // String literal
            TokenKind::String => {
                let value = self.current_text().to_string();
                self.advance()?;
                Ok(ConditionExpr::StringLiteral(StringLiteral {
                    span: EmptySpan,
                    value,
                }))
            }

            // Raw string literal
            TokenKind::RawString => {
                let value = self.current_text().to_string();
                self.advance()?;
                Ok(ConditionExpr::StringLiteral(StringLiteral {
                    span: EmptySpan,
                    value,
                }))
            }

            // Number literal
            TokenKind::Number => {
                let raw = self.current_text().to_string();
                self.advance()?;
                Ok(ConditionExpr::NumberLiteral(NumberLiteral {
                    span: EmptySpan,
                    raw,
                }))
            }

            // Set literal {'a', 'b', 'c'}
            TokenKind::Symbol if self.current_text() == "{" => self.parse_set_literal(),

            // List literal ['a', 'b']
            TokenKind::Symbol if self.current_text() == "[" => self.parse_list_literal(),

            // Identifier (function call, boolean, identifier)
            TokenKind::Ident => {
                let text = self.current_text();
                match text {
                    "true" => {
                        self.advance()?;
                        Ok(ConditionExpr::BooleanLiteral(BooleanLiteral {
                            span: EmptySpan,
                            value: true,
                        }))
                    }
                    "false" => {
                        self.advance()?;
                        Ok(ConditionExpr::BooleanLiteral(BooleanLiteral {
                            span: EmptySpan,
                            value: false,
                        }))
                    }
                    "null" => {
                        self.advance()?;
                        Ok(ConditionExpr::NullLiteral(NullLiteral { span: EmptySpan }))
                    }
                    _ => {
                        let name = text.to_string();
                        self.advance()?;

                        // Check for function call
                        if self.current.0 == TokenKind::Symbol && self.current_text() == "(" {
                            self.parse_function_call(name)
                        } else {
                            // Just an identifier
                            Ok(ConditionExpr::Identifier(IdentifierExpression {
                                span: EmptySpan,
                                name,
                            }))
                        }
                    }
                }
            }

            _ => Err(RbacParseError::UnsupportedCondition(format!(
                "Unexpected token: {:?} '{}'",
                self.current.0,
                self.current_text()
            ))),
        }
    }

    /// Parse attribute reference @Source[namespace:attribute]
    fn parse_attribute_reference(&mut self) -> Result<ConditionExpr, RbacParseError> {
        self.expect(TokenKind::At)?;

        // Parse source (Request, Resource, Principal, Environment, Context)
        if self.current.0 != TokenKind::Ident {
            return Err(RbacParseError::UnsupportedCondition(
                "Expected attribute source after @".to_string(),
            ));
        }

        let source_text = self.current_text();
        let source = match source_text {
            "Request" => AttributeSource::Request,
            "Resource" => AttributeSource::Resource,
            "Principal" => AttributeSource::Principal,
            "Environment" => AttributeSource::Environment,
            "Context" => AttributeSource::Context,
            _ => {
                return Err(RbacParseError::UnsupportedCondition(format!(
                    "Unknown attribute source: {}",
                    source_text
                )))
            }
        };
        self.advance()?;

        // Expect [
        self.expect_symbol("[")?;

        // Parse namespace:attribute or just attribute
        let mut namespace = None;

        // Read until ] - this handles namespace:attribute and complex paths
        let mut parts = Vec::new();
        loop {
            match self.current.0 {
                TokenKind::Symbol if self.current_text() == "]" => break,
                TokenKind::Symbol if self.current_text() == ":" => {
                    // Colon separator
                    parts.push(":".to_string());
                    self.advance()?;
                }
                TokenKind::Ident | TokenKind::String | TokenKind::Symbol => {
                    parts.push(self.current_text().to_string());
                    self.advance()?;
                }
                _ => {
                    return Err(RbacParseError::UnsupportedCondition(format!(
                        "Unexpected token in attribute reference: {:?}",
                        self.current.0
                    )))
                }
            }
        }

        // Join parts and split on last colon
        let full_path = parts.join("");
        let attribute = if let Some(colon_pos) = full_path.rfind(':') {
            namespace = Some(full_path[..colon_pos].to_string());
            full_path[colon_pos + 1..].to_string()
        } else {
            full_path
        };

        self.expect_symbol("]")?;

        Ok(ConditionExpr::AttributeReference(AttributeReference {
            span: EmptySpan,
            source,
            namespace,
            attribute,
            path: Vec::new(), // Path parsing can be added later if needed
        }))
    }

    /// Parse function call
    fn parse_function_call(&mut self, function: String) -> Result<ConditionExpr, RbacParseError> {
        self.expect_symbol("(")?;

        let mut arguments = Vec::new();

        // Parse arguments
        if self.current.0 != TokenKind::Symbol || self.current_text() != ")" {
            loop {
                let arg = self.parse_or_expression()?;
                arguments.push(arg);

                if self.current.0 == TokenKind::Symbol && self.current_text() == "," {
                    self.advance()?;
                } else {
                    break;
                }
            }
        }

        self.expect_symbol(")")?;

        Ok(ConditionExpr::FunctionCall(FunctionCallExpression {
            span: EmptySpan,
            function,
            arguments,
        }))
    }

    /// Parse set literal {'a', 'b', 'c'}
    fn parse_set_literal(&mut self) -> Result<ConditionExpr, RbacParseError> {
        self.expect_symbol("{")?;

        let mut elements = Vec::new();

        if self.current.0 != TokenKind::Symbol || self.current_text() != "}" {
            loop {
                let elem = self.parse_or_expression()?;
                elements.push(elem);

                if self.current.0 == TokenKind::Symbol && self.current_text() == "," {
                    self.advance()?;
                } else {
                    break;
                }
            }
        }

        self.expect_symbol("}")?;

        Ok(ConditionExpr::SetLiteral(SetLiteral {
            span: EmptySpan,
            elements,
        }))
    }

    /// Parse list literal ['a', 'b']
    fn parse_list_literal(&mut self) -> Result<ConditionExpr, RbacParseError> {
        self.expect_symbol("[")?;

        let mut elements = Vec::new();

        if self.current.0 != TokenKind::Symbol || self.current_text() != "]" {
            loop {
                let elem = self.parse_or_expression()?;
                elements.push(elem);

                if self.current.0 == TokenKind::Symbol && self.current_text() == "," {
                    self.advance()?;
                } else {
                    break;
                }
            }
        }

        self.expect_symbol("]")?;

        Ok(ConditionExpr::ListLiteral(ListLiteral {
            span: EmptySpan,
            elements,
        }))
    }

    /// Expect a specific symbol
    fn expect_symbol(&mut self, expected: &str) -> Result<(), RbacParseError> {
        if self.current.0 != TokenKind::Symbol || self.current_text() != expected {
            return Err(RbacParseError::UnsupportedCondition(format!(
                "Expected '{}', found '{}'",
                expected,
                self.current_text()
            )));
        }
        self.advance()?;
        Ok(())
    }
}
