// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure RBAC AST (Abstract Syntax Tree) definitions
//!
//! This module defines the AST structures for representing Azure RBAC policies,
//! including role definitions, role assignments, and condition expressions.

use crate::value::Value;
use crate::*;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Empty span placeholder since we don't need spans for RBAC
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct EmptySpan;

/// Root RBAC policy structure
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RbacPolicy {
    pub span: EmptySpan,
    pub version: String,
    pub role_definitions: Vec<RoleDefinition>,
    pub role_assignments: Vec<RoleAssignment>,
}

/// Role definition - defines what actions can be performed
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoleDefinition {
    pub span: EmptySpan,
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub role_type: RoleType,
    pub permissions: Vec<Permission>,
    pub assignable_scopes: Vec<String>,
}

/// Role type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RoleType {
    BuiltInRole,
    CustomRole,
}

/// Permission set - defines actions that are allowed/denied
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Permission {
    pub span: EmptySpan,
    pub actions: Vec<String>,
    pub not_actions: Vec<String>,
    pub data_actions: Vec<String>,
    pub not_data_actions: Vec<String>,
}

/// Role assignment - assigns a role to a principal at a scope
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub span: EmptySpan,
    pub id: String,
    pub principal_id: String,
    pub principal_type: PrincipalType,
    pub role_definition_id: String,
    pub scope: String,
    pub condition: Option<ConditionExpression>,
    pub condition_version: Option<String>,
}

/// Principal type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PrincipalType {
    User,
    Group,
    ServicePrincipal,
    ManagedServiceIdentity,
}

/// ABAC condition expression
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConditionExpression {
    pub span: EmptySpan,
    pub raw_expression: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expression: Option<ConditionExpr>,
}

impl ConditionExpression {
    pub fn new(span: EmptySpan, expression: String) -> Self {
        Self {
            span,
            raw_expression: expression,
            expression: None,
        }
    }

    pub fn with_parsed(
        span: EmptySpan,
        raw_expression: String,
        parsed: ConditionExpr,
    ) -> Self {
        Self {
            span,
            raw_expression,
            expression: Some(parsed),
        }
    }
}

/// Condition expression node
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ConditionExpr {
    #[serde(rename = "LogicalExpression")]
    Logical(LogicalExpression),
    #[serde(rename = "UnaryExpression")]
    Unary(UnaryExpression),
    #[serde(rename = "BinaryExpression")]
    Binary(BinaryExpression),
    #[serde(rename = "FunctionCall")]
    FunctionCall(FunctionCallExpression),
    #[serde(rename = "AttributeReference")]
    AttributeReference(AttributeReference),
    #[serde(rename = "ArrayExpression")]
    ArrayExpression(ArrayExpression),
    #[serde(rename = "Identifier")]
    Identifier(IdentifierExpression),
    #[serde(rename = "VariableReference")]
    VariableReference(VariableReference),
    #[serde(rename = "PropertyAccess")]
    PropertyAccess(PropertyAccessExpression),
    #[serde(rename = "StringLiteral")]
    StringLiteral(StringLiteral),
    #[serde(rename = "NumberLiteral")]
    NumberLiteral(NumberLiteral),
    #[serde(rename = "BooleanLiteral")]
    BooleanLiteral(BooleanLiteral),
    #[serde(rename = "NullLiteral")]
    NullLiteral(NullLiteral),
    #[serde(rename = "DateTimeLiteral")]
    DateTimeLiteral(DateTimeLiteral),
    #[serde(rename = "TimeLiteral")]
    TimeLiteral(TimeLiteral),
    #[serde(rename = "SetLiteral")]
    SetLiteral(SetLiteral),
    #[serde(rename = "ListLiteral")]
    ListLiteral(ListLiteral),
}

/// Logical (AND/OR) expression
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogicalExpression {
    pub span: EmptySpan,
    pub operator: LogicalOperator,
    pub left: Box<ConditionExpr>,
    pub right: Box<ConditionExpr>,
}

/// Logical operator kinds
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LogicalOperator {
    And,
    Or,
}

/// Unary expression (e.g., NOT)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnaryExpression {
    pub span: EmptySpan,
    pub operator: UnaryOperator,
    pub operand: Box<ConditionExpr>,
}

/// Unary operator kinds
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnaryOperator {
    Not,
    Exists,
    NotExists,
}

/// Binary expression with an operator and two operands
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BinaryExpression {
    pub span: EmptySpan,
    pub operator: ConditionOperator,
    pub left: Box<ConditionExpr>,
    pub right: Box<ConditionExpr>,
}

/// Condition operator wrapper (e.g. StringEquals, NumericGreaterThan)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConditionOperator {
    pub name: String,
}

/// Function call expression (e.g. ToLower(expr))
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionCallExpression {
    pub span: EmptySpan,
    pub function: String,
    pub arguments: Vec<ConditionExpr>,
}

/// Array expression with quantifiers (e.g. ANY tag : ...)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArrayExpression {
    pub span: EmptySpan,
    pub operator: ArrayOperator,
    pub array: Box<ConditionExpr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variable: Option<String>,
    pub condition: Box<ConditionExpr>,
}

/// Array operator descriptor (e.g. ANY, ForAnyOfAnyValues:StringEquals)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArrayOperator {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modifier: Option<String>,
}

/// Attribute reference like @Request[namespace:attribute]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttributeReference {
    pub span: EmptySpan,
    pub source: AttributeSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub attribute: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<AttributePathSegment>,
}

/// Source of an attribute reference
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AttributeSource {
    Request,
    Resource,
    Principal,
    Environment,
    Context,
}

/// A segment of an attribute path (e.g. metadata, 0, category)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AttributePathSegment {
    Key(String),
    Index(usize),
}

/// Identifier expression (unqualified name)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentifierExpression {
    pub span: EmptySpan,
    pub name: String,
}

/// Variable reference (e.g. loop variable in ANY clauses)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VariableReference {
    pub span: EmptySpan,
    pub name: String,
}

/// Property access expression (e.g. tag.key)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PropertyAccessExpression {
    pub span: EmptySpan,
    pub object: Box<ConditionExpr>,
    pub property: String,
}

/// String literal value
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StringLiteral {
    pub span: EmptySpan,
    pub value: String,
}

/// Number literal value (keeps raw representation)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NumberLiteral {
    pub span: EmptySpan,
    pub raw: String,
}

/// Boolean literal value
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BooleanLiteral {
    pub span: EmptySpan,
    pub value: bool,
}

/// Null literal
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NullLiteral {
    pub span: EmptySpan,
}

/// Date-time literal value (ISO-8601 formatted)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DateTimeLiteral {
    pub span: EmptySpan,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized: Option<String>,
}

/// Time literal value (HH:MM or HH:MM:SS)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimeLiteral {
    pub span: EmptySpan,
    pub value: String,
}

/// Set literal value (e.g. {'a', 'b'})
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SetLiteral {
    pub span: EmptySpan,
    pub elements: Vec<ConditionExpr>,
}

/// List literal value (e.g. ['start', 'end'])
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListLiteral {
    pub span: EmptySpan,
    pub elements: Vec<ConditionExpr>,
}

/// Evaluation context - what information is available when evaluating RBAC policies
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvaluationContext {
    pub principal: Principal,
    pub resource: Resource,
    pub request: RequestContext,
    pub environment: EnvironmentContext,
    pub action: Option<String>,
    pub suboperation: Option<String>,
}

/// Principal information (user, group, service principal, etc.)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Principal {
    pub id: String,
    pub principal_type: PrincipalType,
    pub custom_security_attributes: Value,
}

/// Resource information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    pub id: String,
    pub resource_type: String,
    pub scope: String,
    pub attributes: Value,
}

/// Request context information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestContext {
    pub action: Option<String>,
    pub data_action: Option<String>,
    pub attributes: Value,
}

/// Environment context information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentContext {
    pub is_private_link: Option<bool>,
    pub private_endpoint: Option<String>,
    pub subnet: Option<String>,
    pub utc_now: Option<String>,
}

/// Result of RBAC policy evaluation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EvaluationResult {
    Allow,
    Deny,
    NotApplicable,
}

impl Default for RbacPolicy {
    fn default() -> Self {
        Self {
            span: EmptySpan::default(),
            version: "2.0".to_string(),
            role_definitions: Vec::new(),
            role_assignments: Vec::new(),
        }
    }
}
