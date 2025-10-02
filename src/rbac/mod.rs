// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure RBAC (Role-Based Access Control) support for Regorus
//!
//! This module provides comprehensive support for Azure RBAC policies, including:
//! - Parsing Azure RBAC policies from JSON format
//! - Compiling RBAC policies to Regorus RVM bytecode
//! - Evaluating RBAC conditions and assignments
//! - Supporting Azure RBAC condition expression language (ABAC)
//!
//! # Azure RBAC Overview
//!
//! Azure RBAC provides fine-grained access management for Azure resources using:
//! - **Role Definitions**: Define what actions can be performed
//! - **Role Assignments**: Assign roles to principals (users, groups, service principals)
//! - **Scopes**: Define where the role assignment applies (subscription, resource group, resource)
//! - **Conditions**: Optional ABAC conditions using Azure's condition expression language
//!
//! # Usage
//!
//! ```rust
//! use regorus::rbac::{RbacParser, RbacCompiler};
//!
//! // Parse RBAC policy from JSON
//! let policy = RbacParser::parse_policy(json_string)?;
//!
//! // Compile to RVM instructions
//! let instructions = RbacCompiler::compile(&policy)?;
//! ```
//!
//! # Azure RBAC Condition Expression Language
//!
//! Azure RBAC supports ABAC (Attribute-Based Access Control) through condition expressions:
//!
//! - **Functions**: `ActionMatches()`, `SubOperationMatches()`, `Exists()`
//! - **Logical Operators**: `&&` (AND), `||` (OR), `!` (NOT)
//! - **Comparison Operators**: `==`, `!=`, `<`, `>`, `<=`, `>=`
//! - **Cross-Product Operators**: `ForAnyOfAnyValues:*`, `ForAllOfAnyValues:*`, etc.
//! - **Attribute Sources**: `@Environment`, `@Principal`, `@Request`, `@Resource`
//!
//! Note: Condition expression parsing is initially not implemented and will raise errors
//! as specified in the requirements.

pub mod ast;
pub mod compiler;
pub mod parser;
#[cfg(feature = "yaml")]
pub mod test_runner;

pub use ast::*;
pub use compiler::*;
pub use parser::*;
#[cfg(feature = "yaml")]
pub use test_runner::*;

use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};

/// RBAC evaluation engine
pub struct RbacEngine;

impl RbacEngine {
    /// Evaluate an RBAC policy against an evaluation context
    pub fn evaluate(
        policy: &RbacPolicy,
        context: &EvaluationContext,
    ) -> Result<bool, RbacCompileError> {
        // Check each role assignment
        for assignment in &policy.role_assignments {
            if RbacCompiler::matches_assignment(assignment, context) {
                // Find the role definition
                if let Some(role_def) = policy
                    .role_definitions
                    .iter()
                    .find(|rd| rd.id == assignment.role_definition_id)
                {
                    // Check if the requested action is allowed
                    let permissions = RbacCompiler::get_role_permissions(role_def);
                    for permission in permissions {
                        if let Some(action) = &context.request.action {
                            if RbacCompiler::action_allowed(permission, action) {
                                return Ok(true);
                            }
                        }
                        if let Some(data_action) = &context.request.data_action {
                            if RbacCompiler::data_action_allowed(permission, data_action) {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    /// Parse and compile RBAC policy from JSON
    pub fn compile_from_json(json: &str) -> Result<Vec<crate::rvm::Instruction>, RbacCompileError> {
        let policy = RbacParser::parse_policy(json)
            .map_err(|e| RbacCompileError::CompilationError(e.to_string()))?;

        RbacCompiler::compile(&policy)
    }

    /// Create a simple evaluation context for testing
    pub fn create_test_context(
        principal_id: &str,
        principal_type: PrincipalType,
        resource_scope: &str,
        action: Option<&str>,
        data_action: Option<&str>,
    ) -> EvaluationContext {
        EvaluationContext {
            principal: Principal {
                id: principal_id.to_string(),
                principal_type,
                custom_security_attributes: crate::Value::new_object(),
            },
            resource: Resource {
                id: format!("{}/resource", resource_scope),
                resource_type: "Microsoft.Storage/storageAccounts".to_string(),
                scope: resource_scope.to_string(),
                attributes: crate::Value::new_object(),
            },
            request: RequestContext {
                action: action.map(|s| s.to_string()),
                data_action: data_action.map(|s| s.to_string()),
                attributes: crate::Value::new_object(),
            },
            environment: EnvironmentContext {
                is_private_link: None,
                private_endpoint: None,
                subnet: None,
                utc_now: None,
            },
            action: action.map(|s| s.to_string()),
            suboperation: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_rbac_parser_basic() {
        let json = r#"{
            "version": "2.0",
            "roleDefinitions": [{
                "id": "role1",
                "name": "Storage Blob Data Reader",
                "type": "BuiltInRole",
                "permissions": [{
                    "actions": ["Microsoft.Storage/storageAccounts/blobServices/containers/read"],
                    "dataActions": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"]
                }]
            }],
            "roleAssignments": [{
                "id": "assignment1",
                "principalId": "user123",
                "principalType": "User", 
                "roleDefinitionId": "role1",
                "scope": "/subscriptions/sub1/resourceGroups/rg1"
            }]
        }"#;

        let policy = RbacParser::parse_policy(json).expect("Failed to parse policy");
        assert_eq!(policy.version, "2.0");
        assert_eq!(policy.role_definitions.len(), 1);
        assert_eq!(policy.role_assignments.len(), 1);

        let role_def = &policy.role_definitions[0];
        assert_eq!(role_def.name, "Storage Blob Data Reader");
        assert_eq!(role_def.permissions.len(), 1);

        let assignment = &policy.role_assignments[0];
        assert_eq!(assignment.principal_id, "user123");
        assert_eq!(assignment.principal_type, PrincipalType::User);
    }

    #[test]
    fn test_rbac_compiler_basic() {
        let policy = RbacPolicy {
            span: EmptySpan::default(),
            version: "2.0".to_string(),
            role_definitions: vec![RoleDefinition {
                span: EmptySpan::default(),
                id: "role1".to_string(),
                name: "Test Role".to_string(),
                description: None,
                role_type: RoleType::CustomRole,
                permissions: vec![],
                assignable_scopes: vec![],
            }],
            role_assignments: vec![RoleAssignment {
                span: EmptySpan::default(),
                id: "assignment1".to_string(),
                principal_id: "user123".to_string(),
                principal_type: PrincipalType::User,
                role_definition_id: "role1".to_string(),
                scope: "/subscriptions/sub1".to_string(),
                condition: None,
                condition_version: None,
            }],
        };

        let instructions = RbacCompiler::compile(&policy).expect("Failed to compile policy");
        assert!(!instructions.is_empty());
    }

    #[test]
    fn test_rbac_engine_evaluation() {
        let policy = RbacPolicy {
            span: EmptySpan::default(),
            version: "2.0".to_string(),
            role_definitions: vec![RoleDefinition {
                span: EmptySpan::default(),
                id: "role1".to_string(),
                name: "Test Role".to_string(),
                description: None,
                role_type: RoleType::CustomRole,
                permissions: vec![Permission {
                    span: EmptySpan::default(),
                    actions: vec!["Microsoft.Storage/*/read".to_string()],
                    not_actions: vec![],
                    data_actions: vec![],
                    not_data_actions: vec![],
                }],
                assignable_scopes: vec![],
            }],
            role_assignments: vec![RoleAssignment {
                span: EmptySpan::default(),
                id: "assignment1".to_string(),
                principal_id: "user123".to_string(),
                principal_type: PrincipalType::User,
                role_definition_id: "role1".to_string(),
                scope: "/subscriptions/sub1".to_string(),
                condition: None,
                condition_version: None,
            }],
        };

        let context = RbacEngine::create_test_context(
            "user123",
            PrincipalType::User,
            "/subscriptions/sub1/resourceGroups/rg1",
            Some("Microsoft.Storage/storageAccounts/read"),
            None,
        );

        let result = RbacEngine::evaluate(&policy, &context).expect("Failed to evaluate policy");
        assert!(result);
    }

    #[test]
    fn test_condition_expression_support() {
        // Condition expressions are now supported - test with a parsed expression
        let condition_str = "true && false";
        let condition_expr = RbacParser::parse_condition_expression(condition_str)
            .expect("Failed to parse simple boolean condition");
        
        assert!(condition_expr.expression.is_some(), "Should have parsed expression");
        
        let policy = RbacPolicy {
            span: EmptySpan::default(),
            version: "2.0".to_string(),
            role_definitions: vec![RoleDefinition {
                span: EmptySpan::default(),
                id: "role1".to_string(),
                name: "Test Role".to_string(),
                description: None,
                role_type: RoleType::CustomRole,
                permissions: vec![Permission {
                    span: EmptySpan::default(),
                    actions: vec!["*".to_string()],
                    not_actions: vec![],
                    data_actions: vec![],
                    not_data_actions: vec![],
                }],
                assignable_scopes: vec![],
            }],
            role_assignments: vec![RoleAssignment {
                span: EmptySpan::default(),
                id: "assignment1".to_string(),
                principal_id: "user123".to_string(),
                principal_type: PrincipalType::User,
                role_definition_id: "role1".to_string(),
                scope: "/subscriptions/sub1".to_string(),
                condition: Some(condition_expr),
                condition_version: Some("2.0".to_string()),
            }],
        };

        // Condition expressions are now supported
        let result = RbacCompiler::compile(&policy);
        assert!(result.is_ok(), "Compilation should succeed with condition expressions");
    }
}
