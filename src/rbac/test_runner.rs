// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RBAC Test Runner for RVM Integration
//!
//! This module provides a comprehensive test framework that:
//! 1. Loads RBAC test cases from YAML files
//! 2. Compiles test scenarios to RVM programs
//! 3. Executes RVM programs with test inputs
//! 4. Asserts expected outputs and results

use crate::rbac::ast::*;
use crate::rbac::compiler::*;
use crate::rvm::{Program, RegoVM};
use crate::value::Value;
use crate::*;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

extern crate alloc;
extern crate std;

#[cfg(feature = "yaml")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "yaml")]
use serde_yaml;

/// Test case definition loaded from YAML
#[cfg(feature = "yaml")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RbacTestCase {
    pub name: String,
    pub description: String,
    pub policy: TestPolicy,
    pub input: TestInput,
    pub expected: TestExpectedResult,
}

/// Policy definition in test case
#[cfg(feature = "yaml")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestPolicy {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(rename = "roleDefinition")]
    pub role_definition: TestRoleDefinition,
    #[serde(default)]
    pub conditions: Vec<TestCondition>,
    #[serde(default, rename = "roleAssignment")]
    pub role_assignment: Option<TestRoleAssignment>,
    #[serde(default, rename = "roleAssignments")]
    pub role_assignments: Vec<TestRoleAssignment>,
}

/// Role definition in test policy
#[cfg(feature = "yaml")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestRoleDefinition {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default, rename = "notActions")]
    pub not_actions: Vec<String>,
    #[serde(default, rename = "dataActions")]
    pub data_actions: Vec<String>,
    #[serde(default, rename = "notDataActions")]
    pub not_data_actions: Vec<String>,
    #[serde(default, rename = "assignableScopes")]
    pub assignable_scopes: Vec<String>,
}

/// Role assignment definition in test policy
#[cfg(feature = "yaml")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestRoleAssignment {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(rename = "principalId")]
    pub principal_id: Option<String>,
    #[serde(default, rename = "principalType")]
    pub principal_type: Option<String>,
    #[serde(rename = "roleDefinitionId")]
    pub role_definition_id: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// Condition definition in test
#[cfg(feature = "yaml")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestCondition {
    pub action: String,
    pub expression: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// Test input definition
#[cfg(feature = "yaml")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestInput {
    pub principal: Option<TestPrincipal>,
    pub resource: Option<TestResource>,
    pub action: String,
    #[serde(default, rename = "actionType")]
    pub action_type: Option<String>,
    #[serde(default, rename = "subOperation")]
    pub sub_operation: Option<String>,
    #[serde(default)]
    pub request: Option<TestRequest>,
    #[serde(default)]
    pub environment: Option<TestEnvironment>,
    pub evaluation_context: Option<BTreeMap<String, Value>>,
}

/// Principal definition in test input
#[cfg(feature = "yaml")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestPrincipal {
    pub id: Option<String>,
    #[serde(default)]
    pub principal_type: Option<String>,
    pub attributes: Option<BTreeMap<String, Value>>,
}

/// Resource definition in test input
#[cfg(feature = "yaml")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestResource {
    pub id: Option<String>,
    pub resource_type: Option<String>,
    pub scope: Option<String>,
    pub attributes: Option<BTreeMap<String, Value>>,
}

/// Request details in test input
#[cfg(feature = "yaml")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestRequest {
    #[serde(default)]
    pub attributes: Option<BTreeMap<String, Value>>,
    #[serde(default, rename = "dataAction")]
    pub data_action: Option<String>,
    #[serde(default, rename = "subOperation")]
    pub sub_operation: Option<String>,
}

/// Environment details in test input
#[cfg(feature = "yaml")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestEnvironment {
    #[serde(default, rename = "isPrivateLink")]
    pub is_private_link: Option<bool>,
    #[serde(default, rename = "privateEndpoint")]
    pub private_endpoint: Option<String>,
    #[serde(default)]
    pub subnet: Option<String>,
    #[serde(default, rename = "utcNow")]
    pub utc_now: Option<String>,
}

/// Expected result definition
#[cfg(feature = "yaml")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestExpectedResult {
    #[serde(rename = "result")]
    pub decision: String,
    #[serde(default, rename = "reason")]
    pub reason: Option<String>,
    #[serde(default)]
    pub reasons: Option<Vec<String>>,
}

/// Test suite containing multiple test cases
#[cfg(feature = "yaml")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RbacTestSuite {
    pub name: String,
    pub description: String,
    pub tests: Vec<RbacTestCase>,
}

/// Result of executing a single test case
#[derive(Debug, Clone)]
pub struct TestExecutionResult {
    pub test_name: String,
    pub passed: bool,
    pub decision: String,
    pub expected_decision: String,
    pub error: Option<String>,
    pub execution_time_us: Option<u64>,
    pub rvm_instructions: Option<usize>,
}

/// Summary of test suite execution
#[derive(Debug, Clone)]
pub struct TestSuiteResult {
    pub suite_name: String,
    pub total_tests: usize,
    pub passed_tests: usize,
    pub failed_tests: usize,
    pub results: Vec<TestExecutionResult>,
    pub total_execution_time_us: Option<u64>,
}

/// Main test runner for RBAC RVM integration
pub struct RbacTestRunner;

impl RbacTestRunner {
    /// Create a new test runner instance
    pub fn new() -> Self {
        Self
    }

    /// Load test cases from a YAML file
    #[cfg(feature = "yaml")]
    pub fn load_test_suite<P: AsRef<std::path::Path>>(
        &self,
        file_path: P,
    ) -> Result<RbacTestSuite, String> {
        std::println!("Loading test cases from: {}", file_path.as_ref().display());

        let content = std::fs::read_to_string(&file_path)
            .map_err(|e| format!("Failed to read test file: {}", e))?;

        let test_suite: RbacTestSuite = serde_yaml::from_str(&content)
            .map_err(|e| format!("Failed to parse YAML test file: {}", e))?;

        Ok(test_suite)
    }

    /// Convert test policy to RBAC policy
    pub fn convert_test_policy(
        &self,
        test_policy: &TestPolicy,
        context: &EvaluationContext,
    ) -> RbacPolicy {
        let role_def = &test_policy.role_definition;

        let permissions = vec![Permission {
            span: EmptySpan,
            actions: if role_def.actions.is_empty() {
                vec![context
                    .request
                    .action
                    .clone()
                    .unwrap_or_else(|| "*".to_string())]
            } else {
                role_def.actions.clone()
            },
            not_actions: role_def.not_actions.clone(),
            data_actions: role_def.data_actions.clone(),
            not_data_actions: role_def.not_data_actions.clone(),
        }];

        let assignable_scopes = if role_def.assignable_scopes.is_empty() {
            vec!["/".to_string()]
        } else {
            role_def.assignable_scopes.clone()
        };

        let role_definition = RoleDefinition {
            span: EmptySpan,
            id: role_def.id.clone(),
            name: role_def
                .name
                .clone()
                .unwrap_or_else(|| "Test Role".to_string()),
            description: role_def.description.clone(),
            role_type: RoleType::CustomRole,
            permissions,
            assignable_scopes,
        };

        let mut role_assignments = Vec::new();

        if !test_policy.role_assignments.is_empty() {
            for assignment in &test_policy.role_assignments {
                role_assignments.push(self.convert_test_role_assignment(
                    assignment,
                    &role_definition,
                    context,
                ));
            }
        } else if let Some(assignment) = &test_policy.role_assignment {
            role_assignments.push(self.convert_test_role_assignment(
                assignment,
                &role_definition,
                context,
            ));
        } else {
            role_assignments.push(RoleAssignment {
                span: EmptySpan,
                id: format!("assignment-{}", context.principal.id),
                principal_id: context.principal.id.clone(),
                principal_type: context.principal.principal_type.clone(),
                role_definition_id: role_definition.id.clone(),
                scope: if context.resource.scope.is_empty() {
                    "/".to_string()
                } else {
                    context.resource.scope.clone()
                },
                condition: None,
                condition_version: None,
            });
        }

        RbacPolicy {
            span: EmptySpan,
            version: test_policy
                .version
                .clone()
                .unwrap_or_else(|| "1.0".to_string()),
            role_definitions: vec![role_definition],
            role_assignments,
        }
    }

    fn convert_test_role_assignment(
        &self,
        assignment: &TestRoleAssignment,
        role_definition: &RoleDefinition,
        context: &EvaluationContext,
    ) -> RoleAssignment {
        let principal_id = assignment
            .principal_id
            .clone()
            .unwrap_or_else(|| context.principal.id.clone());

        let principal_type = assignment
            .principal_type
            .as_deref()
            .map(Self::parse_principal_type)
            .unwrap_or_else(|| context.principal.principal_type.clone());

        let scope = assignment.scope.clone().unwrap_or_else(|| {
            if context.resource.scope.is_empty() {
                "/".to_string()
            } else {
                context.resource.scope.clone()
            }
        });

        let role_definition_id = assignment
            .role_definition_id
            .clone()
            .unwrap_or_else(|| role_definition.id.clone());

        let assignment_id = assignment
            .id
            .clone()
            .unwrap_or_else(|| format!("assignment-{}", principal_id));

        RoleAssignment {
            span: EmptySpan,
            id: assignment_id,
            principal_id,
            principal_type,
            role_definition_id,
            scope,
            condition: None,
            condition_version: None,
        }
    }

    fn parse_principal_type(principal_type: &str) -> PrincipalType {
        match principal_type {
            "Group" => PrincipalType::Group,
            "ServicePrincipal" => PrincipalType::ServicePrincipal,
            "ManagedServiceIdentity" => PrincipalType::ManagedServiceIdentity,
            _ => PrincipalType::User,
        }
    }

    /// Convert test input to evaluation context
    pub fn convert_test_input(&self, test_input: &TestInput) -> EvaluationContext {
        let principal = if let Some(test_principal) = &test_input.principal {
            Principal {
                id: test_principal
                    .id
                    .clone()
                    .unwrap_or_else(|| "test-user".to_string()),
                principal_type: match test_principal.principal_type.as_deref().unwrap_or("User") {
                    "User" => PrincipalType::User,
                    "Group" => PrincipalType::Group,
                    "ServicePrincipal" => PrincipalType::ServicePrincipal,
                    "ManagedServiceIdentity" => PrincipalType::ManagedServiceIdentity,
                    _ => PrincipalType::User,
                },
                custom_security_attributes: test_principal
                    .attributes
                    .as_ref()
                    .map(|attrs| {
                        let mut value_map = BTreeMap::new();
                        for (key, val) in attrs {
                            value_map.insert(Value::String(key.clone().into()), val.clone());
                        }
                        Value::from_map(value_map)
                    })
                    .unwrap_or_else(|| Value::new_object()),
            }
        } else {
            Principal {
                id: "test-user".to_string(),
                principal_type: PrincipalType::User,
                custom_security_attributes: Value::new_object(),
            }
        };

        let resource = if let Some(test_resource) = &test_input.resource {
            Resource {
                id: test_resource
                    .id
                    .clone()
                    .unwrap_or_else(|| "test-resource".to_string()),
                resource_type: test_resource
                    .resource_type
                    .clone()
                    .unwrap_or_else(|| "Microsoft.Test/resources".to_string()),
                scope: test_resource
                    .scope
                    .clone()
                    .unwrap_or_else(|| "/test/scope".to_string()),
                attributes: test_resource
                    .attributes
                    .as_ref()
                    .map(|attrs| {
                        let mut value_map = BTreeMap::new();
                        for (key, val) in attrs {
                            value_map.insert(Value::String(key.clone().into()), val.clone());
                        }
                        Value::from_map(value_map)
                    })
                    .unwrap_or_else(|| Value::new_object()),
            }
        } else {
            Resource {
                id: "test-resource".to_string(),
                resource_type: "Microsoft.Test/resources".to_string(),
                scope: "/test/scope".to_string(),
                attributes: Value::new_object(),
            }
        };

        let mut request_attrs = BTreeMap::new();
        if let Some(test_request) = &test_input.request {
            if let Some(attrs) = &test_request.attributes {
                for (key, value) in attrs {
                    request_attrs.insert(Value::String(key.clone().into()), value.clone());
                }
            }
        }
        if let Some(extra_context) = &test_input.evaluation_context {
            for (key, value) in extra_context {
                request_attrs.insert(Value::String(key.clone().into()), value.clone());
            }
        }

        let explicit_data_action = test_input
            .request
            .as_ref()
            .and_then(|req| req.data_action.clone());
        let is_data_action = test_input.action_type.as_deref() == Some("dataAction")
            || explicit_data_action.is_some();
        let data_action_value = explicit_data_action.unwrap_or_else(|| test_input.action.clone());

        let suboperation = test_input.sub_operation.clone().or_else(|| {
            test_input
                .request
                .as_ref()
                .and_then(|req| req.sub_operation.clone())
        });

        let environment = if let Some(env) = &test_input.environment {
            EnvironmentContext {
                is_private_link: env.is_private_link,
                private_endpoint: env.private_endpoint.clone(),
                subnet: env.subnet.clone(),
                utc_now: env.utc_now.clone(),
            }
        } else {
            EnvironmentContext {
                is_private_link: None,
                private_endpoint: None,
                subnet: None,
                utc_now: None,
            }
        };

        EvaluationContext {
            principal,
            resource,
            request: RequestContext {
                action: if is_data_action {
                    None
                } else {
                    Some(test_input.action.clone())
                },
                data_action: if is_data_action {
                    Some(data_action_value)
                } else {
                    None
                },
                attributes: Value::from_map(request_attrs),
            },
            environment,
            action: Some(test_input.action.clone()),
            suboperation,
        }
    }

    /// Execute a single test case
    pub fn execute_test_case(&mut self, test_case: &RbacTestCase) -> TestExecutionResult {
        let start_time = std::time::Instant::now();

        // Convert test definitions to RBAC structures
        let context = self.convert_test_input(&test_case.input);
        let policy = self.convert_test_policy(&test_case.policy, &context);

        // Compile to RVM program
        match RbacCompiler::compile_to_program(&policy, &context) {
            Ok(program) => {
                let instructions_count = program.instructions.len();
                std::println!(
                    "Compiled {} RVM instructions for test '{}'",
                    instructions_count,
                    test_case.name
                );

                // Execute RVM program
                match self.execute_rvm_program(&program, &context) {
                    Ok(decision) => {
                        let execution_time = start_time.elapsed().as_micros() as u64;
                        let passed = decision == test_case.expected.decision;

                        TestExecutionResult {
                            test_name: test_case.name.clone(),
                            passed,
                            decision: decision.clone(),
                            expected_decision: test_case.expected.decision.clone(),
                            error: if !passed {
                                Some(format!(
                                    "Decision mismatch: expected '{}', got '{}'",
                                    test_case.expected.decision, decision
                                ))
                            } else {
                                None
                            },
                            execution_time_us: Some(execution_time),
                            rvm_instructions: Some(instructions_count),
                        }
                    }
                    Err(e) => TestExecutionResult {
                        test_name: test_case.name.clone(),
                        passed: false,
                        decision: "Error".to_string(),
                        expected_decision: test_case.expected.decision.clone(),
                        error: Some(format!("RVM execution failed: {}", e)),
                        execution_time_us: Some(start_time.elapsed().as_micros() as u64),
                        rvm_instructions: None,
                    },
                }
            }
            Err(e) => TestExecutionResult {
                test_name: test_case.name.clone(),
                passed: false,
                decision: "CompileError".to_string(),
                expected_decision: test_case.expected.decision.clone(),
                error: Some(format!("Compilation failed: {}", e)),
                execution_time_us: Some(start_time.elapsed().as_micros() as u64),
                rvm_instructions: None,
            },
        }
    }

    /// Execute RVM program and return decision
    pub fn execute_rvm_program(
        &self,
        program: &Program,
        context: &EvaluationContext,
    ) -> Result<String, String> {
        let vm_input = Self::build_vm_input(context)?;

        let mut vm = RegoVM::new();
        vm.load_program(Arc::new(program.clone()));

        if let Err(err) = vm.set_data(Value::new_object()) {
            return Err(format!("Failed to set VM data: {}", err));
        }

        vm.set_input(vm_input);

        match vm.execute() {
            Ok(Value::Bool(true)) => Ok("allow".to_string()),
            Ok(Value::Bool(false)) => Ok("deny".to_string()),
            Ok(Value::Undefined) => {
                // Undefined means no assignment matched (e.g., all conditions failed)
                // In RBAC, this should result in deny
                Ok("deny".to_string())
            }
            Ok(Value::String(result)) => Ok(result.as_ref().to_ascii_lowercase()),
            Ok(other) => Err(format!("Unexpected VM result: {:?}", other)),
            Err(err) => Err(format!("VM execution failed: {}", err)),
        }
    }

    fn build_vm_input(context: &EvaluationContext) -> Result<Value, String> {
        let mut input_map: BTreeMap<Value, Value> = BTreeMap::new();

        input_map.insert(
            Value::String("principalId".into()),
            Value::String(context.principal.id.clone().into()),
        );
        input_map.insert(
            Value::String("principalType".into()),
            Value::String(format!("{:?}", context.principal.principal_type).into()),
        );
        input_map.insert(
            Value::String("principalAttributes".into()),
            context.principal.custom_security_attributes.clone(),
        );

        input_map.insert(
            Value::String("resourceId".into()),
            Value::String(context.resource.id.clone().into()),
        );
        input_map.insert(
            Value::String("resourceType".into()),
            Value::String(context.resource.resource_type.clone().into()),
        );
        input_map.insert(
            Value::String("resourceScope".into()),
            Value::String(context.resource.scope.clone().into()),
        );
        input_map.insert(
            Value::String("resource".into()),
            Value::String(context.resource.scope.clone().into()),
        );
        input_map.insert(
            Value::String("resourceAttributes".into()),
            context.resource.attributes.clone(),
        );

        let (action_value, action_type) = Self::determine_action_fields(context)?;
        input_map.insert(
            Value::String("action".into()),
            Value::String(action_value.into()),
        );
        input_map.insert(
            Value::String("actionType".into()),
            Value::String(action_type.into()),
        );

        if let Some(suboperation) = &context.suboperation {
            input_map.insert(
                Value::String("subOperation".into()),
                Value::String(suboperation.clone().into()),
            );
        }

        input_map.insert(
            Value::String("requestAttributes".into()),
            context.request.attributes.clone(),
        );

        if let Some(env_value) = Self::build_environment_value(&context.environment) {
            input_map.insert(Value::String("environment".into()), env_value);
        }

        Ok(Value::from_map(input_map))
    }

    fn determine_action_fields(context: &EvaluationContext) -> Result<(String, String), String> {
        if let Some(data_action) = &context.request.data_action {
            return Ok((data_action.clone(), "dataAction".to_string()));
        }

        if let Some(action) = &context.request.action {
            return Ok((action.clone(), "action".to_string()));
        }

        if let Some(action) = &context.action {
            return Ok((action.clone(), "action".to_string()));
        }

        Err("Evaluation context missing action information".to_string())
    }

    fn build_environment_value(environment: &EnvironmentContext) -> Option<Value> {
        let mut env_map: BTreeMap<Value, Value> = BTreeMap::new();

        if let Some(is_private_link) = environment.is_private_link {
            env_map.insert(
                Value::String("isPrivateLink".into()),
                Value::Bool(is_private_link),
            );
        }

        if let Some(private_endpoint) = &environment.private_endpoint {
            env_map.insert(
                Value::String("privateEndpoint".into()),
                Value::String(private_endpoint.clone().into()),
            );
        }

        if let Some(subnet) = &environment.subnet {
            env_map.insert(
                Value::String("subnet".into()),
                Value::String(subnet.clone().into()),
            );
        }

        if let Some(utc_now) = &environment.utc_now {
            env_map.insert(
                Value::String("utcNow".into()),
                Value::String(utc_now.clone().into()),
            );
        }

        if env_map.is_empty() {
            None
        } else {
            Some(Value::from_map(env_map))
        }
    }

    /// Execute all test cases in a test suite
    #[cfg(feature = "yaml")]
    pub fn execute_test_suite(&mut self, test_suite: &RbacTestSuite) -> TestSuiteResult {
        let suite_start_time = std::time::Instant::now();

        if !test_suite.tests.is_empty() {
            std::println!("Executing test suite: {}", test_suite.name);
            std::println!("Description: {}", test_suite.description);
            std::println!("Test cases: {}", test_suite.tests.len());
            std::println!();
        }

        let mut results = Vec::new();
        let mut passed_count = 0;

        for test_case in &test_suite.tests {
            if !test_suite.tests.is_empty() {
                std::println!("Executing test: {}", test_case.name);
            }

            let result = self.execute_test_case(test_case);

            if !test_suite.tests.is_empty() {
                std::println!("  Result: {}", if result.passed { "PASS" } else { "FAIL" });
                if let Some(error) = &result.error {
                    std::println!("  Error: {}", error);
                }
                if let Some(time) = result.execution_time_us {
                    std::println!("  Execution time: {}μs", time);
                }
                std::println!();
            }

            if result.passed {
                passed_count += 1;
            }
            results.push(result);
        }

        let total_execution_time = suite_start_time.elapsed().as_micros() as u64;

        TestSuiteResult {
            suite_name: test_suite.name.clone(),
            total_tests: test_suite.tests.len(),
            passed_tests: passed_count,
            failed_tests: test_suite.tests.len() - passed_count,
            results,
            total_execution_time_us: Some(total_execution_time),
        }
    }

    /// Print test suite result summary
    pub fn print_summary(&self, result: &TestSuiteResult) {
        let total = result.total_tests;
        let passed = result.passed_tests;
        let failed = result.failed_tests;

        std::println!("Test Summary:");
        std::println!("=============");
        std::println!("Total tests: {}", total);
        std::println!("Passed: {}", passed);
        std::println!("Failed: {}", failed);
        std::println!(
            "Success rate: {:.1}%",
            (passed as f64 / total as f64) * 100.0
        );
        std::println!();

        if failed > 0 {
            std::println!("Failed tests:");
            for result in &result.results {
                if !result.passed {
                    std::println!(
                        "  - {}: {}",
                        result.test_name,
                        result
                            .error
                            .as_ref()
                            .unwrap_or(&"Unknown error".to_string())
                    );
                }
            }
        }
    }
}

impl Default for RbacTestRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::RbacEngine;

    #[test]
    fn test_runner_creation() {
        let _runner = RbacTestRunner::new();
        // Just verify we can create a runner - it's a unit struct
    }

    #[cfg(feature = "yaml")]
    #[test]
    fn test_policy_conversion() {
        let runner = RbacTestRunner::new();

        let test_policy = TestPolicy {
            version: Some("1.0".to_string()),
            role_definition: TestRoleDefinition {
                id: "reader".to_string(),
                name: Some("Reader".to_string()),
                description: None,
                actions: vec!["read".to_string()],
                not_actions: Vec::new(),
                data_actions: Vec::new(),
                not_data_actions: Vec::new(),
                assignable_scopes: vec!["/".to_string()],
            },
            conditions: Vec::new(),
            role_assignment: None,
            role_assignments: Vec::new(),
        };

        let context = RbacEngine::create_test_context(
            "user1",
            PrincipalType::User,
            "/subscriptions/sub1",
            Some("read"),
            None,
        );

        let policy = runner.convert_test_policy(&test_policy, &context);
        assert_eq!(policy.role_definitions.len(), 1);
        assert_eq!(policy.role_assignments.len(), 1);
        let permissions = &policy.role_definitions[0].permissions;
        assert_eq!(permissions.len(), 1);
        assert_eq!(permissions[0].actions, vec!["read".to_string()]);
    }
}
