// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure RBAC to Regorus RVM compiler
//!
//! This module compiles Azure RBAC policies to Regorus RVM bytecode instructions.

use crate::rbac::ast::*;
use crate::rvm::instructions::{BuiltinCallParams, ChainedIndexParams, LiteralOrRegister};
use crate::rvm::program::{BuiltinInfo, Program, RuleInfo, RuleType};
use crate::rvm::Instruction;
use crate::value::Value;
use crate::Rc;
use crate::*;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::convert::TryFrom;
#[cfg(feature = "glob")]
use globset::GlobBuilder;

/// Error types for RBAC compilation
#[derive(Debug, Clone)]
pub enum RbacCompileError {
    UnsupportedFeature(String),
    InvalidCondition(String),
    CompilationError(String),
}

fn scope_covers(scope: &str, target_scope: &str) -> bool {
    if scope == target_scope {
        return true;
    }

    let normalized = scope.trim_end_matches('/');
    let prefix = if normalized.is_empty() {
        "/".to_string()
    } else {
        format!("{}/", normalized)
    };

    target_scope.starts_with(&prefix)
}

fn matches_patterns(patterns: &[String], value: &str) -> bool {
    patterns.iter().any(|pattern| {
        if pattern == "*" {
            true
        } else {
            pattern_matches(pattern, value)
        }
    })
}

#[cfg(feature = "glob")]
fn pattern_matches(pattern: &str, value: &str) -> bool {
    GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
        .ok()
        .map(|glob| glob.compile_matcher().is_match(value))
        .unwrap_or(false)
}

#[cfg(not(feature = "glob"))]
fn pattern_matches(pattern: &str, value: &str) -> bool {
    simple_wildcard_match(pattern, value)
}

#[cfg(not(feature = "glob"))]
fn simple_wildcard_match(pattern: &str, value: &str) -> bool {
    fn helper(pattern: &[u8], value: &[u8]) -> bool {
        if pattern.is_empty() {
            return value.is_empty();
        }

        match pattern[0] {
            b'*' => {
                if helper(&pattern[1..], value) {
                    return true;
                }
                if !value.is_empty() {
                    return helper(pattern, &value[1..]);
                }
                false
            }
            byte => {
                if !value.is_empty() && byte == value[0] {
                    helper(&pattern[1..], &value[1..])
                } else {
                    false
                }
            }
        }
    }

    helper(pattern.as_bytes(), value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::RbacEngine;
    use crate::rvm::vm::RegoVM;
    use alloc::collections::BTreeMap;
    use alloc::sync::Arc;

    fn build_input_value(fields: &[(&str, &str)]) -> Value {
        let mut map = BTreeMap::new();
        for (key, value) in fields {
            map.insert(Value::String((*key).into()), Value::String((*value).into()));
        }
        Value::from_map(map)
    }

    fn basic_policy() -> RbacPolicy {
        RbacPolicy {
            span: EmptySpan::default(),
            version: "2.0".to_string(),
            role_definitions: vec![RoleDefinition {
                span: EmptySpan::default(),
                id: "reader".to_string(),
                name: "Reader".to_string(),
                description: None,
                role_type: RoleType::BuiltInRole,
                permissions: vec![Permission {
                    span: EmptySpan::default(),
                    actions: vec!["Microsoft.Storage/storageAccounts/read".to_string()],
                    not_actions: vec![],
                    data_actions: vec![],
                    not_data_actions: vec![],
                }],
                assignable_scopes: vec![],
            }],
            role_assignments: vec![RoleAssignment {
                span: EmptySpan::default(),
                id: "assign-user".to_string(),
                principal_id: "user-123".to_string(),
                principal_type: PrincipalType::User,
                role_definition_id: "reader".to_string(),
                scope: "/subscriptions/sub1".to_string(),
                condition: None,
                condition_version: None,
            }],
        }
    }

    #[test]
    fn compiled_program_allows_matching_action() {
        let policy = basic_policy();
        let context = RbacEngine::create_test_context(
            "user-123",
            PrincipalType::User,
            "/subscriptions/sub1/resourceGroups/rg1",
            Some("Microsoft.Storage/storageAccounts/read"),
            None,
        );

        let program = RbacCompiler::compile_to_program(&policy, &context)
            .expect("policy compilation should succeed");

        let mut vm = RegoVM::new();
        vm.load_program(Arc::new(program));
        vm.set_data(Value::new_object()).expect("set data");
        let input_value = build_input_value(&[
            ("principalId", "user-123"),
            ("resource", "/subscriptions/sub1/resourceGroups/rg1"),
            ("action", "Microsoft.Storage/storageAccounts/read"),
        ]);
        vm.set_input(input_value);

        let result = vm.execute().expect("vm execution");
        assert_eq!(result, Value::Bool(true));
    }

    #[test]
    fn compiled_program_denies_mismatched_action() {
        let policy = basic_policy();
        let context = RbacEngine::create_test_context(
            "user-123",
            PrincipalType::User,
            "/subscriptions/sub1/resourceGroups/rg1",
            Some("Microsoft.Storage/storageAccounts/delete"),
            None,
        );

        let program = RbacCompiler::compile_to_program(&policy, &context)
            .expect("policy compilation should succeed");

        let mut vm = RegoVM::new();
        vm.load_program(Arc::new(program));
        vm.set_data(Value::new_object()).expect("set data");
        let input_value = build_input_value(&[
            ("principalId", "user-123"),
            ("resource", "/subscriptions/sub1/resourceGroups/rg1"),
            ("action", "Microsoft.Storage/storageAccounts/delete"),
        ]);
        vm.set_input(input_value);

        let result = vm.execute().expect("vm execution");
        assert_eq!(result, Value::Bool(false));
    }

    #[test]
    fn compiled_program_allows_data_action() {
        let policy = RbacPolicy {
            span: EmptySpan::default(),
            version: "2.0".to_string(),
            role_definitions: vec![RoleDefinition {
                span: EmptySpan::default(),
                id: "data-reader".to_string(),
                name: "Data Reader".to_string(),
                description: None,
                role_type: RoleType::BuiltInRole,
                permissions: vec![Permission {
                    span: EmptySpan::default(),
                    actions: vec![],
                    not_actions: vec![],
                    data_actions: vec![
                        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
                            .to_string(),
                    ],
                    not_data_actions: vec![],
                }],
                assignable_scopes: vec![],
            }],
            role_assignments: vec![RoleAssignment {
                span: EmptySpan::default(),
                id: "assign-user".to_string(),
                principal_id: "user-123".to_string(),
                principal_type: PrincipalType::User,
                role_definition_id: "data-reader".to_string(),
                scope: "/subscriptions/sub1".to_string(),
                condition: None,
                condition_version: None,
            }],
        };

        let action = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read";
        let context = RbacEngine::create_test_context(
            "user-123",
            PrincipalType::User,
            "/subscriptions/sub1/resourceGroups/storage",
            Some(action),
            Some(action),
        );

        let program = RbacCompiler::compile_to_program(&policy, &context)
            .expect("policy compilation should succeed");

        let mut vm = RegoVM::new();
        vm.load_program(Arc::new(program));
        vm.set_data(Value::new_object()).expect("set data");
        let input_value = build_input_value(&[
            ("principalId", "user-123"),
            ("resource", "/subscriptions/sub1/resourceGroups/storage"),
            ("action", action),
            ("actionType", "dataAction"),
        ]);
        vm.set_input(input_value);

        let result = vm.execute().expect("vm execution");
        assert_eq!(result, Value::Bool(true));
    }
}

impl core::fmt::Display for RbacCompileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RbacCompileError::UnsupportedFeature(feature) => {
                write!(f, "Unsupported RBAC feature: {}", feature)
            }
            RbacCompileError::InvalidCondition(cond) => {
                write!(f, "Invalid condition expression: {}", cond)
            }
            RbacCompileError::CompilationError(msg) => write!(f, "Compilation error: {}", msg),
        }
    }
}

/// RBAC to RVM compiler
pub struct RbacCompiler;

impl RbacCompiler {
    /// Core compilation routine that emits an RVM program with a single RBAC entry point
    fn compile_program(policy: &RbacPolicy) -> Result<Program, RbacCompileError> {
        let mut program_builder = ProgramBuilder::new();
        program_builder.compile_policy(policy)?;
        let mut program = program_builder.finish();
        program
            .initialize_resolved_builtins()
            .map_err(|err| RbacCompileError::CompilationError(err.to_string()))?;
        Ok(program)
    }

    /// Compile an RBAC policy to RVM instructions
    pub fn compile(policy: &RbacPolicy) -> Result<Vec<Instruction>, RbacCompileError> {
        let program = Self::compile_program(policy)?;
        Ok(program.instructions.clone())
    }

    /// Compile an RBAC policy to a complete RVM program
    pub fn compile_to_program(
        policy: &RbacPolicy,
        context: &EvaluationContext,
    ) -> Result<Program, RbacCompileError> {
        let mut program = Self::compile_program(policy)?;

        // Add evaluation context as a literal for future use by the VM entry point
        let context_value = Self::evaluation_context_to_value(context);
        program.add_literal(context_value);

        Ok(program)
    }

    /// Convert evaluation context to Value for RVM input  
    fn evaluation_context_to_value(context: &EvaluationContext) -> Value {
        // Create evaluation context as structured Value
        let mut context_obj = BTreeMap::new();

        // Add principal information
        let mut principal_obj = BTreeMap::new();
        principal_obj.insert(
            Value::String("id".into()),
            Value::String(context.principal.id.clone().into()),
        );
        principal_obj.insert(
            Value::String("principal_type".into()),
            Value::String(format!("{:?}", context.principal.principal_type).into()),
        );
        principal_obj.insert(
            Value::String("custom_security_attributes".into()),
            context.principal.custom_security_attributes.clone(),
        );
        context_obj.insert(
            Value::String("principal".into()),
            Value::from_map(principal_obj),
        );

        // Add resource information
        let mut resource_obj = BTreeMap::new();
        resource_obj.insert(
            Value::String("id".into()),
            Value::String(context.resource.id.clone().into()),
        );
        resource_obj.insert(
            Value::String("resource_type".into()),
            Value::String(context.resource.resource_type.clone().into()),
        );
        resource_obj.insert(
            Value::String("scope".into()),
            Value::String(context.resource.scope.clone().into()),
        );
        resource_obj.insert(
            Value::String("attributes".into()),
            context.resource.attributes.clone(),
        );
        context_obj.insert(
            Value::String("resource".into()),
            Value::from_map(resource_obj),
        );

        // Add request information
        let mut request_obj = BTreeMap::new();
        if let Some(action) = &context.request.action {
            request_obj.insert(
                Value::String("action".into()),
                Value::String(action.clone().into()),
            );
        }
        if let Some(data_action) = &context.request.data_action {
            request_obj.insert(
                Value::String("data_action".into()),
                Value::String(data_action.clone().into()),
            );
        }
        request_obj.insert(
            Value::String("attributes".into()),
            context.request.attributes.clone(),
        );
        context_obj.insert(
            Value::String("request".into()),
            Value::from_map(request_obj),
        );

        // Add environment information
        let mut env_obj = BTreeMap::new();
        if let Some(is_private_link) = context.environment.is_private_link {
            env_obj.insert(
                Value::String("is_private_link".into()),
                Value::Bool(is_private_link),
            );
        }
        if let Some(utc_now) = &context.environment.utc_now {
            env_obj.insert(
                Value::String("utc_now".into()),
                Value::String(utc_now.clone().into()),
            );
        }
        context_obj.insert(
            Value::String("environment".into()),
            Value::from_map(env_obj),
        );

        // Add top-level action for convenience
        if let Some(action) = &context.action {
            context_obj.insert(
                Value::String("action".into()),
                Value::String(action.clone().into()),
            );
        }

        Value::from_map(context_obj)
    }
}

/// Helper for building a minimal RVM program for RBAC evaluation
struct ProgramBuilder {
    program: Program,
    rule_infos: Vec<RuleInfo>,
    rule_num_registers: Vec<u8>,
    entry_point_registers: usize,
    next_register: u8,
    max_register_used: u8,
    builtin_indices: BTreeMap<&'static str, u16>,
    null_register: Option<u8>,
}

impl ProgramBuilder {
    fn new() -> Self {
        Self {
            program: Program::new(),
            rule_infos: Vec::new(),
            rule_num_registers: Vec::new(),
            entry_point_registers: 0,
            next_register: 1,
            max_register_used: 0,
            builtin_indices: BTreeMap::new(),
            null_register: None,
        }
    }

    fn reset_allocator(&mut self) {
        self.next_register = 1;
        self.max_register_used = 0;
        self.null_register = None;
    }

    fn alloc_register(&mut self) -> u8 {
        if self.next_register == u8::MAX {
            panic!("RBAC compiler exceeded register allocation limit");
        }
        let reg = self.next_register;
        self.next_register += 1;
        self.max_register_used = self.max_register_used.max(reg);
        reg
    }

    fn add_literal_value(&mut self, value: Value) -> u16 {
        let idx = self.program.add_literal(value);
        u16::try_from(idx).expect("RBAC compiler literal table overflow")
    }

    fn add_literal_string(&mut self, value: &str) -> u16 {
        self.add_literal_value(Value::String(value.into()))
    }

    fn load_string(&mut self, value: &str) -> u8 {
        let reg = self.alloc_register();
        let literal_idx = self.add_literal_string(value);
        self.program.add_instruction(
            Instruction::Load {
                dest: reg,
                literal_idx,
            },
            None,
        );
        reg
    }

    fn load_bool(&mut self, value: bool) -> u8 {
        let reg = self.alloc_register();
        if value {
            self.program
                .add_instruction(Instruction::LoadTrue { dest: reg }, None);
        } else {
            self.program
                .add_instruction(Instruction::LoadFalse { dest: reg }, None);
        }
        reg
    }

    fn null_register(&mut self) -> u8 {
        if let Some(reg) = self.null_register {
            reg
        } else {
            let reg = self.alloc_register();
            self.program
                .add_instruction(Instruction::LoadNull { dest: reg }, None);
            self.null_register = Some(reg);
            reg
        }
    }

    fn ensure_builtin(&mut self, name: &'static str, num_args: u16) -> u16 {
        if let Some(&idx) = self.builtin_indices.get(name) {
            return idx;
        }

        let index = self.program.add_builtin_info(BuiltinInfo {
            name: name.to_string(),
            num_args,
        });
        self.builtin_indices.insert(name, index);
        index
    }

    fn emit_builtin_call(&mut self, name: &'static str, args: &[u8]) -> u8 {
        let dest = self.alloc_register();
        let builtin_index = self.ensure_builtin(name, args.len() as u16);
        let mut arg_regs = [0u8; 8];
        for (idx, reg) in args.iter().enumerate() {
            arg_regs[idx] = *reg;
        }

        let params_index = self.program.add_builtin_call_params(BuiltinCallParams {
            dest,
            builtin_index,
            num_args: args.len() as u8,
            args: arg_regs,
        });

        self.program
            .add_instruction(Instruction::BuiltinCall { params_index }, None);
        dest
    }

    fn emit_or_in_place(&mut self, dest: u8, other: u8) {
        self.program.add_instruction(
            Instruction::Or {
                dest,
                left: dest,
                right: other,
            },
            None,
        );
    }

    fn emit_and_in_place(&mut self, dest: u8, other: u8) {
        self.program.add_instruction(
            Instruction::And {
                dest,
                left: dest,
                right: other,
            },
            None,
        );
    }

    fn emit_and(&mut self, left: u8, right: u8) -> u8 {
        let dest = self.alloc_register();
        self.program
            .add_instruction(Instruction::And { dest, left, right }, None);
        dest
    }

    fn emit_or(&mut self, left: u8, right: u8) -> u8 {
        let dest = self.alloc_register();
        self.program
            .add_instruction(Instruction::Or { dest, left, right }, None);
        dest
    }

    fn emit_not(&mut self, operand: u8) -> u8 {
        let dest = self.alloc_register();
        self.program
            .add_instruction(Instruction::Not { dest, operand }, None);
        dest
    }

    fn emit_input_lookup(&mut self, input_reg: u8, field: &str) -> u8 {
        let dest = self.alloc_register();
        let literal_idx = self.add_literal_string(field);
        let params_index =
            self.program
                .instruction_data
                .add_chained_index_params(ChainedIndexParams {
                    dest,
                    root: input_reg,
                    path_components: vec![LiteralOrRegister::Literal(literal_idx)],
                });
        self.program
            .add_instruction(Instruction::ChainedIndex { params_index }, None);
        dest
    }

    fn emit_object_get(&mut self, object_reg: u8, key: &str, default_reg: u8) -> u8 {
        let key_reg = self.load_string(key);
        self.emit_builtin_call("object.get", &[object_reg, key_reg, default_reg])
    }

    fn compile_policy(&mut self, policy: &RbacPolicy) -> Result<(), RbacCompileError> {
        Self::ensure_supported(policy)?;

        let rule_index = self.rule_infos.len() as u16;

        let entry_pc = self.emit_entry_point(rule_index);
        self.program
            .add_entry_point("rbac_policy_eval".to_string(), entry_pc);
        self.program.main_entry_point = entry_pc;
        self.entry_point_registers = self.entry_point_registers.max(1);

        let rule_info = self.emit_allow_rule(rule_index, policy)?;
        self.rule_num_registers.push(rule_info.num_registers);
        self.rule_infos.push(rule_info);

        Ok(())
    }

    fn emit_entry_point(&mut self, rule_index: u16) -> usize {
        let entry_pc = self.program.instructions.len();
        self.program.add_instruction(
            Instruction::CallRule {
                dest: 0,
                rule_index,
            },
            None,
        );
        self.program
            .add_instruction(Instruction::Return { value: 0 }, None);
        entry_pc
    }

    fn emit_allow_rule(
        &mut self,
        rule_index: u16,
        policy: &RbacPolicy,
    ) -> Result<RuleInfo, RbacCompileError> {
        self.reset_allocator();

        let result_reg = 0;
        let rule_start = self.program.instructions.len();

        self.program.add_instruction(
            Instruction::RuleInit {
                result_reg,
                rule_index,
            },
            None,
        );
        self.program
            .add_instruction(Instruction::LoadFalse { dest: result_reg }, None);

        let mut role_definitions = BTreeMap::new();
        for definition in &policy.role_definitions {
            role_definitions.insert(definition.id.as_str(), definition);
        }

        let input_reg = self.alloc_register();
        self.program
            .add_instruction(Instruction::LoadInput { dest: input_reg }, None);

        let principal_reg = self.emit_input_lookup(input_reg, "principalId");
    let resource_reg = self.emit_input_lookup(input_reg, "resource");
    let action_reg = self.emit_input_lookup(input_reg, "action");
    let null_reg = self.null_register();
    let action_type_reg = self.emit_object_get(input_reg, "actionType", null_reg);

        let data_action_literal_reg = self.load_string("dataAction");
        let action_type_matches_reg = self.alloc_register();
        self.program.add_instruction(
            Instruction::Eq {
                dest: action_type_matches_reg,
                left: action_type_reg,
                right: data_action_literal_reg,
            },
            None,
        );

        let true_reg = self.load_bool(true);
        let is_data_action_reg = self.alloc_register();
        self.program.add_instruction(
            Instruction::Eq {
                dest: is_data_action_reg,
                left: action_type_matches_reg,
                right: true_reg,
            },
            None,
        );

        let not_data_action_reg = self.emit_not(is_data_action_reg);

        for assignment in &policy.role_assignments {
            let role_def = role_definitions
                .get(assignment.role_definition_id.as_str())
                .ok_or_else(|| {
                    RbacCompileError::CompilationError(format!(
                        "Role definition '{}' referenced by assignment '{}' was not found",
                        assignment.role_definition_id, assignment.id
                    ))
                })?;

            self.emit_assignment_block(
                assignment,
                role_def,
                result_reg,
                principal_reg,
                resource_reg,
                action_reg,
                is_data_action_reg,
                not_data_action_reg,
            );
        }

        self.program
            .add_instruction(Instruction::RuleReturn {}, None);

        let definitions = Rc::new(vec![vec![rule_start as u32]]);
        let num_registers = self.max_register_used.checked_add(1).unwrap_or(u8::MAX);
        let mut rule_info = RuleInfo::new(
            "data.rbac.allow".to_string(),
            RuleType::Complete,
            definitions,
            result_reg,
            num_registers,
        );

        self.program
            .add_rule_to_tree(&["rbac".to_string()], "allow", rule_index as usize)
            .map_err(|err| RbacCompileError::CompilationError(err.to_string()))?;

        let default_literal_index = self.add_literal_value(Value::Bool(false));
        rule_info.set_default_literal_index(default_literal_index);

        Ok(rule_info)
    }

    fn emit_assignment_block(
        &mut self,
        assignment: &RoleAssignment,
        role_def: &RoleDefinition,
        result_reg: u8,
        principal_reg: u8,
        resource_reg: u8,
        action_reg: u8,
        is_data_action_reg: u8,
        not_data_action_reg: u8,
    ) {
        let principal_literal_reg = self.load_string(&assignment.principal_id);
        let principal_match_reg = self.alloc_register();
        self.program.add_instruction(
            Instruction::Eq {
                dest: principal_match_reg,
                left: principal_reg,
                right: principal_literal_reg,
            },
            None,
        );

        let scope_match_reg = self.emit_scope_match(resource_reg, &assignment.scope);
        let mut assignment_match_reg = self.emit_and(principal_match_reg, scope_match_reg);

        // If there's a condition, evaluate it and AND with assignment match
        // We DON'T use AssertCondition here because:
        // 1. AssertCondition causes early exit from the entire rule
        // 2. We want to try other assignments even if this one's condition fails
        // 3. The AND logic naturally makes this assignment not contribute to the result
        if let Some(condition) = &assignment.condition {
            if let Some(ref parsed_expr) = condition.expression {
                let condition_result_reg = self.emit_condition_expr(parsed_expr);
                assignment_match_reg = self.emit_and(assignment_match_reg, condition_result_reg);
            }
        }

        let permission_allowed_reg = self.emit_role_allows(
            role_def,
            action_reg,
            is_data_action_reg,
            not_data_action_reg,
        );

        let assignment_allows_reg = self.emit_and(assignment_match_reg, permission_allowed_reg);
        self.emit_or_in_place(result_reg, assignment_allows_reg);
    }

    fn emit_scope_match(&mut self, resource_reg: u8, scope: &str) -> u8 {
        let scope_literal_reg = self.load_string(scope);
        let equals_reg = self.alloc_register();
        self.program.add_instruction(
            Instruction::Eq {
                dest: equals_reg,
                left: resource_reg,
                right: scope_literal_reg,
            },
            None,
        );

        let trimmed_scope = scope.trim_end_matches('/');
        let prefix = if trimmed_scope.is_empty() {
            "/".to_string()
        } else {
            format!("{}/", trimmed_scope)
        };

        let prefix_reg = self.load_string(&prefix);
        let starts_with_reg = self.emit_builtin_call("startswith", &[resource_reg, prefix_reg]);

        self.emit_or(equals_reg, starts_with_reg)
    }

    fn emit_role_allows(
        &mut self,
        role_def: &RoleDefinition,
        action_reg: u8,
        is_data_action_reg: u8,
        not_data_action_reg: u8,
    ) -> u8 {
        if role_def.permissions.is_empty() {
            return self.load_bool(false);
        }

        let allowed_reg = self.load_bool(false);
        for permission in &role_def.permissions {
            let permission_allowed = self.emit_permission_allows(
                permission,
                action_reg,
                is_data_action_reg,
                not_data_action_reg,
            );
            self.emit_or_in_place(allowed_reg, permission_allowed);
        }
        allowed_reg
    }

    fn emit_permission_allows(
        &mut self,
        permission: &Permission,
        action_reg: u8,
        is_data_action_reg: u8,
        not_data_action_reg: u8,
    ) -> u8 {
        let action_allowed =
            self.emit_allow_list(action_reg, &permission.actions, &permission.not_actions);
        let data_action_allowed = self.emit_allow_list(
            action_reg,
            &permission.data_actions,
            &permission.not_data_actions,
        );

        let normal_branch = self.emit_and(action_allowed, not_data_action_reg);
        let data_branch = self.emit_and(data_action_allowed, is_data_action_reg);
        self.emit_or(normal_branch, data_branch)
    }

    fn emit_allow_list(
        &mut self,
        action_reg: u8,
        allow_patterns: &[String],
        deny_patterns: &[String],
    ) -> u8 {
        if allow_patterns.is_empty() {
            return self.load_bool(false);
        }

        let allow_reg = self.emit_any_match(action_reg, allow_patterns);
        if deny_patterns.is_empty() {
            return allow_reg;
        }

        let deny_reg = self.emit_any_match(action_reg, deny_patterns);
        let not_deny_reg = self.emit_not(deny_reg);
        self.emit_and_in_place(allow_reg, not_deny_reg);
        allow_reg
    }

    fn emit_any_match(&mut self, value_reg: u8, patterns: &[String]) -> u8 {
        if patterns.is_empty() {
            return self.load_bool(false);
        }

        if patterns.iter().any(|p| p == "*") {
            return self.load_bool(true);
        }

        let accumulator = self.load_bool(false);
        for pattern in patterns {
            let matches = self.emit_pattern_match(value_reg, pattern);
            self.emit_or_in_place(accumulator, matches);
        }
        accumulator
    }

    fn emit_pattern_match(&mut self, value_reg: u8, pattern: &str) -> u8 {
        let pattern_reg = self.load_string(pattern);
        let null_reg = self.null_register();
        self.emit_builtin_call("glob.match", &[pattern_reg, null_reg, value_reg])
    }

    /// Compile a condition expression to RVM instructions
    fn emit_condition_expr(&mut self, expr: &ConditionExpr) -> u8 {
        match expr {
            ConditionExpr::Logical(logical) => self.emit_logical_expr(logical),
            ConditionExpr::Unary(unary) => self.emit_unary_expr(unary),
            ConditionExpr::Binary(binary) => self.emit_binary_expr(binary),
            ConditionExpr::FunctionCall(call) => self.emit_function_call_expr(call),
            ConditionExpr::AttributeReference(attr) => self.emit_attribute_reference(attr),
            ConditionExpr::ArrayExpression(array) => self.emit_array_expr(array),
            ConditionExpr::StringLiteral(lit) => self.load_string(&lit.value),
            ConditionExpr::NumberLiteral(lit) => {
                let reg = self.alloc_register();
                let num_value = lit.raw.parse::<f64>().unwrap_or(0.0);
                let literal_idx = self.add_literal_value(Value::from(num_value));
                self.program
                    .add_instruction(Instruction::Load { dest: reg, literal_idx }, None);
                reg
            }
            ConditionExpr::BooleanLiteral(lit) => self.load_bool(lit.value),
            ConditionExpr::NullLiteral(_) => self.null_register(),
            ConditionExpr::ListLiteral(list) => self.emit_list_literal(&list.elements),
            ConditionExpr::SetLiteral(set) => self.emit_list_literal(&set.elements),
            ConditionExpr::DateTimeLiteral(lit) => self.load_string(&lit.value),
            ConditionExpr::TimeLiteral(lit) => self.load_string(&lit.value),
            ConditionExpr::Identifier(id) => {
                // Identifiers might reference built-in values or context
                self.load_string(&id.name)
            }
            ConditionExpr::VariableReference(_var) => {
                // Variables are not yet supported in basic implementation
                self.null_register()
            }
            ConditionExpr::PropertyAccess(_prop) => {
                // Property access not yet supported
                self.null_register()
            }
        }
    }

    fn emit_logical_expr(&mut self, logical: &LogicalExpression) -> u8 {
        let left_reg = self.emit_condition_expr(&logical.left);
        let right_reg = self.emit_condition_expr(&logical.right);
        match logical.operator {
            LogicalOperator::And => self.emit_and(left_reg, right_reg),
            LogicalOperator::Or => self.emit_or(left_reg, right_reg),
        }
    }

    fn emit_unary_expr(&mut self, unary: &UnaryExpression) -> u8 {
        match unary.operator {
            UnaryOperator::Not => {
                let operand_reg = self.emit_condition_expr(&unary.operand);
                self.emit_not(operand_reg)
            }
            UnaryOperator::Exists => {
                let operand_reg = self.emit_condition_expr(&unary.operand);
                self.emit_builtin_call("rbac.attribute_exists", &[operand_reg])
            }
            UnaryOperator::NotExists => {
                let operand_reg = self.emit_condition_expr(&unary.operand);
                self.emit_builtin_call("rbac.attribute_not_exists", &[operand_reg])
            }
        }
    }

    fn emit_binary_expr(&mut self, binary: &BinaryExpression) -> u8 {
        let left_reg = self.emit_condition_expr(&binary.left);
        let right_reg = self.emit_condition_expr(&binary.right);
        
        // Map RBAC operators to builtin functions or instructions
        match binary.operator.name.as_str() {
            // String operators
            "StringEquals" => {
                let dest = self.alloc_register();
                self.program.add_instruction(
                    Instruction::Eq { dest, left: left_reg, right: right_reg },
                    None,
                );
                dest
            }
            "StringNotEquals" => {
                let eq_reg = self.alloc_register();
                self.program.add_instruction(
                    Instruction::Eq { dest: eq_reg, left: left_reg, right: right_reg },
                    None,
                );
                self.emit_not(eq_reg)
            }
            "StringEqualsIgnoreCase" => {
                let op_reg = self.load_string("StringEquals");
                self.emit_builtin_call("rbac.for_any_of_any_values", &[left_reg, right_reg, op_reg])
            }
            "StringNotEqualsIgnoreCase" => {
                let op_reg = self.load_string("StringNotEquals");
                self.emit_builtin_call("rbac.for_any_of_any_values", &[left_reg, right_reg, op_reg])
            }
            "StringLike" | "StringMatches" => {
                self.emit_builtin_call("rbac.action_matches", &[left_reg, right_reg])
            }
            "StringNotLike" | "StringNotMatches" => {
                let result_reg = self.emit_builtin_call("rbac.action_matches", &[left_reg, right_reg]);
                self.emit_not(result_reg)
            }
            
            // Numeric operators
            "NumericEquals" => {
                let dest = self.alloc_register();
                self.program.add_instruction(
                    Instruction::Eq { dest, left: left_reg, right: right_reg },
                    None,
                );
                dest
            }
            "NumericNotEquals" => {
                let eq_reg = self.alloc_register();
                self.program.add_instruction(
                    Instruction::Eq { dest: eq_reg, left: left_reg, right: right_reg },
                    None,
                );
                self.emit_not(eq_reg)
            }
            "NumericLessThan" => {
                let dest = self.alloc_register();
                self.program.add_instruction(
                    Instruction::Lt { dest, left: left_reg, right: right_reg },
                    None,
                );
                dest
            }
            "NumericLessThanEquals" => {
                // left <= right is equivalent to !(left > right)
                let gt_reg = self.alloc_register();
                self.program.add_instruction(
                    Instruction::Gt { dest: gt_reg, left: left_reg, right: right_reg },
                    None,
                );
                self.emit_not(gt_reg)
            }
            "NumericGreaterThan" => {
                let dest = self.alloc_register();
                self.program.add_instruction(
                    Instruction::Gt { dest, left: left_reg, right: right_reg },
                    None,
                );
                dest
            }
            "NumericGreaterThanEquals" => {
                // left >= right is equivalent to !(left < right)
                let lt_reg = self.alloc_register();
                self.program.add_instruction(
                    Instruction::Lt { dest: lt_reg, left: left_reg, right: right_reg },
                    None,
                );
                self.emit_not(lt_reg)
            }
            "NumericInRange" => {
                self.emit_builtin_call("rbac.numeric_in_range", &[left_reg, right_reg])
            }
            
            // List operators
            "ListContains" => {
                self.emit_builtin_call("rbac.list_contains", &[left_reg, right_reg])
            }
            "ListNotContains" => {
                self.emit_builtin_call("rbac.list_not_contains", &[left_reg, right_reg])
            }
            
            // Cross-product operators
            "ForAnyOfAnyValues:StringEquals" | "ForAnyOfAnyValues" => {
                let op_reg = self.load_string("StringEquals");
                self.emit_builtin_call("rbac.for_any_of_any_values", &[left_reg, right_reg, op_reg])
            }
            "ForAllOfAnyValues:StringEquals" | "ForAllOfAnyValues" => {
                let op_reg = self.load_string("StringEquals");
                self.emit_builtin_call("rbac.for_all_of_any_values", &[left_reg, right_reg, op_reg])
            }
            "ForAnyOfAllValues:StringEquals" | "ForAnyOfAllValues" => {
                let op_reg = self.load_string("StringEquals");
                self.emit_builtin_call("rbac.for_any_of_all_values", &[left_reg, right_reg, op_reg])
            }
            "ForAllOfAllValues:StringEquals" | "ForAllOfAllValues" => {
                let op_reg = self.load_string("StringEquals");
                self.emit_builtin_call("rbac.for_all_of_all_values", &[left_reg, right_reg, op_reg])
            }
            
            // Default: equality comparison
            _ => {
                let dest = self.alloc_register();
                self.program.add_instruction(
                    Instruction::Eq { dest, left: left_reg, right: right_reg },
                    None,
                );
                dest
            }
        }
    }

    fn emit_function_call_expr(&mut self, call: &FunctionCallExpression) -> u8 {
        let arg_regs: Vec<u8> = call
            .arguments
            .iter()
            .map(|arg| self.emit_condition_expr(arg))
            .collect();
        
        // Map function names to RBAC builtins (need static str)
        match call.function.as_str() {
            "ActionMatches" => self.emit_builtin_call("rbac.action_matches", &arg_regs),
            "SubOperationMatches" => self.emit_builtin_call("rbac.suboperation_matches", &arg_regs),
            "Exists" => self.emit_builtin_call("rbac.attribute_exists", &arg_regs),
            "NotExists" => self.emit_builtin_call("rbac.attribute_not_exists", &arg_regs),
            "TimeOfDayEquals" => self.emit_builtin_call("rbac.time_of_day_equals", &arg_regs),
            "TimeOfDayNotEquals" => self.emit_builtin_call("rbac.time_of_day_not_equals", &arg_regs),
            "TimeOfDayGreaterThan" => self.emit_builtin_call("rbac.time_of_day_greater_than", &arg_regs),
            "TimeOfDayGreaterThanEquals" => self.emit_builtin_call("rbac.time_of_day_greater_than_equals", &arg_regs),
            "TimeOfDayLessThan" => self.emit_builtin_call("rbac.time_of_day_less_than", &arg_regs),
            "TimeOfDayLessThanEquals" => self.emit_builtin_call("rbac.time_of_day_less_than_equals", &arg_regs),
            "TimeOfDayInRange" => self.emit_builtin_call("rbac.time_of_day_in_range", &arg_regs),
            "IpMatch" => self.emit_builtin_call("rbac.ip_match", &arg_regs),
            "IpNotMatch" => self.emit_builtin_call("rbac.ip_not_match", &arg_regs),
            "IpInRange" => self.emit_builtin_call("rbac.ip_in_range", &arg_regs),
            // Default: treat as regular builtin
            _ => self.load_bool(false), // Unknown function returns false
        }
    }

    fn emit_attribute_reference(&mut self, attr: &AttributeReference) -> u8 {
        // Load input to access context
        let input_reg = self.alloc_register();
        self.program
            .add_instruction(Instruction::LoadInput { dest: input_reg }, None);
        
        // Map attribute source to input field
        let source_field = match attr.source {
            AttributeSource::Request => "request",
            AttributeSource::Resource => "resource",
            AttributeSource::Principal => "principal",
            AttributeSource::Environment => "environment",
            AttributeSource::Context => "context",
        };
        
        // Navigate to source object
        let source_reg = self.emit_input_lookup(input_reg, source_field);
        
        // If there's a namespace, navigate further
        let null_reg = self.null_register();
        let object_reg = if let Some(ref namespace) = attr.namespace {
            self.emit_object_get(source_reg, namespace, null_reg)
        } else {
            source_reg
        };
        
        // Get the attribute
        let result_reg = self.emit_object_get(object_reg, &attr.attribute, null_reg);
        
        // Navigate any additional path segments
        let mut current_reg = result_reg;
        for segment in &attr.path {
            match segment {
                AttributePathSegment::Key(key) => {
                    let null_reg = self.null_register();
                    current_reg = self.emit_object_get(current_reg, key, null_reg);
                }
                AttributePathSegment::Index(idx) => {
                    let idx_reg = self.alloc_register();
                    let idx_literal = self.add_literal_value(Value::from(*idx as i64));
                    self.program
                        .add_instruction(Instruction::Load { dest: idx_reg, literal_idx: idx_literal }, None);
                    let null_reg = self.null_register();
                    current_reg = self.emit_builtin_call("object.get", &[current_reg, idx_reg, null_reg]);
                }
            }
        }
        
        current_reg
    }

    fn emit_array_expr(&mut self, _array: &ArrayExpression) -> u8 {
        // Array quantifier expressions not yet fully supported
        // Return false for now
        self.load_bool(false)
    }

    fn emit_list_literal(&mut self, elements: &[ConditionExpr]) -> u8 {
        // Create an empty array as literal
        let empty_array_idx = self.add_literal_value(Value::new_array());
        let array_reg = self.alloc_register();
        self.program.add_instruction(
            Instruction::Load {
                dest: array_reg,
                literal_idx: empty_array_idx,
            },
            None,
        );
        
        // Append each element to the array
        for elem in elements {
            let elem_reg = self.emit_condition_expr(elem);
            let elem_array_idx = self.add_literal_value(Value::new_array());
            let temp_array_reg = self.alloc_register();
            self.program.add_instruction(
                Instruction::Load {
                    dest: temp_array_reg,
                    literal_idx: elem_array_idx,
                },
                None,
            );
            
            // Use array.concat to build up the array
            let concat_result = self.emit_builtin_call("array.concat", &[array_reg, elem_reg]);
            self.program.add_instruction(
                Instruction::Move {
                    dest: array_reg,
                    src: concat_result,
                },
                None,
            );
        }
        
        array_reg
    }

    fn finish(mut self) -> Program {
        self.program.rule_infos = self.rule_infos;

        let max_rule_window = self
            .rule_num_registers
            .iter()
            .copied()
            .map(|count| count as usize)
            .max()
            .unwrap_or(1);

        self.program.max_rule_window_size = max_rule_window;
        self.program.dispatch_window_size =
            core::cmp::max(self.entry_point_registers, max_rule_window).max(1);

        if self.program.instruction_spans.len() < self.program.instructions.len() {
            self.program
                .instruction_spans
                .resize(self.program.instructions.len(), None);
        }

        self.program
    }

    fn ensure_supported(_policy: &RbacPolicy) -> Result<(), RbacCompileError> {
        // Condition expressions are now supported
        Ok(())
    }
}

/// Utility functions for RBAC compilation
impl RbacCompiler {
    /// Check if a role assignment matches the current evaluation context
    pub fn matches_assignment(assignment: &RoleAssignment, context: &EvaluationContext) -> bool {
        if assignment.principal_id != context.principal.id {
            return false;
        }

        if !scope_covers(&assignment.scope, &context.resource.scope) {
            return false;
        }

        // Conditions are not yet supported
        assignment.condition.is_none()
    }

    /// Get permissions for a role definition
    pub fn get_role_permissions(role_def: &RoleDefinition) -> Vec<&Permission> {
        role_def.permissions.iter().collect()
    }

    /// Check if an action is allowed by a permission
    pub fn action_allowed(permission: &Permission, action: &str) -> bool {
        matches_patterns(&permission.actions, action)
            && !matches_patterns(&permission.not_actions, action)
    }

    /// Check if a data action is allowed by a permission
    pub fn data_action_allowed(permission: &Permission, data_action: &str) -> bool {
        matches_patterns(&permission.data_actions, data_action)
            && !matches_patterns(&permission.not_data_actions, data_action)
    }
}
