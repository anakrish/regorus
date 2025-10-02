// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(non_snake_case)]

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
/// WASM wrapper for [`regorus::PolicyModule`]
pub struct PolicyModule {
    id: String,
    content: String,
}

#[wasm_bindgen]
impl PolicyModule {
    #[wasm_bindgen(constructor)]
    /// Create a new PolicyModule
    /// * `id`: Identifier for the policy module (e.g., filename)
    /// * `content`: Rego policy content
    pub fn new(id: String, content: String) -> PolicyModule {
        PolicyModule { id, content }
    }

    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn content(&self) -> String {
        self.content.clone()
    }
}

#[wasm_bindgen]
/// WASM wrapper for [`regorus::Engine`]
pub struct Engine {
    engine: regorus::Engine,
}

fn error_to_jsvalue<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&format!("{e}"))
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Engine {
    /// Clone a [`Engine`]
    ///
    /// To avoid having to parse same policy again, the engine can be cloned
    /// after policies and data have been added.
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
        }
    }
}

#[wasm_bindgen]
impl Engine {
    #[wasm_bindgen(constructor)]
    /// Construct a new Engine
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html
    pub fn new() -> Self {
        Self {
            engine: regorus::Engine::new(),
        }
    }

    /// Turn on rego v0.
    ///
    /// Regorus defaults to rego v1.
    ///
    /// * `enable`: Whether to enable or disable rego v0.
    pub fn setRegoV0(&mut self, enable: bool) {
        self.engine.set_rego_v0(enable)
    }

    /// Add a policy
    ///
    /// The policy is parsed into AST.
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.add_policy
    ///
    /// * `path`: A filename to be associated with the policy.
    /// * `rego`: Rego policy.
    pub fn addPolicy(&mut self, path: String, rego: String) -> Result<String, JsValue> {
        self.engine.add_policy(path, rego).map_err(error_to_jsvalue)
    }

    /// Add policy data.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.add_data
    /// * `data`: JSON encoded value to be used as policy data.
    pub fn addDataJson(&mut self, data: String) -> Result<(), JsValue> {
        let data = regorus::Value::from_json_str(&data).map_err(error_to_jsvalue)?;
        self.engine.add_data(data).map_err(error_to_jsvalue)
    }

    /// Get the list of packages defined by loaded policies.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.get_packages
    pub fn getPackages(&self) -> Result<Vec<String>, JsValue> {
        self.engine.get_packages().map_err(error_to_jsvalue)
    }

    /// Get the list of policies.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.get_policies
    pub fn getPolicies(&self) -> Result<String, JsValue> {
        self.engine.get_policies_as_json().map_err(error_to_jsvalue)
    }

    /// Clear policy data.
    ///
    /// See https://docs.rs/regorus/0.1.0-alpha.2/regorus/struct.Engine.html#method.clear_data
    pub fn clearData(&mut self) -> Result<(), JsValue> {
        self.engine.clear_data();
        Ok(())
    }

    /// Set input.
    ///
    /// See https://docs.rs/regorus/0.1.0-alpha.2/regorus/struct.Engine.html#method.set_input
    /// * `input`: JSON encoded value to be used as input to query.
    pub fn setInputJson(&mut self, input: String) -> Result<(), JsValue> {
        let input = regorus::Value::from_json_str(&input).map_err(error_to_jsvalue)?;
        self.engine.set_input(input);
        Ok(())
    }

    /// Evaluate query.
    ///
    /// See https://docs.rs/regorus/0.1.0-alpha.2/regorus/struct.Engine.html#method.eval_query
    /// * `query`: Rego expression to be evaluate.
    pub fn evalQuery(&mut self, query: String) -> Result<String, JsValue> {
        let results = self
            .engine
            .eval_query(query, false)
            .map_err(error_to_jsvalue)?;
        serde_json::to_string_pretty(&results).map_err(error_to_jsvalue)
    }

    /// Evaluate rule(s) at given path.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.eval_rule
    ///
    /// * `path`: The full path to the rule(s).
    pub fn evalRule(&mut self, path: String) -> Result<String, JsValue> {
        let v = self.engine.eval_rule(path).map_err(error_to_jsvalue)?;
        v.to_json_str().map_err(error_to_jsvalue)
    }

    /// Gather output from print statements instead of emiting to stderr.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.set_gather_prints
    /// * `b`: Whether to enable gathering prints or not.
    pub fn setGatherPrints(&mut self, b: bool) {
        self.engine.set_gather_prints(b)
    }

    /// Take the gathered output of print statements.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.take_prints
    pub fn takePrints(&mut self) -> Result<Vec<String>, JsValue> {
        self.engine.take_prints().map_err(error_to_jsvalue)
    }

    /// Enable/disable policy coverage.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.set_enable_coverage
    /// * `b`: Whether to enable gathering coverage or not.
    #[cfg(feature = "coverage")]
    pub fn setEnableCoverage(&mut self, enable: bool) {
        self.engine.set_enable_coverage(enable)
    }

    /// Get the coverage report as json.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.get_coverage_report
    #[cfg(feature = "coverage")]
    pub fn getCoverageReport(&self) -> Result<String, JsValue> {
        let report = self
            .engine
            .get_coverage_report()
            .map_err(error_to_jsvalue)?;
        serde_json::to_string_pretty(&report).map_err(error_to_jsvalue)
    }

    /// Clear gathered coverage data.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.clear_coverage_data
    #[cfg(feature = "coverage")]
    pub fn clearCoverageData(&mut self) {
        self.engine.clear_coverage_data()
    }

    /// Get ANSI color coded coverage report.
    ///
    /// See https://docs.rs/regorus/latest/regorus/coverage/struct.Report.html#method.to_string_pretty
    #[cfg(feature = "coverage")]
    pub fn getCoverageReportPretty(&self) -> Result<String, JsValue> {
        let report = self
            .engine
            .get_coverage_report()
            .map_err(error_to_jsvalue)?;
        report.to_string_pretty().map_err(error_to_jsvalue)
    }

    /// Get AST of policies.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.get_ast_as_json
    #[cfg(feature = "ast")]
    pub fn getAstAsJson(&self) -> Result<String, JsValue> {
        self.engine.get_ast_as_json().map_err(error_to_jsvalue)
    }

    /// Compile a policy with a specific entry point rule.
    ///
    /// This method creates a compiled policy that can be used to generate RVM programs.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.compile_with_entrypoint
    /// * `rule`: The specific rule path to evaluate (e.g., "data.policy.allow")
    pub fn compileWithEntrypoint(&mut self, rule: String) -> Result<CompiledPolicy, JsValue> {
        let rule_rc: regorus::Rc<str> = rule.into();
        let compiled_policy = self.engine.compile_with_entrypoint(&rule_rc).map_err(error_to_jsvalue)?;
        Ok(CompiledPolicy::new(compiled_policy))
    }
}

#[wasm_bindgen]
/// WASM wrapper for [`regorus::CompiledPolicy`]
pub struct CompiledPolicy {
    policy: regorus::CompiledPolicy,
}

impl CompiledPolicy {
    fn new(policy: regorus::CompiledPolicy) -> Self {
        Self { policy }
    }
}

#[wasm_bindgen]
impl CompiledPolicy {
    /// Evaluate the compiled policy with the given input using the interpreter.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.CompiledPolicy.html#method.eval_with_input
    /// * `input`: JSON encoded input value for policy evaluation
    pub fn evalWithInput(&self, input: String) -> Result<String, JsValue> {
        let input_value = regorus::Value::from_json_str(&input).map_err(error_to_jsvalue)?;
        let result = self.policy.eval_with_input(input_value).map_err(error_to_jsvalue)?;
        result.to_json_str().map_err(error_to_jsvalue)
    }

    /// Get the entry point rule for this compiled policy.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.CompiledPolicy.html#method.entrypoint
    pub fn getEntrypoint(&self) -> String {
        self.policy.entrypoint().to_string()
    }

    /// Compile this policy to an RVM program.
    ///
    /// * `entry_points`: Array of entry point rules to include in the program
    pub fn compileToRvmProgram(&self, entry_points: Vec<String>) -> Result<RvmProgram, JsValue> {
        let entry_points_strs: Vec<&str> = entry_points.iter().map(|s| s.as_str()).collect();
        let program = regorus::rvm::compiler::Compiler::compile_from_policy(&self.policy, &entry_points_strs)
            .map_err(error_to_jsvalue)?;
        Ok(RvmProgram::new(program))
    }
}

#[wasm_bindgen]
/// WASM wrapper for RVM Program
pub struct RvmProgram {
    program: std::sync::Arc<regorus::rvm::program::Program>,
}

impl RvmProgram {
    fn new(program: std::sync::Arc<regorus::rvm::program::Program>) -> Self {
        Self { program }
    }
}

#[wasm_bindgen]
impl RvmProgram {
    /// Get the number of instructions in this program.
    pub fn getInstructionCount(&self) -> usize {
        self.program.instructions.len()
    }

    /// Get the number of entry points in this program.
    pub fn getEntryPointCount(&self) -> usize {
        self.program.entry_points.len()
    }

    /// Get the list of entry point names.
    pub fn getEntryPointNames(&self) -> Vec<String> {
        self.program.entry_points.keys().map(|k| k.to_string()).collect()
    }

    /// Serialize the program to binary format.
    pub fn serializeBinary(&self) -> Result<Vec<u8>, JsValue> {
        self.program.serialize_binary().map_err(error_to_jsvalue)
    }

    /// Serialize the program to JSON format for inspection.
    pub fn toJson(&self) -> Result<String, JsValue> {
        serde_json::to_string_pretty(&*self.program).map_err(error_to_jsvalue)
    }

    /// Get a formatted assembly listing of the program.
    pub fn toAssemblyListing(&self) -> String {
        use regorus::rvm::{generate_assembly_listing, AssemblyListingConfig};
        
        let config = AssemblyListingConfig::default();
        generate_assembly_listing(&self.program, &config)
    }
}

#[wasm_bindgen]
/// WASM wrapper for RVM Virtual Machine
pub struct RegoVM {
    vm: regorus::rvm::vm::RegoVM,
}

#[wasm_bindgen]
impl RegoVM {
    #[wasm_bindgen(constructor)]
    /// Create a new RVM instance.
    pub fn new() -> Self {
        Self {
            vm: regorus::rvm::vm::RegoVM::new(),
        }
    }

    /// Create a new RVM instance with a compiled policy.
    pub fn newWithPolicy(policy: &CompiledPolicy) -> Self {
        Self {
            vm: regorus::rvm::vm::RegoVM::new_with_policy(policy.policy.clone()),
        }
    }

    /// Load a program into the VM.
    pub fn loadProgram(&mut self, program: &RvmProgram) -> Result<(), JsValue> {
        self.vm.load_program(program.program.clone());
        Ok(())
    }

    /// Set the input data for evaluation.
    /// * `input`: JSON encoded input value
    pub fn setInput(&mut self, input: String) -> Result<(), JsValue> {
        let input_value = regorus::Value::from_json_str(&input).map_err(error_to_jsvalue)?;
        self.vm.set_input(input_value);
        Ok(())
    }

    /// Set the data for evaluation.
    /// * `data`: JSON encoded data value
    pub fn setData(&mut self, data: String) -> Result<(), JsValue> {
        let data_value = regorus::Value::from_json_str(&data).map_err(error_to_jsvalue)?;
        self.vm.set_data(data_value).map_err(error_to_jsvalue)?;
        Ok(())
    }

    /// Execute the loaded program.
    pub fn execute(&mut self) -> Result<String, JsValue> {
        let result = self.vm.execute().map_err(error_to_jsvalue)?;
        result.to_json_str().map_err(error_to_jsvalue)
    }

    /// Execute a specific entry point by index.
    /// * `index`: The index of the entry point to execute (0-based)
    pub fn executeEntryPointByIndex(&mut self, index: usize) -> Result<String, JsValue> {
        let result = self.vm.execute_entry_point_by_index(index).map_err(error_to_jsvalue)?;
        result.to_json_str().map_err(error_to_jsvalue)
    }

    /// Execute a specific entry point by name.
    /// * `name`: The name of the entry point to execute (e.g., "data.policy.allow")
    pub fn executeEntryPointByName(&mut self, name: String) -> Result<String, JsValue> {
        let result = self.vm.execute_entry_point_by_name(&name).map_err(error_to_jsvalue)?;
        result.to_json_str().map_err(error_to_jsvalue)
    }

    /// Get the number of entry points available in the loaded program.
    pub fn getEntryPointCount(&self) -> usize {
        self.vm.get_entry_point_count()
    }

    /// Get all entry point names available in the loaded program.
    pub fn getEntryPointNames(&self) -> Vec<String> {
        self.vm.get_entry_point_names()
    }
}

/// Compile a policy from data and modules with a specific entry point rule.
///
/// This is a convenience function that sets up an Engine internally and calls
/// the appropriate compilation method.
///
/// See https://docs.rs/regorus/latest/regorus/fn.compile_policy_with_entrypoint.html
/// * `data_json`: JSON string containing static data for policy evaluation
/// * `modules`: Array of PolicyModule objects to compile
/// * `entry_point_rule`: The specific rule path to evaluate (e.g., "data.policy.allow")
#[wasm_bindgen]
pub fn compilePolicyWithEntrypoint(
    data_json: String,
    modules: Vec<PolicyModule>,
    entry_point_rule: String,
) -> Result<CompiledPolicy, JsValue> {
    let data = regorus::Value::from_json_str(&data_json).map_err(error_to_jsvalue)?;
    
    let policy_modules: Vec<regorus::PolicyModule> = modules
        .into_iter()
        .map(|m| regorus::PolicyModule {
            id: m.id.into(),
            content: m.content.into(),
        })
        .collect();

    let entry_point_rc: regorus::Rc<str> = entry_point_rule.into();
    let compiled_policy = regorus::compile_policy_with_entrypoint(data, &policy_modules, entry_point_rc)
        .map_err(error_to_jsvalue)?;
    
    Ok(CompiledPolicy::new(compiled_policy))
}

/// Compile a policy directly to an RVM program.
///
/// This is a convenience function that compiles a policy and immediately
/// creates an RVM program from it.
///
/// * `data_json`: JSON string containing static data for policy evaluation
/// * `modules`: Array of PolicyModule objects to compile
/// * `entry_points`: Array of entry point rules to include in the program
#[wasm_bindgen]
pub fn compileToRvmProgram(
    data_json: String,
    modules: Vec<PolicyModule>,
    entry_points: Vec<String>,
) -> Result<RvmProgram, JsValue> {
    if entry_points.is_empty() {
        return Err(JsValue::from_str("At least one entry point is required"));
    }
    
    // Use the first entry point for compilation
    let first_entry_point = entry_points[0].clone();
    let compiled_policy = compilePolicyWithEntrypoint(data_json, modules, first_entry_point)?;
    
    // Convert all entry points to RVM program
    compiled_policy.compileToRvmProgram(entry_points)
}

// ============================================================================
// RBAC API
// ============================================================================

#[wasm_bindgen]
/// WASM wrapper for RBAC Policy
pub struct RbacPolicy {
    policy: regorus::rbac::RbacPolicy,
}

#[wasm_bindgen]
impl RbacPolicy {
    /// Parse an RBAC policy from JSON string
    /// * `policy_json`: JSON string containing the RBAC policy definition
    #[wasm_bindgen(constructor)]
    pub fn fromJson(policy_json: String) -> Result<RbacPolicy, JsValue> {
        let policy = regorus::rbac::RbacParser::parse_policy(&policy_json)
            .map_err(error_to_jsvalue)?;
        Ok(RbacPolicy { policy })
    }

    /// Get the version of the RBAC policy
    pub fn getVersion(&self) -> String {
        self.policy.version.clone()
    }

    /// Get the number of role definitions in the policy
    pub fn getRoleDefinitionCount(&self) -> usize {
        self.policy.role_definitions.len()
    }

    /// Get the number of role assignments in the policy
    pub fn getRoleAssignmentCount(&self) -> usize {
        self.policy.role_assignments.len()
    }

    /// Compile the RBAC policy to an RVM program
    /// * `context_json`: JSON string containing the evaluation context
    pub fn compileToRvmProgram(&self, context_json: String) -> Result<RvmProgram, JsValue> {
        // Parse the context JSON manually
        let context_value: serde_json::Value = serde_json::from_str(&context_json)
            .map_err(error_to_jsvalue)?;
        
        let context = parse_evaluation_context(&context_value)
            .map_err(error_to_jsvalue)?;
        
        let program = regorus::rbac::RbacCompiler::compile_to_program(&self.policy, &context)
            .map_err(error_to_jsvalue)?;
        
        Ok(RvmProgram::new(std::sync::Arc::new(program)))
    }
}

#[wasm_bindgen]
/// WASM wrapper for RBAC Evaluation Context
pub struct RbacEvaluationContext {
    context: regorus::rbac::EvaluationContext,
}

#[wasm_bindgen]
impl RbacEvaluationContext {
    /// Create an evaluation context from JSON string
    /// * `context_json`: JSON string with principal, resource, action fields
    #[wasm_bindgen(constructor)]
    pub fn fromJson(context_json: String) -> Result<RbacEvaluationContext, JsValue> {
        let context_value: serde_json::Value = serde_json::from_str(&context_json)
            .map_err(error_to_jsvalue)?;
        
        let context = parse_evaluation_context(&context_value)
            .map_err(error_to_jsvalue)?;
        
        Ok(RbacEvaluationContext { context })
    }

    /// Get the principal ID from the context
    pub fn getPrincipalId(&self) -> String {
        self.context.principal.id.clone()
    }

    /// Get the resource scope from the context
    pub fn getResourceScope(&self) -> String {
        self.context.resource.scope.clone()
    }

    /// Get the action being requested
    pub fn getAction(&self) -> Option<String> {
        self.context.action.clone()
    }
}

#[wasm_bindgen]
/// WASM wrapper for RBAC Engine
pub struct RbacEngine {
    policy: Option<regorus::rbac::RbacPolicy>,
}

#[wasm_bindgen]
impl RbacEngine {
    /// Create a new RBAC engine instance
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            policy: None,
        }
    }

    /// Load an RBAC policy from JSON string
    /// * `policy_json`: JSON string containing the RBAC policy definition
    pub fn loadPolicyFromJson(&mut self, policy_json: String) -> Result<(), JsValue> {
        let policy = regorus::rbac::RbacParser::parse_policy(&policy_json)
            .map_err(error_to_jsvalue)?;
        self.policy = Some(policy);
        Ok(())
    }

    /// Evaluate whether an action is allowed
    /// * `context_json`: JSON string with principal, resource, action fields
    pub fn evaluate(&self, context_json: String) -> Result<bool, JsValue> {
        let policy = self.policy.as_ref()
            .ok_or_else(|| JsValue::from_str("No policy loaded"))?;
        
        let context_value: serde_json::Value = serde_json::from_str(&context_json)
            .map_err(error_to_jsvalue)?;
        
        let context = parse_evaluation_context(&context_value)
            .map_err(error_to_jsvalue)?;
        
        regorus::rbac::RbacEngine::evaluate(policy, &context).map_err(error_to_jsvalue)
    }

    /// Evaluate and return detailed result as JSON
    /// * `context_json`: JSON string with principal, resource, action fields
    pub fn evaluateDetailed(&self, context_json: String) -> Result<String, JsValue> {
        let policy = self.policy.as_ref()
            .ok_or_else(|| JsValue::from_str("No policy loaded"))?;
        
        let context_value: serde_json::Value = serde_json::from_str(&context_json)
            .map_err(error_to_jsvalue)?;
        
        let context = parse_evaluation_context(&context_value)
            .map_err(error_to_jsvalue)?;
        
        let result = regorus::rbac::RbacEngine::evaluate(policy, &context).map_err(error_to_jsvalue)?;
        
        let response = serde_json::json!({
            "allowed": result,
            "principal_id": context.principal.id,
            "resource_scope": context.resource.scope,
            "action": context.action,
        });
        
        serde_json::to_string(&response).map_err(error_to_jsvalue)
    }
}

impl Default for RbacEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Compile an RBAC policy directly to an RVM program
/// 
/// This is a convenience function that parses an RBAC policy and compiles it
/// to an RVM program in one step.
///
/// * `policy_json`: JSON string containing the RBAC policy definition
/// * `context_json`: JSON string containing the evaluation context
#[wasm_bindgen]
pub fn compileRbacToRvmProgram(
    policy_json: String,
    context_json: String,
) -> Result<RvmProgram, JsValue> {
    let policy = regorus::rbac::RbacParser::parse_policy(&policy_json)
        .map_err(error_to_jsvalue)?;
    
    let context_value: serde_json::Value = serde_json::from_str(&context_json)
        .map_err(error_to_jsvalue)?;
    let context = parse_evaluation_context(&context_value)
        .map_err(error_to_jsvalue)?;
    
    let program = regorus::rbac::RbacCompiler::compile_to_program(&policy, &context)
        .map_err(error_to_jsvalue)?;
    
    Ok(RvmProgram::new(std::sync::Arc::new(program)))
}

/// Evaluate an RBAC policy using the RVM
///
/// This is a convenience function that compiles an RBAC policy to RVM and executes it.
///
/// * `policy_json`: JSON string containing the RBAC policy definition
/// * `context_json`: JSON string containing the evaluation context
#[wasm_bindgen]
pub fn evaluateRbacPolicy(
    policy_json: String,
    context_json: String,
) -> Result<bool, JsValue> {
    let policy = regorus::rbac::RbacParser::parse_policy(&policy_json)
        .map_err(error_to_jsvalue)?;
    
    let context_value: serde_json::Value = serde_json::from_str(&context_json)
        .map_err(error_to_jsvalue)?;
    let context = parse_evaluation_context(&context_value)
        .map_err(error_to_jsvalue)?;
    
    let program = regorus::rbac::RbacCompiler::compile_to_program(&policy, &context)
        .map_err(error_to_jsvalue)?;
    
    let mut vm = regorus::rvm::vm::RegoVM::new();
    vm.load_program(std::sync::Arc::new(program));
    
    // Build VM input from context
    let vm_input = build_vm_input(&context);
    vm.set_input(vm_input);
    vm.set_data(regorus::Value::new_object()).map_err(error_to_jsvalue)?;
    
    let result = vm.execute().map_err(error_to_jsvalue)?;
    
    match result {
        regorus::Value::Bool(b) => Ok(b),
        regorus::Value::Undefined => Ok(false), // Undefined means deny
        _ => Err(JsValue::from_str(&format!("Unexpected result type: {:?}", result))),
    }
}

// Helper functions for WASM bindings

fn parse_evaluation_context(json: &serde_json::Value) -> Result<regorus::rbac::EvaluationContext, String> {
    use regorus::rbac::*;
    use regorus::Value;
    
    // Parse principal
    let principal_obj = json.get("principal")
        .ok_or_else(|| "Missing 'principal' field".to_string())?;
    
    let principal_id = principal_obj.get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing or invalid 'principal.id'".to_string())?;
    
    let principal_type_str = principal_obj.get("principalType")
        .and_then(|v| v.as_str())
        .unwrap_or("User");
    
    let principal_type = match principal_type_str {
        "User" => PrincipalType::User,
        "Group" => PrincipalType::Group,
        "ServicePrincipal" => PrincipalType::ServicePrincipal,
        "ManagedServiceIdentity" => PrincipalType::ManagedServiceIdentity,
        _ => PrincipalType::User,
    };
    
    let principal_attributes = principal_obj.get("attributes")
        .and_then(|v| serde_json::from_value::<Value>(v.clone()).ok())
        .unwrap_or_else(Value::new_object);
    
    // Parse resource
    let resource_obj = json.get("resource")
        .ok_or_else(|| "Missing 'resource' field".to_string())?;
    
    let resource_scope = resource_obj.get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or("/");
    
    let resource_id = resource_obj.get("id")
        .and_then(|v| v.as_str())
        .unwrap_or(resource_scope);
    
    let resource_type = resource_obj.get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("Microsoft.Resources/subscriptions");
    
    let resource_attributes = resource_obj.get("attributes")
        .and_then(|v| serde_json::from_value::<Value>(v.clone()).ok())
        .unwrap_or_else(Value::new_object);
    
    // Parse action
    let action = json.get("action")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    
    let suboperation = json.get("subOperation")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    
    // Parse request attributes
    let request_attributes = json.get("request")
        .and_then(|req| req.get("attributes"))
        .and_then(|v| serde_json::from_value::<Value>(v.clone()).ok())
        .unwrap_or_else(Value::new_object);
    
    Ok(EvaluationContext {
        principal: Principal {
            id: principal_id.to_string(),
            principal_type,
            custom_security_attributes: principal_attributes,
        },
        resource: Resource {
            id: resource_id.to_string(),
            resource_type: resource_type.to_string(),
            scope: resource_scope.to_string(),
            attributes: resource_attributes,
        },
        request: RequestContext {
            action: action.clone(),
            data_action: None,
            attributes: request_attributes,
        },
        environment: EnvironmentContext {
            is_private_link: None,
            private_endpoint: None,
            subnet: None,
            utc_now: None,
        },
        action,
        suboperation,
    })
}

fn build_vm_input(context: &regorus::rbac::EvaluationContext) -> regorus::Value {
    use regorus::Value;
    use std::collections::BTreeMap;
    
    let mut input_map: BTreeMap<Value, Value> = BTreeMap::new();

    // The RBAC compiler expects input with these fields:
    // - principalId: the principal making the request
    // - resource: the resource being accessed (uses scope)
    // - action: the action being performed
    // - actionType: "dataAction" or "action"
    
    input_map.insert(
        Value::String("principalId".into()),
        Value::String(context.principal.id.clone().into()),
    );
    
    input_map.insert(
        Value::String("resource".into()),
        Value::String(context.resource.scope.clone().into()),
    );
    
    // Determine action and actionType following the same logic as test_runner.rs
    let (action_value, action_type) = if let Some(data_action) = &context.request.data_action {
        (data_action.clone(), "dataAction")
    } else if let Some(action) = &context.request.action {
        (action.clone(), "action")
    } else if let Some(action) = &context.action {
        (action.clone(), "action")
    } else {
        (String::new(), "action")
    };
    
    input_map.insert(
        Value::String("action".into()),
        Value::String(action_value.into()),
    );
    
    input_map.insert(
        Value::String("actionType".into()),
        Value::String(action_type.into()),
    );

    Value::from(input_map)
}

#[cfg(test)]
mod tests {
    use crate::{error_to_jsvalue, PolicyModule, RegoVM};
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    #[allow(dead_code)]
    pub fn basic() -> Result<(), JsValue> {
        let mut engine = crate::Engine::new();
        engine.setEnableCoverage(true);

        // Exercise all APIs.
        engine.addDataJson(
            r#"
        {
           "foo" : "bar"
        }
        "#
            .to_string(),
        )?;

        engine.setInputJson(
            r#"
        {
           "message" : "Hello"
        }
        "#
            .to_string(),
        )?;

        let pkg = engine.addPolicy(
            "hello.rego".to_string(),
            r#"
            package test
            message = input.message"#
                .to_string(),
        )?;
        assert_eq!(pkg, "data.test");

        let results = engine.evalQuery("data".to_string())?;
        let r = regorus::Value::from_json_str(&results).map_err(error_to_jsvalue)?;

        let v = &r["result"][0]["expressions"][0]["value"];

        // Ensure that input and policy were evaluated.
        assert_eq!(v["test"]["message"], regorus::Value::from("Hello"));

        // Test that data was set.
        assert_eq!(v["foo"], regorus::Value::from("bar"));

        // Use eval_rule to perform same query.
        let v = engine.evalRule("data.test.message".to_owned())?;
        let v = regorus::Value::from_json_str(&v).map_err(error_to_jsvalue)?;

        // Ensure that input and policy were evaluated.
        assert_eq!(v, regorus::Value::from("Hello"));

        let pkgs = engine.getPackages()?;
        assert_eq!(pkgs, vec!["data.test"]);

        engine.setGatherPrints(true);
        let _ = engine.evalQuery("print(\"Hello\")".to_owned());
        let prints = engine.takePrints()?;
        assert_eq!(prints, vec!["<query.rego>:1: Hello"]);

        // Test clone.
        let mut engine1 = engine.clone();

        // Test code coverage.
        let report = engine1.getCoverageReport()?;
        let r = regorus::Value::from_json_str(&report).map_err(error_to_jsvalue)?;

        assert_eq!(
            r["files"][0]["covered"]
                .as_array()
                .map_err(crate::error_to_jsvalue)?,
            &vec![regorus::Value::from(3)]
        );

        println!("{}", engine1.getCoverageReportPretty()?);

        engine1.clearCoverageData();

        let policies = engine1.getPolicies()?;
        let v = regorus::Value::from_json_str(&policies).map_err(error_to_jsvalue)?;
        assert_eq!(
            v[0]["path"].as_string().map_err(error_to_jsvalue)?.as_ref(),
            "hello.rego"
        );

        // Test compilation
        let compiled_policy = engine1.compileWithEntrypoint("data.test.message".to_string())?;
        assert_eq!(compiled_policy.getEntrypoint(), "data.test.message");
        
        // Test interpreter evaluation
        let interp_result = compiled_policy.evalWithInput(r#"{"message": "Hello Compiled"}"#.to_string())?;
        let interp_value = regorus::Value::from_json_str(&interp_result).map_err(error_to_jsvalue)?;
        assert_eq!(interp_value, regorus::Value::from("Hello Compiled"));

        // Test RVM compilation and execution
        let rvm_program = compiled_policy.compileToRvmProgram(vec!["data.test.message".to_string()])?;
        assert_eq!(rvm_program.getInstructionCount() > 0, true);
        assert_eq!(rvm_program.getEntryPointCount(), 1);
        
        let mut vm = RegoVM::newWithPolicy(&compiled_policy);
        vm.loadProgram(&rvm_program)?;
        vm.setInput(r#"{"message": "Hello RVM"}"#.to_string())?;
        let rvm_result = vm.execute()?;
        let rvm_value = regorus::Value::from_json_str(&rvm_result).map_err(error_to_jsvalue)?;
        assert_eq!(rvm_value, regorus::Value::from("Hello RVM"));

        // Test standalone compilation function
        let module = PolicyModule::new(
            "standalone.rego".to_string(),
            r#"package standalone
            result := input.value * 2"#.to_string(),
        );
        let standalone_program = crate::compileToRvmProgram(
            r#"{"base": 10}"#.to_string(),
            vec![module],
            vec!["data.standalone.result".to_string()],
        )?;
        
        let mut standalone_vm = RegoVM::new();
        standalone_vm.loadProgram(&standalone_program)?;
        standalone_vm.setData(r#"{"base": 10}"#.to_string())?;
        standalone_vm.setInput(r#"{"value": 21}"#.to_string())?;
        let standalone_result = standalone_vm.execute()?;
        let standalone_value = regorus::Value::from_json_str(&standalone_result).map_err(error_to_jsvalue)?;
        assert_eq!(standalone_value, regorus::Value::from(42));

        Ok(())
    }

    #[wasm_bindgen_test]
    pub fn rvm_program_api_test() -> Result<(), JsValue> {
        // Test RVM Program serialization and metadata APIs
        let module = PolicyModule::new(
            "test.rego".to_string(),
            r#"package test
            allow := true if input.user == "admin"
            deny := true if input.user == "guest"
            message := sprintf("Hello %s", [input.user])"#.to_string(),
        );

        // Compile with multiple entry points
        let program = crate::compileToRvmProgram(
            r#"{"allowed_users": ["admin", "user"]}"#.to_string(),
            vec![module],
            vec![
                "data.test.allow".to_string(),
                "data.test.deny".to_string(),
                "data.test.message".to_string()
            ],
        )?;

        // Test program metadata
        assert_eq!(program.getEntryPointCount(), 3);
        assert!(program.getInstructionCount() > 0);
        
        let entry_points = program.getEntryPointNames();
        assert_eq!(entry_points.len(), 3);
        assert!(entry_points.contains(&"data.test.allow".to_string()));
        assert!(entry_points.contains(&"data.test.deny".to_string()));
        assert!(entry_points.contains(&"data.test.message".to_string()));

        // Test binary serialization
        let serialized = program.serializeBinary()?;
        assert!(serialized.len() > 0);

        // Test RVM execution with different inputs
        let mut vm = RegoVM::new();
        vm.loadProgram(&program)?;
        vm.setData(r#"{"allowed_users": ["admin", "user"]}"#.to_string())?;

        // Test admin user
        vm.setInput(r#"{"user": "admin"}"#.to_string())?;
        let result = vm.execute()?;
        let result_value = regorus::Value::from_json_str(&result).map_err(error_to_jsvalue)?;
        // The main program should return the result of the first entry point (allow)
        assert_eq!(result_value, regorus::Value::from(true));

        // Test guest user
        vm.setInput(r#"{"user": "guest"}"#.to_string())?;
        let result = vm.execute()?;
        let result_value = regorus::Value::from_json_str(&result).map_err(error_to_jsvalue)?;
        // Should return false for allow rule
        assert_eq!(result_value, regorus::Value::from(false));

        Ok(())
    }

    #[wasm_bindgen_test]
    pub fn rvm_error_handling_test() -> Result<(), JsValue> {
        // Test error handling in RVM
        let module = PolicyModule::new(
            "error_test.rego".to_string(),
            r#"package error_test
            result := input.nonexistent.field"#.to_string(),
        );

        let program = crate::compileToRvmProgram(
            r#"{}"#.to_string(),
            vec![module],
            vec!["data.error_test.result".to_string()],
        )?;

        let mut vm = RegoVM::new();
        vm.loadProgram(&program)?;
        vm.setInput(r#"{"valid": "field"}"#.to_string())?;
        
        // This should not crash, should return undefined
        let result = vm.execute()?;
        let result_value = regorus::Value::from_json_str(&result).map_err(error_to_jsvalue)?;
        assert_eq!(result_value, regorus::Value::Undefined);

        Ok(())
    }

    #[wasm_bindgen_test]
    pub fn rbac_basic_test() -> Result<(), JsValue> {
        // Test basic RBAC policy evaluation
        let policy_json = r#"{
            "version": "1.0",
            "roleDefinitions": [{
                "id": "reader",
                "name": "Reader",
                "permissions": [{
                    "actions": ["read"],
                    "notActions": [],
                    "dataActions": [],
                    "notDataActions": []
                }],
                "assignableScopes": ["/"]
            }],
            "roleAssignments": [{
                "id": "assignment1",
                "principalId": "user1",
                "principalType": "User",
                "roleDefinitionId": "reader",
                "scope": "/"
            }]
        }"#;

        let context_json = r#"{
            "principal": {
                "id": "user1",
                "principalType": "User"
            },
            "resource": {
                "scope": "/subscriptions/sub1"
            },
            "action": "read"
        }"#;

        // Test RbacPolicy parsing
        let policy = crate::RbacPolicy::fromJson(policy_json.to_string())?;
        assert_eq!(policy.getVersion(), "1.0");
        assert_eq!(policy.getRoleDefinitionCount(), 1);
        assert_eq!(policy.getRoleAssignmentCount(), 1);

        // Test RbacEvaluationContext parsing
        let context = crate::RbacEvaluationContext::fromJson(context_json.to_string())?;
        assert_eq!(context.getPrincipalId(), "user1");
        assert_eq!(context.getAction(), Some("read".to_string()));

        // Test RbacEngine evaluation
        let mut engine = crate::RbacEngine::new();
        engine.loadPolicyFromJson(policy_json.to_string())?;
        let allowed = engine.evaluate(context_json.to_string())?;
        assert_eq!(allowed, true);

        // Test detailed evaluation
        let detailed = engine.evaluateDetailed(context_json.to_string())?;
        let detailed_value = regorus::Value::from_json_str(&detailed).map_err(error_to_jsvalue)?;
        assert_eq!(detailed_value["allowed"], regorus::Value::Bool(true));
        assert_eq!(detailed_value["principal_id"], regorus::Value::from("user1"));

        Ok(())
    }

    #[wasm_bindgen_test]
    pub fn rbac_compilation_test() -> Result<(), JsValue> {
        // Test RBAC policy compilation to RVM
        let policy_json = r#"{
            "version": "1.0",
            "roleDefinitions": [{
                "id": "admin",
                "name": "Administrator",
                "permissions": [{
                    "actions": ["*"],
                    "notActions": [],
                    "dataActions": [],
                    "notDataActions": []
                }],
                "assignableScopes": ["/"]
            }],
            "roleAssignments": [{
                "id": "assignment1",
                "principalId": "admin1",
                "principalType": "User",
                "roleDefinitionId": "admin",
                "scope": "/"
            }]
        }"#;

        let context_json = r#"{
            "principal": {
                "id": "admin1",
                "principalType": "User"
            },
            "resource": {
                "scope": "/subscriptions/sub1"
            },
            "action": "write"
        }"#;

        // Test compileRbacToRvmProgram
        let program = crate::compileRbacToRvmProgram(
            policy_json.to_string(),
            context_json.to_string(),
        )?;
        
        assert!(program.getInstructionCount() > 0);

        // Test evaluateRbacPolicy convenience function
        let allowed = crate::evaluateRbacPolicy(
            policy_json.to_string(),
            context_json.to_string(),
        )?;
        assert_eq!(allowed, true);

        // Test with non-matching principal
        let context_json_deny = r#"{
            "principal": {
                "id": "user2",
                "principalType": "User"
            },
            "resource": {
                "scope": "/subscriptions/sub1"
            },
            "action": "write"
        }"#;

        let denied = crate::evaluateRbacPolicy(
            policy_json.to_string(),
            context_json_deny.to_string(),
        )?;
        assert_eq!(denied, false);

        Ok(())
    }

    #[wasm_bindgen_test]
    pub fn rbac_conditions_test() -> Result<(), JsValue> {
        // Test RBAC policy with conditions
        let policy_json = r#"{
            "version": "1.0",
            "roleDefinitions": [{
                "id": "conditional-reader",
                "name": "Conditional Reader",
                "permissions": [{
                    "actions": ["read"],
                    "notActions": [],
                    "dataActions": [],
                    "notDataActions": []
                }],
                "assignableScopes": ["/"]
            }],
            "roleAssignments": [{
                "id": "assignment1",
                "principalId": "user1",
                "principalType": "User",
                "roleDefinitionId": "conditional-reader",
                "scope": "/",
                "condition": {
                    "version": "2.0",
                    "expression": "@Resource[name] StringEquals 'allowed-resource'"
                }
            }]
        }"#;

        // Test with matching condition
        let context_allow = r#"{
            "principal": {
                "id": "user1",
                "principalType": "User"
            },
            "resource": {
                "scope": "/subscriptions/sub1",
                "attributes": {
                    "name": "allowed-resource"
                }
            },
            "action": "read"
        }"#;

        let allowed = crate::evaluateRbacPolicy(
            policy_json.to_string(),
            context_allow.to_string(),
        )?;
        assert_eq!(allowed, true);

        // Test with non-matching condition
        let context_deny = r#"{
            "principal": {
                "id": "user1",
                "principalType": "User"
            },
            "resource": {
                "scope": "/subscriptions/sub1",
                "attributes": {
                    "name": "forbidden-resource"
                }
            },
            "action": "read"
        }"#;

        let denied = crate::evaluateRbacPolicy(
            policy_json.to_string(),
            context_deny.to_string(),
        )?;
        assert_eq!(denied, false);

        Ok(())
    }
}
