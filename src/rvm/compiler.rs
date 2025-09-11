use super::instructions::{LoopMode, LoopStartParams, ObjectCreateParams};
use super::program::Program;
use super::Instruction;
use crate::ast::{Expr, ExprRef, Rule, RuleHead};
use crate::builtins;
use crate::interpreter::Interpreter;
use crate::lexer::Span;
use crate::rvm::program::RuleType;
use crate::rvm::program::SpanInfo;
use crate::rvm::tracing_utils::{debug, info, span};
use crate::utils::get_path_string;
use crate::{CompiledPolicy, Value};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use std::collections::HashMap;
use std::sync::Arc;

pub type Register = u8;
use anyhow::{bail, Result};

#[derive(Debug, Clone, Default)]
struct Scope {
    bound_vars: BTreeMap<String, Register>,
    unbound_vars: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub enum ComprehensionType {
    Array,
    Object,
    Set,
}

#[derive(Debug, Clone)]
pub enum ContextType {
    Comprehension(ComprehensionType),
    Rule(RuleType),
    Every,
}

/// Compilation context for handling different types of rule bodies and comprehensions
#[derive(Debug, Clone)]
pub struct CompilationContext {
    context_type: ContextType,
    dest_register: Register,
    key_expr: Option<ExprRef>,
    value_expr: Option<ExprRef>,
    span: Span,
    key_value_loops_hoisted: bool,
}

pub struct Compiler<'a> {
    program: Program, // Program being built with instructions and parameter data
    spans: Vec<SpanInfo>,
    register_counter: Register,
    scopes: Vec<Scope>,         // Stack of variable scopes (like the interpreter)
    policy: &'a CompiledPolicy, // Reference to the compiled policy for rule lookup
    current_package: String,    // Current package path (e.g., "data.test")
    current_module_index: u32,  // Current module index for scheduler lookup
    // Three-level hierarchy compilation fields
    rule_index_map: HashMap<String, u16>, // Maps rule paths to their assigned rule indices
    rule_worklist: Vec<String>,           // Rules that need to be compiled
    rule_definitions: Vec<Vec<Vec<usize>>>, // rule_index -> Vec<definition> where definition is Vec<body_entry_point>
    rule_types: Vec<RuleType>,              // rule_index -> true if set rule, false if regular rule
    rule_function_params: Vec<Option<Vec<String>>>, // rule_index -> Some(param_names) for function rules, None for others
    // Context stack for output expression handling
    context_stack: Vec<CompilationContext>, // Stack of compilation contexts
    loop_expr_register_map: BTreeMap<ExprRef, Register>, // Map from loop expressions to their allocated registers
    // Source tracking for span information (0-based indices)
    source_to_index: HashMap<String, usize>, // Maps source file paths to source indices (0-based)
    // Builtin management
    builtin_index_map: HashMap<String, u16>, // Maps builtin names to their assigned indices
    // Input/Data loading optimization - track registers per rule definition
    current_input_register: Option<Register>, // Register holding input in current rule definition
    current_data_register: Option<Register>,  // Register holding data in current rule definition
}

impl<'a> Compiler<'a> {
    pub fn with_policy(policy: &'a CompiledPolicy, package: String) -> Self {
        Self {
            program: Program::new(),
            spans: Vec::new(),
            register_counter: 1,
            scopes: vec![Scope::default()],
            policy,
            current_package: package,
            current_module_index: 0, // TODO: Determine proper module index
            rule_index_map: HashMap::new(),
            rule_worklist: Vec::new(),
            rule_definitions: Vec::new(),
            rule_types: Vec::new(),
            rule_function_params: Vec::new(),
            context_stack: vec![], // Default context
            loop_expr_register_map: BTreeMap::new(),
            source_to_index: HashMap::new(),
            builtin_index_map: HashMap::new(),
            current_input_register: None,
            current_data_register: None,
        }
    }

    /// Check if a function path is a builtin function (similar to interpreter's is_builtin)
    fn is_builtin(&self, path: &str) -> bool {
        path == "print" || builtins::BUILTINS.contains_key(path)
    }

    /// Check if a function path is a user-defined function rule
    fn is_user_defined_function(&self, rule_path: &str) -> bool {
        self.policy.inner.rules.contains_key(rule_path)
    }

    /// Get builtin index for a builtin function
    fn get_builtin_index(&mut self, builtin_name: &str) -> Result<u16> {
        if !self.is_builtin(builtin_name) {
            bail!("Not a builtin function: {}", builtin_name);
        }

        // Check if we already have an index for this builtin
        if let Some(&index) = self.builtin_index_map.get(builtin_name) {
            return Ok(index);
        }

        // Get the builtin function info to determine number of arguments
        let num_args = if builtin_name == "print" {
            2 // Special case for print
        } else if let Some(builtin_fcn) = builtins::BUILTINS.get(builtin_name) {
            builtin_fcn.1 as u16 // Second element is the number of arguments
        } else {
            bail!("Unknown builtin function: {}", builtin_name);
        };

        // Create builtin info and add it to the program
        let builtin_info = crate::rvm::program::BuiltinInfo {
            name: builtin_name.to_string(),
            num_args,
        };
        let index = self.program.add_builtin_info(builtin_info);

        // Store in our mapping
        self.builtin_index_map
            .insert(builtin_name.to_string(), index);

        debug!(
            "Assigned builtin index {} to '{}' (num_args={})",
            index, builtin_name, num_args
        );
        Ok(index)
    }

    pub fn alloc_register(&mut self) -> Register {
        // Assert that we don't exceed 256 registers (u8::MAX + 1)
        assert!(
            self.register_counter < 255,
            "Register overflow: attempted to allocate register {}, but maximum is 255. \
             Consider using register windowing or spill handling.",
            self.register_counter
        );

        let reg = self.register_counter;
        self.register_counter += 1;

        // Debug logging for register allocation tracking
        if self.register_counter > 200 {
            debug!(
                "High register usage - allocated register {}, approaching 256 limit",
                reg
            );
        }

        reg
    }

    /// Add a literal value to the literal table, returning its index
    pub fn add_literal(&mut self, value: Value) -> u16 {
        // Check if literal already exists to avoid duplication
        // TODO: Optimize lookup
        for (idx, existing) in self.program.literals.iter().enumerate() {
            if existing == &value {
                return idx as u16;
            }
        }

        let idx = self.program.literals.len() as u16;
        self.program.literals.push(value);
        idx
    }

    /// Push a new variable scope (like the interpreter)
    pub fn push_scope(&mut self) {
        self.scopes.push(Scope::default());
    }

    /// Pop the current variable scope (like the interpreter)
    pub fn pop_scope(&mut self) {
        if self.scopes.len() > 1 {
            self.scopes.pop();
        }
    }

    /// Reset input/data registers for a new rule definition
    /// This ensures input and data are loaded only once per rule definition
    pub fn reset_rule_definition_registers(&mut self) {
        self.current_input_register = None;
        self.current_data_register = None;
    }

    /// Push a new compilation context onto the context stack
    pub fn push_context(&mut self, context: CompilationContext) {
        self.context_stack.push(context);
    }

    /// Pop the current compilation context from the context stack
    pub fn pop_context(&mut self) -> Option<CompilationContext> {
        // Don't pop the last context (default RegularRule)
        if self.context_stack.len() > 1 {
            self.context_stack.pop()
        } else {
            None
        }
    }

    /// Emit the appropriate instruction for yielding a value in the current context
    pub fn emit_context_yield(&mut self) -> Result<()> {
        if let Some(context) = self.context_stack.last().cloned() {
            let dest_register = context.dest_register;
            let span = &context.span;
            let value_register = match context.value_expr {
                Some(expr) => self.compile_rego_expr(&expr)?,
                None => {
                    let value_reg = self.alloc_register();
                    self.emit_instruction(
                        Instruction::LoadBool {
                            dest: value_reg,
                            value: true,
                        },
                        span,
                    );
                    value_reg
                }
            };

            let key_register = context
                .key_expr
                .map(|key_expr| self.compile_rego_expr(&key_expr))
                .unwrap_or(Ok(value_register))?;

            match context.context_type {
                ContextType::Comprehension(ComprehensionType::Array) => {
                    self.emit_instruction(
                        Instruction::ArrayPush {
                            arr: dest_register,
                            value: value_register,
                        },
                        span,
                    );
                }
                ContextType::Comprehension(ComprehensionType::Set)
                | ContextType::Rule(RuleType::PartialSet) => {
                    self.emit_instruction(
                        Instruction::SetAdd {
                            set: dest_register,
                            value: value_register,
                        },
                        span,
                    );
                }
                ContextType::Comprehension(ComprehensionType::Object)
                | ContextType::Rule(RuleType::PartialObject) => {
                    self.emit_instruction(
                        Instruction::ObjectSet {
                            obj: dest_register,
                            key: key_register,
                            value: value_register,
                        },
                        span,
                    );
                }
                ContextType::Rule(RuleType::Complete) => {
                    self.emit_instruction(
                        Instruction::Move {
                            dest: dest_register,
                            src: value_register,
                        },
                        span,
                    );
                }
                ContextType::Every => {
                    // Every quantifiers don't emit any yield instructions
                    // They are assertion-only contexts
                }
            }
            Ok(())
        } else {
            bail!("internal: missing context for yield")
        }
    }

    /// Get the current scope mutably
    fn current_scope_mut(&mut self) -> &mut Scope {
        self.scopes.last_mut().expect("No active scope")
    }

    /// Add a variable to the current scope (like interpreter's add_variable)
    pub fn add_variable(&mut self, var_name: &str, register: Register) {
        if var_name != "_" {
            // Don't store anonymous variables
            self.current_scope_mut()
                .bound_vars
                .insert(var_name.to_string(), register);
        }
    }

    /// Look up a variable in all scopes starting from innermost (like interpreter's lookup_local_var)
    pub fn lookup_local_var(&self, var_name: &str) -> Option<Register> {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.bound_vars.get(var_name).copied())
    }

    pub fn add_unbound_variable(&mut self, var_name: &str) {
        self.current_scope_mut()
            .unbound_vars
            .insert(var_name.to_string());
    }

    pub fn is_unbound_var(&self, var_name: &str) -> bool {
        self.lookup_local_var(var_name).is_none()
            && self
                .scopes
                .iter()
                .rev()
                .any(|scope| scope.unbound_vars.contains(var_name))
    }

    pub fn bind_unbound_variable(&mut self, var_name: &str) {
        self.current_scope_mut().unbound_vars.remove(var_name);
    }

    /// Check if a variable can be resolved either locally or as a rule
    fn can_resolve_variable(&self, var_name: &str) -> bool {
        // Check local variables first
        if self.lookup_variable(var_name).is_some() {
            return true;
        }

        // Check if there's a rule for this variable
        let rule_path = format!("{}.{}", &self.current_package, var_name);
        self.policy.inner.rules.contains_key(&rule_path)
    }

    /// Store a variable mapping (backward compatibility)
    /// Look up a variable, first in local scope, then as a rule reference
    fn resolve_variable(&mut self, var_name: &str, span: &Span) -> Result<Register> {
        debug!("resolve_variable called for '{}'", var_name);

        // Handle special built-in variables first
        match var_name {
            "input" => {
                // Check if input is already loaded in current rule definition
                if let Some(register) = self.current_input_register {
                    debug!(
                        "Variable 'input' already loaded in register {} for current rule definition",
                        register
                    );
                    return Ok(register);
                }

                // Load input for the first time in this rule definition
                let dest = self.alloc_register();
                self.emit_instruction(Instruction::LoadInput { dest }, span);
                self.current_input_register = Some(dest);
                debug!(
                    "Variable 'input' resolved to LoadInput instruction, register {} (first load in rule definition)",
                    dest
                );
                return Ok(dest);
            }
            "data" => {
                // Check if data is already loaded in current rule definition
                if let Some(register) = self.current_data_register {
                    debug!(
                        "Variable 'data' already loaded in register {} for current rule definition",
                        register
                    );
                    return Ok(register);
                }

                // Load data for the first time in this rule definition
                // TODO: Fully qualified rule paths.
                // TODO: data overrides rule in same path
                let dest = self.alloc_register();
                self.emit_instruction(Instruction::LoadData { dest }, span);
                self.current_data_register = Some(dest);
                debug!(
                    "Variable 'data' resolved to LoadData instruction, register {} (first load in rule definition)",
                    dest
                );
                return Ok(dest);
            }
            _ => {
                // Continue with normal variable resolution
            }
        }

        // First check local variables
        if let Some(var_reg) = self.lookup_variable(var_name) {
            debug!(
                "Variable '{}' found in local scope at register {}",
                var_name, var_reg
            );
            return Ok(var_reg);
        }

        debug!(
            "Variable '{}' not found in local scope, checking rules",
            var_name
        );

        let rule_path = format!("{}.{}", &self.current_package, var_name);

        // Always emit CallRule for all rules.
        // TODO: Inline rules
        let rule_index = self.get_or_assign_rule_index(&rule_path)?;
        let dest = self.alloc_register();

        self.emit_instruction(Instruction::CallRule { dest, rule_index }, span);
        Ok(dest)
    }

    fn compute_rule_type(&self, rule_path: &str) -> Result<RuleType> {
        let Some(definitions) = self.policy.inner.rules.get(rule_path) else {
            panic!(
                "internal: no definitions found for rule path '{}'",
                rule_path
            );
            //bail!("{rule_path} is not a valid rule path");
        };

        let rule_types: BTreeSet<RuleType> = definitions
            .iter()
            .map(|def| {
                if let crate::ast::Rule::Spec { head, .. } = def.as_ref() {
                    let result = match head {
                        crate::ast::RuleHead::Set { .. } => RuleType::PartialSet,
                        crate::ast::RuleHead::Compr { refr, assign, .. } => match refr.as_ref() {
                            crate::ast::Expr::RefBrack { .. } if assign.is_some() => {
                                RuleType::PartialObject
                            }
                            crate::ast::Expr::RefBrack { .. } => RuleType::PartialSet,
                            _ => RuleType::Complete,
                        },
                        _ => RuleType::Complete,
                    };
                    debug!(
                        "Rule '{}' head type: {:?}, is_set: {:?}",
                        rule_path, head, result
                    );
                    result
                } else {
                    debug!("Rule '{}' is not a Spec rule", rule_path);
                    RuleType::Complete
                }
            })
            .collect();

        if rule_types.len() > 1 {
            bail!(
                "internal: rule '{}' has multiple types: {:?}",
                rule_path,
                rule_types
            );
        }

        rule_types
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("internal: no rule type found for '{}'", rule_path))
    }

    /// Get or assign a rule index for CallRule instructions
    fn get_or_assign_rule_index(&mut self, rule_path: &str) -> Result<u16> {
        if let Some(&index) = self.rule_index_map.get(rule_path) {
            Ok(index)
        } else {
            let rule_type = self.compute_rule_type(rule_path)?;

            // Start rule indices from 1 (0 is reserved for main entrypoint)
            // TODO: Revisit this
            let index = self.rule_index_map.len() as u16;

            self.rule_index_map.insert(rule_path.to_string(), index);
            self.rule_worklist.push(rule_path.to_string());

            // Initialize rule definitions structure
            // Ensure rule_definitions has enough capacity
            while self.rule_definitions.len() <= index as usize {
                self.rule_definitions.push(Vec::new());
            }

            // Ensure rule_types has enough capacity and record the rule type
            while self.rule_types.len() <= index as usize {
                self.rule_types.push(RuleType::Complete); // Default to non-set rule
            }
            self.rule_types[index as usize] = rule_type;

            // Ensure rule_function_params has enough capacity
            while self.rule_function_params.len() <= index as usize {
                self.rule_function_params.push(None); // Default to None (not a function)
            }

            debug!("Assigned rule index {} to '{}'", index, rule_path);
            Ok(index)
        }
    }

    fn store_variable(&mut self, var_name: String, register: Register) {
        debug!("Storing variable '{}' in register {}", var_name, register);
        self.add_variable(&var_name, register);
    }

    /// Look up a variable register (backward compatibility)
    fn lookup_variable(&self, var_name: &str) -> Option<Register> {
        self.lookup_local_var(var_name)
    }

    /// Emit an instruction with span tracking
    pub fn emit_instruction(&mut self, instruction: Instruction, span: &Span) {
        self.program.instructions.push(instruction);

        // Get the source path and find its index (0-based, matching program source table)
        let source_path = span.source.get_path().to_string();
        let source_index = self.get_or_create_source_index(&source_path);

        self.spans
            .push(SpanInfo::from_lexer_span(span, source_index));
    }

    /// Get or create a source index for the given source path (0-based, matching program source table)
    fn get_or_create_source_index(&mut self, source_path: &str) -> usize {
        if let Some(&index) = self.source_to_index.get(source_path) {
            index
        } else {
            // The source index matches what will be in the program's source table (0-based)
            let index = self.source_to_index.len(); // This will be 0-based like program source table
            self.source_to_index.insert(source_path.to_string(), index);
            index
        }
    }

    pub fn emit_return(&mut self, result_reg: Register) {
        // Add return instruction
        self.program
            .instructions
            .push(Instruction::Return { value: result_reg });
        self.spans.push(SpanInfo::new(0, 0, 0, 0)); // Default span for return instruction
    }

    pub fn emit_call_rule(&mut self, dest: Register, rule_index: u16) {
        // Add call rule instruction
        self.program
            .instructions
            .push(Instruction::CallRule { dest, rule_index });
        self.spans.push(SpanInfo::new(0, 0, 0, 0)); // Default span for call rule instruction
    }

    pub fn finish(mut self) -> crate::rvm::program::Program {
        // Update the program with final values
        self.program.main_entry_point = 0;
        self.program.num_registers = self.register_counter as usize;

        // Set the rule definitions from the compiler
        let mut rule_infos_map = BTreeMap::new();

        // First, collect all rule info without default evaluation
        for (rule_path, &rule_index) in &self.rule_index_map {
            let definitions = self.rule_definitions[rule_index as usize].clone();
            let rule_type = self.rule_types[rule_index as usize].clone();
            let function_params = &self.rule_function_params[rule_index as usize];

            let rule_info = match function_params {
                Some(param_names) => {
                    // This is a function rule
                    crate::rvm::program::RuleInfo::new_function(
                        rule_path.clone(),
                        rule_type,
                        crate::Rc::new(definitions),
                        param_names.clone(),
                    )
                }
                None => {
                    // This is a regular rule
                    crate::rvm::program::RuleInfo::new(
                        rule_path.clone(),
                        rule_type,
                        crate::Rc::new(definitions),
                    )
                }
            };

            rule_infos_map.insert(rule_index as usize, rule_info);
        }

        // Now evaluate default rules for Complete rules and update their literal indices
        let rule_paths_to_evaluate: Vec<(String, usize)> = self
            .rule_index_map
            .iter()
            .filter_map(|(rule_path, &rule_index)| {
                let rule_type = &self.rule_types[rule_index as usize];
                if *rule_type == crate::rvm::program::RuleType::Complete {
                    Some((rule_path.clone(), rule_index as usize))
                } else {
                    None
                }
            })
            .collect();

        for (rule_path, rule_index) in rule_paths_to_evaluate {
            if let Some(default_literal_index) = self.evaluate_default_rule(&rule_path) {
                if let Some(rule_info) = rule_infos_map.get_mut(&rule_index) {
                    rule_info.set_default_literal_index(default_literal_index);
                }
            }
        }

        self.program.rule_infos = rule_infos_map.into_values().collect();

        // Debug: Print rule definitions
        #[cfg(feature = "rvm-tracing")]
        {
            debug!("Rule definitions in program:");
            for (rule_idx, rule_info) in self.program.rule_infos.iter().enumerate() {
                let function_info = match &rule_info.function_info {
                    Some(func_info) => format!(
                        " (function with {} params: {:?})",
                        func_info.num_params, func_info.param_names
                    ),
                    None => String::new(),
                };
                debug!(
                    "  Rule {}: {} definitions{}",
                    rule_idx,
                    rule_info.definitions.len(),
                    function_info
                );
                for (def_idx, bodies) in rule_info.definitions.iter().enumerate() {
                    debug!(
                        "    Definition {}: {} bodies at entry points {:?}",
                        def_idx,
                        bodies.len(),
                        bodies
                    );
                }
            }
        }

        // Extract source contents from the policy modules and add them to the program
        for module in self.policy.get_modules().iter() {
            let source = &module.package.refr.span().source;
            let source_path = source.get_path().to_string();
            let source_content = source.get_contents().to_string();
            self.program.add_source(source_path, source_content);
        }

        // Transfer spans to program (they already have correct source indices)
        self.program.instruction_spans = self.spans.into_iter().map(Some).collect();

        debug!(
            "Final program has {} instructions, {} rule infos",
            self.program.instructions.len(),
            self.program.rule_infos.len()
        );
        debug!("Program requires {} registers", self.program.num_registers);

        // Initialize resolved builtins if we have builtin info
        if !self.program.builtin_info_table.is_empty() {
            // Convert HashMap to BTreeMap for compatibility
            let builtin_map: std::collections::BTreeMap<&'static str, crate::builtins::BuiltinFcn> =
                crate::builtins::BUILTINS
                    .iter()
                    .map(|(&k, &v)| (k, v))
                    .collect();
            self.program.initialize_resolved_builtins(&builtin_map);
            debug!(
                "Initialized {} resolved builtins",
                self.program.resolved_builtins.len()
            );
        }

        self.program
    }

    /// Compile a Rego expression to RVM instructions
    pub fn compile_rego_expr(&mut self, expr: &ExprRef) -> Result<Register> {
        self.compile_rego_expr_with_span(expr, expr.span(), false)
    }

    /// Compile a Rego expression to RVM instructions with span tracking
    pub fn compile_rego_expr_with_span(
        &mut self,
        expr: &ExprRef,
        span: &Span,
        assert_condition: bool,
    ) -> Result<Register> {
        // TODO: If expr is a loop expr or a loop var, look up.
        if let Some(reg) = self.loop_expr_register_map.get(expr).cloned() {
            debug!("Found loop expression in map, using register {}", reg);
            let result_reg = reg;
            // If this expression should be asserted as a condition, emit AssertCondition
            if assert_condition {
                self.emit_instruction(
                    Instruction::AssertCondition {
                        condition: result_reg,
                    },
                    span,
                );
            }
            return Ok(result_reg);
        }

        let result_reg = match expr.as_ref() {
            Expr::Number { value, .. } => {
                let dest = self.alloc_register();
                let literal_idx = self.add_literal(value.clone());
                self.emit_instruction(Instruction::Load { dest, literal_idx }, span);
                dest
            }
            Expr::String { value, .. } => {
                let dest = self.alloc_register();
                let literal_idx = self.add_literal(value.clone());
                self.emit_instruction(Instruction::Load { dest, literal_idx }, span);
                dest
            }
            Expr::Bool { value, .. } => {
                let dest = self.alloc_register();
                let literal_idx = self.add_literal(value.clone());
                self.emit_instruction(Instruction::Load { dest, literal_idx }, span);
                dest
            }
            Expr::Null { .. } => {
                let dest = self.alloc_register();
                let literal_idx = self.add_literal(Value::Null);
                self.emit_instruction(Instruction::Load { dest, literal_idx }, span);
                dest
            }
            Expr::Array { items, .. } => {
                // Create empty array first
                let dest = self.alloc_register();
                self.emit_instruction(Instruction::ArrayNew { dest }, span);

                // Add each item to the array
                for item in items {
                    // Don't assert conditions for array items
                    let item_reg = self.compile_rego_expr_with_span(item, item.span(), false)?;

                    // Push the item to the array
                    self.emit_instruction(
                        Instruction::ArrayPush {
                            arr: dest,
                            value: item_reg,
                        },
                        span,
                    );
                }

                dest
            }
            Expr::Set { items, .. } => {
                // Create empty set first
                let dest = self.alloc_register();
                self.emit_instruction(Instruction::SetNew { dest }, span);

                // Add each item to the set
                for item in items {
                    // Don't assert conditions for set items
                    let item_reg = self.compile_rego_expr_with_span(item, item.span(), false)?;

                    // Add the item to the set
                    self.emit_instruction(
                        Instruction::SetAdd {
                            set: dest,
                            value: item_reg,
                        },
                        span,
                    );
                }

                dest
            }
            Expr::Object { fields, .. } => {
                let dest = self.alloc_register();

                // First pass: compile all values and store in array
                let mut value_regs = Vec::new();
                for (_, _key_expr, value_expr) in fields {
                    let value_reg =
                        self.compile_rego_expr_with_span(value_expr, value_expr.span(), false)?;
                    value_regs.push(value_reg);
                }

                // Second pass: determine keys and categorize them
                let mut literal_key_fields = Vec::new();
                let mut non_literal_key_fields = Vec::new();
                let mut literal_keys = Vec::new();

                for (field_idx, (_, key_expr, _value_expr)) in fields.iter().enumerate() {
                    let value_reg = value_regs[field_idx];

                    // Check if key expression is a literal (String, Number, Bool, Null, etc.)
                    let key_literal = match key_expr.as_ref() {
                        Expr::String { value, .. }
                        | Expr::RawString { value, .. }
                        | Expr::Number { value, .. }
                        | Expr::Bool { value, .. }
                        | Expr::Null { value, .. } => Some(value.clone()),
                        _ => None,
                    };

                    if let Some(key_value) = key_literal {
                        // Key is a literal - add to literal table and use literal key field
                        let literal_idx = self.add_literal(key_value.clone());
                        literal_key_fields.push((literal_idx, value_reg));
                        literal_keys.push(key_value);
                    } else {
                        // Key is not a literal - compile it and use non-literal key field
                        let key_reg =
                            self.compile_rego_expr_with_span(key_expr, key_expr.span(), false)?;
                        non_literal_key_fields.push((key_reg, value_reg));
                    }
                }

                // Always create template object - even if empty for consistency
                let template_literal_idx = {
                    // Collect all literal keys for template
                    let mut template_keys = literal_keys.clone();
                    template_keys.sort();

                    // Create template object with all literal keys set to undefined
                    use std::collections::BTreeMap;
                    let mut template_obj = BTreeMap::new();
                    for key in &template_keys {
                        template_obj.insert(key.clone(), Value::Undefined);
                    }

                    let template_value = Value::Object(std::sync::Arc::new(template_obj));
                    self.add_literal(template_value)
                };

                // Sort literal key fields by literal key value for better performance
                literal_key_fields.sort_by(|a, b| {
                    let key_a = &self.program.literals[a.0 as usize];
                    let key_b = &self.program.literals[b.0 as usize];
                    key_a.cmp(key_b)
                });

                // Create ObjectCreate instruction
                let params = ObjectCreateParams {
                    dest,
                    template_literal_idx,
                    literal_key_fields,
                    fields: non_literal_key_fields,
                };
                let params_index = self
                    .program
                    .instruction_data
                    .add_object_create_params(params);
                self.emit_instruction(Instruction::ObjectCreate { params_index }, span);

                dest
            }
            Expr::ArithExpr { lhs, op, rhs, .. } => {
                // Don't assert conditions for operands
                // TODO: Determine assertion
                let lhs_reg = self.compile_rego_expr_with_span(lhs, lhs.span(), false)?;
                let rhs_reg = self.compile_rego_expr_with_span(rhs, rhs.span(), false)?;
                let dest = self.alloc_register();

                match op {
                    crate::ast::ArithOp::Add => {
                        self.emit_instruction(
                            Instruction::Add {
                                dest,
                                left: lhs_reg,
                                right: rhs_reg,
                            },
                            span,
                        );
                    }
                    crate::ast::ArithOp::Sub => {
                        self.emit_instruction(
                            Instruction::Sub {
                                dest,
                                left: lhs_reg,
                                right: rhs_reg,
                            },
                            span,
                        );
                    }
                    crate::ast::ArithOp::Mul => {
                        self.emit_instruction(
                            Instruction::Mul {
                                dest,
                                left: lhs_reg,
                                right: rhs_reg,
                            },
                            span,
                        );
                    }
                    crate::ast::ArithOp::Div => {
                        self.emit_instruction(
                            Instruction::Div {
                                dest,
                                left: lhs_reg,
                                right: rhs_reg,
                            },
                            span,
                        );
                    }
                    _ => {
                        // For other operations, just return the left operand for now
                        return Ok(lhs_reg);
                    }
                }
                dest
            }
            Expr::BoolExpr { lhs, op, rhs, .. } => {
                // Don't assert conditions for operands
                let lhs_reg = self.compile_rego_expr_with_span(lhs, lhs.span(), false)?;
                let rhs_reg = self.compile_rego_expr_with_span(rhs, rhs.span(), false)?;
                let dest = self.alloc_register();

                match op {
                    crate::ast::BoolOp::Eq => {
                        self.emit_instruction(
                            Instruction::Eq {
                                dest,
                                left: lhs_reg,
                                right: rhs_reg,
                            },
                            span,
                        );
                    }
                    crate::ast::BoolOp::Lt => {
                        self.emit_instruction(
                            Instruction::Lt {
                                dest,
                                left: lhs_reg,
                                right: rhs_reg,
                            },
                            span,
                        );
                    }
                    crate::ast::BoolOp::Gt => {
                        self.emit_instruction(
                            Instruction::Gt {
                                dest,
                                left: lhs_reg,
                                right: rhs_reg,
                            },
                            span,
                        );
                    }
                    crate::ast::BoolOp::Ge => {
                        self.emit_instruction(
                            Instruction::Ge {
                                dest,
                                left: lhs_reg,
                                right: rhs_reg,
                            },
                            span,
                        );
                    }
                    crate::ast::BoolOp::Le => {
                        self.emit_instruction(
                            Instruction::Le {
                                dest,
                                left: lhs_reg,
                                right: rhs_reg,
                            },
                            span,
                        );
                    }
                    _ => {
                        // For other operations, return true for now
                        let literal_idx = self.add_literal(Value::Bool(true));
                        self.emit_instruction(Instruction::Load { dest, literal_idx }, span);
                    }
                }
                dest
            }
            Expr::AssignExpr { lhs, rhs, .. } => {
                // TODO: Really complex. Look at interpreter, esp make_bindings
                // Handle variable assignment like x := 10
                // First compile the right-hand side value (don't assert - this is assignment)
                let rhs_reg = self.compile_rego_expr_with_span(rhs, rhs.span(), false)?;

                // Then bind the variable if lhs is a variable
                if let Expr::Var {
                    value: Value::String(var_name),
                    ..
                } = lhs.as_ref()
                {
                    // Allocate a NEW register for the LHS variable
                    let lhs_reg = self.alloc_register();

                    // Copy the value from RHS to LHS register
                    self.emit_instruction(
                        Instruction::Move {
                            dest: lhs_reg,
                            src: rhs_reg,
                        },
                        span,
                    );

                    // Store the variable binding to the NEW register
                    debug!(
                        "Assignment '{}' := value from register {} to new register {}",
                        var_name, rhs_reg, lhs_reg
                    );
                    self.add_variable(var_name.as_ref(), lhs_reg);

                    // Return the register containing the assigned value
                    return Ok(lhs_reg);
                }

                // Return the register containing the assigned value
                return Ok(rhs_reg); // Note: assignments don't get asserted
            }
            Expr::Var { value, .. } => {
                // Check if this is a variable reference that we should resolve
                if let Value::String(var_name) = value {
                    debug!("Resolving variable '{}' - looking up in scopes", var_name);
                    return self.resolve_variable(var_name.as_ref(), span);
                }

                // Otherwise, load as literal value
                let dest = self.alloc_register();
                let literal_idx = self.add_literal(value.clone());
                self.emit_instruction(Instruction::Load { dest, literal_idx }, span);
                dest
            }
            // TODO: chained ref dot from interpreter
            Expr::RefDot { refr, field, .. } => {
                // Compile the object reference (don't assert)
                let obj_reg = self.compile_rego_expr_with_span(refr, refr.span(), false)?;

                // The field is a (Span, Value) tuple - get the value
                let field_value = &field.1;

                // Use IndexLiteral instruction for optimization - avoid loading literal into register
                let literal_idx = self.add_literal(field_value.clone());

                // Get the field value using IndexLiteral
                let dest = self.alloc_register();
                self.emit_instruction(
                    Instruction::IndexLiteral {
                        dest,
                        container: obj_reg,
                        literal_idx,
                    },
                    span,
                );

                dest
            }
            Expr::RefBrack { refr, index, .. } => {
                // Compile the object reference (don't assert)
                let obj_reg = self.compile_rego_expr_with_span(refr, refr.span(), false)?;

                // Compile the index expression (don't assert)
                let key_reg = self.compile_rego_expr_with_span(index, index.span(), false)?;

                // Get the field value using the dynamic key
                let dest = self.alloc_register();
                self.emit_instruction(
                    Instruction::Index {
                        dest,
                        container: obj_reg,
                        key: key_reg,
                    },
                    span,
                );

                dest
            }
            Expr::Membership {
                value, collection, ..
            } => {
                // Compile the value to check (don't assert)
                let value_reg = self.compile_rego_expr_with_span(value, value.span(), false)?;

                // Compile the collection (don't assert)
                let collection_reg =
                    self.compile_rego_expr_with_span(collection, collection.span(), false)?;

                // Check membership using a specialized instruction
                let dest = self.alloc_register();
                self.emit_instruction(
                    Instruction::Contains {
                        dest,
                        collection: collection_reg,
                        value: value_reg,
                    },
                    span,
                );

                dest
            }
            Expr::ArrayCompr { term, query, .. } => {
                debug!("Compiling array comprehension");
                self.compile_array_comprehension(term, query, span)?
            }
            Expr::SetCompr { term, query, .. } => {
                debug!("Compiling set comprehension");
                self.compile_set_comprehension(term, query, span)?
            }
            Expr::ObjectCompr {
                key, value, query, ..
            } => {
                debug!("Compiling object comprehension");
                self.compile_object_comprehension(key, value, query, span)?
            }
            Expr::Call { fcn, params, .. } => {
                // Compile function call
                self.compile_function_call(fcn, params, span.clone())?
            }
            _ => {
                // For other expression types, return null for now
                let dest = self.alloc_register();
                let literal_idx = self.add_literal(Value::Null);
                self.emit_instruction(Instruction::Load { dest, literal_idx }, span);
                dest
            }
        };

        // If this expression should be asserted as a condition, emit AssertCondition
        if assert_condition {
            self.emit_instruction(
                Instruction::AssertCondition {
                    condition: result_reg,
                },
                span,
            );
        }

        Ok(result_reg)
    }

    /// Compile from a CompiledPolicy to RVM Program
    pub fn compile_from_policy(policy: &CompiledPolicy, rule_name: &str) -> Result<Arc<Program>> {
        let _span = span!(
            tracing::Level::INFO,
            "compile_from_policy",
            rule_name = rule_name
        );
        let _enter = _span.enter();
        info!("Starting compilation for rule: {}", rule_name);

        // Extract package name from rule_name
        let package = if let Some(last_dot) = rule_name.rfind('.') {
            rule_name[..last_dot].to_string()
        } else {
            "data".to_string()
        };
        debug!("Extracted package: {}", package);

        let mut compiler = Compiler::with_policy(policy, package);
        let rules = policy.get_rules();

        #[cfg(feature = "rvm-tracing")]
        {
            debug!("Available rules in policy:");
            for (key, rule_list) in rules.iter() {
                debug!("  Rule key: '{}' ({} variants)", key, rule_list.len());
            }
            debug!("Looking for rule: '{}'", rule_name);
        }

        // Emit CallRule instruction for the main entry point
        let result_reg = compiler.alloc_register();
        let rule_idx = compiler.get_or_assign_rule_index(rule_name)?;
        debug!("Assigned rule index {} for rule '{}'", rule_idx, rule_name);
        compiler.emit_call_rule(result_reg, rule_idx);

        // Add Return instruction for main execution
        compiler.emit_return(result_reg);

        info!(
            "Starting worklist compilation for {} rule groups",
            rules.len()
        );
        compiler.compile_worklist_rules(rules)?;

        let program = Arc::new(compiler.finish());
        info!(
            "Compilation completed successfully, program has {} instructions",
            program.instructions.len()
        );
        Ok(program)
    }

    fn compile_worklist_rules(
        &mut self,
        rules: &HashMap<String, Vec<crate::ast::NodeRef<Rule>>>,
    ) -> Result<()> {
        let _span = span!(tracing::Level::DEBUG, "compile_worklist_rules");
        debug!(
            "Starting worklist compilation with {} rules in worklist",
            self.rule_worklist.len()
        );

        // Now compile all rules in the worklist (set rules referenced via CallRule)
        while !self.rule_worklist.is_empty() {
            let rule_to_compile = self.rule_worklist.remove(0);
            debug!("Compiling worklist rule: '{}'", rule_to_compile);
            self.compile_worklist_rule(&rule_to_compile, rules)?;
        }
        debug!("Worklist compilation completed");
        Ok(())
    }

    /// Compile a set rule from the worklist - each variant gets its own entry point
    fn compile_worklist_rule(
        &mut self,
        rule_path: &str,
        rules: &HashMap<String, Vec<crate::ast::NodeRef<Rule>>>,
    ) -> Result<()> {
        let _span = span!(
            tracing::Level::DEBUG,
            "compile_worklist_rule",
            rule_path = rule_path
        );
        debug!("Starting compilation of worklist rule: '{}'", rule_path);

        if let Some(rule_definitions) = rules.get(rule_path) {
            let rule_index = self.rule_index_map.get(rule_path).copied().unwrap_or(1);
            let rule_type = self.rule_types[rule_index as usize].clone();
            let dest_register = self.alloc_register();

            debug!(
                "Rule '{}' has {} definitions",
                rule_path,
                rule_definitions.len()
            );

            // Ensure rule_definitions vec has space for this rule
            while self.rule_definitions.len() <= rule_index as usize {
                self.rule_definitions.push(Vec::new());
            }

            // Compile each definition (Rule::Spec)
            for (def_idx, rule_ref) in rule_definitions.iter().enumerate() {
                if let Rule::Spec { head, bodies, span } = rule_ref.as_ref() {
                    debug!(
                        "Compiling definition {} with {} bodies",
                        def_idx,
                        bodies.len()
                    );

                    let mut is_function_rule = false;

                    let (key_expr, value_expr) = match head {
                        RuleHead::Compr { refr, assign, .. } => {
                            let output_expr = assign.as_ref().map(|assign| assign.value.clone());
                            let key_expr = match refr.as_ref() {
                                Expr::RefBrack { index, .. } => {
                                    // For RefBrack, the index is the key expression
                                    Some(index.clone())
                                }
                                _ => {
                                    // For non-RefBrack, no key expression
                                    None
                                }
                            };
                            (key_expr, output_expr)
                        }
                        RuleHead::Set { key, .. } => {
                            // For set rules, no separate key_expr, output_expr is the key
                            (None, key.clone())
                        }
                        RuleHead::Func { assign, args, .. } => {
                            // Allocate registers for function parameters and add them to scope
                            // Function parameters start from register 1 (register 0 is for return value)
                            self.push_scope();
                            let mut param_names = Vec::new();
                            for (i, arg) in args.iter().enumerate() {
                                if let Expr::Var {
                                    value: Value::String(param_name),
                                    ..
                                } = arg.as_ref()
                                {
                                    param_names.push(param_name.to_string());
                                    let param_reg = (i + 1) as u8; // Parameters start at register 1
                                    self.scopes
                                        .last_mut()
                                        .unwrap()
                                        .bound_vars
                                        .insert(param_name.to_string(), param_reg);
                                    debug!(
                                        "Function parameter '{}' assigned to register {}",
                                        param_name, param_reg
                                    );
                                }
                            }
                            // Store function parameters for this rule
                            self.rule_function_params[rule_index as usize] = Some(param_names);
                            is_function_rule = true;

                            // For function rules, the output expression comes from the assignment
                            match assign {
                                Some(assignment) => (None, Some(assignment.value.clone())),
                                None => (None, None),
                            }
                        }
                    };

                    let span = match (&key_expr, &value_expr) {
                        (_, Some(expr)) => expr.span().clone(),
                        (Some(expr), _) => expr.span().clone(),
                        _ => span.clone(),
                    };

                    let context = CompilationContext {
                        dest_register,
                        context_type: ContextType::Rule(rule_type.clone()),
                        key_expr,
                        value_expr,
                        span,
                        key_value_loops_hoisted: false,
                    };
                    self.push_context(context);
                    let mut body_entry_points = Vec::new();

                    // Handle rules with no bodies but assignment expressions (like my_set := {1, 2, 3})
                    if bodies.is_empty() {
                        let value_expr_opt = self.context_stack.last().unwrap().value_expr.clone();
                        if let Some(value_expr) = value_expr_opt {
                            // Create a single body entry point for the assignment
                            let body_entry_point = self.program.instructions.len();
                            body_entry_points.push(body_entry_point);

                            self.push_scope();
                            // Reset input/data registers for this rule body
                            self.reset_rule_definition_registers();

                            self.emit_instruction(
                                Instruction::RuleInit {
                                    result_reg: dest_register,
                                    rule_index,
                                },
                                value_expr.span(),
                            );

                            // Compile the assignment expression
                            let value_reg = self.compile_rego_expr(&value_expr)?;
                            self.emit_instruction(
                                Instruction::Move {
                                    dest: dest_register,
                                    src: value_reg,
                                },
                                value_expr.span(),
                            );

                            // Emit Rule Return
                            self.emit_instruction(Instruction::RuleReturn {}, value_expr.span());
                            self.pop_scope();
                        }
                    } else {
                        // Compile each body within this definition
                        for (body_idx, body) in bodies.iter().enumerate() {
                            self.push_scope();
                            // Reset input/data registers for each rule body
                            self.reset_rule_definition_registers();

                            let body_entry_point = self.program.instructions.len();
                            body_entry_points.push(body_entry_point);

                            debug!(
                                "Compiling body {} at entry point {}",
                                body_idx, body_entry_point
                            );

                            self.emit_instruction(
                                Instruction::RuleInit {
                                    result_reg: dest_register,
                                    rule_index,
                                },
                                &body.span,
                            );

                            // 1. Compile the query (with proper loop hoisting)
                            if !body.query.stmts.is_empty() {
                                self.compile_query(&body.query)?;
                            } else {
                                // Check if there's an assignment expression in the rule head (for rules like my_set := {1, 2, 3})
                                let value_expr_opt =
                                    self.context_stack.last().unwrap().value_expr.clone();
                                if let Some(value_expr) = value_expr_opt {
                                    // For rules with empty bodies but assignment expressions
                                    // compile the assignment expression and store it in the result register
                                    let value_reg = self.compile_rego_expr(&value_expr)?;
                                    self.emit_instruction(
                                        Instruction::Move {
                                            dest: dest_register,
                                            src: value_reg,
                                        },
                                        value_expr.span(),
                                    );
                                }
                            }

                            // 2. Emit Rule Return
                            self.emit_instruction(Instruction::RuleReturn {}, &body.span);
                            self.pop_scope();
                        }
                    }

                    if is_function_rule {
                        self.pop_scope(); // Pop function parameter scope
                    }

                    // Store the body entry points for this definition
                    self.rule_definitions[rule_index as usize].push(body_entry_points);

                    debug!(
                        "Definition {} compiled with {} bodies",
                        def_idx,
                        bodies.len()
                    );
                }
            }

            debug!(
                "Rule '{}' compiled with {} definitions",
                rule_path,
                rule_definitions.len()
            );
        }

        Ok(())
    }

    /// Compile a query (statements with proper loop hoisting, similar to interpreter's eval_stmts)
    fn compile_query(&mut self, query: &crate::ast::Query) -> Result<()> {
        // Push a new scope for this query
        self.push_scope();

        let result = {
            let schedule = {
                self.policy
                    .inner
                    .schedule
                    .as_ref()
                    .and_then(|s| s.queries.get(self.current_module_index, query.qidx))
            };

            let ordered_stmts: Vec<&crate::ast::LiteralStmt> = match schedule {
                Some(schedule) => schedule
                    .order
                    .iter()
                    .map(|i| &query.stmts[*i as usize])
                    .collect(),
                None => query.stmts.iter().collect(),
            };
            self.hoist_loops_and_compile_statements(&ordered_stmts)
        };

        // Pop the scope after compilation
        self.pop_scope();

        result
    }

    /// Hoist loops from statements and compile them with proper sequencing (similar to interpreter's eval_stmts)
    fn hoist_loops_and_compile_statements(
        &mut self,
        stmts: &[&crate::ast::LiteralStmt],
    ) -> Result<()> {
        debug!("Compiling {} statements with loop hoisting", stmts.len());

        for (idx, stmt) in stmts.iter().enumerate() {
            debug!(
                "Processing statement {} of {}: {}",
                idx + 1,
                stmts.len(),
                stmt.span.text()
            );

            // Hoist loops from this statement (like interpreter)
            let loop_exprs = self.hoist_loops_from_literal(&stmt.literal)?;

            if !loop_exprs.is_empty() {
                debug!(
                    "Found {} loop expressions in statement {} {}",
                    loop_exprs.len(),
                    idx,
                    stmt.span.text()
                );
                // If there are hoisted loop expressions, execute subsequent statements within loops
                return self.compile_hoisted_loops(&stmts[idx..], &loop_exprs);
            }

            // No loops, compile statement normally
            debug!("Compiling statement {} normally (no loops)", idx + 1);
            self.compile_single_statement(stmt)?;
        }

        debug!("Finished compiling all statements, calling emit_context_yield");
        self.hoist_loops_and_emit_context_yield()
    }

    /// TODO: Share code with interpreter
    /// Hoist loops from a literal (similar to interpreter's hoist_loops)
    fn hoist_loops_from_literal(
        &mut self,
        literal: &crate::ast::Literal,
    ) -> Result<Vec<HoistedLoop>> {
        let mut loops = Vec::new();

        use crate::ast::Literal::*;
        match literal {
            SomeIn {
                key,
                value,
                collection,
                ..
            } => {
                debug!("Found SomeIn literal - creating loop");
                if let Some(key) = key {
                    self.hoist_loops_from_expr(key, &mut loops)?;
                }
                self.hoist_loops_from_expr(value, &mut loops)?;
                self.hoist_loops_from_expr(collection, &mut loops)?;
                loops.push(HoistedLoop {
                    loop_expr: None,
                    key: key.clone(),
                    value: value.clone(),
                    collection: collection.clone(),
                    loop_type: LoopType::SomeIn,
                });
            }
            Expr { expr, .. } => {
                // Hoist loops from expressions (like array[_] patterns)
                self.hoist_loops_from_expr(expr, &mut loops)?;
            }
            Every {
                key: _key,
                value: _value,
                domain: _domain,
                query: _query,
                ..
            } => {
                // Every quantifiers are not hoisted as loops
                // They are compiled directly in compile_single_statement
                self.hoist_loops_from_expr(_domain, &mut loops)?;
            }
            _ => {
                // Other literal types don't have loops to hoist
            }
        }

        Ok(loops)
    }

    /// Hoist loops from expressions (like array[_] patterns)
    fn hoist_loops_from_expr(
        &mut self,
        expr: &ExprRef,
        loops: &mut Vec<HoistedLoop>,
    ) -> Result<()> {
        use crate::ast::Expr::*;
        match expr.as_ref() {
            // Primitive types - no loops to hoist
            String { .. }
            | RawString { .. }
            | Number { .. }
            | Bool { .. }
            | Null { .. }
            | Var { .. } => {
                // No sub-expressions to process
            }

            // Collection types - hoist from items
            Array { items, .. } => {
                for item in items {
                    self.hoist_loops_from_expr(item, loops)?;
                }
            }
            Set { items, .. } => {
                for item in items {
                    self.hoist_loops_from_expr(item, loops)?;
                }
            }
            Object { fields, .. } => {
                for (_, key_expr, value_expr) in fields {
                    self.hoist_loops_from_expr(key_expr, loops)?;
                    self.hoist_loops_from_expr(value_expr, loops)?;
                }
            }

            // Comprehensions - hoist from term and query
            ArrayCompr { .. } | SetCompr { .. } | ObjectCompr { .. } => {
                // Will be hoisted by their queries
            }

            // Function calls - hoist from function and parameters
            Call { fcn, params, .. } => {
                self.hoist_loops_from_expr(fcn, loops)?;
                for param in params {
                    self.hoist_loops_from_expr(param, loops)?;
                }
            }

            // Unary expressions - hoist from operand
            UnaryExpr { expr, .. } => {
                self.hoist_loops_from_expr(expr, loops)?;
            }

            // Reference expressions - check for array[_] patterns
            RefDot { refr, .. } => {
                self.hoist_loops_from_expr(refr, loops)?;
            }
            RefBrack { refr, index, .. } => {
                // Recursively hoist from sub-expressions
                self.hoist_loops_from_expr(refr, loops)?;
                self.hoist_loops_from_expr(index, loops)?;

                // Check if this is an array[_] pattern or unbound variable pattern
                if let Var {
                    value: Value::String(var_name),
                    ..
                } = index.as_ref()
                {
                    if var_name.as_ref() == "_"
                        || self.is_unbound_var(var_name.as_ref())
                        || !self.can_resolve_variable(var_name.as_ref())
                    {
                        if var_name.as_ref() == "_" {
                            // Anonymous variable
                        } else if self.is_unbound_var(var_name.as_ref()) {
                            // Already marked as unbound variable
                        } else {
                            // Add as unbound variable for proper tracking
                            self.add_unbound_variable(var_name.as_ref());
                        }
                        // This is array[_] or object[unbound_var] - create a loop to iterate over the collection
                        loops.push(HoistedLoop {
                            loop_expr: Some(expr.clone()),
                            key: Some(index.clone()),
                            value: expr.clone(),
                            collection: refr.clone(),
                            loop_type: LoopType::IndexIteration,
                        });
                        // Bind the unbound variable so that its usage is not misinterpreted as a loop
                        if var_name.as_ref() != "_" {
                            self.bind_unbound_variable(var_name.as_ref());
                        }
                        return Ok(());
                    }
                }
            }

            // Binary expressions - hoist from both operands
            BinExpr { lhs, rhs, .. } => {
                self.hoist_loops_from_expr(lhs, loops)?;
                self.hoist_loops_from_expr(rhs, loops)?;
            }
            BoolExpr { lhs, rhs, .. } => {
                self.hoist_loops_from_expr(lhs, loops)?;
                self.hoist_loops_from_expr(rhs, loops)?;
            }
            ArithExpr { lhs, rhs, .. } => {
                self.hoist_loops_from_expr(lhs, loops)?;
                self.hoist_loops_from_expr(rhs, loops)?;
            }
            AssignExpr { lhs, rhs, .. } => {
                self.hoist_loops_from_expr(lhs, loops)?;
                self.hoist_loops_from_expr(rhs, loops)?;
            }

            // Membership expressions - hoist from key, value, and collection
            Membership {
                key,
                value,
                collection,
                ..
            } => {
                if let Some(key_expr) = key {
                    self.hoist_loops_from_expr(key_expr, loops)?;
                }
                self.hoist_loops_from_expr(value, loops)?;
                self.hoist_loops_from_expr(collection, loops)?;
            }

            // Handle conditionally compiled expression types
            #[cfg(feature = "rego-extensions")]
            OrExpr { lhs, rhs, .. } => {
                self.hoist_loops_from_expr(lhs, loops)?;
                self.hoist_loops_from_expr(rhs, loops)?;
            }
        }
        Ok(())
    }

    /// Compile statements within loops (similar to interpreter's eval_stmts_in_loop)
    fn compile_hoisted_loops(
        &mut self,
        stmts: &[&crate::ast::LiteralStmt],
        loops: &[HoistedLoop],
    ) -> Result<()> {
        if loops.is_empty() {
            // No more loops, compile the current statement.
            if !stmts.is_empty() {
                self.compile_single_statement(stmts[0])?;
                // Remaining statements may have loops, so compile them recursively.
                return self.hoist_loops_and_compile_statements(&stmts[1..]);
            } else {
                self.hoist_loops_and_emit_context_yield()?;
            }
        }

        let current_loop = &loops[0];
        let remaining_loops = &loops[1..];

        debug!("Compiling loop of type {:?}", current_loop.loop_type);

        match current_loop.loop_type {
            LoopType::SomeIn => {
                // Compile SomeIn loop with remaining statements as body
                self.compile_some_in_loop_with_remaining_statements(
                    &current_loop.key,
                    &current_loop.value,
                    &current_loop.collection,
                    stmts,
                    remaining_loops,
                )?;
                Ok(())
            }
            LoopType::IndexIteration => {
                // Compile index iteration loop
                self.compile_index_iteration_loop(
                    &current_loop.loop_expr,
                    &current_loop.key,
                    &current_loop.value,
                    &current_loop.collection,
                    stmts,
                    remaining_loops,
                )?;
                Ok(())
            }
        }
    }

    fn hoist_loops_and_emit_context_yield(&mut self) -> Result<(), anyhow::Error> {
        // Check if we're in an Every quantifier context - if so, don't emit context yield
        // Every quantifiers are assertions, not value-producing expressions
        if let Some(context) = self.context_stack.last() {
            // Check if this is an Every context that doesn't need context yield
            match &context.context_type {
                ContextType::Every => {
                    // Every quantifiers don't emit context yield
                    debug!("Skipping context yield for Every quantifier context");
                    return Ok(());
                }
                ContextType::Rule(_) => {
                    // This is a rule context, proceed with normal context yield logic
                }
                ContextType::Comprehension(_) => {
                    // This is a comprehension context, proceed with normal context yield logic
                }
            }
        }

        if let Some(context) = self.context_stack.last_mut() {
            if context.key_value_loops_hoisted {
                // Loops already hoisted, emit context yield
                self.emit_context_yield()
            } else {
                // Need to hoist loops from key/value expressions first
                let mut key_value_loops = Vec::new();

                // Clone expressions to avoid borrowing issues
                let key_expr = context.key_expr.clone();
                let value_expr = context.value_expr.clone();

                // Collect loops from key expression
                if let Some(ref expr) = key_expr {
                    self.hoist_loops_from_expr(expr, &mut key_value_loops)?;
                }

                // Collect loops from value expression
                if let Some(ref expr) = value_expr {
                    self.hoist_loops_from_expr(expr, &mut key_value_loops)?;
                }

                if !key_value_loops.is_empty() {
                    // Mark that we've hoisted loops to prevent infinite recursion
                    self.context_stack
                        .last_mut()
                        .unwrap()
                        .key_value_loops_hoisted = true;

                    // Recursively compile the hoisted loops
                    self.compile_hoisted_loops(&[], &key_value_loops)
                } else {
                    // No loops to hoist, emit context yield
                    self.emit_context_yield()
                }
            }
        } else {
            // No context, just return without error
            Ok(())
        }
    }

    /// Compile an Every quantifier
    fn compile_every_quantifier(
        &mut self,
        key: &Option<crate::lexer::Span>,
        value: &crate::lexer::Span,
        domain: &ExprRef,
        query: &crate::ast::Query,
        span: &crate::lexer::Span,
    ) -> Result<()> {
        debug!("Compiling Every quantifier with domain and query");

        // Compile the domain expression
        let collection_reg = self.compile_rego_expr(domain)?;

        // Allocate registers for loop variables
        let key_reg = self.alloc_register();
        let value_reg = self.alloc_register();
        let result_reg = self.alloc_register();

        // Extract variable names from the spans
        let value_var_name = value.text().to_string();
        let key_var_name = key.as_ref().map(|k| k.text().to_string());

        // Check if key is actually needed (not None and not underscore)
        let actual_key_reg =
            if key_var_name.is_none() || key_var_name.as_ref() == Some(&"_".to_string()) {
                value_reg // Set key_reg = value_reg to indicate key not needed
            } else {
                key_reg
            };

        debug!(
            "Every quantifier - value var: '{}', key var: {:?}",
            value_var_name, key_var_name
        );

        // Generate loop start instruction for Every mode
        let loop_params_index = self.program.add_loop_params(LoopStartParams {
            mode: LoopMode::Every,
            collection: collection_reg,
            key_reg: actual_key_reg,
            value_reg,
            result_reg,
            body_start: 0, // Will be updated
            loop_end: 0,   // Will be updated
        });

        self.emit_instruction(
            Instruction::LoopStart {
                params_index: loop_params_index,
            },
            span,
        );

        let body_start = self.program.instructions.len() as u16;

        // Push new scope for loop variables (Every needs explicit scope management)
        self.push_scope();

        // Push Every context - this will prevent context yield emission
        let every_context = CompilationContext {
            context_type: ContextType::Every,
            dest_register: result_reg, // Not used for Every but required
            key_expr: None,
            value_expr: None,
            span: span.clone(),
            key_value_loops_hoisted: false,
        };
        self.push_context(every_context);

        // Add loop variables to scope using their actual names
        self.add_variable(&value_var_name, value_reg);
        if let Some(ref key_name) = key_var_name {
            self.add_variable(key_name, key_reg);
        }

        debug!(
            "Added Every loop variables to scope - value: '{}' -> reg {}, key: {:?}",
            value_var_name,
            value_reg,
            key_var_name.as_ref().map(|k| (k, key_reg))
        );

        // Compile the query body using standard query compilation
        // Note: compile_query will push/pop its own additional scope
        self.compile_query(query)?;

        // Pop Every context and scope
        self.pop_context();
        self.pop_scope();

        // Add LoopNext instruction
        self.emit_instruction(
            Instruction::LoopNext {
                body_start,
                loop_end: 0, // Will be updated
            },
            span,
        );

        let loop_end = self.program.instructions.len() as u16;

        // Update the loop parameters with actual body_start and loop_end
        self.program
            .update_loop_params(loop_params_index, |params| {
                params.body_start = body_start;
                params.loop_end = loop_end;
            });

        // Update the LoopNext instruction
        let loop_next_idx = self.program.instructions.len() - 1;
        if let Instruction::LoopNext {
            loop_end: ref mut end,
            ..
        } = &mut self.program.instructions[loop_next_idx]
        {
            *end = loop_end;
        }

        debug!(
            "Every quantifier compiled - body_start={}, loop_end={}",
            body_start, loop_end
        );

        Ok(())
    }

    /// Compile a single statement without loops
    fn compile_single_statement(&mut self, stmt: &crate::ast::LiteralStmt) -> Result<()> {
        debug!("Compiling single statement: {}", stmt.span.text());
        match &stmt.literal {
            crate::ast::Literal::Expr { expr, .. } => {
                // Compile the condition and assert it must be true
                let _condition_reg = self.compile_rego_expr_with_span(expr, &stmt.span, true)?;
            }
            crate::ast::Literal::SomeIn { .. } => {
                // Should have been handled by loop hoisting
                return Err(anyhow::anyhow!("SomeIn should have been hoisted as a loop"));
            }
            crate::ast::Literal::Every {
                key,
                value,
                domain,
                query,
                ..
            } => {
                debug!("Compiling Every quantifier");
                self.compile_every_quantifier(key, value, domain, query, &stmt.span)?;

                // Every quantifier acts as an assertion - if it succeeds,
                // we continue with the next statement
                debug!("Every quantifier completed - continuing with next statements");
            }
            crate::ast::Literal::SomeVars { span, vars } => {
                debug!(
                    "Compiling SomeVars statement with {:?} variables at span {:?}",
                    vars.iter().map(|v| v.text()),
                    span
                );
                // Add each variable to the current scope's unbound variables
                for var in vars {
                    self.add_unbound_variable(var.text());
                }
            }
            _ => {
                debug!("Skipping complex literal: {:?}", stmt.literal);
                // For other literal types, skip for now
            }
        }
        Ok(())
    }

    /// Compile index iteration loop (for patterns like collection[_], collection[idx], etc.)
    fn compile_index_iteration_loop(
        &mut self,
        loop_expr: &Option<ExprRef>,
        key_var: &Option<ExprRef>,
        _value_var: &ExprRef,
        collection: &ExprRef,
        remaining_stmts: &[&crate::ast::LiteralStmt],
        remaining_loops: &[HoistedLoop],
    ) -> Result<()> {
        debug!("Compiling index iteration loop");

        // Compile the collection expression
        let collection_reg = self.compile_rego_expr(collection)?;

        // Allocate registers for loop variables
        let key_reg = self.alloc_register(); // index
        let value_reg = self.alloc_register(); // element
        let result_reg = self.alloc_register();

        if let Some(loop_expr) = loop_expr {
            self.loop_expr_register_map
                .insert(loop_expr.clone(), value_reg);
        }
        debug!("Index iteration loop for {key_var:?} over {loop_expr:?}");
        if let Some(key_var) = key_var {
            // Store loop variable in scope (extract variable name from key_var)
            if let crate::ast::Expr::Var { value, .. } = key_var.as_ref() {
                let var_name = match value {
                    Value::String(s) => {
                        if s.as_ref() == "_" {
                            // For underscore, we'll use the value (array element), not the index
                            "".to_string() // Will be handled specially
                        } else {
                            s.to_string()
                        }
                    }
                    _ => value.to_string(),
                };
                if !var_name.is_empty() && var_name != "_" {
                    self.store_variable(var_name, key_reg);
                }
            }
            self.loop_expr_register_map.insert(key_var.clone(), key_reg);
        }

        // Generate loop start instruction
        let loop_params_index = self.program.add_loop_params(LoopStartParams {
            mode: LoopMode::ForEach,
            collection: collection_reg,
            key_reg,
            value_reg,
            result_reg,
            body_start: 0, // Will be updated
            loop_end: 0,   // Will be updated
        });
        self.emit_instruction(
            Instruction::LoopStart {
                params_index: loop_params_index,
            },
            collection.span(),
        );

        let body_start = self.program.instructions.len() as u16;

        // Include the first statement as part of the loop body, then compile remaining statements.
        let body_stmts = &remaining_stmts[0..];

        // Compile remaining loops and statements as loop body
        self.compile_hoisted_loops(body_stmts, remaining_loops)?;

        // Add LoopNext instruction
        self.emit_instruction(
            Instruction::LoopNext {
                body_start,
                loop_end: 0, // Will be updated
            },
            collection.span(),
        );

        let loop_end = self.program.instructions.len() as u16;

        // Update the loop parameters with actual body_start and loop_end
        self.program
            .update_loop_params(loop_params_index, |params| {
                params.body_start = body_start;
                params.loop_end = loop_end;
            });

        // Update the LoopNext instruction
        let loop_next_idx = self.program.instructions.len() - 1;
        if let Instruction::LoopNext {
            loop_end: ref mut end,
            ..
        } = &mut self.program.instructions[loop_next_idx]
        {
            *end = loop_end;
        }

        debug!(
            "Array iteration loop compiled - body_start={}, loop_end={}",
            body_start, loop_end
        );

        Ok(())
    }

    /// Compile SomeIn with remaining statements
    fn compile_some_in_loop_with_remaining_statements(
        &mut self,
        key: &Option<ExprRef>,
        value: &ExprRef,
        collection: &ExprRef,
        remaining_stmts: &[&crate::ast::LiteralStmt],
        _remaining_loops: &[HoistedLoop],
    ) -> Result<Register> {
        // Use the existing compile_some_in_loop_with_body method but with proper statement handling
        // Skip the first statement (which is the SomeIn) and use the rest as loop body
        let loop_body_stmts = &remaining_stmts[1..];
        let result_reg =
            self.compile_some_in_loop_with_body(key, value, collection, loop_body_stmts)?;
        Ok(result_reg)
    }
}

/// Helper types for loop hoisting
#[derive(Debug, Clone)]
struct HoistedLoop {
    loop_expr: Option<ExprRef>,
    key: Option<ExprRef>,
    value: ExprRef,
    collection: ExprRef,
    loop_type: LoopType,
}

#[derive(Debug, Clone)]
enum LoopType {
    SomeIn,
    IndexIteration,
}

impl<'a> Compiler<'a> {
    fn compile_some_in_loop_with_body(
        &mut self,
        key: &Option<ExprRef>,
        value: &ExprRef,
        collection: &ExprRef,
        loop_body_stmts: &[&crate::ast::LiteralStmt],
    ) -> Result<Register> {
        // Compile collection expression
        let collection_reg = self.compile_rego_expr(collection)?;

        // Allocate registers for loop variables
        let key_reg = self.alloc_register();
        let value_reg = self.alloc_register();
        let result_reg = self.alloc_register();

        // Initialize result register as empty set
        self.program
            .instructions
            .push(Instruction::SetNew { dest: result_reg });

        // Start the existential loop - we'll calculate the correct loop_end after compiling the body

        // Add LoopStart instruction with parameters
        let loop_params_index = self.program.add_loop_params(LoopStartParams {
            mode: LoopMode::SetComprehension, // Use SetComprehension for set rules with some...in
            collection: collection_reg,
            key_reg,
            value_reg,
            result_reg,
            body_start: 0, // Will be calculated after adding LoopStart
            loop_end: 0,   // Placeholder
        });
        self.emit_instruction(
            Instruction::LoopStart {
                params_index: loop_params_index,
            },
            collection.span(),
        );

        // Calculate body_start after adding LoopStart instruction
        let body_start = self.program.instructions.len() as u16;

        // Store loop variables in scope for body compilation
        if let Some(key_expr) = key {
            if let crate::ast::Expr::Var {
                value: var_name, ..
            } = key_expr.as_ref()
            {
                debug!(
                    "Storing loop key variable '{}' at register {}",
                    var_name, key_reg
                );
                self.store_variable(var_name.to_string(), key_reg);
            }
        }

        if let crate::ast::Expr::Var {
            value: var_name, ..
        } = value.as_ref()
        {
            debug!("Variable name value: {:?}", var_name);

            // Extract the string value from the Value
            let clean_var_name = match var_name {
                crate::value::Value::String(s) => s.to_string(),
                _ => var_name.to_string(),
            };

            debug!(
                "Storing loop value variable '{}' at register {} (from '{:?}')",
                clean_var_name, value_reg, var_name
            );
            self.store_variable(clean_var_name.clone(), value_reg);

            // Debug: Check if variable is actually stored
            debug!(
                "Checking if variable '{}' is now in scope...",
                clean_var_name
            );
            if let Some(reg) = self.lookup_variable(&clean_var_name) {
                debug!(
                    "Yes, variable '{}' found at register {}",
                    clean_var_name, reg
                );
            } else {
                debug!(
                    "ERROR - variable '{}' not found after storing!",
                    clean_var_name
                );
            }
        }

        // Compile the loop body statements
        self.hoist_loops_and_compile_statements(loop_body_stmts)?;

        // Add LoopNext instruction to continue to next iteration
        self.emit_instruction(
            Instruction::LoopNext {
                body_start,
                loop_end: 0, // Will be updated
            },
            collection.span(),
        );

        // Calculate the correct loop_end (points to instruction after LoopNext)
        let loop_end = self.program.instructions.len() as u16;

        // Update the loop parameters with actual body_start and loop_end
        self.program
            .update_loop_params(loop_params_index, |params| {
                params.body_start = body_start;
                params.loop_end = loop_end;
            });

        // Update the LoopNext instruction with the correct loop_end
        let loop_next_idx = self.program.instructions.len() - 1;
        if let Instruction::LoopNext {
            loop_end: ref mut end,
            ..
        } = &mut self.program.instructions[loop_next_idx]
        {
            *end = loop_end;
        }

        debug!(
            "SomeIn loop compiled - body_start={}, loop_end={}",
            body_start, loop_end
        );

        // Debug: Print all instructions generated for this loop
        debug!(
            "Generated {} instructions for SomeIn loop:",
            self.program.instructions.len()
        );
        for (i, instr) in self.program.instructions.iter().enumerate() {
            debug!("  {}: {:?}", i, instr);
        }

        // Debug: Print literals table
        debug!("Literals table:");
        for (i, literal) in self.program.literals.iter().enumerate() {
            debug!("  literal_idx {}: {:?}", i, literal);
        }

        Ok(result_reg)
    }

    /// Compile array comprehension [term | query]
    fn compile_array_comprehension(
        &mut self,
        term: &ExprRef,
        query: &crate::ast::Query,
        span: &Span,
    ) -> Result<Register> {
        debug!("Compiling array comprehension");

        // Allocate result register and initialize as empty array
        let result_reg = self.alloc_register();
        self.emit_instruction(Instruction::ArrayNew { dest: result_reg }, span);

        // Push comprehension context with the term as output expression
        let comprehension_context = CompilationContext {
            context_type: ContextType::Comprehension(ComprehensionType::Array),
            dest_register: result_reg,
            key_expr: None,
            value_expr: Some(term.clone()),
            span: span.clone(),
            key_value_loops_hoisted: false,
        };
        self.push_context(comprehension_context);

        // Compile the query - this will push/pop its own scope
        self.compile_query(query)?;

        // Pop context
        self.pop_context();

        Ok(result_reg)
    }

    /// Compile set comprehension {term | query}
    fn compile_set_comprehension(
        &mut self,
        term: &ExprRef,
        query: &crate::ast::Query,
        span: &Span,
    ) -> Result<Register> {
        debug!("Compiling set comprehension");

        // Allocate result register and initialize as empty set
        let result_reg = self.alloc_register();
        self.emit_instruction(Instruction::SetNew { dest: result_reg }, span);

        // Push comprehension context with the term as output expression
        let comprehension_context = CompilationContext {
            context_type: ContextType::Comprehension(ComprehensionType::Set),
            dest_register: result_reg,
            key_expr: None,
            value_expr: Some(term.clone()),
            span: span.clone(),
            key_value_loops_hoisted: false,
        };
        self.push_context(comprehension_context);

        // Compile the query - this will push/pop its own scope
        self.compile_query(query)?;

        // Pop context
        self.pop_context();

        Ok(result_reg)
    }

    /// Compile object comprehension {key: value | query}
    fn compile_object_comprehension(
        &mut self,
        key: &ExprRef,
        value: &ExprRef,
        query: &crate::ast::Query,
        span: &Span,
    ) -> Result<Register> {
        debug!("Compiling object comprehension");

        // Allocate result register and initialize as empty object
        let result_reg = self.alloc_register();

        // Create empty template object
        let template_literal_idx = self.add_literal(Value::Object(Arc::new(BTreeMap::new())));

        // Create ObjectCreate parameters for empty object
        let params = ObjectCreateParams {
            dest: result_reg,
            template_literal_idx,
            literal_key_fields: Vec::new(),
            fields: Vec::new(),
        };
        let params_index = self
            .program
            .instruction_data
            .add_object_create_params(params);
        self.emit_instruction(Instruction::ObjectCreate { params_index }, span);

        // Push comprehension context with both key and value expressions
        let comprehension_context = CompilationContext {
            context_type: ContextType::Comprehension(ComprehensionType::Object),
            dest_register: result_reg,
            key_expr: Some(key.clone()),
            value_expr: Some(value.clone()),
            span: span.clone(),
            key_value_loops_hoisted: false,
        };
        self.push_context(comprehension_context);

        // Compile the query - this will push/pop its own scope
        self.compile_query(query)?;

        // Pop context
        self.pop_context();

        Ok(result_reg)
    }

    /// Compile a function call expression
    fn compile_function_call(
        &mut self,
        fcn: &ExprRef,
        params: &[ExprRef],
        span: Span,
    ) -> Result<Register> {
        // Get the function path
        let fcn_path = get_path_string(fcn, None)
            .map_err(|_| anyhow::anyhow!("Invalid function expression"))?;

        let _span = span!(tracing::Level::DEBUG, "compile_function_call");
        let _enter = _span.enter();
        debug!(
            "Compiling function call: '{}' with {} parameters",
            fcn_path,
            params.len()
        );

        // Try to find user-defined function first with the original path
        let original_fcn_path = fcn_path.clone();
        let full_fcn_path = if self.policy.inner.rules.contains_key(&fcn_path) {
            debug!("Found user-defined function: '{}'", fcn_path);
            fcn_path
        } else {
            // If not found, try with current package prefix
            let with_package = get_path_string(fcn, Some(&self.current_package))
                .map_err(|_| anyhow::anyhow!("Invalid function expression with package"))?;
            debug!("Trying with package prefix: '{}'", with_package);
            with_package
        };

        // Compile all parameter expressions first
        let mut arg_regs = Vec::new();
        for param in params.iter() {
            let param_reg = self.compile_rego_expr_with_span(param, param.span(), false)?;
            arg_regs.push(param_reg);
        }

        // Allocate destination register for the result
        let dest = self.alloc_register();
        debug!("Allocated destination register: {}", dest);

        // First check if this is a user-defined function rule
        if self.is_user_defined_function(&full_fcn_path) {
            debug!("Compiling as user-defined function: '{}'", full_fcn_path);
            // Get the function rule index for user-defined functions
            let rule_index = self.get_or_assign_rule_index(&full_fcn_path)?;
            debug!("Function rule index: {}", rule_index);

            // Create function call parameters with fixed-size array
            let mut args_array = [0u8; 8];
            let num_args = arg_regs.len().min(8) as u8; // Limit to 8 arguments
            for (i, &reg) in arg_regs.iter().take(8).enumerate() {
                args_array[i] = reg;
            }

            let params_index =
                self.program
                    .add_function_call_params(super::instructions::FunctionCallParams {
                        func_rule_index: rule_index,
                        dest,
                        num_args,
                        args: args_array,
                    });

            // Emit the FunctionCall instruction
            self.emit_instruction(Instruction::FunctionCall { params_index }, &span);
            debug!("Emitted FunctionCall instruction for user-defined function");
        } else if self.is_builtin(&original_fcn_path) {
            debug!("Compiling as builtin function: '{}'", original_fcn_path);

            // Get builtin index
            let builtin_index = self.get_builtin_index(&original_fcn_path)?;
            debug!("Builtin index: {}", builtin_index);

            // Create builtin call parameters with fixed-size array
            let mut args_array = [0u8; 8];
            let num_args = arg_regs.len().min(8) as u8; // Limit to 8 arguments
            for (i, &reg) in arg_regs.iter().take(8).enumerate() {
                args_array[i] = reg;
            }

            let params_index =
                self.program
                    .add_builtin_call_params(super::instructions::BuiltinCallParams {
                        dest,
                        builtin_index,
                        num_args,
                        args: args_array,
                    });

            // Emit the BuiltinCall instruction
            self.emit_instruction(Instruction::BuiltinCall { params_index }, &span);

            debug!(
                "Builtin call compiled - dest={}, params_index={}, builtin_index={}",
                dest, params_index, builtin_index
            );
        } else {
            debug!(
                "Function '{}' not found as user-defined or builtin",
                original_fcn_path
            );
            bail!("Unknown function: '{}'", original_fcn_path);
        }

        debug!(
            "Function call compilation completed, result in register {}",
            dest
        );
        Ok(dest)
    }

    /// Evaluate simple literal default rules and store results in literal table
    fn evaluate_default_rule(&mut self, rule_path: &str) -> Option<u16> {
        // Check if there are default rules for this path in the compiled policy
        if !self.policy.inner.default_rules.contains_key(rule_path) {
            debug!("No default rules found for '{}'", rule_path);
            return None;
        }

        // Create an interpreter to evaluate the default rule
        let mut interpreter = Interpreter::new_from_compiled_policy(self.policy.inner.clone());

        // Use the compiler-specific function to evaluate the default rule and get its value
        match interpreter.eval_default_rule_for_compiler(rule_path) {
            Ok(computed_value) => {
                if computed_value != Value::Undefined {
                    debug!(
                        "Evaluated default rule for '{}': {:?}",
                        rule_path, computed_value
                    );

                    // Add the computed value to the literal table
                    let literal_index = self.add_literal(computed_value);
                    return Some(literal_index as u16);
                }
            }
            Err(_e) => {
                debug!(
                    "Failed to evaluate default rule for '{}': {}",
                    rule_path, _e
                );
            }
        }

        None
    }
}
