use super::instructions::LoopMode;
use super::program::Program;
use super::Instruction;
use crate::ast::{Expr, ExprRef, Rule, RuleHead};
use crate::lexer::Span;
use crate::rvm::program::RuleType;
use crate::rvm::program::SpanInfo;
use crate::{CompiledPolicy, Value};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use std::collections::HashMap;
use std::sync::Arc;

pub type Register = u16;
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
    instructions: Vec<Instruction>,
    literals: Vec<Value>,
    spans: Vec<SpanInfo>,
    register_counter: Register,
    scopes: Vec<Scope>,         // Stack of variable scopes (like the interpreter)
    policy: &'a CompiledPolicy, // Reference to the compiled policy for rule lookup
    current_package: String,    // Current package path (e.g., "data.test")
    // Three-level hierarchy compilation fields
    rule_index_map: HashMap<String, u16>, // Maps rule paths to their assigned rule indices
    rule_worklist: Vec<String>,           // Rules that need to be compiled
    rule_definitions: Vec<Vec<Vec<usize>>>, // rule_index -> Vec<definition> where definition is Vec<body_entry_point>
    rule_types: Vec<RuleType>,              // rule_index -> true if set rule, false if regular rule
    // Context stack for output expression handling
    context_stack: Vec<CompilationContext>, // Stack of compilation contexts
    loop_expr_register_map: BTreeMap<ExprRef, Register>, // Map from loop expressions to their allocated registers
}

impl<'a> Compiler<'a> {
    pub fn with_policy(policy: &'a CompiledPolicy, package: String) -> Self {
        Self {
            instructions: Vec::new(),
            literals: Vec::new(),
            spans: Vec::new(),
            register_counter: 1,
            scopes: vec![Scope::default()],
            policy,
            current_package: package,
            rule_index_map: HashMap::new(),
            rule_worklist: Vec::new(),
            rule_definitions: Vec::new(),
            rule_types: Vec::new(),
            context_stack: vec![], // Default context
            loop_expr_register_map: BTreeMap::new(),
        }
    }

    pub fn alloc_register(&mut self) -> Register {
        let reg = self.register_counter;
        self.register_counter += 1;
        reg
    }

    /// Add a literal value to the literal table, returning its index
    pub fn add_literal(&mut self, value: Value) -> u16 {
        // Check if literal already exists to avoid duplication
        // TODO: Optimize lookup
        for (idx, existing) in self.literals.iter().enumerate() {
            if existing == &value {
                return idx as u16;
            }
        }

        let idx = self.literals.len() as u16;
        self.literals.push(value);
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

    /// Store a variable mapping (backward compatibility)
    /// Look up a variable, first in local scope, then as a rule reference
    fn resolve_variable(&mut self, var_name: &str, span: &Span) -> Result<Register> {
        std::println!("Debug: resolve_variable called for '{}'", var_name);

        // Handle special built-in variables first
        match var_name {
            "input" => {
                let dest = self.alloc_register();
                self.emit_instruction(Instruction::LoadInput { dest }, span);
                std::println!(
                    "Debug: Variable 'input' resolved to LoadInput instruction, register {}",
                    dest
                );
                return Ok(dest);
            }
            "data" => {
                // TODO: Fully qualified rule paths.
                // TODO: data overrides rule in same path
                let dest = self.alloc_register();
                self.emit_instruction(Instruction::LoadData { dest }, span);
                std::println!(
                    "Debug: Variable 'data' resolved to LoadData instruction, register {}",
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
            std::println!(
                "Debug: Variable '{}' found in local scope at register {}",
                var_name,
                var_reg
            );
            return Ok(var_reg);
        }

        std::println!(
            "Debug: Variable '{}' not found in local scope, checking rules",
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
                    std::println!(
                        "Debug: Rule '{}' head type: {:?}, is_set: {:?}",
                        rule_path,
                        head,
                        result
                    );
                    result
                } else {
                    std::println!("Debug: Rule '{}' is not a Spec rule", rule_path);
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

            std::println!("Debug: Assigned rule index {} to '{}'", index, rule_path);
            Ok(index)
        }
    }

    fn store_variable(&mut self, var_name: String, register: Register) {
        self.add_variable(&var_name, register);
    }

    /// Look up a variable register (backward compatibility)
    fn lookup_variable(&self, var_name: &str) -> Option<Register> {
        self.lookup_local_var(var_name)
    }

    /// Emit an instruction with span tracking
    pub fn emit_instruction(&mut self, instruction: Instruction, span: &Span) {
        self.instructions.push(instruction);
        self.spans.push(SpanInfo::from_lexer_span(span, 0)); // Use source index 0 for now
    }

    pub fn emit_return(&mut self, result_reg: Register) {
        // Add return instruction
        self.instructions
            .push(Instruction::Return { value: result_reg });
        self.spans.push(SpanInfo::new(0, 0, 0, 0)); // Default span for return instruction
    }

    pub fn finish(self) -> crate::rvm::program::Program {
        // Convert to Program
        let mut program = Program::new();
        program.instructions = self.instructions;
        program.literals = self.literals;
        program.main_entry_point = 0;

        // Set the rule definitions from the compiler
        let mut rule_infos_map = BTreeMap::new();
        for (rule_path, &rule_index) in &self.rule_index_map {
            let definitions = self.rule_definitions[rule_index as usize].clone();
            let rule_type = self.rule_types[rule_index as usize].clone();
            let rule_info = crate::rvm::program::RuleInfo::new(
                rule_path.clone(),
                rule_type,
                crate::Rc::new(definitions),
            );
            rule_infos_map.insert(rule_index as usize, rule_info);
        }

        program.rule_infos = rule_infos_map.into_values().collect();

        // Debug: Print rule definitions
        std::println!("Debug: Rule definitions in program:");
        for (rule_idx, rule_info) in program.rule_infos.iter().enumerate() {
            std::println!(
                "  Rule {}: {} definitions",
                rule_idx,
                rule_info.definitions.len()
            );
            for (def_idx, bodies) in rule_info.definitions.iter().enumerate() {
                std::println!(
                    "    Definition {}: {} bodies at entry points {:?}",
                    def_idx,
                    bodies.len(),
                    bodies
                );
            }
        }

        // Add worklist rules to the mapping (they use 1-based indices)
        for (rule_path, &rule_index) in &self.rule_index_map {
            program
                .rule_name_to_index
                .insert(rule_path.clone(), rule_index as usize);
        }

        // Extract source contents from the policy modules
        for module in self.policy.get_modules().iter() {
            let source = &module.package.refr.span().source;
            let source_path = source.get_path().to_string();
            let source_content = source.get_contents().to_string();
            program.add_source(source_path, source_content);
        }

        // Convert spans
        program.instruction_spans = self.spans.into_iter().map(|_span| None).collect();

        std::println!(
            "Debug: Final program has {} instructions, {} rule infos",
            program.instructions.len(),
            program.rule_infos.len()
        );

        program
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
            std::println!(
                "Debug: Found loop expression in map, using register {}",
                reg
            );
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
                // Create empty object first
                let dest = self.alloc_register();
                self.emit_instruction(Instruction::ObjectNew { dest }, span);

                // Add each field to the object
                for (_, key_expr, value_expr) in fields {
                    // Compile key and value
                    let key_reg =
                        self.compile_rego_expr_with_span(key_expr, key_expr.span(), false)?;
                    let value_reg =
                        self.compile_rego_expr_with_span(value_expr, value_expr.span(), false)?;

                    // Set the field in the object
                    self.emit_instruction(
                        Instruction::ObjectSet {
                            obj: dest,
                            key: key_reg,
                            value: value_reg,
                        },
                        span,
                    );
                }

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
                    self.instructions.push(Instruction::Move {
                        dest: lhs_reg,
                        src: rhs_reg,
                    });

                    // Store the variable binding to the NEW register
                    std::println!(
                        "Debug: Assignment '{}' := value from register {} to new register {}",
                        var_name,
                        rhs_reg,
                        lhs_reg
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
                    std::println!(
                        "Debug: Resolving variable '{}' - looking up in scopes",
                        var_name
                    );
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

                // Create register for field key
                let key_reg = self.alloc_register();
                let literal_idx = self.add_literal(field_value.clone());
                self.emit_instruction(
                    Instruction::Load {
                        dest: key_reg,
                        literal_idx,
                    },
                    span,
                );

                // Get the field value
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
                std::println!("Debug: Compiling array comprehension");
                self.compile_array_comprehension(term, query, span)?
            }
            Expr::SetCompr { term, query, .. } => {
                std::println!("Debug: Compiling set comprehension");
                self.compile_set_comprehension(term, query, span)?
            }
            Expr::ObjectCompr {
                key, value, query, ..
            } => {
                std::println!("Debug: Compiling object comprehension");
                self.compile_object_comprehension(key, value, query, span)?
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
        // Extract package name from rule_name
        let package = if let Some(last_dot) = rule_name.rfind('.') {
            rule_name[..last_dot].to_string()
        } else {
            "data".to_string()
        };

        let mut compiler = Compiler::with_policy(policy, package);
        let rules = policy.get_rules();

        std::println!("Debug: Available rules in policy:");
        for (key, rule_list) in rules.iter() {
            std::println!("  Rule key: '{}' ({} variants)", key, rule_list.len());
        }
        std::println!("Debug: Looking for rule: '{}'", rule_name);

        // Emit CallRule instruction for the main entry point
        let result_reg = compiler.alloc_register();
        let rule_idx = compiler.get_or_assign_rule_index(rule_name)?;
        compiler.instructions.push(Instruction::CallRule {
            dest: result_reg,
            rule_index: rule_idx,
        });

        // Add Return instruction for main execution
        compiler
            .instructions
            .push(Instruction::Return { value: result_reg });

        compiler.compile_worklist_rules(rules)?;

        Ok(Arc::new(compiler.finish()))
    }

    fn compile_worklist_rules(
        &mut self,
        rules: &HashMap<String, Vec<crate::ast::NodeRef<Rule>>>,
    ) -> Result<()> {
        // Now compile all rules in the worklist (set rules referenced via CallRule)
        while !self.rule_worklist.is_empty() {
            let rule_to_compile = self.rule_worklist.remove(0);
            std::println!("Debug: Compiling worklist rule: '{}'", rule_to_compile);
            self.compile_worklist_rule(&rule_to_compile, rules)?;
        }
        Ok(())
    }

    /// Compile a set rule from the worklist - each variant gets its own entry point
    fn compile_worklist_rule(
        &mut self,
        rule_path: &str,
        rules: &HashMap<String, Vec<crate::ast::NodeRef<Rule>>>,
    ) -> Result<()> {
        std::println!("Debug: Compiling worklist rule: '{}'", rule_path);

        if let Some(rule_definitions) = rules.get(rule_path) {
            let rule_index = self.rule_index_map.get(rule_path).copied().unwrap_or(1);
            let rule_type = self.rule_types[rule_index as usize].clone();
            let dest_register = self.alloc_register();

            std::println!(
                "Debug: Rule '{}' has {} definitions",
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
                    std::println!(
                        "Debug: Compiling definition {} with {} bodies",
                        def_idx,
                        bodies.len()
                    );

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
                        _ => unimplemented!("rule head type"),
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

                    // Compile each body within this definition
                    for (body_idx, body) in bodies.iter().enumerate() {
                        let body_entry_point = self.instructions.len();
                        body_entry_points.push(body_entry_point);

                        std::println!(
                            "Debug: Compiling body {} at entry point {}",
                            body_idx,
                            body_entry_point
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
                        }

                        // 2. Emit Rule Return
                        self.emit_instruction(Instruction::RuleReturn {}, &body.span);
                    }

                    // Store the body entry points for this definition
                    self.rule_definitions[rule_index as usize].push(body_entry_points);

                    std::println!(
                        "Debug: Definition {} compiled with {} bodies",
                        def_idx,
                        bodies.len()
                    );
                }
            }

            std::println!(
                "Debug: Rule '{}' compiled with {} definitions",
                rule_path,
                rule_definitions.len()
            );
        }

        Ok(())
    }

    /// Compile a query (statements with proper loop hoisting, similar to interpreter's eval_stmts)
    fn compile_query(&mut self, query: &crate::ast::Query) -> Result<()> {
        self.hoist_loops_and_compile_statements(&query.stmts)
    }

    /// Hoist loops from statements and compile them with proper sequencing (similar to interpreter's eval_stmts)
    fn hoist_loops_and_compile_statements(
        &mut self,
        stmts: &[crate::ast::LiteralStmt],
    ) -> Result<()> {
        std::println!(
            "Debug: Compiling {} statements with loop hoisting",
            stmts.len()
        );

        for (idx, stmt) in stmts.iter().enumerate() {
            std::println!("Debug: Processing statement {} of {}", idx + 1, stmts.len());

            // Hoist loops from this statement (like interpreter)
            let loop_exprs = self.hoist_loops_from_literal(&stmt.literal)?;

            if !loop_exprs.is_empty() {
                std::println!(
                    "Debug: Found {} loop expressions in statement {}",
                    loop_exprs.len(),
                    idx
                );
                // If there are hoisted loop expressions, execute subsequent statements within loops
                return self.compile_hoisted_loops(&stmts[idx..], &loop_exprs);
            }

            // No loops, compile statement normally
            self.compile_single_statement(stmt)?;
        }

        self.hoist_loops_and_emit_context_yield()
    }

    /// TODO: Share code with interpreter
    /// Hoist loops from a literal (similar to interpreter's hoist_loops)
    fn hoist_loops_from_literal(&self, literal: &crate::ast::Literal) -> Result<Vec<HoistedLoop>> {
        let mut loops = Vec::new();

        use crate::ast::Literal::*;
        match literal {
            SomeIn {
                key,
                value,
                collection,
                ..
            } => {
                std::println!("Debug: Found SomeIn literal - creating loop");
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
                ..
            } => {
                self.hoist_loops_from_expr(_domain, &mut loops)?;
                std::println!("Debug: Found Every literal - creating universal loop: TODO");
            }
            _ => {
                // Other literal types don't have loops to hoist
            }
        }

        Ok(loops)
    }

    /// Hoist loops from expressions (like array[_] patterns)
    fn hoist_loops_from_expr(&self, expr: &ExprRef, loops: &mut Vec<HoistedLoop>) -> Result<()> {
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

                // Check if this is an array[_] pattern
                if let Var {
                    value: Value::String(var_name),
                    ..
                } = index.as_ref()
                {
                    if var_name.as_ref() == "_" || self.is_unbound_var(var_name.as_ref()) {
                        std::println!("Debug: Found array[_] pattern - creating iteration loop");
                        // This is array[_] - create a loop to iterate over the array
                        loops.push(HoistedLoop {
                            loop_expr: Some(expr.clone()),
                            key: None,
                            value: index.clone(), // The _ variable
                            collection: refr.clone(),
                            loop_type: LoopType::IndexIteration,
                        });
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
        stmts: &[crate::ast::LiteralStmt],
        loops: &[HoistedLoop],
    ) -> Result<()> {
        if loops.is_empty() {
            // No more loops, compile the current statement.
            if !stmts.is_empty() {
                self.compile_single_statement(&stmts[0])?;
                // Remaining statements may have loops, so compile them recursively.
                return self.hoist_loops_and_compile_statements(&stmts[1..]);
            } else {
                self.hoist_loops_and_emit_context_yield()?;
            }
        }

        let current_loop = &loops[0];
        let remaining_loops = &loops[1..];

        std::println!("Debug: Compiling loop of type {:?}", current_loop.loop_type);

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
            // No context, emit context yield
            self.emit_context_yield()
        }
    }

    /// Compile a single statement without loops
    fn compile_single_statement(&mut self, stmt: &crate::ast::LiteralStmt) -> Result<()> {
        match &stmt.literal {
            crate::ast::Literal::Expr { expr, .. } => {
                // Compile the condition and assert it must be true
                let _condition_reg = self.compile_rego_expr_with_span(expr, &stmt.span, true)?;
            }
            crate::ast::Literal::SomeIn { .. } => {
                // Should have been handled by loop hoisting
                return Err(anyhow::anyhow!("SomeIn should have been hoisted as a loop"));
            }
            crate::ast::Literal::Every { .. } => {
                // Should have been handled by loop hoisting
                return Err(anyhow::anyhow!("Every should have been hoisted as a loop"));
            }
            crate::ast::Literal::SomeVars { span, vars } => {
                std::println!(
                    "Debug: Compiling SomeVars statement with {:?} variables at span {:?}",
                    vars.iter().map(|v| v.text()),
                    span
                );
                // Add each variable to the current scope's unbound variables
                for var in vars {
                    self.add_unbound_variable(var.text());
                }
            }
            _ => {
                std::println!("Debug: Skipping complex literal: {:?}", stmt.literal);
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
        remaining_stmts: &[crate::ast::LiteralStmt],
        remaining_loops: &[HoistedLoop],
    ) -> Result<()> {
        std::println!("Debug: Compiling index iteration loop");

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
                    self.store_variable(var_name, value_reg);
                }
            }
            self.loop_expr_register_map.insert(key_var.clone(), key_reg);
        }

        // Generate loop start instruction
        let loop_start_idx = self.instructions.len();
        self.instructions.push(Instruction::LoopStart {
            mode: LoopMode::Existential, // For array iteration in set rules
            collection: collection_reg,
            key_reg,
            value_reg,
            result_reg,
            body_start: 0, // Will be updated
            loop_end: 0,   // Will be updated
        });

        let body_start = self.instructions.len() as u16;

        // Include the first statement as part of the loop body, then compile remaining statements.
        let body_stmts = &remaining_stmts[0..];

        // Compile remaining loops and statements as loop body
        self.compile_hoisted_loops(body_stmts, remaining_loops)?;

        // Add LoopNext instruction
        self.instructions.push(Instruction::LoopNext {
            body_start,
            loop_end: 0, // Will be updated
        });

        let loop_end = self.instructions.len() as u16;

        // Update the LoopStart instruction
        if let Instruction::LoopStart {
            body_start: ref mut start,
            loop_end: ref mut end,
            ..
        } = &mut self.instructions[loop_start_idx]
        {
            *start = body_start;
            *end = loop_end;
        }

        // Update the LoopNext instruction
        let loop_next_idx = self.instructions.len() - 1;
        if let Instruction::LoopNext {
            loop_end: ref mut end,
            ..
        } = &mut self.instructions[loop_next_idx]
        {
            *end = loop_end;
        }

        std::println!(
            "Debug: Array iteration loop compiled - body_start={}, loop_end={}",
            body_start,
            loop_end
        );

        Ok(())
    }

    /// Compile SomeIn with remaining statements
    fn compile_some_in_loop_with_remaining_statements(
        &mut self,
        key: &Option<ExprRef>,
        value: &ExprRef,
        collection: &ExprRef,
        remaining_stmts: &[crate::ast::LiteralStmt],
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
        loop_body_stmts: &[crate::ast::LiteralStmt],
    ) -> Result<Register> {
        // Compile collection expression
        let collection_reg = self.compile_rego_expr(collection)?;

        // Allocate registers for loop variables
        let key_reg = self.alloc_register();
        let value_reg = self.alloc_register();
        let result_reg = self.alloc_register();

        // Initialize result register as empty set
        self.instructions
            .push(Instruction::SetNew { dest: result_reg });

        // Start the existential loop - we'll calculate the correct loop_end after compiling the body
        let loop_start_idx = self.instructions.len();

        // Add placeholder LoopStart instruction (we'll update loop_end later)
        self.instructions.push(Instruction::LoopStart {
            mode: LoopMode::SetComprehension, // Use SetComprehension for set rules with some...in
            collection: collection_reg,
            key_reg,
            value_reg,
            result_reg,
            body_start: 0, // Will be calculated after adding LoopStart
            loop_end: 0,   // Placeholder
        });

        // Calculate body_start after adding LoopStart instruction
        let body_start = self.instructions.len() as u16;

        // Store loop variables in scope for body compilation
        if let Some(key_expr) = key {
            if let crate::ast::Expr::Var {
                value: var_name, ..
            } = key_expr.as_ref()
            {
                std::println!(
                    "Debug: Storing loop key variable '{}' at register {}",
                    var_name,
                    key_reg
                );
                self.store_variable(var_name.to_string(), key_reg);
            }
        }

        if let crate::ast::Expr::Var {
            value: var_name, ..
        } = value.as_ref()
        {
            std::println!("Debug: Variable name value: {:?}", var_name);

            // Extract the string value from the Value
            let clean_var_name = match var_name {
                crate::value::Value::String(s) => s.to_string(),
                _ => var_name.to_string(),
            };

            std::println!(
                "Debug: Storing loop value variable '{}' at register {} (from '{:?}')",
                clean_var_name,
                value_reg,
                var_name
            );
            self.store_variable(clean_var_name.clone(), value_reg);

            // Debug: Check if variable is actually stored
            std::println!(
                "Debug: Checking if variable '{}' is now in scope...",
                clean_var_name
            );
            if let Some(reg) = self.lookup_variable(&clean_var_name) {
                std::println!(
                    "Debug: Yes, variable '{}' found at register {}",
                    clean_var_name,
                    reg
                );
            } else {
                std::println!(
                    "Debug: ERROR - variable '{}' not found after storing!",
                    clean_var_name
                );
            }
        }

        // Compile the loop body statements
        self.hoist_loops_and_compile_statements(loop_body_stmts)?;

        // Add LoopNext instruction to continue to next iteration
        self.instructions.push(Instruction::LoopNext {
            body_start,
            loop_end: 0, // Will be updated
        });

        // Calculate the correct loop_end (points to instruction after LoopNext)
        let loop_end = self.instructions.len() as u16;

        // Update the LoopStart instruction with the correct body_start and loop_end
        if let Instruction::LoopStart {
            body_start: ref mut start,
            loop_end: ref mut end,
            ..
        } = &mut self.instructions[loop_start_idx]
        {
            *start = body_start;
            *end = loop_end;
        }

        // Update the LoopNext instruction with the correct loop_end
        let loop_next_idx = self.instructions.len() - 1;
        if let Instruction::LoopNext {
            loop_end: ref mut end,
            ..
        } = &mut self.instructions[loop_next_idx]
        {
            *end = loop_end;
        }

        std::println!(
            "Debug: SomeIn loop compiled - body_start={}, loop_end={}",
            body_start,
            loop_end
        );

        // Debug: Print all instructions generated for this loop
        std::println!(
            "Debug: Generated {} instructions for SomeIn loop:",
            self.instructions.len()
        );
        for (i, instr) in self.instructions.iter().enumerate() {
            std::println!("  {}: {:?}", i, instr);
        }

        // Debug: Print literals table
        std::println!("Debug: Literals table:");
        for (i, literal) in self.literals.iter().enumerate() {
            std::println!("  literal_idx {}: {:?}", i, literal);
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
        // For array comprehension, we need to parse the query to extract loop patterns
        // For now, create a simple hardcoded collection for testing
        let collection_reg = self.alloc_register();
        let literal_idx = self.add_literal(Value::Array(Arc::new(vec![
            Value::Number(1i64.into()),
            Value::Number(2i64.into()),
            Value::Number(3i64.into()),
        ])));
        self.emit_instruction(
            Instruction::Load {
                dest: collection_reg,
                literal_idx,
            },
            span,
        );

        // Allocate registers for loop variables
        let key_reg = self.alloc_register(); // For array index
        let value_reg = self.alloc_register(); // For array value
        let result_reg = self.alloc_register();

        // Start the array comprehension loop
        let body_start = (self.instructions.len() + 1) as u16;
        let loop_start_idx = self.instructions.len();

        // Add LoopStart with placeholder loop_end
        self.instructions.push(Instruction::LoopStart {
            mode: LoopMode::ArrayComprehension,
            collection: collection_reg,
            key_reg,
            value_reg,
            result_reg,
            body_start,
            loop_end: 0, // Will be updated below
        });

        // Store the loop variable in scope
        self.store_variable("x".to_string(), value_reg);

        // Compile the query conditions first
        if !query.stmts.is_empty() {
            self.compile_query(query)?;
        }

        // Compile the term expression
        let term_reg = self.compile_rego_expr(term)?;

        // Accumulate the term
        self.instructions.push(Instruction::LoopAccumulate {
            value: term_reg,
            key: None,
        });

        // Add loop control instructions
        let actual_loop_end = (self.instructions.len() + 1) as u16;
        self.instructions.push(Instruction::LoopNext {
            body_start,
            loop_end: actual_loop_end,
        });

        // Update the LoopStart instruction with the correct loop_end
        if let Some(Instruction::LoopStart { loop_end, .. }) =
            self.instructions.get_mut(loop_start_idx)
        {
            *loop_end = actual_loop_end;
        }

        Ok(result_reg)
    }

    /// Compile set comprehension {term | query}
    fn compile_set_comprehension(
        &mut self,
        term: &ExprRef,
        query: &crate::ast::Query,
        span: &Span,
    ) -> Result<Register> {
        // Similar to array comprehension but with SetComprehension mode
        let collection_reg = self.alloc_register();
        let literal_idx = self.add_literal(Value::Array(Arc::new(vec![
            Value::Number(1i64.into()),
            Value::Number(2i64.into()),
            Value::Number(3i64.into()),
        ])));
        self.emit_instruction(
            Instruction::Load {
                dest: collection_reg,
                literal_idx,
            },
            span,
        );

        let key_reg = self.alloc_register();
        let value_reg = self.alloc_register();
        let result_reg = self.alloc_register();

        let body_start = (self.instructions.len() + 1) as u16;
        let loop_start_idx = self.instructions.len();

        self.instructions.push(Instruction::LoopStart {
            mode: LoopMode::SetComprehension,
            collection: collection_reg,
            key_reg,
            value_reg,
            result_reg,
            body_start,
            loop_end: 0, // Will be updated below
        });

        self.store_variable("x".to_string(), value_reg);

        // Compile the query conditions first
        if !query.stmts.is_empty() {
            self.compile_query(query)?;
        }

        let term_reg = self.compile_rego_expr(term)?;

        self.instructions.push(Instruction::LoopAccumulate {
            value: term_reg,
            key: None,
        });

        let actual_loop_end = (self.instructions.len() + 1) as u16;
        self.instructions.push(Instruction::LoopNext {
            body_start,
            loop_end: actual_loop_end,
        });

        // Update the LoopStart instruction with the correct loop_end
        if let Some(Instruction::LoopStart { loop_end, .. }) =
            self.instructions.get_mut(loop_start_idx)
        {
            *loop_end = actual_loop_end;
        }

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
        // For object comprehension, use a hardcoded object to iterate over
        let collection_reg = self.alloc_register();
        let literal_idx = self.add_literal(Value::Object(Arc::new(BTreeMap::from([
            (Value::String("a".into()), Value::Number(1i64.into())),
            (Value::String("b".into()), Value::Number(2i64.into())),
            (Value::String("c".into()), Value::Number(3i64.into())),
        ]))));
        self.emit_instruction(
            Instruction::Load {
                dest: collection_reg,
                literal_idx,
            },
            span,
        );

        let key_reg = self.alloc_register(); // For object key
        let value_reg = self.alloc_register(); // For object value
        let result_reg = self.alloc_register();

        let body_start = (self.instructions.len() + 1) as u16;
        let loop_start_idx = self.instructions.len();

        self.instructions.push(Instruction::LoopStart {
            mode: LoopMode::ObjectComprehension,
            collection: collection_reg,
            key_reg,
            value_reg,
            result_reg,
            body_start,
            loop_end: 0, // Will be updated below
        });

        // Store loop variables in scope (hardcoded for now)
        self.store_variable("k".to_string(), key_reg); // key variable
        self.store_variable("v".to_string(), value_reg); // value variable

        // Compile the query conditions first
        if !query.stmts.is_empty() {
            self.compile_query(query)?;
        }

        // Compile the key and value expressions
        let key_result_reg = self.compile_rego_expr(key)?;
        let value_result_reg = self.compile_rego_expr(value)?;

        // Accumulate the key-value pair
        self.instructions.push(Instruction::LoopAccumulate {
            value: value_result_reg,
            key: Some(key_result_reg),
        });

        let actual_loop_end = (self.instructions.len() + 1) as u16;
        self.instructions.push(Instruction::LoopNext {
            body_start,
            loop_end: actual_loop_end,
        });

        // Update the LoopStart instruction with the correct loop_end
        if let Some(Instruction::LoopStart { loop_end, .. }) =
            self.instructions.get_mut(loop_start_idx)
        {
            *loop_end = actual_loop_end;
        }

        Ok(result_reg)
    }
}
