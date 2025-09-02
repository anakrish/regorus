use super::Instruction;
use crate::ast::{Expr, Module, Ref, Rule, RuleHead};
use crate::lexer::Span;
use crate::{CompiledPolicy, Value};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

pub type Register = u16;
pub type Result<T> = anyhow::Result<T>;
type Scope = BTreeMap<String, Register>;

/// Span information for debugging and source mapping
#[derive(Debug, Clone)]
pub struct SpanInfo {
    pub source_file_idx: u32,
    pub start: u32,
    pub end: u32,
    pub line: u32,
    pub col: u32,
}

impl From<&Span> for SpanInfo {
    fn from(span: &Span) -> Self {
        SpanInfo {
            source_file_idx: 0, // TODO: Extract from span.source
            start: span.start,
            end: span.end,
            line: span.line,
            col: span.col,
        }
    }
}

/// Result of compilation including instructions and their corresponding spans
#[derive(Debug)]
pub struct CompiledProgram {
    pub instructions: Vec<Instruction>,
    pub literals: Vec<Value>,
    pub spans: Vec<SpanInfo>,
}

pub struct Compiler<'a> {
    instructions: Vec<Instruction>,
    literals: Vec<Value>,
    spans: Vec<SpanInfo>,
    register_counter: Register,
    constants: HashMap<Value, Register>,
    scopes: Vec<Scope>, // Stack of variable scopes (like the interpreter)
    policy: Option<&'a CompiledPolicy>, // Reference to the compiled policy for rule lookup
    current_package: String, // Current package path (e.g., "data.test")
}

impl<'a> Compiler<'a> {
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            literals: Vec::new(),
            spans: Vec::new(),
            register_counter: 1, // Reserve register 0 for special uses
            constants: HashMap::new(),
            scopes: vec![Scope::new()], // Start with one global scope
            policy: None,
            current_package: String::new(),
        }
    }

    pub fn with_policy(policy: &'a CompiledPolicy, package: String) -> Self {
        Self {
            instructions: Vec::new(),
            literals: Vec::new(),
            spans: Vec::new(),
            register_counter: 1,
            constants: HashMap::new(),
            scopes: vec![Scope::new()],
            policy: Some(policy),
            current_package: package,
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
        self.scopes.push(Scope::new());
    }

    /// Pop the current variable scope (like the interpreter)
    pub fn pop_scope(&mut self) {
        if self.scopes.len() > 1 {
            self.scopes.pop();
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
                .insert(var_name.to_string(), register);
        }
    }

    /// Look up a variable in all scopes starting from innermost (like interpreter's lookup_local_var)
    pub fn lookup_local_var(&self, var_name: &str) -> Option<Register> {
        for scope in self.scopes.iter().rev() {
            if let Some(register) = scope.get(var_name) {
                return Some(*register);
            }
        }
        None
    }

    /// Store a variable mapping (backward compatibility)
    /// Look up a variable, first in local scope, then as a rule reference
    fn resolve_variable(&mut self, var_name: &str, span: &Span) -> Result<Register> {
        // First check local variables
        if let Some(var_reg) = self.lookup_variable(var_name) {
            return Ok(var_reg);
        }

        // If not found locally, check if it's a rule reference
        if let Some(policy) = self.policy {
            // Construct potential rule path: current_package.var_name
            let rule_path = format!("{}.{}", self.current_package, var_name);

            // Check if this rule exists in the policy
            let rules = policy.get_rules();
            if let Some(rule_variants) = rules.get(&rule_path) {
                if let Some(rule_ref) = rule_variants.first() {
                    // Recursively compile this rule to get its value
                    match self.compile_rule_reference(rule_ref, &rule_path)? {
                        Some(reg) => return Ok(reg),
                        None => {
                            // Rule exists but returned no value, load null
                            let dest = self.alloc_register();
                            let literal_idx = self.add_literal(Value::Null);
                            self.emit_instruction(Instruction::Load { dest, literal_idx }, span);
                            return Ok(dest);
                        }
                    }
                }
            }
        }

        // Variable not found anywhere, load null
        let dest = self.alloc_register();
        let literal_idx = self.add_literal(Value::Null);
        self.emit_instruction(Instruction::Load { dest, literal_idx }, span);
        Ok(dest)
    }

    /// Compile a rule reference and return the register containing its value
    fn compile_rule_reference(
        &mut self,
        rule: &crate::ast::Rule,
        _rule_path: &str,
    ) -> Result<Option<Register>> {
        match rule {
            crate::ast::Rule::Spec { head, bodies, .. } => {
                // For head-only rules (simple assignments like x = 42)
                if bodies.is_empty() {
                    match head {
                        crate::ast::RuleHead::Compr { assign, .. } => {
                            if let Some(assign) = assign {
                                // Compile the assignment value directly
                                let reg = self.compile_rego_expr(&assign.value)?;
                                return Ok(Some(reg));
                            }
                        }
                        _ => {
                            // Other head types not implemented yet
                            return Ok(None);
                        }
                    }
                }
                // Rules with bodies would need more complex handling
                // For now, return None
                Ok(None)
            }
            crate::ast::Rule::Default { value, .. } => {
                // Compile the default value
                let reg = self.compile_rego_expr(value)?;
                Ok(Some(reg))
            }
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
        self.spans.push(SpanInfo::from(span));
    }

    pub fn finish(mut self, result_reg: Register) -> CompiledProgram {
        // Add return instruction
        self.instructions
            .push(Instruction::Return { value: result_reg });
        self.spans.push(SpanInfo {
            source_file_idx: 0,
            start: 0,
            end: 0,
            line: 0,
            col: 0,
        });

        CompiledProgram {
            instructions: self.instructions,
            literals: self.literals,
            spans: self.spans,
        }
    }

    /// Compile a Rego expression to RVM instructions
    pub fn compile_rego_expr(&mut self, expr: &Expr) -> Result<Register> {
        self.compile_rego_expr_with_span(expr, &expr.span(), false)
    }

    /// Compile a Rego expression to RVM instructions with span tracking
    pub fn compile_rego_expr_with_span(
        &mut self,
        expr: &Expr,
        span: &Span,
        assert_condition: bool,
    ) -> Result<Register> {
        let result_reg = match expr {
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
                    let item_reg = self.compile_rego_expr_with_span(item, &item.span(), false)?;

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
                    let item_reg = self.compile_rego_expr_with_span(item, &item.span(), false)?;

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
                        self.compile_rego_expr_with_span(key_expr, &key_expr.span(), false)?;
                    let value_reg =
                        self.compile_rego_expr_with_span(value_expr, &value_expr.span(), false)?;

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
                let lhs_reg = self.compile_rego_expr_with_span(lhs, &lhs.span(), false)?;
                let rhs_reg = self.compile_rego_expr_with_span(rhs, &rhs.span(), false)?;
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
                let lhs_reg = self.compile_rego_expr_with_span(lhs, &lhs.span(), false)?;
                let rhs_reg = self.compile_rego_expr_with_span(rhs, &rhs.span(), false)?;
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
                    _ => {
                        // For other operations, return true for now
                        let literal_idx = self.add_literal(Value::Bool(true));
                        self.emit_instruction(Instruction::Load { dest, literal_idx }, span);
                    }
                }
                dest
            }
            Expr::AssignExpr { lhs, rhs, .. } => {
                // Handle variable assignment like x := 10
                // First compile the right-hand side value (don't assert - this is assignment)
                let rhs_reg = self.compile_rego_expr_with_span(rhs, &rhs.span(), false)?;

                // Then bind the variable if lhs is a variable
                if let Expr::Var { value, .. } = lhs.as_ref() {
                    if let Value::String(var_name) = value {
                        // Store the variable binding
                        self.add_variable(var_name.as_ref(), rhs_reg);
                    }
                }

                // Return the register containing the assigned value
                return Ok(rhs_reg); // Note: assignments don't get asserted
            }
            Expr::Var { value, .. } => {
                // Check if this is a variable reference that we should resolve
                if let Value::String(var_name) = value {
                    return self.resolve_variable(var_name.as_ref(), span);
                }

                // Otherwise, load as literal value
                let dest = self.alloc_register();
                let literal_idx = self.add_literal(value.clone());
                self.emit_instruction(Instruction::Load { dest, literal_idx }, span);
                dest
            }
            Expr::RefDot { refr, field, .. } => {
                // Compile the object reference (don't assert)
                let obj_reg = self.compile_rego_expr_with_span(refr, &refr.span(), false)?;

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
                let obj_reg = self.compile_rego_expr_with_span(refr, &refr.span(), false)?;

                // Compile the index expression (don't assert)
                let key_reg = self.compile_rego_expr_with_span(index, &index.span(), false)?;

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
                let value_reg = self.compile_rego_expr_with_span(value, &value.span(), false)?;

                // Compile the collection (don't assert)
                let collection_reg =
                    self.compile_rego_expr_with_span(collection, &collection.span(), false)?;

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

    /// Compile from a CompiledPolicy to RVM instructions
    pub fn compile_from_policy(
        policy: &CompiledPolicy,
        rule_name: &str,
    ) -> Result<CompiledProgram> {
        // Extract package name from rule_name (e.g., "data.test.main" -> "data.test")
        let package = if let Some(last_dot) = rule_name.rfind('.') {
            rule_name[..last_dot].to_string()
        } else {
            "data".to_string()
        };

        let mut compiler = Compiler::with_policy(policy, package);

        // Access the compiled policy rules
        let rules = policy.get_rules();

        // Debug: Print available rules
        std::println!("Debug: Available rules in policy:");
        for (key, rule_list) in rules.iter() {
            std::println!("  Rule key: '{}' ({} variants)", key, rule_list.len());
        }
        std::println!("Debug: Looking for rule: '{}'", rule_name);

        // Find the specified rule in the compiled policy
        if let Some(rule_list) = rules.get(rule_name) {
            if let Some(rule) = rule_list.first() {
                std::println!("Debug: Found rule, analyzing structure...");
                let mut last_result_reg = 0;

                // Compile based on rule type
                match rule.as_ref() {
                    Rule::Spec { head, bodies, .. } => {
                        std::println!("Debug: Rule is a Spec with {} bodies", bodies.len());

                        // Compile rule bodies first
                        for (i, body) in bodies.iter().enumerate() {
                            std::println!("Debug: Processing body {}", i);

                            // If there's an assignment in the body, compile it
                            if let Some(assign) = &body.assign {
                                std::println!("Debug: Found assignment in body");
                                last_result_reg = compiler.compile_rego_expr(&assign.value)?;
                            }

                            // Compile expressions in the query
                            for (j, stmt) in body.query.stmts.iter().enumerate() {
                                std::println!("Debug: Processing statement {} in body {}", j, i);
                                match &stmt.literal {
                                    crate::ast::Literal::Expr { expr, .. } => {
                                        std::println!("Debug: Found expression literal");
                                        // This is a bare expression/condition - assert it's truthy
                                        let _condition_reg = compiler
                                            .compile_rego_expr_with_span(expr, &stmt.span, true)?;
                                    }
                                    crate::ast::Literal::SomeVars { .. }
                                    | crate::ast::Literal::SomeIn { .. }
                                    | crate::ast::Literal::Every { .. }
                                    | crate::ast::Literal::NotExpr { .. } => {
                                        std::println!("Debug: Found complex literal (skipped)");
                                        // For complex literals, we'd need more sophisticated handling
                                        // For now, skip these
                                    }
                                }
                            }
                        }

                        // Compile head based on its type
                        std::println!("Debug: Processing rule head");
                        match head {
                            RuleHead::Compr { refr, assign, .. } => {
                                std::println!("Debug: Rule head is Compr");
                                // For comprehensions, compile the reference
                                last_result_reg = compiler.compile_rego_expr(refr)?;

                                // If there's an assignment, compile the value
                                if let Some(assign) = assign {
                                    std::println!("Debug: Compr has assignment");
                                    std::println!("Debug: Assignment value: {:?}", assign.value);
                                    last_result_reg = compiler.compile_rego_expr(&assign.value)?;
                                }
                            }
                            RuleHead::Set { refr, key, .. } => {
                                std::println!("Debug: Rule head is Set");
                                // For set rules, compile the key if present, otherwise the reference
                                if let Some(key_expr) = key {
                                    last_result_reg = compiler.compile_rego_expr(key_expr)?;
                                } else {
                                    last_result_reg = compiler.compile_rego_expr(refr)?;
                                }
                            }
                            RuleHead::Func { refr, assign, .. } => {
                                std::println!("Debug: Rule head is Func");
                                // For function rules, compile the reference
                                last_result_reg = compiler.compile_rego_expr(refr)?;

                                // If there's an assignment, compile the value
                                if let Some(assign) = assign {
                                    std::println!("Debug: Func has assignment");
                                    last_result_reg = compiler.compile_rego_expr(&assign.value)?;
                                }
                            }
                        }
                    }
                    Rule::Default { value, .. } => {
                        // For default rules, compile the default value
                        last_result_reg = compiler.compile_rego_expr(value)?;
                    }
                }

                // If no expressions found, return null
                if last_result_reg == 0 {
                    let null_reg = compiler.alloc_register();
                    let literal_idx = compiler.add_literal(Value::Null);
                    compiler.instructions.push(Instruction::Load {
                        dest: null_reg,
                        literal_idx,
                    });
                    last_result_reg = null_reg;
                }

                return Ok(compiler.finish(last_result_reg));
            }
        }

        // If rule not found, return empty program that returns null
        let null_reg = compiler.alloc_register();
        let literal_idx = compiler.add_literal(Value::Null);
        compiler.instructions.push(Instruction::Load {
            dest: null_reg,
            literal_idx,
        });
        Ok(compiler.finish(null_reg))
    }

    /// Compile all rules from a CompiledPolicy
    pub fn compile_all_rules_from_policy(
        policy: &CompiledPolicy,
    ) -> Result<Vec<(String, CompiledProgram)>> {
        let mut compiled_rules = Vec::new();
        let rules = policy.get_rules();

        for (rule_name, _rule_list) in rules.iter() {
            let program = Self::compile_from_policy(policy, rule_name)?;
            compiled_rules.push((rule_name.clone(), program));
        }

        Ok(compiled_rules)
    }

    /// Compile a specific rule from modules directly
    pub fn compile_rule_from_modules(
        modules: &[Ref<Module>],
        rule_path: &str,
    ) -> Result<CompiledProgram> {
        let mut compiler = Compiler::new();

        // Parse the rule path (e.g., "data.package.rule_name")
        let parts: Vec<&str> = rule_path.split('.').collect();
        if parts.len() < 3 {
            return Ok(compiler.finish(0)); // Invalid path
        }

        let package_path = &parts[1..parts.len() - 1].join(".");
        let rule_name = parts[parts.len() - 1];

        // Find the module with matching package
        for module in modules {
            let module_package = &module.package.refr;

            // Check if this module matches the package we're looking for
            if let Expr::Var { value, .. } = module_package.as_ref() {
                if let Value::String(pkg_name) = value {
                    if pkg_name.as_ref() == package_path {
                        // Found the right module, now find the rule
                        for rule in &module.policy {
                            // Extract rule name from the rule reference
                            let rule_matches = match rule.as_ref() {
                                Rule::Spec { head, .. } => {
                                    // For Spec rules, check the head reference
                                    match head {
                                        RuleHead::Compr { refr, .. }
                                        | RuleHead::Set { refr, .. }
                                        | RuleHead::Func { refr, .. } => {
                                            if let Expr::Var { value, .. } = refr.as_ref() {
                                                if let Value::String(name) = value {
                                                    name.as_ref() == rule_name
                                                } else {
                                                    false
                                                }
                                            } else {
                                                false
                                            }
                                        }
                                    }
                                }
                                Rule::Default { refr, .. } => {
                                    if let Expr::Var { value, .. } = refr.as_ref() {
                                        if let Value::String(name) = value {
                                            name.as_ref() == rule_name
                                        } else {
                                            false
                                        }
                                    } else {
                                        false
                                    }
                                }
                            };

                            if rule_matches {
                                // Found the rule, compile it
                                let mut last_result_reg = 0;

                                // Compile based on rule type
                                match rule.as_ref() {
                                    Rule::Spec { head, bodies, .. } => {
                                        // Compile rule bodies
                                        for body in bodies {
                                            // If there's an assignment in the body, compile it
                                            if let Some(assign) = &body.assign {
                                                last_result_reg =
                                                    compiler.compile_rego_expr(&assign.value)?;
                                            }

                                            // Compile expressions in the query
                                            for stmt in &body.query.stmts {
                                                match &stmt.literal {
                                                    crate::ast::Literal::Expr { expr, .. } => {
                                                        let _condition_reg = compiler
                                                            .compile_rego_expr_with_span(
                                                                expr, &stmt.span, true,
                                                            )?;
                                                    }
                                                    _ => {
                                                        // Skip other literal types for now
                                                    }
                                                }
                                            }
                                        }

                                        // Compile head expressions
                                        match head {
                                            RuleHead::Compr { refr, assign, .. } => {
                                                last_result_reg =
                                                    compiler.compile_rego_expr(refr)?;
                                                if let Some(assign) = assign {
                                                    last_result_reg = compiler
                                                        .compile_rego_expr(&assign.value)?;
                                                }
                                            }
                                            RuleHead::Set { refr, key, .. } => {
                                                if let Some(key_expr) = key {
                                                    last_result_reg =
                                                        compiler.compile_rego_expr(key_expr)?;
                                                } else {
                                                    last_result_reg =
                                                        compiler.compile_rego_expr(refr)?;
                                                }
                                            }
                                            RuleHead::Func { refr, assign, .. } => {
                                                last_result_reg =
                                                    compiler.compile_rego_expr(refr)?;
                                                if let Some(assign) = assign {
                                                    last_result_reg = compiler
                                                        .compile_rego_expr(&assign.value)?;
                                                }
                                            }
                                        }
                                    }
                                    Rule::Default { value, .. } => {
                                        last_result_reg = compiler.compile_rego_expr(value)?;
                                    }
                                }

                                if last_result_reg == 0 {
                                    let null_reg = compiler.alloc_register();
                                    let literal_idx = compiler.add_literal(Value::Null);
                                    compiler.instructions.push(Instruction::Load {
                                        dest: null_reg,
                                        literal_idx,
                                    });
                                    last_result_reg = null_reg;
                                }

                                return Ok(compiler.finish(last_result_reg));
                            }
                        }
                    }
                }
            }
        }

        // Rule not found
        let null_reg = compiler.alloc_register();
        let literal_idx = compiler.add_literal(Value::Null);
        compiler.instructions.push(Instruction::Load {
            dest: null_reg,
            literal_idx,
        });
        Ok(compiler.finish(null_reg))
    }
}
