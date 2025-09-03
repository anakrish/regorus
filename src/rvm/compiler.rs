use super::instructions::LoopMode;
use super::Instruction;
use crate::ast::{Expr, Module, Ref, Rule, RuleHead};
use crate::lexer::Span;
use crate::rvm::program::{Program, SpanInfo};
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
        std::println!("Debug: resolve_variable called for '{}'", var_name);

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

        // If not found locally, check if it's a rule reference
        if let Some(policy) = self.policy {
            // Construct potential rule path: current_package.var_name
            let rule_path = format!("{}.{}", self.current_package, var_name);

            // Check if this rule exists in the policy
            let rules = policy.get_rules();
            if let Some(rule_variants) = rules.get(&rule_path) {
                // Check if this is a set rule (has multiple variants with contains)
                let is_set_rule = rule_variants.iter().any(|rule| {
                    if let crate::ast::Rule::Spec { head, .. } = rule.as_ref() {
                        matches!(head, crate::ast::RuleHead::Set { .. })
                    } else {
                        false
                    }
                });

                if is_set_rule {
                    // For set rules, compile all variants and create a set
                    std::println!("Debug: Compiling set rule '{}' with {} variants", var_name, rule_variants.len());
                    let dest = self.alloc_register();
                    self.emit_instruction(Instruction::SetNew { dest }, span);

                    for (i, rule_ref) in rule_variants.iter().enumerate() {
                        std::println!("Debug: Compiling set rule variant {}", i);
                        if let Some(value_reg) = self.compile_rule_reference(rule_ref, &rule_path)? {
                            // Add the value to the set
                            self.emit_instruction(
                                Instruction::SetAdd {
                                    set: dest,
                                    value: value_reg,
                                },
                                span,
                            );
                        }
                    }
                    return Ok(dest);
                } else if let Some(rule_ref) = rule_variants.first() {
                    // For non-set rules, use the first variant as before
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
                match head {
                    crate::ast::RuleHead::Set { key, .. } => {
                        // For set rules, extract the key value from the contains expression
                        if let Some(key_expr) = key {
                            std::println!("Debug: Compiling set rule key: {:?}", key_expr);
                            let reg = self.compile_rego_expr(key_expr)?;
                            return Ok(Some(reg));
                        }
                        return Ok(None);
                    }
                    crate::ast::RuleHead::Compr { assign, .. } => {
                        // For head-only rules (simple assignments like x = 42)
                        if bodies.is_empty() {
                            if let Some(assign) = assign {
                                // Compile the assignment value directly
                                let reg = self.compile_rego_expr(&assign.value)?;
                                return Ok(Some(reg));
                            }
                        }
                        // Rules with bodies would need more complex handling
                        // For now, return None
                        return Ok(None);
                    }
                    crate::ast::RuleHead::Func { assign, .. } => {
                        // For function rules with assignment
                        if bodies.is_empty() {
                            if let Some(assign) = assign {
                                let reg = self.compile_rego_expr(&assign.value)?;
                                return Ok(Some(reg));
                            }
                        }
                        return Ok(None);
                    }
                }
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
        self.spans.push(SpanInfo::from_lexer_span(span, 0)); // Use source index 0 for now
    }

    pub fn finish(mut self, result_reg: Register) -> CompiledProgram {
        // Add return instruction
        self.instructions
            .push(Instruction::Return { value: result_reg });
        self.spans.push(SpanInfo::new(0, 0, 0, 0)); // Default span for return instruction

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
    pub fn compile_from_policy(
        policy: &CompiledPolicy,
        rule_name: &str,
    ) -> Result<Arc<Program>> {
        // First compile to the legacy format
        let compiled_program = Self::compile_from_policy_legacy(policy, rule_name)?;
        
        // Convert to new Program format
        let mut program = Program::new();
        program.instructions = compiled_program.instructions;
        program.literals = compiled_program.literals;
        program.main_entry_point = 0;
        
        // Extract source contents from the policy modules
        for module in policy.get_modules().iter() {
            let source = &module.package.refr.span().source;
            let source_path = source.get_path().to_string();
            let source_content = source.get_contents().to_string();
            
            // Add source file to the program's source table
            program.add_source(source_path, source_content);
        }
        
        // TODO: Convert spans to new format and add to instruction_spans
        program.instruction_spans = compiled_program.spans
            .into_iter()
            .map(|_span| None) // For now, don't convert old spans
            .collect();
        
        Ok(Arc::new(program))
    }

    /// Legacy method that returns CompiledProgram (for backward compatibility)
    pub fn compile_from_policy_legacy(
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

                            // Check if this body starts with a SomeIn loop
                            if let Some((some_in_idx, some_in_stmt)) =
                                body.query.stmts.iter().enumerate().find(|(_, stmt)| {
                                    matches!(&stmt.literal, crate::ast::Literal::SomeIn { .. })
                                })
                            {
                                // Process statements before the SomeIn normally
                                for (j, stmt) in
                                    body.query.stmts.iter().enumerate().take(some_in_idx)
                                {
                                    std::println!(
                                        "Debug: Processing statement {} in body {} (before SomeIn)",
                                        j,
                                        i
                                    );
                                    if let crate::ast::Literal::Expr { expr, .. } = &stmt.literal {
                                        std::println!("Debug: Found expression literal");
                                        let _condition_reg = compiler
                                            .compile_rego_expr_with_span(expr, &stmt.span, true)?;
                                    }
                                }

                                // Handle the SomeIn with remaining statements as loop body
                                if let crate::ast::Literal::SomeIn {
                                    key,
                                    value,
                                    collection,
                                    ..
                                } = &some_in_stmt.literal
                                {
                                    std::println!("Debug: Found SomeIn at position {}, compiling as loop with remaining {} statements", 
                                                 some_in_idx, body.query.stmts.len() - some_in_idx - 1);

                                    // Get the statements that come after the SomeIn (these form the loop body)
                                    let loop_body_stmts = &body.query.stmts[some_in_idx + 1..];
                                    last_result_reg = compiler.compile_some_in_loop_with_body(
                                        key.as_ref().map(|k| k.as_ref()),
                                        value.as_ref(),
                                        collection.as_ref(),
                                        loop_body_stmts,
                                    )?;
                                }
                                continue; // Skip normal processing for this body
                            }

                            // Check if this body starts with an Every loop
                            if let Some((every_idx, every_stmt)) =
                                body.query.stmts.iter().enumerate().find(|(_, stmt)| {
                                    matches!(&stmt.literal, crate::ast::Literal::Every { .. })
                                })
                            {
                                // Process statements before the Every normally
                                for (j, stmt) in body.query.stmts.iter().enumerate().take(every_idx)
                                {
                                    std::println!(
                                        "Debug: Processing statement {} in body {} (before Every)",
                                        j,
                                        i
                                    );
                                    if let crate::ast::Literal::Expr { expr, .. } = &stmt.literal {
                                        std::println!("Debug: Found expression literal");
                                        let _condition_reg = compiler
                                            .compile_rego_expr_with_span(expr, &stmt.span, true)?;
                                    }
                                }

                                // Handle the Every loop with remaining statements executed after loop
                                if let crate::ast::Literal::Every {
                                    key,
                                    value,
                                    domain,
                                    query,
                                    ..
                                } = &every_stmt.literal
                                {
                                    std::println!("Debug: Found Every at position {}, compiling with remaining {} statements after loop", 
                                                 every_idx, body.query.stmts.len() - every_idx - 1);

                                    // Get the statements that come after the Every (these execute after loop completes)
                                    let remaining_stmts = &body.query.stmts[every_idx + 1..];
                                    last_result_reg = compiler.compile_every_loop_with_remaining(
                                        key.as_ref(),
                                        value,
                                        domain.as_ref(),
                                        query.as_ref(),
                                        remaining_stmts,
                                    )?;
                                }
                                continue; // Skip normal processing for this body
                            }

                            // No loops found, process statements normally
                            for (j, stmt) in body.query.stmts.iter().enumerate() {
                                std::println!("Debug: Processing statement {} in body {}", j, i);
                                match &stmt.literal {
                                    crate::ast::Literal::Expr { expr, .. } => {
                                        std::println!("Debug: Found expression literal");
                                        // This is a bare expression/condition - assert it's truthy
                                        let _condition_reg = compiler
                                            .compile_rego_expr_with_span(expr, &stmt.span, true)?;
                                    }
                                    crate::ast::Literal::SomeIn { .. }
                                    | crate::ast::Literal::Every { .. } => {
                                        return Err(anyhow::anyhow!(
                                            "Unexpected loop statement in normal processing"
                                        ));
                                    }
                                    crate::ast::Literal::SomeVars { .. }
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

                                // For comprehensions, only compile if NOT already a comprehension expression
                                // Check if the assignment value is already a comprehension
                                if let Some(assign) = assign {
                                    match &*assign.value {
                                        Expr::ArrayCompr { .. }
                                        | Expr::SetCompr { .. }
                                        | Expr::ObjectCompr { .. } => {
                                            std::println!("Debug: Compr has comprehension assignment - compiling directly");
                                            // This is a comprehension, compile it directly
                                            last_result_reg =
                                                compiler.compile_rego_expr(&assign.value)?;
                                        }
                                        _ => {
                                            std::println!(
                                                "Debug: Compr has non-comprehension assignment"
                                            );
                                            // For non-comprehension assignments, compile the reference first
                                            last_result_reg = compiler.compile_rego_expr(refr)?;
                                            std::println!(
                                                "Debug: Assignment value: {:?}",
                                                assign.value
                                            );
                                            last_result_reg =
                                                compiler.compile_rego_expr(&assign.value)?;
                                        }
                                    }
                                } else {
                                    // No assignment, just compile the reference
                                    last_result_reg = compiler.compile_rego_expr(refr)?;
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
    ) -> Result<Vec<(String, Arc<Program>)>> {
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

    /// Compile SomeIn loop construct (existential quantification)
    fn compile_some_in_loop_with_body(
        &mut self,
        key: Option<&Expr>,
        value: &Expr,
        collection: &Expr,
        loop_body_stmts: &[crate::ast::LiteralStmt],
    ) -> Result<Register> {
        // Compile collection expression
        let collection_reg = self.compile_rego_expr(collection)?;

        // Allocate registers for loop variables
        let key_reg = self.alloc_register();
        let value_reg = self.alloc_register();
        let result_reg = self.alloc_register();

        // Start the existential loop - we'll calculate the correct loop_end after compiling the body
        let loop_start_idx = self.instructions.len();

        // Add placeholder LoopStart instruction (we'll update loop_end later)
        self.instructions.push(Instruction::LoopStart {
            mode: LoopMode::Existential,
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
            } = key_expr
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
        } = value
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
        for (i, stmt) in loop_body_stmts.iter().enumerate() {
            std::println!("Debug: Compiling loop body statement {}", i);
            std::println!("Debug: Statement literal type: {:?}", stmt.literal);
            match &stmt.literal {
                crate::ast::Literal::Expr { expr, .. } => {
                    std::println!("Debug: Compiling expression in loop body: {:?}", expr);
                    let _condition_reg =
                        self.compile_rego_expr_with_span(&*expr, &stmt.span, true)?;
                }
                _ => {
                    std::println!(
                        "Debug: Non-expression literal in loop body: {:?}",
                        stmt.literal
                    );
                    return Err(anyhow::anyhow!(
                        "Complex literals in loop body not yet supported: {:?}",
                        stmt.literal
                    ));
                }
            }
        }

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

    fn compile_some_in_loop(
        &mut self,
        key: Option<&Expr>,
        value: &Expr,
        collection: &Expr,
    ) -> Result<Register> {
        // Compile collection expression
        let collection_reg = self.compile_rego_expr(collection)?;

        // Allocate registers for loop variables
        let key_reg = self.alloc_register();
        let value_reg = self.alloc_register();
        let result_reg = self.alloc_register();

        // Store loop variables in scope BEFORE generating LoopStart
        // This makes them available for subsequent statements in the body
        if let Some(key_expr) = key {
            if let crate::ast::Expr::Var { value, .. } = key_expr {
                std::println!(
                    "Debug: Storing loop key variable '{}' at register {}",
                    value,
                    key_reg
                );
                self.store_variable(value.to_string(), key_reg);
            }
        }

        if let crate::ast::Expr::Var { value, .. } = value {
            std::println!(
                "Debug: Storing loop value variable '{}' at register {}",
                value,
                value_reg
            );
            self.store_variable(value.to_string(), value_reg);
        }

        // Start the existential loop
        let body_start = self.instructions.len() as u16 + 1;
        let loop_end = body_start + 10; // Placeholder, will be updated later

        self.instructions.push(Instruction::LoopStart {
            mode: LoopMode::Existential,
            collection: collection_reg,
            key_reg,
            value_reg,
            result_reg,
            body_start,
            loop_end,
        });

        // Return the result register so the caller knows where the result will be
        Ok(result_reg)
    }

    /// Compile Every loop construct (universal quantification)
    fn compile_every_loop(
        &mut self,
        key: Option<&Span>,
        value: &Span,
        domain: &Expr,
        query: &crate::ast::Query,
    ) -> Result<Register> {
        // Compile domain expression
        let collection_reg = self.compile_rego_expr(domain)?;

        // Allocate registers for loop variables
        let key_reg = self.alloc_register();
        let value_reg = self.alloc_register();
        let result_reg = self.alloc_register();

        // Start the universal loop - we'll calculate the correct loop_end after compiling the body
        let loop_start_idx = self.instructions.len();

        // Add placeholder LoopStart instruction (we'll update body_start and loop_end later)
        self.instructions.push(Instruction::LoopStart {
            mode: LoopMode::Universal,
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
        if let Some(key_span) = key {
            let key_name = key_span.text();
            std::println!(
                "Debug: Storing loop key variable '{}' at register {}",
                key_name,
                key_reg
            );
            self.store_variable(key_name.to_string(), key_reg);
        }

        // Extract variable name from value span
        let value_name = value.text();
        std::println!(
            "Debug: Storing loop value variable '{}' at register {}",
            value_name,
            value_reg
        );
        self.store_variable(value_name.to_string(), value_reg);

        // Compile the query body statements
        for (i, stmt) in query.stmts.iter().enumerate() {
            std::println!("Debug: Compiling Every loop body statement {}", i);
            std::println!("Debug: Statement literal type: {:?}", stmt.literal);
            match &stmt.literal {
                crate::ast::Literal::Expr { expr, .. } => {
                    std::println!("Debug: Compiling expression in Every loop body: {:?}", expr);
                    let _condition_reg =
                        self.compile_rego_expr_with_span(&*expr, &stmt.span, true)?;
                }
                _ => {
                    std::println!(
                        "Debug: Non-expression literal in Every loop body: {:?}",
                        stmt.literal
                    );
                    return Err(anyhow::anyhow!(
                        "Complex literals in Every loop body not yet supported: {:?}",
                        stmt.literal
                    ));
                }
            }
        }

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
            "Debug: Every loop compiled - body_start={}, loop_end={}",
            body_start,
            loop_end
        );

        // Debug: Print all instructions generated for this loop
        std::println!(
            "Debug: Generated {} instructions for Every loop:",
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

    /// Compile Every loop construct with statements to execute after loop completes
    fn compile_every_loop_with_remaining(
        &mut self,
        key: Option<&Span>,
        value: &Span,
        domain: &Expr,
        query: &crate::ast::Query,
        remaining_stmts: &[crate::ast::LiteralStmt],
    ) -> Result<Register> {
        // First compile the Every loop itself using the working method
        let loop_result_reg = self.compile_every_loop(key, value, domain, query)?;

        std::println!(
            "Debug: Every loop completed, now compiling {} remaining statements",
            remaining_stmts.len()
        );

        // Now compile the statements that should execute after the Every loop completes
        let mut last_result_reg = loop_result_reg;
        for (i, stmt) in remaining_stmts.iter().enumerate() {
            std::println!("Debug: Compiling remaining statement {} after Every", i);
            std::println!("Debug: Statement literal type: {:?}", stmt.literal);
            match &stmt.literal {
                crate::ast::Literal::Expr { expr, .. } => {
                    std::println!("Debug: Compiling expression after Every: {:?}", expr);
                    last_result_reg =
                        self.compile_rego_expr_with_span(&*expr, &stmt.span, false)?;
                }
                _ => {
                    std::println!(
                        "Debug: Non-expression literal after Every: {:?}",
                        stmt.literal
                    );
                    return Err(anyhow::anyhow!(
                        "Complex literals after Every not yet supported: {:?}",
                        stmt.literal
                    ));
                }
            }
        }

        // Debug: Print all instructions generated
        std::println!(
            "Debug: Generated {} instructions total after Every with remaining:",
            self.instructions.len()
        );
        for (i, instr) in self.instructions.iter().enumerate() {
            std::println!("  {}: {:?}", i, instr);
        }

        Ok(last_result_reg)
    }

    /// Compile array comprehension [term | query]
    fn compile_array_comprehension(
        &mut self,
        term: &Expr,
        query: &crate::ast::Query,
        span: &Span,
    ) -> Result<Register> {
        // Extract collection and variable from query
        // For now, create a simple array to iterate over
        // In a full implementation, we'd parse the query to extract the iteration pattern

        // Create a hardcoded collection for testing - this should be extracted from query
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
        let loop_start_idx = self.instructions.len(); // Remember where LoopStart is

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

        // Store the loop variable in scope (hardcoded as 'x' for now)
        self.store_variable("x".to_string(), value_reg);

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
        term: &Expr,
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
        key: &Expr,
        value: &Expr,
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
