// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Symbolic translator: walks RVM bytecode and builds Z3 constraints.
//!
//! This is the core engine. It maintains a symbolic register file that mirrors
//! the concrete VM's register array, translating each instruction into Z3
//! expressions and/or path-condition constraints.

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use std::collections::HashMap;

use z3::ast::{Ast, Bool as Z3Bool, Int as Z3Int, Real as Z3Real, String as Z3String};

use crate::rvm::instructions::{Instruction, LiteralOrRegister};
use crate::rvm::program::{Program, RuleType};
use crate::value::Value;

use super::path_registry::PathRegistry;
use super::types::{Definedness, SymRegister, SymSetElement, SymValue, ValueSort};
use super::AnalysisConfig;

/// Result of translating a block (sequence of instructions until termination).
#[allow(dead_code)]
pub struct BlockResult<'ctx> {
    /// The path condition at the end of the block (conjunction of all assertions).
    pub path_condition: Z3Bool<'ctx>,
    /// The value of the result register at the end (if applicable).
    pub result: SymValue<'ctx>,
    /// Whether the block terminated normally (vs. assertion failure).
    pub succeeded: bool,
}

/// The symbolic translator engine.
#[allow(missing_debug_implementations)]
pub struct Translator<'ctx, 'a> {
    ctx: &'ctx z3::Context,
    program: &'a Program,
    data: &'a Value,
    registry: &'a mut PathRegistry<'ctx>,
    config: &'a AnalysisConfig,

    /// Symbolic register file.
    registers: Vec<SymRegister<'ctx>>,

    /// Path condition: conjunction of all branch decisions taken.
    pub path_condition: Z3Bool<'ctx>,

    /// All emitted constraints.
    pub constraints: Vec<Z3Bool<'ctx>>,

    /// Current program counter.
    pc: usize,

    /// Path condition at each PC (for coverage targeting).
    pc_path_conditions: HashMap<usize, Z3Bool<'ctx>>,

    /// Accumulated caller path conditions (AND of outer path conditions
    /// at each `translate_call_rule` boundary). Used to contextualise
    /// the inner `pc_path_conditions` so that line-coverage constraints
    /// reflect the full call-chain reachability.
    caller_path_condition: Z3Bool<'ctx>,

    /// Warnings about unmodeled features.
    pub warnings: Vec<String>,

    /// Rule call cache: rule_index → (result_value, result_defined, path_condition).
    rule_cache: HashMap<u16, (SymValue<'ctx>, Definedness<'ctx>)>,

    /// Current rule inlining depth (for recursion detection).
    rule_depth: usize,

    /// Counter for generating fresh variable names.
    #[allow(dead_code)]
    fresh_counter: u32,

    // -- Partial-set element tracking --

    /// True while translating the body of a PartialSet rule.
    is_in_partial_set_body: bool,

    /// Register index of the outermost loop's value_reg during
    /// partial-set body translation.  Set once at the first LoopStart
    /// inside the body and used at SetAdd to identify the element path.
    partial_set_main_value_reg: Option<u8>,

    /// Accumulated set element witnesses for the current partial-set rule.
    partial_set_elements: Vec<SymSetElement<'ctx>>,
}

impl<'ctx, 'a> Translator<'ctx, 'a> {
    /// Create a new translator.
    pub fn new(
        ctx: &'ctx z3::Context,
        program: &'a Program,
        data: &'a Value,
        registry: &'a mut PathRegistry<'ctx>,
        config: &'a AnalysisConfig,
    ) -> Self {
        let num_regs = program.dispatch_window_size.max(program.max_rule_window_size);
        let registers = (0..num_regs)
            .map(|_| SymRegister::undefined())
            .collect::<Vec<_>>();

        Self {
            ctx,
            program,
            data,
            registry,
            config,
            registers,
            path_condition: Z3Bool::from_bool(ctx, true),
            constraints: Vec::new(),
            pc: 0,
            pc_path_conditions: HashMap::new(),
            caller_path_condition: Z3Bool::from_bool(ctx, true),
            warnings: Vec::new(),
            rule_cache: HashMap::new(),
            rule_depth: 0,
            fresh_counter: 0,
            is_in_partial_set_body: false,
            partial_set_main_value_reg: None,
            partial_set_elements: Vec::new(),
        }
    }

    /// Take the accumulated PC → path-condition map (consumes it).
    pub fn take_pc_path_conditions(&mut self) -> HashMap<usize, Z3Bool<'ctx>> {
        core::mem::take(&mut self.pc_path_conditions)
    }

    /// Translate starting from an entry point PC.
    /// Returns the symbolic result (value of register 0 at Halt).
    pub fn translate_entry_point(
        &mut self,
        entry_pc: usize,
    ) -> anyhow::Result<SymValue<'ctx>> {
        self.translate_block(entry_pc)
    }

    /// Translate a block of instructions starting at `start_pc`.
    /// Returns the result value when the block terminates (Halt/Return/RuleReturn).
    fn translate_block(&mut self, start_pc: usize) -> anyhow::Result<SymValue<'ctx>> {
        self.pc = start_pc;

        while self.pc < self.program.instructions.len() {
            let instruction = self.program.instructions[self.pc];
            let current_pc = self.pc;

            match self.translate_instruction(instruction)? {
                InstructionAction::Continue => {
                    // Record path condition AFTER the instruction executes so
                    // that AssertCondition effects are captured. This means
                    // "covering line L" requires that the assertion on L held.
                    let full_pc_cond = Z3Bool::and(
                        self.ctx,
                        &[&self.caller_path_condition, &self.path_condition],
                    );
                    self.pc_path_conditions.insert(current_pc, full_pc_cond);
                    self.pc += 1;
                }
                InstructionAction::Return(value) => {
                    return Ok(value);
                }
                InstructionAction::Jump(target) => {
                    self.pc = target;
                }
            }
        }

        // Fell off the end — return register 0.
        Ok(self.get_register(0).value.clone())
    }

    // -----------------------------------------------------------------------
    // Per-instruction translation
    // -----------------------------------------------------------------------

    fn translate_instruction(
        &mut self,
        instruction: Instruction,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        use Instruction::*;

        match instruction {
            // -- Loads --
            Load { dest, literal_idx } => {
                let value = self.program.literals[literal_idx as usize].clone();
                self.set_register_concrete(dest, value);
                Ok(InstructionAction::Continue)
            }
            LoadTrue { dest } => {
                self.set_register_concrete(dest, Value::Bool(true));
                Ok(InstructionAction::Continue)
            }
            LoadFalse { dest } => {
                self.set_register_concrete(dest, Value::Bool(false));
                Ok(InstructionAction::Continue)
            }
            LoadNull { dest } => {
                self.set_register_concrete(dest, Value::Null);
                Ok(InstructionAction::Continue)
            }
            LoadBool { dest, value } => {
                self.set_register_concrete(dest, Value::Bool(value));
                Ok(InstructionAction::Continue)
            }
            LoadData { dest } => {
                self.set_register_concrete(dest, self.data.clone());
                Ok(InstructionAction::Continue)
            }
            LoadInput { dest } => {
                // Input is symbolic — mark register as the symbolic input root.
                self.set_register_sym(
                    dest,
                    SymValue::Concrete(Value::new_object()),
                    Definedness::Defined,
                    Some("input".to_string()),
                );
                Ok(InstructionAction::Continue)
            }
            Move { dest, src } => {
                let reg = self.get_register(src).clone();
                self.registers[dest as usize] = reg;
                Ok(InstructionAction::Continue)
            }

            // -- Arithmetic --
            Add { dest, left, right } => {
                self.translate_arithmetic(dest, left, right, ArithOp::Add)
            }
            Sub { dest, left, right } => {
                self.translate_arithmetic(dest, left, right, ArithOp::Sub)
            }
            Mul { dest, left, right } => {
                self.translate_arithmetic(dest, left, right, ArithOp::Mul)
            }
            Div { dest, left, right } => {
                self.translate_arithmetic(dest, left, right, ArithOp::Div)
            }
            Mod { dest, left, right } => {
                self.translate_arithmetic(dest, left, right, ArithOp::Mod)
            }

            // -- Comparisons --
            Eq { dest, left, right } => self.translate_comparison(dest, left, right, CmpOp::Eq),
            Ne { dest, left, right } => self.translate_comparison(dest, left, right, CmpOp::Ne),
            Lt { dest, left, right } => self.translate_comparison(dest, left, right, CmpOp::Lt),
            Le { dest, left, right } => self.translate_comparison(dest, left, right, CmpOp::Le),
            Gt { dest, left, right } => self.translate_comparison(dest, left, right, CmpOp::Gt),
            Ge { dest, left, right } => self.translate_comparison(dest, left, right, CmpOp::Ge),

            // -- Logical --
            And { dest, left, right } => self.translate_logical_and(dest, left, right),
            Or { dest, left, right } => self.translate_logical_or(dest, left, right),
            Not { dest, operand } => self.translate_logical_not(dest, operand),

            // -- Assertions (control flow) --
            AssertCondition { condition } => self.translate_assert_condition(condition),
            AssertNotUndefined { register } => self.translate_assert_not_undefined(register),

            // -- Indexing --
            Index { dest, container, key } => self.translate_index(dest, container, key),
            IndexLiteral {
                dest,
                container,
                literal_idx,
            } => self.translate_index_literal(dest, container, literal_idx),
            ChainedIndex { params_index } => self.translate_chained_index(params_index),

            // -- Rule calls --
            CallRule { dest, rule_index } => self.translate_call_rule(dest, rule_index),
            RuleInit {
                result_reg,
                rule_index,
            } => self.translate_rule_init(result_reg, rule_index),
            RuleReturn {} => {
                // Return register 0 from the current rule body.
                let result = self.get_register(0).value.clone();
                Ok(InstructionAction::Return(result))
            }
            DestructuringSuccess {} => {
                // Destructuring passed — continue normally.
                let result = self.get_register(0).value.clone();
                Ok(InstructionAction::Return(result))
            }
            Return { value } => {
                let reg = self.get_register(value).clone();
                // Incorporate the register's definedness into the path condition.
                // This is critical when a Complete rule's body has conditions
                // (e.g., count(violation) == 2) that are captured as
                // symbolic definedness on the result register.  Without this,
                // the entry-point Return would return a concrete value like
                // `true` while silently dropping the body constraint.
                let def_cond = reg.defined.to_z3_bool(self.ctx);
                self.path_condition =
                    Z3Bool::and(self.ctx, &[&self.path_condition, &def_cond]);
                Ok(InstructionAction::Return(reg.value))
            }
            Halt {} => {
                let result = self.get_register(0).value.clone();
                Ok(InstructionAction::Return(result))
            }

            // -- Collections (Phase 2 stubs) --
            ArrayNew { dest } => {
                self.set_register_concrete(dest, Value::new_array());
                Ok(InstructionAction::Continue)
            }
            SetNew { dest } => {
                self.set_register_concrete(dest, Value::new_set());
                Ok(InstructionAction::Continue)
            }
            ObjectCreate { params_index } => {
                self.translate_object_create(params_index)
            }
            ArrayCreate { params_index } => {
                self.translate_array_create(params_index)
            }
            SetCreate { params_index } => {
                self.translate_set_create(params_index)
            }
            ObjectSet { obj: _, key: _, value: _ } => {
                // Stub: treat as opaque mutation.
                self.warnings.push(format!(
                    "PC {}: ObjectSet modeled as no-op (incomplete)",
                    self.pc
                ));
                Ok(InstructionAction::Continue)
            }
            ArrayPush { arr: _, value: _ } => {
                self.warnings.push(format!(
                    "PC {}: ArrayPush modeled as no-op (incomplete)",
                    self.pc
                ));
                Ok(InstructionAction::Continue)
            }
            SetAdd { set: _, value } => {
                if self.is_in_partial_set_body {
                    // Determine the key_path from the actual SetAdd value
                    // register (e.g., r12 = server.id) and the element_path
                    // from the outermost loop's value_reg (e.g., server).
                    let key_path = self.registers[value as usize].source_path.clone();

                    // The element condition must include the definedness of
                    // the value register.  E.g. `violation contains server.id`
                    // should only succeed when server.id is actually defined.
                    let val_defined = self.registers[value as usize].defined.to_z3_bool(self.ctx);
                    let cond = Z3Bool::and(self.ctx, &[&self.path_condition, &val_defined]);



                    let iter_info: Option<(String, ValueSort)> =
                        if let Some(vreg) = self.partial_set_main_value_reg {
                            let reg = &self.registers[vreg as usize];
                            reg.source_path.as_ref().map(|p| (p.clone(), reg.value.sort()))
                        } else {
                            None
                        };

                    if let Some((elem_path, elem_sort)) = iter_info {
                        self.partial_set_elements.push(SymSetElement {
                            condition: cond.clone(),
                            element_path: elem_path.clone(),
                            key_path: key_path.unwrap_or(elem_path),
                            element_sort: elem_sort,
                        });
                    } else if let Some(kp) = key_path {
                        // No outermost loop info — use the key path as both.
                        let val_reg = &self.registers[value as usize];
                        self.partial_set_elements.push(SymSetElement {
                            condition: cond.clone(),
                            element_path: kp.clone(),
                            key_path: kp,
                            element_sort: val_reg.value.sort(),
                        });
                    } else {
                        self.warnings.push(format!(
                            "PC {}: SetAdd in partial set body but no source path on value r{} or outermost loop",
                            self.pc, value
                        ));
                    }
                } else {
                    self.warnings.push(format!(
                        "PC {}: SetAdd modeled as no-op (incomplete)",
                        self.pc
                    ));
                }
                Ok(InstructionAction::Continue)
            }
            Contains {
                dest,
                collection,
                value,
            } => {
                self.translate_contains(dest, collection, value)
            }
            Count { dest, collection } => {
                self.translate_count(dest, collection)
            }

            // -- Loops (Phase 3 stubs) --
            LoopStart { params_index } => {
                self.translate_loop_start(params_index)
            }
            LoopNext { body_start: _, loop_end: _ } => {
                // In our symbolic model, loops are unrolled at LoopStart.
                // LoopNext is handled as part of the unrolling.
                Ok(InstructionAction::Continue)
            }

            // -- Builtins --
            BuiltinCall { params_index } => self.translate_builtin_call(params_index),

            // -- Function calls --
            FunctionCall { params_index } => self.translate_function_call(params_index),

            // -- Virtual data document --
            VirtualDataDocumentLookup { params_index } => {
                self.translate_virtual_data_lookup(params_index)
            }

            // -- Comprehensions (Phase 3 stubs) --
            ComprehensionBegin { params_index } => {
                self.warnings.push(format!(
                    "PC {}: ComprehensionBegin not yet modeled",
                    self.pc
                ));
                // Skip to comprehension end
                let params = self
                    .program
                    .instruction_data
                    .get_comprehension_begin_params(params_index)
                    .ok_or_else(|| {
                        anyhow::anyhow!("Invalid comprehension params index {}", params_index)
                    })?;
                let end_pc = params.comprehension_end as usize;
                Ok(InstructionAction::Jump(end_pc))
            }
            ComprehensionYield { .. } => Ok(InstructionAction::Continue),
            ComprehensionEnd {} => Ok(InstructionAction::Continue),

            // -- Host await (external I/O) --
            HostAwait { dest, .. } => {
                self.warnings.push(format!(
                    "PC {}: HostAwait modeled as unconstrained symbolic value",
                    self.pc
                ));
                let name = format!("host_await_{}", self.pc);
                let var = Z3String::new_const(self.ctx, name.as_str());
                self.set_register_sym(dest, SymValue::Str(var), Definedness::Defined, None);
                Ok(InstructionAction::Continue)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Arithmetic
    // -----------------------------------------------------------------------

    fn translate_arithmetic(
        &mut self,
        dest: u8,
        left: u8,
        right: u8,
        op: ArithOp,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        // Sort promotion: promote path placeholders to Int for arithmetic.
        self.promote_path_register_to_sort(left, ValueSort::Int);
        self.promote_path_register_to_sort(right, ValueSort::Int);

        let a = self.get_register(left).clone();
        let b = self.get_register(right).clone();

        // Undefined propagation: if either is undefined, result is undefined.
        if a.defined.is_undefined() || b.defined.is_undefined() {
            self.set_register_sym(dest, SymValue::Concrete(Value::Undefined), Definedness::Undefined, None);
            return Ok(InstructionAction::Continue);
        }

        // Both concrete → concrete arithmetic.
        if let (SymValue::Concrete(va), SymValue::Concrete(vb)) = (&a.value, &b.value) {
            if let (Ok(na), Ok(nb)) = (va.as_number(), vb.as_number()) {
                let result = match op {
                    ArithOp::Add => na.add(nb),
                    ArithOp::Sub => na.sub(nb),
                    ArithOp::Mul => na.mul(nb),
                    ArithOp::Div => na.clone().divide(nb),
                    ArithOp::Mod => na.clone().modulo(nb),
                };
                if let Ok(r) = result {
                    self.set_register_concrete(dest, Value::Number(r));
                } else {
                    self.set_register_sym(dest, SymValue::Concrete(Value::Undefined), Definedness::Undefined, None);
                }
                return Ok(InstructionAction::Continue);
            }
        }

        // At least one side is symbolic — promote both to Z3 Int.
        let za = a.value.to_z3_int(self.ctx)?;
        let zb = b.value.to_z3_int(self.ctx)?;

        let result = match op {
            ArithOp::Add => za + zb,
            ArithOp::Sub => za - zb,
            ArithOp::Mul => za * zb,
            ArithOp::Div => {
                // Guard against division by zero.
                let zero = Z3Int::from_i64(self.ctx, 0);
                self.constraints.push(zb._eq(&zero).not());
                za / zb
            }
            ArithOp::Mod => {
                let zero = Z3Int::from_i64(self.ctx, 0);
                self.constraints.push(zb._eq(&zero).not());
                za.rem(&zb)
            }
        };

        let defined = Definedness::and(self.ctx, &a.defined, &b.defined);
        self.set_register_sym(dest, SymValue::Int(result), defined, None);
        Ok(InstructionAction::Continue)
    }

    // -----------------------------------------------------------------------
    // Comparisons
    // -----------------------------------------------------------------------

    fn translate_comparison(
        &mut self,
        dest: u8,
        left: u8,
        right: u8,
        op: CmpOp,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        // Sort promotion: if one register is a path placeholder and the other
        // has a known sort, promote the path register to that sort.
        self.promote_path_registers(left, right);

        let a = self.get_register(left).clone();
        let b = self.get_register(right).clone();

        // Undefined propagation.
        if a.defined.is_undefined() || b.defined.is_undefined() {
            self.set_register_sym(dest, SymValue::Concrete(Value::Undefined), Definedness::Undefined, None);
            return Ok(InstructionAction::Continue);
        }

        // Both concrete → concrete comparison.
        if let (SymValue::Concrete(va), SymValue::Concrete(vb)) = (&a.value, &b.value) {
            let result = match op {
                CmpOp::Eq => va == vb,
                CmpOp::Ne => va != vb,
                CmpOp::Lt => va < vb,
                CmpOp::Le => va <= vb,
                CmpOp::Gt => va > vb,
                CmpOp::Ge => va >= vb,
            };
            self.set_register_concrete(dest, Value::Bool(result));
            return Ok(InstructionAction::Continue);
        }

        // Determine the sort to compare in based on what we have.
        let result_bool = self.make_comparison(&a.value, &b.value, op)?;
        let defined = Definedness::and(self.ctx, &a.defined, &b.defined);
        self.set_register_sym(dest, SymValue::Bool(result_bool), defined, None);
        Ok(InstructionAction::Continue)
    }

    /// Create a Z3 comparison expression between two SymValues.
    fn make_comparison(
        &mut self,
        a: &SymValue<'ctx>,
        b: &SymValue<'ctx>,
        op: CmpOp,
    ) -> anyhow::Result<Z3Bool<'ctx>> {
        // Determine the common sort.
        let sort = match (a.sort(), b.sort()) {
            (s, ValueSort::Unknown) | (ValueSort::Unknown, s) => s,
            (a_sort, b_sort) if a_sort == b_sort => a_sort,
            // Int and Real can be compared (promote Int to Real).
            (ValueSort::Int, ValueSort::Real) | (ValueSort::Real, ValueSort::Int) => {
                ValueSort::Real
            }
            (a_sort, b_sort) => {
                anyhow::bail!("Cannot compare {:?} with {:?}", a_sort, b_sort);
            }
        };

        match sort {
            ValueSort::Bool => {
                let za = a.to_z3_bool(self.ctx)?;
                let zb = b.to_z3_bool(self.ctx)?;
                match op {
                    CmpOp::Eq => Ok(za._eq(&zb)),
                    CmpOp::Ne => Ok(za._eq(&zb).not()),
                    _ => anyhow::bail!("Ordering comparison on booleans not supported"),
                }
            }
            ValueSort::Int => {
                let za = a.to_z3_int(self.ctx)?;
                let zb = b.to_z3_int(self.ctx)?;
                Ok(match op {
                    CmpOp::Eq => za._eq(&zb),
                    CmpOp::Ne => za._eq(&zb).not(),
                    CmpOp::Lt => za.lt(&zb),
                    CmpOp::Le => za.le(&zb),
                    CmpOp::Gt => za.gt(&zb),
                    CmpOp::Ge => za.ge(&zb),
                })
            }
            ValueSort::Real => {
                let za = a.to_z3_real(self.ctx)?;
                let zb = b.to_z3_real(self.ctx)?;
                Ok(match op {
                    CmpOp::Eq => za._eq(&zb),
                    CmpOp::Ne => za._eq(&zb).not(),
                    CmpOp::Lt => za.lt(&zb),
                    CmpOp::Le => za.le(&zb),
                    CmpOp::Gt => za.gt(&zb),
                    CmpOp::Ge => za.ge(&zb),
                })
            }
            ValueSort::String => {
                let za = a.to_z3_string(self.ctx)?;
                let zb = b.to_z3_string(self.ctx)?;
                match op {
                    CmpOp::Eq => Ok(za._eq(&zb)),
                    CmpOp::Ne => Ok(za._eq(&zb).not()),
                    _ => {
                        // Z3 string ordering via str.< is possible, but complex.
                        // For now, use uninterpreted comparison.
                        self.warnings.push(format!(
                            "PC {}: String ordering comparison approximated",
                            self.pc
                        ));
                        let name = format!("str_cmp_{}_{}", self.pc, op as u8);
                        Ok(Z3Bool::new_const(self.ctx, name.as_str()))
                    }
                }
            }
            ValueSort::Unknown => {
                // Both unknown: default to string comparison.
                let za = a.to_z3_string(self.ctx)?;
                let zb = b.to_z3_string(self.ctx)?;
                match op {
                    CmpOp::Eq => Ok(za._eq(&zb)),
                    CmpOp::Ne => Ok(za._eq(&zb).not()),
                    _ => anyhow::bail!("Cannot order-compare unknown-sorted values"),
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Logical operations
    // -----------------------------------------------------------------------

    fn translate_logical_and(
        &mut self,
        dest: u8,
        left: u8,
        right: u8,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        let a = self.get_register(left).clone();
        let b = self.get_register(right).clone();

        if a.defined.is_undefined() || b.defined.is_undefined() {
            self.set_register_sym(dest, SymValue::Concrete(Value::Undefined), Definedness::Undefined, None);
            return Ok(InstructionAction::Continue);
        }

        let za = a.value.to_z3_bool(self.ctx)?;
        let zb = b.value.to_z3_bool(self.ctx)?;
        let result = Z3Bool::and(self.ctx, &[&za, &zb]);
        let defined = Definedness::and(self.ctx, &a.defined, &b.defined);
        self.set_register_sym(dest, SymValue::Bool(result), defined, None);
        Ok(InstructionAction::Continue)
    }

    fn translate_logical_or(
        &mut self,
        dest: u8,
        left: u8,
        right: u8,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        let a = self.get_register(left).clone();
        let b = self.get_register(right).clone();

        if a.defined.is_undefined() || b.defined.is_undefined() {
            self.set_register_sym(dest, SymValue::Concrete(Value::Undefined), Definedness::Undefined, None);
            return Ok(InstructionAction::Continue);
        }

        let za = a.value.to_z3_bool(self.ctx)?;
        let zb = b.value.to_z3_bool(self.ctx)?;
        let result = Z3Bool::or(self.ctx, &[&za, &zb]);
        let defined = Definedness::and(self.ctx, &a.defined, &b.defined);
        self.set_register_sym(dest, SymValue::Bool(result), defined, None);
        Ok(InstructionAction::Continue)
    }

    fn translate_logical_not(
        &mut self,
        dest: u8,
        operand: u8,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        // Promote path registers to Bool sort (e.g., `not input.suspended`).
        self.promote_path_register_to_sort(operand, ValueSort::Bool);

        let a = self.get_register(operand).clone();

        // Rego special: `not undefined` → true.
        if a.defined.is_undefined() {
            self.set_register_concrete(dest, Value::Bool(true));
            return Ok(InstructionAction::Continue);
        }

        match &a.defined {
            Definedness::Symbolic(def_bool) => {
                // If operand might be undefined: not(undefined) → true, not(defined_val) → !val
                // For path registers with Bool sort: result = NOT(defined AND value)
                match &a.value {
                    SymValue::Bool(val) => {
                        let result = Z3Bool::and(self.ctx, &[def_bool, val]).not();
                        self.set_register_sym(dest, SymValue::Bool(result), Definedness::Defined, None);
                    }
                    SymValue::Concrete(Value::Undefined) => {
                        // Path placeholder that wasn't promoted (shouldn't happen after promotion above).
                        // `not undefined` → true.
                        self.set_register_concrete(dest, Value::Bool(true));
                    }
                    _ => {
                        let val = a.value.to_z3_bool(self.ctx)?;
                        let result = def_bool.ite(&val.not(), &Z3Bool::from_bool(self.ctx, true));
                        self.set_register_sym(dest, SymValue::Bool(result), Definedness::Defined, None);
                    }
                }
            }
            Definedness::Defined => {
                let val = a.value.to_z3_bool(self.ctx)?;
                self.set_register_sym(dest, SymValue::Bool(val.not()), Definedness::Defined, None);
            }
            Definedness::Undefined => unreachable!(), // handled above
        }
        Ok(InstructionAction::Continue)
    }

    // -----------------------------------------------------------------------
    // Assertions (control flow)
    // -----------------------------------------------------------------------

    fn translate_assert_condition(
        &mut self,
        condition: u8,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        let reg = self.get_register(condition).clone();

        // Path registers have SymValue::Concrete(Value::Undefined) as a
        // placeholder but are actually symbolic.  When used as a boolean
        // condition (e.g., `input.networks[j].public`), promote to a
        // symbolic Bool and gate by definedness.
        if reg.source_path.is_some() {
            self.ensure_register_sort(condition, ValueSort::Bool)?;
            let reg = self.get_register(condition).clone();
            let bool_val = reg.value.to_z3_bool(self.ctx)?;
            let def = reg.defined.to_z3_bool(self.ctx);
            let cond_z3 = Z3Bool::and(self.ctx, &[&def, &bool_val]);
            self.path_condition = Z3Bool::and(self.ctx, &[&self.path_condition, &cond_z3]);
            return Ok(InstructionAction::Continue);
        }

        let cond_z3 = match &reg.value {
            SymValue::Concrete(Value::Bool(b)) => {
                // Gate concrete bool by definedness: a rule returning
                // Concrete(true) with Symbolic definedness must still
                // propagate the definedness constraint.
                let val = Z3Bool::from_bool(self.ctx, *b);
                match &reg.defined {
                    Definedness::Defined => val,
                    Definedness::Undefined => Z3Bool::from_bool(self.ctx, false),
                    Definedness::Symbolic(def) => {
                        if *b {
                            // assert(true) when symbolically defined → just require defined
                            def.clone()
                        } else {
                            // assert(false) → always fails
                            Z3Bool::from_bool(self.ctx, false)
                        }
                    }
                }
            }
            SymValue::Concrete(Value::Undefined) => Z3Bool::from_bool(self.ctx, false),
            SymValue::Concrete(_) => {
                // Non-bool concrete values are truthy in Rego.
                reg.defined.to_z3_bool(self.ctx)
            }
            SymValue::Bool(b) => {
                // Gate by definedness: defined AND value.
                match &reg.defined {
                    Definedness::Defined => b.clone(),
                    Definedness::Undefined => Z3Bool::from_bool(self.ctx, false),
                    Definedness::Symbolic(def) => Z3Bool::and(self.ctx, &[def, b]),
                }
            }
            _ => {
                // Non-bool symbolic values: treat as truthy if defined.
                reg.defined.to_z3_bool(self.ctx)
            }
        };

        // Conjoin to path condition.
        self.path_condition = Z3Bool::and(self.ctx, &[&self.path_condition, &cond_z3]);
        Ok(InstructionAction::Continue)
    }

    fn translate_assert_not_undefined(
        &mut self,
        register: u8,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        let reg = self.get_register(register).clone();
        let def_z3 = reg.defined.to_z3_bool(self.ctx);
        self.path_condition = Z3Bool::and(self.ctx, &[&self.path_condition, &def_z3]);
        Ok(InstructionAction::Continue)
    }

    // -----------------------------------------------------------------------
    // Indexing
    // -----------------------------------------------------------------------

    fn translate_index(
        &mut self,
        dest: u8,
        container: u8,
        key: u8,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        let container_reg = self.get_register(container).clone();
        let key_reg = self.get_register(key).clone();

        // If container has a source path and key is concrete, create a path variable.
        if let (Some(path), SymValue::Concrete(key_val)) =
            (&container_reg.source_path, &key_reg.value)
        {
            let key_str = value_to_path_segment(key_val);
            let new_path = format!("{}.{}", path, key_str);
            return self.create_path_register(dest, &new_path, ValueSort::Unknown);
        }

        // Concrete container + concrete key → concrete indexing.
        if let (SymValue::Concrete(container_val), SymValue::Concrete(key_val)) =
            (&container_reg.value, &key_reg.value)
        {
            let result = container_val[key_val].clone();
            self.set_register_concrete(dest, result);
            return Ok(InstructionAction::Continue);
        }

        // Dynamic index into symbolic container — limited precision.
        self.warnings.push(format!(
            "PC {}: Dynamic index into symbolic container — limited precision",
            self.pc
        ));
        let name = format!("dyn_idx_{}", self.pc);
        let var = Z3String::new_const(self.ctx, name.as_str());
        self.set_register_sym(dest, SymValue::Str(var), Definedness::Defined, None);
        Ok(InstructionAction::Continue)
    }

    fn translate_index_literal(
        &mut self,
        dest: u8,
        container: u8,
        literal_idx: u16,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        let key_val = self.program.literals[literal_idx as usize].clone();
        let container_reg = self.get_register(container).clone();

        // If container traces to input/data path → create path variable.
        if let Some(path) = &container_reg.source_path {
            let key_str = value_to_path_segment(&key_val);
            let new_path = format!("{}.{}", path, key_str);
            return self.create_path_register(dest, &new_path, ValueSort::Unknown);
        }

        // Concrete container → concrete index.
        if let SymValue::Concrete(container_val) = &container_reg.value {
            let result = container_val[&key_val].clone();
            self.set_register_concrete(dest, result);
            return Ok(InstructionAction::Continue);
        }

        // Symbolic container with literal key — still limited.
        self.warnings.push(format!(
            "PC {}: IndexLiteral on symbolic non-path container",
            self.pc
        ));
        let name = format!("idx_lit_{}_{}", self.pc, literal_idx);
        let var = Z3String::new_const(self.ctx, name.as_str());
        self.set_register_sym(dest, SymValue::Str(var), Definedness::Defined, None);
        Ok(InstructionAction::Continue)
    }

    fn translate_chained_index(
        &mut self,
        params_index: u16,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        let params = self
            .program
            .instruction_data
            .get_chained_index_params(params_index)
            .ok_or_else(|| {
                anyhow::anyhow!("Invalid chained index params index {}", params_index)
            })?
            .clone();

        let root_reg = self.get_register(params.root).clone();

        // Build the path by walking components.
        let mut current_path = root_reg.source_path.clone();

        for component in &params.path_components {
            match component {
                LiteralOrRegister::Literal(idx) => {
                    let key = &self.program.literals[*idx as usize];
                    let segment = value_to_path_segment(key);
                    if let Some(ref mut path) = current_path {
                        *path = format!("{}.{}", path, segment);
                    }
                }
                LiteralOrRegister::Register(reg) => {
                    let reg_val = self.get_register(*reg);
                    // If register has a source_path, graft it into the chain.
                    if let Some(ref reg_path) = reg_val.source_path {
                        // Replace the current path with the register's path
                        // (e.g., root="input", component=Register(val_reg)
                        //  where val_reg.source_path="input.users[0]" →
                        //  current_path becomes "input.users[0]").
                        current_path = Some(reg_path.clone());
                    } else if let SymValue::Concrete(v) = &reg_val.value {
                        // Concrete register value → use as path segment.
                        // Common case: loop key register with concrete index.
                        let segment = value_to_path_segment(v);
                        if let Some(ref mut path) = current_path {
                            *path = format!("{}[{}]", path, segment);
                        }
                    } else {
                        current_path = None; // Truly dynamic — breaks path.
                    }
                }
            }
        }

        // Static path → path variable.
        if let Some(path) = current_path {
            return self.create_path_register(params.dest, &path, ValueSort::Unknown);
        }

        // Mixed/dynamic path → concrete evaluation if possible.
        if let SymValue::Concrete(mut current_val) = root_reg.value.clone() {
            for component in &params.path_components {
                let key = match component {
                    LiteralOrRegister::Literal(idx) => {
                        self.program.literals[*idx as usize].clone()
                    }
                    LiteralOrRegister::Register(reg) => {
                        if let SymValue::Concrete(v) = &self.get_register(*reg).value {
                            v.clone()
                        } else {
                            // Can't resolve dynamically — give up.
                            self.warnings.push(format!(
                                "PC {}: ChainedIndex with symbolic register component",
                                self.pc
                            ));
                            let name = format!("chain_idx_{}", self.pc);
                            let var = Z3String::new_const(self.ctx, name.as_str());
                            self.set_register_sym(
                                params.dest,
                                SymValue::Str(var),
                                Definedness::Defined,
                                None,
                            );
                            return Ok(InstructionAction::Continue);
                        }
                    }
                };
                current_val = current_val[&key].clone();
            }
            self.set_register_concrete(params.dest, current_val);
            return Ok(InstructionAction::Continue);
        }

        // Fully symbolic — opaque.
        self.warnings.push(format!(
            "PC {}: ChainedIndex on fully symbolic container",
            self.pc
        ));
        let name = format!("chain_idx_{}", self.pc);
        let var = Z3String::new_const(self.ctx, name.as_str());
        self.set_register_sym(params.dest, SymValue::Str(var), Definedness::Defined, None);
        Ok(InstructionAction::Continue)
    }

    // -----------------------------------------------------------------------
    // Rule calls
    // -----------------------------------------------------------------------

    fn translate_call_rule(
        &mut self,
        dest: u8,
        rule_index: u16,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        // Check rule cache first.
        if let Some((cached_val, cached_def)) = self.rule_cache.get(&rule_index).cloned() {
            self.set_register_sym(dest, cached_val, cached_def, None);
            return Ok(InstructionAction::Continue);
        }

        // Recursion depth check.
        if self.rule_depth >= self.config.max_rule_depth {
            self.warnings.push(format!(
                "PC {}: Max rule depth ({}) reached for rule {}; returning Undefined",
                self.pc, self.config.max_rule_depth, rule_index
            ));
            self.set_register_sym(
                dest,
                SymValue::Concrete(Value::Undefined),
                Definedness::Undefined,
                None,
            );
            return Ok(InstructionAction::Continue);
        }

        let rule_idx = rule_index as usize;
        let rule_info = self
            .program
            .rule_infos
            .get(rule_idx)
            .ok_or_else(|| anyhow::anyhow!("Rule index {} out of bounds", rule_index))?
            .clone();

        let is_function = rule_info.function_info.is_some();

        // Save current state.
        let saved_pc = self.pc;
        let saved_path_cond = self.path_condition.clone();
        let saved_registers: Vec<SymRegister<'ctx>> = self.registers.clone();
        let saved_caller_path_cond = self.caller_path_condition.clone();
        let saved_is_in_partial_set_body = self.is_in_partial_set_body;
        let saved_partial_set_main_value_reg = self.partial_set_main_value_reg;
        let saved_partial_set_elements = core::mem::take(&mut self.partial_set_elements);

        // Push the current (outer) path condition into caller_path_condition
        // so that inner pc_path_conditions reflect the full call chain.
        self.caller_path_condition = Z3Bool::and(
            self.ctx,
            &[&self.caller_path_condition, &self.path_condition],
        );

        self.rule_depth += 1;

        // Set up register window for the rule.
        let num_regs = rule_info.num_registers as usize;
        self.registers.resize_with(num_regs.max(self.registers.len()), SymRegister::undefined);
        // Clear rule registers (keep any existing ones for arguments).
        for i in 0..num_regs {
            self.registers[i] = SymRegister::undefined();
        }

        // Translate each definition's body.
        let mut body_results: Vec<(Z3Bool<'ctx>, SymValue<'ctx>)> = Vec::new();
        let is_partial_set = rule_info.rule_type == RuleType::PartialSet;

        // Set up partial set element tracking.
        if is_partial_set {
            self.is_in_partial_set_body = true;
            self.partial_set_main_value_reg = None;
            self.partial_set_elements.clear();
        }

        for (def_idx, bodies) in rule_info.definitions.iter().enumerate() {
            for body_pc in bodies.iter() {
                // Reset path condition for this body.
                self.path_condition = Z3Bool::from_bool(self.ctx, true);

                // Re-initialize registers for this body attempt.
                for i in 0..num_regs {
                    self.registers[i] = SymRegister::undefined();
                }

                // Reset the outermost-loop tracking for each body so that
                // body 1's loops don't inherit body 0's register index.
                if is_partial_set {
                    self.partial_set_main_value_reg = None;
                }

                // Translate destructuring block if present.
                let destr_ok = if let Some(Some(destr_pc)) =
                    rule_info.destructuring_blocks.get(def_idx)
                {
                    let _destr_result = self.translate_block(*destr_pc as usize);
                    // If destructuring failed (path condition is unsat), skip this body.
                    // For simplicity, we don't check satisfiability here; we just record
                    // the path condition.
                    true
                } else {
                    true
                };

                if !destr_ok {
                    continue;
                }

                // Translate the body.
                let _body_result = self.translate_block(*body_pc as usize)?;

                // The result is in the result register.
                let result_value = self.get_register(rule_info.result_reg).clone();
                let body_path_cond = self.path_condition.clone();

                // For partial set rules, the body's success is determined solely
                // by the path condition — if all assertions passed, this body
                // contributes an element to the set. The result_reg stays
                // Undefined because SetAdd is a no-op in symbolic mode.
                //
                // For complete rules, we also need the result to be defined.
                let body_succeeded = if is_partial_set {
                    body_path_cond.clone()
                } else {
                    let result_defined = result_value.defined.to_z3_bool(self.ctx);
                    Z3Bool::and(self.ctx, &[&body_path_cond, &result_defined])
                };

                body_results.push((body_succeeded, result_value.value.clone()));

                // For partial set rules, ALL bodies in ALL definitions execute
                // (they accumulate into the set). For complete rules, the first
                // successful body in a definition wins.
                if !is_partial_set {
                    break;
                }
            }
        }

        self.rule_depth -= 1;

        // Collect partial set elements before restoring state.
        let collected_partial_set_elements = if is_partial_set {
            core::mem::take(&mut self.partial_set_elements)
        } else {
            Vec::new()
        };

        // Restore state.
        self.registers = saved_registers;
        self.pc = saved_pc;
        self.path_condition = saved_path_cond;
        self.caller_path_condition = saved_caller_path_cond;
        self.is_in_partial_set_body = saved_is_in_partial_set_body;
        self.partial_set_main_value_reg = saved_partial_set_main_value_reg;
        self.partial_set_elements = saved_partial_set_elements;

        // -------------------------------------------------------------------
        // Partial set rules: build a SymbolicSet with cardinality + elements.
        //
        // Rego sets contain **distinct** values.  Multiple loop iterations
        // that produce the same set key (e.g., the same `server.id`) should
        // count as 1, not N.  We therefore GROUP elements by their
        // `element_path` (which determines the key value) and count the
        // number of groups where at least one element's condition is true.
        //
        // When no per-element information is available (no SetAdd calls were
        // observed), we fall back to the old body-level counting.
        // -------------------------------------------------------------------
        if is_partial_set {
            let cardinality = if !collected_partial_set_elements.is_empty() {
                // Group elements by their key path (key_path).
                // Elements with the same key produce the same set value,
                // so they should contribute at most 1 to the cardinality.
                let mut groups: HashMap<&str, Vec<&Z3Bool<'ctx>>> = HashMap::new();
                for elem in &collected_partial_set_elements {
                    groups
                        .entry(&elem.key_path)
                        .or_default()
                        .push(&elem.condition);
                }

                let zero = Z3Int::from_i64(self.ctx, 0);
                let one = Z3Int::from_i64(self.ctx, 1);
                let mut sum = Z3Int::from_i64(self.ctx, 0);
                let mut group_info: Vec<(&str, Z3Bool<'ctx>)> = Vec::new();
                for (key, conds) in &groups {
                    // This group contributes 1 if ANY element in it succeeded.
                    let any_succeeded = if conds.len() == 1 {
                        (*conds[0]).clone()
                    } else {
                        Z3Bool::or(self.ctx, conds)
                    };
                    let contrib = any_succeeded.ite(&one, &zero);
                    sum = Z3Int::add(self.ctx, &[&sum, &contrib]);
                    group_info.push((key, any_succeeded));
                }

                // Enforce pairwise value distinctness: if two key_path groups
                // both contribute to the set, their Z3 values must differ.
                // This ensures the set semantics (no duplicate values).
                // Only applies when the key_path sort is a known scalar type;
                // for objects/arrays (Unknown sort) we cannot compare values.
                for i in 0..group_info.len() {
                    for j in (i + 1)..group_info.len() {
                        let (path_i, ref cond_i) = group_info[i];
                        let (path_j, ref cond_j) = group_info[j];
                        let sort_i = self.registry.get_sort(path_i);
                        let sort_j = self.registry.get_sort(path_j);
                        // Only enforce distinctness for matching scalar sorts.
                        let both_active = Z3Bool::and(self.ctx, &[cond_i, cond_j]);
                        match (sort_i, sort_j) {
                            (Some(ValueSort::String), Some(ValueSort::String)) => {
                                let v_i = self.registry.get_string(path_i);
                                let v_j = self.registry.get_string(path_j);
                                self.constraints.push(both_active.implies(&v_i._eq(&v_j).not()));
                            }
                            (Some(ValueSort::Int), Some(ValueSort::Int)) => {
                                let v_i = self.registry.get_int(path_i);
                                let v_j = self.registry.get_int(path_j);
                                self.constraints.push(both_active.implies(&v_i._eq(&v_j).not()));
                            }
                            (Some(ValueSort::Bool), Some(ValueSort::Bool)) => {
                                let v_i = self.registry.get_bool(path_i);
                                let v_j = self.registry.get_bool(path_j);
                                self.constraints.push(both_active.implies(&v_i._eq(&v_j).not()));
                            }
                            (Some(ValueSort::Real), Some(ValueSort::Real)) => {
                                let v_i = self.registry.get_real(path_i);
                                let v_j = self.registry.get_real(path_j);
                                self.constraints.push(both_active.implies(&v_i._eq(&v_j).not()));
                            }
                            _ => {
                                // Unknown or mixed sorts — skip distinctness.
                            }
                        }
                    }
                }

                self.warnings.push(format!(
                    "PC {}: Set cardinality: {} elements grouped into {} distinct key(s)",
                    self.pc,
                    collected_partial_set_elements.len(),
                    groups.len()
                ));
                sum
            } else if body_results.is_empty() {
                Z3Int::from_i64(self.ctx, 0)
            } else {
                // Fallback: body-level cardinality.
                let zero = Z3Int::from_i64(self.ctx, 0);
                let one = Z3Int::from_i64(self.ctx, 1);
                let mut sum = Z3Int::from_i64(self.ctx, 0);
                for (cond, _val) in &body_results {
                    let contrib = cond.ite(&one, &zero);
                    sum = Z3Int::add(self.ctx, &[&sum, &contrib]);
                }
                sum
            };

            // Cardinality is always >= 0 (and always defined for partial sets).
            self.constraints.push(cardinality.ge(&Z3Int::from_i64(self.ctx, 0)));

            let result_value = if collected_partial_set_elements.is_empty() {
                self.warnings.push(format!(
                    "PC {}: Partial set rule {} → {} body conds, no element paths → SetCardinality",
                    self.pc, rule_index, body_results.len()
                ));
                SymValue::SetCardinality(cardinality)
            } else {
                self.warnings.push(format!(
                    "PC {}: Partial set rule {} → {} body conds, {} element(s) → SymbolicSet",
                    self.pc, rule_index, body_results.len(), collected_partial_set_elements.len()
                ));
                SymValue::SymbolicSet {
                    cardinality,
                    elements: collected_partial_set_elements,
                }
            };

            if !is_function {
                self.rule_cache.insert(
                    rule_index,
                    (result_value.clone(), Definedness::Defined),
                );
            }

            self.set_register_sym(
                dest,
                result_value,
                Definedness::Defined,
                None,
            );
            return Ok(InstructionAction::Continue);
        }

        // -------------------------------------------------------------------
        // Complete rules: combine body results.
        // -------------------------------------------------------------------
        let (final_value, final_defined) = if body_results.is_empty() {
            // No bodies → Undefined.
            (
                SymValue::Concrete(Value::Undefined),
                Definedness::Undefined,
            )
        } else if body_results.len() == 1 {
            let (cond, val) = body_results.into_iter().next().unwrap();
            (val, Definedness::Symbolic(cond))
        } else {
            // Multiple bodies: use ITE chain.
            // Last body is the fallback.
            let mut iter = body_results.into_iter().rev();
            let (last_cond, last_val) = iter.next().unwrap();

            // For now, if multiple bodies produce different sorts,
            // fall back to the first body's result gated by its condition.
            // A more complete implementation would use a Z3 ITE chain.
            let any_succeeded = last_cond.clone();
            // TODO: Build proper ITE chain for multiple definitions.
            (last_val, Definedness::Symbolic(any_succeeded))
        };

        // Apply default value if the rule has one.
        let (final_value, final_defined) = if let Some(default_idx) =
            rule_info.default_literal_index
        {
            let default_val = self.program.literals[default_idx as usize].clone();
            match &final_defined {
                Definedness::Undefined => (
                    SymValue::Concrete(default_val),
                    Definedness::Defined,
                ),
                Definedness::Defined => (final_value, final_defined),
                Definedness::Symbolic(def_bool) => {
                    // If defined → use rule result; else → use default.
                    // We need both values to have the same Z3 sort for ITE.
                    // For the common case (bool rule with bool default), this works directly.
                    match (&final_value, &default_val) {
                        (SymValue::Bool(rule_bool), Value::Bool(def_b)) => {
                            let def_z3 = Z3Bool::from_bool(self.ctx, *def_b);
                            let result = def_bool.ite(rule_bool, &def_z3);
                            (SymValue::Bool(result), Definedness::Defined)
                        }
                        (SymValue::Concrete(Value::Bool(rule_b)), Value::Bool(def_b)) => {
                            let rule_z3 = Z3Bool::from_bool(self.ctx, *rule_b);
                            let def_z3 = Z3Bool::from_bool(self.ctx, *def_b);
                            let result = def_bool.ite(&rule_z3, &def_z3);
                            (SymValue::Bool(result), Definedness::Defined)
                        }
                        _ => {
                            // Different sorts or complex types — just use default if all bodies failed.
                            // This is a simplification; a full implementation would handle all cases.
                            (final_value, final_defined)
                        }
                    }
                }
            }
        } else {
            // No default. For PartialSet/PartialObject, the default is empty collection.
            match rule_info.rule_type {
                RuleType::PartialSet if final_defined.is_undefined() => {
                    (SymValue::Concrete(Value::new_set()), Definedness::Defined)
                }
                RuleType::PartialObject if final_defined.is_undefined() => {
                    (SymValue::Concrete(Value::new_object()), Definedness::Defined)
                }
                _ => (final_value, final_defined),
            }
        };

        // Cache the result for non-function rules.
        if !is_function {
            self.rule_cache
                .insert(rule_index, (final_value.clone(), final_defined.clone()));
        }

        self.set_register_sym(dest, final_value, final_defined, None);
        Ok(InstructionAction::Continue)
    }

    fn translate_rule_init(
        &mut self,
        result_reg: u8,
        _rule_index: u16,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        // RuleInit sets up the result register. In our model, initialize to Undefined.
        self.set_register_sym(
            result_reg,
            SymValue::Concrete(Value::Undefined),
            Definedness::Undefined,
            None,
        );
        Ok(InstructionAction::Continue)
    }

    // -----------------------------------------------------------------------
    // Collections
    // -----------------------------------------------------------------------

    fn translate_object_create(
        &mut self,
        params_index: u16,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        let params = self
            .program
            .instruction_data
            .get_object_create_params(params_index)
            .ok_or_else(|| anyhow::anyhow!("Invalid ObjectCreate params {}", params_index))?
            .clone();

        // Check if any value is undefined.
        let mut any_undefined = false;
        for &(_, value_reg) in params.literal_key_field_pairs() {
            if self.get_register(value_reg).defined.is_undefined() {
                any_undefined = true;
                break;
            }
        }
        if !any_undefined {
            for &(key_reg, value_reg) in params.field_pairs() {
                if self.get_register(key_reg).defined.is_undefined()
                    || self.get_register(value_reg).defined.is_undefined()
                {
                    any_undefined = true;
                    break;
                }
            }
        }

        if any_undefined {
            self.set_register_sym(
                params.dest,
                SymValue::Concrete(Value::Undefined),
                Definedness::Undefined,
                None,
            );
        } else {
            // Build concrete object if all values are concrete.
            let template = self.program.literals.get(params.template_literal_idx as usize)
                .cloned()
                .unwrap_or_else(Value::new_object);
            // For now, pass through the template (simplified).
            self.set_register_concrete(params.dest, template);
        }
        Ok(InstructionAction::Continue)
    }

    fn translate_array_create(
        &mut self,
        params_index: u16,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        let params = self
            .program
            .instruction_data
            .get_array_create_params(params_index)
            .ok_or_else(|| anyhow::anyhow!("Invalid ArrayCreate params {}", params_index))?
            .clone();

        let any_undefined = params
            .element_registers()
            .iter()
            .any(|&r| self.get_register(r).defined.is_undefined());

        if any_undefined {
            self.set_register_sym(
                params.dest,
                SymValue::Concrete(Value::Undefined),
                Definedness::Undefined,
                None,
            );
        } else {
            // Build concrete array if all elements are concrete.
            let mut elements = Vec::new();
            let mut all_concrete = true;
            for &reg in params.element_registers() {
                if let SymValue::Concrete(v) = &self.get_register(reg).value {
                    elements.push(v.clone());
                } else {
                    all_concrete = false;
                    break;
                }
            }
            if all_concrete {
                self.set_register_concrete(
                    params.dest,
                    Value::from_array(elements),
                );
            } else {
                self.warnings.push(format!(
                    "PC {}: ArrayCreate with symbolic elements not fully modeled",
                    self.pc
                ));
                self.set_register_concrete(params.dest, Value::new_array());
            }
        }
        Ok(InstructionAction::Continue)
    }

    fn translate_set_create(
        &mut self,
        params_index: u16,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        let params = self
            .program
            .instruction_data
            .get_set_create_params(params_index)
            .ok_or_else(|| anyhow::anyhow!("Invalid SetCreate params {}", params_index))?
            .clone();

        let any_undefined = params
            .element_registers()
            .iter()
            .any(|&r| self.get_register(r).defined.is_undefined());

        if any_undefined {
            self.set_register_sym(
                params.dest,
                SymValue::Concrete(Value::Undefined),
                Definedness::Undefined,
                None,
            );
        } else {
            self.set_register_concrete(params.dest, Value::new_set());
        }
        Ok(InstructionAction::Continue)
    }

    fn translate_contains(
        &mut self,
        dest: u8,
        collection: u8,
        value: u8,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        let coll = self.get_register(collection).clone();
        let val = self.get_register(value).clone();

        // Combine operand definedness: if either is undefined, result is undefined.
        // This prevents false positives where Z3 sets an undefined path variable
        // to a value that happens to match collection elements.
        let result_defined = Definedness::and(self.ctx, &coll.defined, &val.defined);

        // Concrete case — but skip if the collection is a path placeholder
        // (Undefined with source_path), since that is a symbolic collection.
        let coll_is_path_placeholder = matches!(&coll.value, SymValue::Concrete(Value::Undefined))
            && coll.source_path.is_some();

        if !coll_is_path_placeholder {
            if let (SymValue::Concrete(cv), SymValue::Concrete(vv)) = (&coll.value, &val.value) {
                let result = match cv {
                    Value::Set(s) => s.contains(vv),
                    Value::Array(a) => a.contains(vv),
                    Value::Object(o) => o.contains_key(vv) || o.values().any(|v| v == vv),
                    _ => false,
                };
                self.set_register_concrete(dest, Value::Bool(result));
                return Ok(InstructionAction::Continue);
            }
        }

        // Symbolic collection from a path: enumerate array-element children
        // in the PathRegistry and build OR(child_defined AND child == value).
        if let Some(ref coll_path) = coll.source_path {
            let prefix = format!("{}[", coll_path);

            // Collect direct array-element children (e.g. "path[0]", "path[1]").
            let child_paths: Vec<(std::string::String, ValueSort)> = self
                .registry
                .iter()
                .filter(|(p, _)| {
                    if let Some(rest) = p.strip_prefix(prefix.as_str()) {
                        // Direct child: rest is "N]" (digits + closing bracket, no dots).
                        rest.ends_with(']') && !rest.contains('.')
                    } else {
                        false
                    }
                })
                .map(|(p, e)| (p.to_string(), e.sort))
                .collect();

            if !child_paths.is_empty() {
                // Determine sort for comparison: prefer the value's sort,
                // then the children's sort, else default to String.
                let val_sort = val.value.sort();
                let child_sort_hint = child_paths
                    .iter()
                    .map(|(_, s)| *s)
                    .find(|s| *s != ValueSort::Unknown)
                    .unwrap_or(ValueSort::String);
                let cmp_sort = if val_sort != ValueSort::Unknown {
                    val_sort
                } else {
                    child_sort_hint
                };

                // Get the Z3 expression for the search value.
                let val_z3 = self.get_z3_for_contains_operand(&val, cmp_sort)?;

                // Build disjuncts: child_defined AND child_value == search_value.
                let mut disjuncts = Vec::new();
                for (child_path, _) in &child_paths {
                    let child_defined = self
                        .registry
                        .get(child_path.as_str())
                        .map(|e| e.defined.clone())
                        .unwrap_or_else(|| Z3Bool::from_bool(self.ctx, false));

                    let eq = self.build_path_equality(child_path, cmp_sort, &val_z3)?;
                    disjuncts.push(Z3Bool::and(self.ctx, &[&child_defined, &eq]));
                }

                let result = if disjuncts.is_empty() {
                    Z3Bool::from_bool(self.ctx, false)
                } else {
                    let refs: Vec<&Z3Bool> = disjuncts.iter().collect();
                    Z3Bool::or(self.ctx, &refs)
                };

                self.set_register_sym(
                    dest,
                    SymValue::Bool(result),
                    result_defined.clone(),
                    None,
                );
                return Ok(InstructionAction::Continue);
            }
        }

        // Symbolic set: check if any element matches.
        if let SymValue::SymbolicSet { elements, .. } = &coll.value {
            if !elements.is_empty() {
                let val_sort = val.value.sort();
                let elem_sort = elements
                    .iter()
                    .map(|e| e.element_sort)
                    .find(|s| *s != ValueSort::Unknown)
                    .unwrap_or(ValueSort::String);
                let cmp_sort = if val_sort != ValueSort::Unknown {
                    val_sort
                } else {
                    elem_sort
                };

                let val_z3 = self.get_z3_for_contains_operand(&val, cmp_sort)?;
                let elements_clone: Vec<_> = elements.clone();

                let mut disjuncts = Vec::new();
                for elem in &elements_clone {
                    let eq =
                        self.build_path_equality(&elem.key_path, cmp_sort, &val_z3)?;
                    disjuncts.push(Z3Bool::and(self.ctx, &[&elem.condition, &eq]));
                }

                let result = if disjuncts.is_empty() {
                    Z3Bool::from_bool(self.ctx, false)
                } else {
                    let refs: Vec<&Z3Bool> = disjuncts.iter().collect();
                    Z3Bool::or(self.ctx, &refs)
                };

                self.set_register_sym(
                    dest,
                    SymValue::Bool(result),
                    result_defined.clone(),
                    None,
                );
                return Ok(InstructionAction::Continue);
            }
        }

        // Fallback: create unconstrained boolean with warning.
        self.warnings.push(format!(
            "PC {}: Contains with symbolic values — limited precision",
            self.pc
        ));
        let name = format!("contains_{}", self.pc);
        let var = Z3Bool::new_const(self.ctx, name.as_str());
        self.set_register_sym(dest, SymValue::Bool(var), result_defined, None);
        Ok(InstructionAction::Continue)
    }

    /// Get a Z3 expression for a Contains operand (the search value).
    fn get_z3_for_contains_operand(
        &mut self,
        reg: &SymRegister<'ctx>,
        sort: ValueSort,
    ) -> anyhow::Result<ContainsZ3Value<'ctx>> {
        // If the register has a source_path, get the Z3 variable from the registry.
        if let Some(ref path) = reg.source_path {
            self.registry.refine_sort(path, sort);
            match sort {
                ValueSort::String => {
                    let var = self.registry.get_string(path);
                    return Ok(ContainsZ3Value::Str(var));
                }
                ValueSort::Int => {
                    let var = self.registry.get_int(path);
                    return Ok(ContainsZ3Value::Int(var));
                }
                ValueSort::Bool => {
                    let var = self.registry.get_bool(path);
                    return Ok(ContainsZ3Value::Bool(var));
                }
                ValueSort::Real => {
                    let var = self.registry.get_real(path);
                    return Ok(ContainsZ3Value::Real(var));
                }
                ValueSort::Unknown => {
                    let var = self.registry.get_string(path);
                    return Ok(ContainsZ3Value::Str(var));
                }
            }
        }

        // Otherwise, extract from the symbolic value directly.
        match &reg.value {
            SymValue::Concrete(Value::String(s)) => Ok(ContainsZ3Value::Str(
                z3::ast::String::from_str(self.ctx, s).unwrap(),
            )),
            SymValue::Concrete(Value::Bool(b)) => {
                Ok(ContainsZ3Value::Bool(Z3Bool::from_bool(self.ctx, *b)))
            }
            SymValue::Concrete(Value::Number(n)) => {
                if let Some(i) = n.as_i64() {
                    Ok(ContainsZ3Value::Int(Z3Int::from_i64(self.ctx, i)))
                } else if let Some(f) = n.as_f64() {
                    // Approximate as int
                    Ok(ContainsZ3Value::Int(Z3Int::from_i64(self.ctx, f as i64)))
                } else {
                    anyhow::bail!("Cannot convert number {:?} to Z3 for Contains", n)
                }
            }
            SymValue::Str(s) => Ok(ContainsZ3Value::Str(s.clone())),
            SymValue::Int(i) => Ok(ContainsZ3Value::Int(i.clone())),
            SymValue::Bool(b) => Ok(ContainsZ3Value::Bool(b.clone())),
            SymValue::Real(r) => Ok(ContainsZ3Value::Real(r.clone())),
            _ => {
                // Fallback: treat as unknown string
                let name = format!("contains_val_{}", self.pc);
                Ok(ContainsZ3Value::Str(z3::ast::String::new_const(
                    self.ctx,
                    name.as_str(),
                )))
            }
        }
    }

    /// Build an equality constraint between a path's Z3 variable and a search value.
    fn build_path_equality(
        &mut self,
        path: &str,
        sort: ValueSort,
        val: &ContainsZ3Value<'ctx>,
    ) -> anyhow::Result<Z3Bool<'ctx>> {
        match (sort, val) {
            (ValueSort::String, ContainsZ3Value::Str(v))
            | (ValueSort::Unknown, ContainsZ3Value::Str(v)) => {
                let child_var = self.registry.get_string(path);
                Ok(child_var._eq(v))
            }
            (ValueSort::Int, ContainsZ3Value::Int(v)) => {
                let child_var = self.registry.get_int(path);
                Ok(child_var._eq(v))
            }
            (ValueSort::Bool, ContainsZ3Value::Bool(v)) => {
                let child_var = self.registry.get_bool(path);
                Ok(child_var._eq(v))
            }
            (ValueSort::Real, ContainsZ3Value::Real(v)) => {
                let child_var = self.registry.get_real(path);
                Ok(child_var._eq(v))
            }
            _ => {
                // Mismatched sorts — default to string comparison.
                let child_var = self.registry.get_string(path);
                let v_str = match val {
                    ContainsZ3Value::Str(s) => s.clone(),
                    _ => {
                        let name = format!("contains_cast_{}", path);
                        z3::ast::String::new_const(self.ctx, name.as_str())
                    }
                };
                Ok(child_var._eq(&v_str))
            }
        }
    }

    fn translate_count(
        &mut self,
        dest: u8,
        collection: u8,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        let coll = self.get_register(collection).clone();

        // SetCardinality → extract the symbolic Int directly.
        if let Some(card) = coll.value.as_set_cardinality() {
            self.set_register_sym(
                dest,
                SymValue::Int(card.clone()),
                Definedness::Defined,
                None,
            );
            return Ok(InstructionAction::Continue);
        }

        if let SymValue::Concrete(cv) = &coll.value {
            let count = match cv {
                Value::Array(a) => Some(a.len()),
                Value::Object(o) => Some(o.len()),
                Value::Set(s) => Some(s.len()),
                _ => None,
            };
            if let Some(c) = count {
                self.set_register_concrete(dest, Value::from(c));
                return Ok(InstructionAction::Continue);
            }
        }

        self.set_register_sym(
            dest,
            SymValue::Concrete(Value::Undefined),
            Definedness::Undefined,
            None,
        );
        Ok(InstructionAction::Continue)
    }

    // -----------------------------------------------------------------------
    // Loops (bounded unrolling)
    // -----------------------------------------------------------------------

    fn translate_loop_start(
        &mut self,
        params_index: u16,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        let params = self
            .program
            .instruction_data
            .get_loop_params(params_index)
            .ok_or_else(|| anyhow::anyhow!("Invalid loop params index {}", params_index))?
            .clone();

        let collection = self.get_register(params.collection).clone();

        // Check for symbolic path FIRST — path registers have
        // SymValue::Concrete(Value::Undefined) as their value but are actually
        // symbolic. If we check `SymValue::Concrete` first, they'd be treated
        // as non-iterable concrete values and the loop body would be skipped.
        let is_symbolic_path = collection.source_path.is_some();

        // Concrete collection (non-path) → unroll exactly.
        if !is_symbolic_path {
            if let SymValue::Concrete(cv) = &collection.value {
            let elements: Vec<(Value, Value)> = match cv {
                Value::Array(a) => a
                    .iter()
                    .enumerate()
                    .map(|(i, v)| (Value::from(i), v.clone()))
                    .collect(),
                Value::Object(o) => o
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                Value::Set(s) => s
                    .iter()
                    .map(|v| (v.clone(), v.clone()))
                    .collect(),
                _ => {
                    // Empty / non-iterable → skip to loop end.
                    return Ok(InstructionAction::Jump(params.loop_end as usize));
                }
            };

            if elements.is_empty() {
                // Handle empty collection per mode.
                use crate::rvm::instructions::LoopMode;
                match params.mode {
                    LoopMode::Every => {
                        self.set_register_concrete(params.result_reg, Value::Bool(true));
                    }
                    _ => {
                        self.set_register_concrete(params.result_reg, Value::Bool(false));
                    }
                }
                return Ok(InstructionAction::Jump(params.loop_end as usize));
            }

            // Initialize result.
            self.set_register_concrete(params.result_reg, Value::Bool(false));

            // Unroll: translate the body for each element.
            let body_start = params.body_start as usize;
            let loop_end = params.loop_end as usize;
            let saved_path_cond = self.path_condition.clone();

            let mut success_conditions: Vec<Z3Bool<'ctx>> = Vec::new();

            for (key, value) in &elements {
                // Set up iteration variables.
                self.set_register_concrete(params.key_reg, key.clone());
                self.set_register_concrete(params.value_reg, value.clone());

                // Reset path condition for this iteration.
                self.path_condition = saved_path_cond.clone();

                // Translate body (from body_start to loop_end - 1, which is LoopNext).
                let saved_pc = self.pc;
                let _result = self.translate_block(body_start);
                self.pc = saved_pc;

                // Record whether this iteration's path condition held.
                success_conditions.push(self.path_condition.clone());
            }

            // Combine per loop mode.
            use crate::rvm::instructions::LoopMode;
            let loop_result = match params.mode {
                LoopMode::Any => {
                    // Any iteration succeeded → true.
                    let refs: Vec<&Z3Bool> = success_conditions.iter().collect();
                    Z3Bool::or(self.ctx, &refs)
                }
                LoopMode::Every => {
                    // All iterations succeeded → true.
                    let refs: Vec<&Z3Bool> = success_conditions.iter().collect();
                    Z3Bool::and(self.ctx, &refs)
                }
                LoopMode::ForEach => {
                    // At least one succeeded → true.
                    let refs: Vec<&Z3Bool> = success_conditions.iter().collect();
                    Z3Bool::or(self.ctx, &refs)
                }
            };

            self.path_condition = saved_path_cond;
            self.set_register_sym(
                params.result_reg,
                SymValue::Bool(loop_result),
                Definedness::Defined,
                None,
            );

            return Ok(InstructionAction::Jump(loop_end));
        }
        } // end if !is_symbolic_path / Concrete

        // -------------------------------------------------------------------
        // SymbolicSet collection → iterate over recorded elements.
        //
        // When the collection register holds a SymbolicSet produced by a
        // partial set rule, we iterate over the recorded element witnesses
        // instead of creating disconnected symbolic witnesses.  Each element
        // carries a Z3 condition (the partial-set body succeeded for that
        // witness) and a source path (e.g., "input.servers[0]").
        // -------------------------------------------------------------------
        if let Some(elements) = collection.value.as_symbolic_set_elements() {
            let elements = elements.clone(); // clone to release borrow
            let body_start = params.body_start as usize;
            let loop_end = params.loop_end as usize;
            let saved_path_cond = self.path_condition.clone();

            // Track the value_reg of this SymbolicSet iteration as the
            // outermost loop's value register for nested partial-set tracking.
            // This ensures that if the consumer is itself inside a partial set
            // body, SetAdd captures the correct register (the set element, not
            // an inner loop's value).
            if self.is_in_partial_set_body && self.partial_set_main_value_reg.is_none() {
                self.partial_set_main_value_reg = Some(params.value_reg);
            }

            let mut success_conditions: Vec<Z3Bool<'ctx>> = Vec::new();

            for element in &elements {
                // Create path registers for key and value pointing to element's path.
                // For a Rego set, key == value == element.
                self.create_path_register(
                    params.key_reg,
                    &element.element_path,
                    element.element_sort,
                )?;
                self.create_path_register(
                    params.value_reg,
                    &element.element_path,
                    element.element_sort,
                )?;

                // AND the element's condition into the path condition.
                self.path_condition = Z3Bool::and(
                    self.ctx,
                    &[&saved_path_cond, &element.condition],
                );

                // Translate the consumer loop body.
                let saved_pc = self.pc;
                let _result = self.translate_block(body_start);
                self.pc = saved_pc;

                success_conditions.push(self.path_condition.clone());
            }

            // Combine per loop mode.
            use crate::rvm::instructions::LoopMode;
            let loop_result = if success_conditions.is_empty() {
                match params.mode {
                    LoopMode::Every => Z3Bool::from_bool(self.ctx, true),
                    _ => Z3Bool::from_bool(self.ctx, false),
                }
            } else {
                match params.mode {
                    LoopMode::Any | LoopMode::ForEach => {
                        let refs: Vec<&Z3Bool> = success_conditions.iter().collect();
                        Z3Bool::or(self.ctx, &refs)
                    }
                    LoopMode::Every => {
                        let refs: Vec<&Z3Bool> = success_conditions.iter().collect();
                        Z3Bool::and(self.ctx, &refs)
                    }
                }
            };

            self.warnings.push(format!(
                "PC {}: Loop over SymbolicSet with {} element(s)",
                self.pc,
                elements.len()
            ));

            self.path_condition = Z3Bool::and(self.ctx, &[&saved_path_cond, &loop_result]);
            self.set_register_sym(
                params.result_reg,
                SymValue::Bool(loop_result),
                Definedness::Defined,
                None,
            );
            return Ok(InstructionAction::Jump(loop_end));
        }

        // Symbolic collection → bounded witness instantiation.
        // When the collection is a path register (e.g., input.servers),
        // we create bounded symbolic "witness" elements and translate the
        // loop body with each witness.
        //
        // NOTE on LoopMode semantics: The Rego→RVM compiler currently emits
        // only ForEach and Every (never Any). All `some x in coll`, `coll[_]`,
        // and `x := coll[_]` patterns compile as ForEach, which processes all
        // elements without early exit. We use `max_loop_depth` witnesses for
        // all modes, since even if `Any` were emitted, multiple witnesses
        // provide better coverage and the OR combination is semantically sound.
        let coll_path = collection.source_path.clone();

        let num_witnesses = self.config.max_loop_depth;

        let body_start = params.body_start as usize;
        let loop_end = params.loop_end as usize;
        let saved_path_cond = self.path_condition.clone();

        let mut success_conditions: Vec<Z3Bool<'ctx>> = Vec::new();

        for wi in 0..num_witnesses {
            // Create a symbolic witness element.
            let witness_base = if let Some(ref path) = coll_path {
                format!("{}[{}]", path, wi)
            } else {
                format!("sym_coll_{}_{}", self.pc, wi)
            };

            // Set key register to a concrete index (for array-like iteration).
            self.set_register_concrete(params.key_reg, Value::from(wi));

            // Set value register to a symbolic object rooted at the witness path.
            // This MUST go through create_path_register to register the path in
            // PathRegistry — otherwise sort promotion via ensure_register_sort
            // will silently fail since the path won't exist in the registry.
            self.create_path_register(params.value_reg, &witness_base, ValueSort::Unknown)?;

            // Track outermost loop's value_reg for partial set element.
            // The first LoopStart in a partial set body provides the
            // iteration variable that becomes the set element.
            if self.is_in_partial_set_body && self.partial_set_main_value_reg.is_none() {
                self.partial_set_main_value_reg = Some(params.value_reg);
            }

            // Reset path condition for this witness.
            self.path_condition = saved_path_cond.clone();

            // Translate the body.
            let saved_pc = self.pc;
            let _result = self.translate_block(body_start);
            self.pc = saved_pc;

            // Record whether this witness's path condition held.
            success_conditions.push(self.path_condition.clone());
        }

        // Combine per loop mode.
        use crate::rvm::instructions::LoopMode;
        let loop_result = if success_conditions.is_empty() {
            match params.mode {
                LoopMode::Every => Z3Bool::from_bool(self.ctx, true),
                _ => Z3Bool::from_bool(self.ctx, false),
            }
        } else {
            match params.mode {
                LoopMode::Any | LoopMode::ForEach => {
                    let refs: Vec<&Z3Bool> = success_conditions.iter().collect();
                    Z3Bool::or(self.ctx, &refs)
                }
                LoopMode::Every => {
                    let refs: Vec<&Z3Bool> = success_conditions.iter().collect();
                    Z3Bool::and(self.ctx, &refs)
                }
            }
        };

        if coll_path.is_some() {
            self.warnings.push(format!(
                "PC {}: Loop over symbolic path collection with {} witness(es)",
                self.pc, num_witnesses
            ));
        } else {
            self.warnings.push(format!(
                "PC {}: Loop over symbolic non-path collection with {} witness(es)",
                self.pc, num_witnesses
            ));
        }

        // Restore the path condition and AND the loop result into it.
        // The loop_result encodes the combined success condition from all
        // witnesses. Without this, the constraints from inside the loop body
        // (e.g., input.users[0] == "admin") would be lost — they'd exist only
        // in the loop_result Bool but never reach the solver's path condition.
        self.path_condition = Z3Bool::and(self.ctx, &[&saved_path_cond, &loop_result]);
        self.set_register_sym(
            params.result_reg,
            SymValue::Bool(loop_result),
            Definedness::Defined,
            None,
        );
        Ok(InstructionAction::Jump(loop_end))
    }

    // -----------------------------------------------------------------------
    // Builtins
    // -----------------------------------------------------------------------

    fn translate_builtin_call(
        &mut self,
        params_index: u16,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        let params = self
            .program
            .instruction_data
            .get_builtin_call_params(params_index)
            .ok_or_else(|| anyhow::anyhow!("Invalid builtin params index {}", params_index))?
            .clone();

        let builtin_info = self
            .program
            .builtin_info_table
            .get(params.builtin_index as usize)
            .ok_or_else(|| {
                anyhow::anyhow!("Builtin index {} out of bounds", params.builtin_index)
            })?
            .clone();

        let builtin_name = builtin_info.name.as_str();

        // Handle well-known builtins with proper return types.
        match builtin_name {
            "count" => {
                // count() always returns a non-negative integer.
                // If the argument is a SetCardinality, extract the symbolic Int.
                if params.arg_count() >= 1 {
                    let arg_reg = params.args[0];
                    let arg = self.get_register(arg_reg).clone();

                    if let Some(card) = arg.value.as_set_cardinality() {
                        self.set_register_sym(
                            params.dest,
                            SymValue::Int(card.clone()),
                            Definedness::Defined,
                            None,
                        );
                        return Ok(InstructionAction::Continue);
                    }

                    if let SymValue::Concrete(cv) = &arg.value {
                        let count = match cv {
                            Value::Array(a) => Some(a.len()),
                            Value::Object(o) => Some(o.len()),
                            Value::Set(s) => Some(s.len()),
                            Value::String(s) => Some(s.len()),
                            _ => None,
                        };
                        if let Some(c) = count {
                            self.set_register_concrete(params.dest, Value::from(c));
                            return Ok(InstructionAction::Continue);
                        }
                    }
                }
                // Symbolic: return a fresh non-negative Int.
                self.warnings.push(format!(
                    "PC {}: Builtin 'count' on symbolic collection → unconstrained Int",
                    self.pc
                ));
                let name = format!("builtin_count_{}", self.pc);
                let var = Z3Int::new_const(self.ctx, name.as_str());
                let zero = Z3Int::from_i64(self.ctx, 0);
                self.constraints.push(var.ge(&zero));
                self.set_register_sym(params.dest, SymValue::Int(var), Definedness::Defined, None);
            }

            // Boolean-returning builtins.
            "regex.match" | "startswith" | "endswith" | "contains"
            | "io.jwt.verify_rs256" | "io.jwt.verify_rs384" | "io.jwt.verify_rs512"
            | "io.jwt.verify_es256" | "io.jwt.verify_es384" | "io.jwt.verify_es512"
            | "io.jwt.verify_hs256" | "io.jwt.verify_hs384" | "io.jwt.verify_hs512"
            | "is_string" | "is_number" | "is_boolean" | "is_array" | "is_set" | "is_object"
            | "is_null" => {
                self.warnings.push(format!(
                    "PC {}: Builtin '{}' modeled as unconstrained Bool",
                    self.pc, builtin_name
                ));
                let name = format!("builtin_{}_{}", builtin_name.replace('.', "_"), self.pc);
                let var = Z3Bool::new_const(self.ctx, name.as_str());
                self.set_register_sym(params.dest, SymValue::Bool(var), Definedness::Defined, None);
            }

            // Numeric-returning builtins.
            "sum" | "product" | "min" | "max" | "abs" | "ceil" | "floor" | "round"
            | "to_number" | "bits.and" | "bits.or" | "bits.negate" | "bits.xor"
            | "bits.lsh" | "bits.rsh" | "indexof" => {
                self.warnings.push(format!(
                    "PC {}: Builtin '{}' modeled as unconstrained Int",
                    self.pc, builtin_name
                ));
                let name = format!("builtin_{}_{}", builtin_name.replace('.', "_"), self.pc);
                let var = Z3Int::new_const(self.ctx, name.as_str());
                self.set_register_sym(params.dest, SymValue::Int(var), Definedness::Defined, None);
            }

            // Default: string return (most builtins return strings or complex values).
            _ => {
                self.warnings.push(format!(
                    "PC {}: Builtin '{}' modeled as uninterpreted (String)",
                    self.pc, builtin_name
                ));
                let name = format!("builtin_{}_{}", builtin_name.replace('.', "_"), self.pc);
                let var = Z3String::new_const(self.ctx, name.as_str());
                self.set_register_sym(params.dest, SymValue::Str(var), Definedness::Defined, None);
            }
        }
        Ok(InstructionAction::Continue)
    }

    // -----------------------------------------------------------------------
    // Function calls
    // -----------------------------------------------------------------------

    fn translate_function_call(
        &mut self,
        params_index: u16,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        let params = self
            .program
            .instruction_data
            .get_function_call_params(params_index)
            .ok_or_else(|| anyhow::anyhow!("Invalid function call params {}", params_index))?
            .clone();

        // Translate as a rule call with arguments.
        // For now, delegate to translate_call_rule (arguments are not passed yet).
        self.translate_call_rule(params.dest, params.func_rule_index)
    }

    // -----------------------------------------------------------------------
    // Virtual data document lookup
    // -----------------------------------------------------------------------

    fn translate_virtual_data_lookup(
        &mut self,
        params_index: u16,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        let params = self
            .program
            .instruction_data
            .get_virtual_data_document_lookup_params(params_index)
            .ok_or_else(|| {
                anyhow::anyhow!("Invalid VDDL params index {}", params_index)
            })?
            .clone();

        // Resolve path components.
        let mut path_parts: Vec<String> = vec!["data".to_string()];
        let mut all_concrete = true;

        for component in &params.path_components {
            match component {
                LiteralOrRegister::Literal(idx) => {
                    let key = &self.program.literals[*idx as usize];
                    path_parts.push(value_to_path_segment(key));
                }
                LiteralOrRegister::Register(reg) => {
                    if let SymValue::Concrete(v) = &self.get_register(*reg).value {
                        path_parts.push(value_to_path_segment(v));
                    } else {
                        all_concrete = false;
                        break;
                    }
                }
            }
        }

        if !all_concrete {
            self.warnings.push(format!(
                "PC {}: VDDL with symbolic path component",
                self.pc
            ));
            let name = format!("vddl_{}", self.pc);
            let var = Z3String::new_const(self.ctx, name.as_str());
            self.set_register_sym(params.dest, SymValue::Str(var), Definedness::Defined, None);
            return Ok(InstructionAction::Continue);
        }

        // Walk the rule tree to find what this refers to.
        let mut node = &self.program.rule_tree[&Value::from("data")];
        for part in &path_parts[1..] {
            node = &node[&Value::from(part.as_str())];
        }

        match node {
            Value::Number(n) => {
                // It's a rule index — call the rule.
                if let Some(idx) = n.as_u64() {
                    self.translate_call_rule(params.dest, idx as u16)?;
                } else {
                    self.set_register_concrete(params.dest, Value::Undefined);
                }
            }
            Value::Object(_) => {
                // Subtree of rules — for now, look up in concrete data.
                let mut result = self.data.clone();
                for part in &path_parts[1..] {
                    result = result[&Value::from(part.as_str())].clone();
                }
                self.set_register_concrete(params.dest, result);
            }
            _ => {
                // Pure data access.
                let mut result = self.data.clone();
                for part in &path_parts[1..] {
                    result = result[&Value::from(part.as_str())].clone();
                }
                self.set_register_concrete(params.dest, result);
            }
        }

        Ok(InstructionAction::Continue)
    }

    // -----------------------------------------------------------------------
    // Register helpers
    // -----------------------------------------------------------------------

    fn get_register(&self, reg: u8) -> &SymRegister<'ctx> {
        &self.registers[reg as usize]
    }

    fn set_register_concrete(&mut self, reg: u8, value: Value) {
        let idx = reg as usize;
        if idx >= self.registers.len() {
            self.registers
                .resize_with(idx + 1, SymRegister::undefined);
        }
        self.registers[idx] = SymRegister::concrete(value);
    }

    fn set_register_sym(
        &mut self,
        reg: u8,
        value: SymValue<'ctx>,
        defined: Definedness<'ctx>,
        source_path: Option<String>,
    ) {
        let idx = reg as usize;
        if idx >= self.registers.len() {
            self.registers
                .resize_with(idx + 1, SymRegister::undefined);
        }
        self.registers[idx] = SymRegister {
            value,
            defined,
            source_path,
        };
    }

    /// Create a path variable and assign it to a register.
    fn create_path_register(
        &mut self,
        dest: u8,
        path: &str,
        sort: ValueSort,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        // Create the path entry in the registry (with a defined-variable).
        let _entry = self.registry.get_or_create(path, sort, true, self.pc);

        // The sort may not be known yet — it will be refined when the value is used.
        // For now, create a String variable (most general); it will be refined on first use.
        let defined = self.registry.get(path).unwrap().defined.clone();

        // We don't pick a sort yet — we mark the register with the path and let
        // the consumer (comparison, arithmetic, etc.) decide the sort via `refine_sort`.
        self.set_register_sym(
            dest,
            SymValue::Concrete(Value::Undefined), // Placeholder; sort determined on use.
            Definedness::Symbolic(defined),
            Some(path.to_string()),
        );
        Ok(InstructionAction::Continue)
    }

    /// Generate a fresh unique name.
    #[allow(dead_code)]
    fn fresh_name(&mut self, prefix: &str) -> String {
        let id = self.fresh_counter;
        self.fresh_counter += 1;
        format!("{}_{}", prefix, id)
    }

    /// Promote two registers' path placeholders based on each other's sort.
    /// If one register has a known sort and the other is a path placeholder,
    /// promote the placeholder to the known sort.
    fn promote_path_registers(&mut self, left: u8, right: u8) {
        let left_sort = self.registers[left as usize].value.sort();
        let right_sort = self.registers[right as usize].value.sort();
        let left_has_path = self.registers[left as usize].source_path.is_some();
        let right_has_path = self.registers[right as usize].source_path.is_some();

        // Infer sort from the other operand.
        if left_has_path && left_sort == ValueSort::Unknown && right_sort != ValueSort::Unknown {
            let _ = self.ensure_register_sort(left, right_sort);
        }
        if right_has_path && right_sort == ValueSort::Unknown && left_sort != ValueSort::Unknown {
            let _ = self.ensure_register_sort(right, left_sort);
        }

        // If both are path registers with Unknown sort (no sort hint from
        // either side), promote both to String as a safe default.  Without
        // this, both remain Concrete(Undefined) placeholders and the concrete
        // comparison path would treat them as equal, silently dropping the
        // constraint (e.g., server.ports[k] == ports[j].id).
        if left_has_path
            && right_has_path
            && self.registers[left as usize].value.sort() == ValueSort::Unknown
            && self.registers[right as usize].value.sort() == ValueSort::Unknown
        {
            let _ = self.ensure_register_sort(left, ValueSort::String);
            let _ = self.ensure_register_sort(right, ValueSort::String);
        }
    }

    /// Promote a single register's path placeholder to a specific sort.
    fn promote_path_register_to_sort(&mut self, reg: u8, sort: ValueSort) {
        let idx = reg as usize;
        if idx < self.registers.len()
            && self.registers[idx].source_path.is_some()
            && self.registers[idx].value.sort() == ValueSort::Unknown
        {
            let _ = self.ensure_register_sort(reg, sort);
        }
    }

    /// Ensure a register's value is promoted to the appropriate Z3 sort.
    /// If the register has a source_path but holds a placeholder Concrete(Undefined),
    /// this creates the actual Z3 variable with the given sort.
    #[allow(dead_code)]
    pub(crate) fn ensure_register_sort(
        &mut self,
        reg: u8,
        sort: ValueSort,
    ) -> anyhow::Result<()> {
        let idx = reg as usize;
        let register = &self.registers[idx];

        if let Some(path) = register.source_path.clone() {
            // Refine the registry entry sort.
            self.registry.refine_sort(&path, sort);

            // Get the Z3 variable for this path+sort.
            if let Some(sym_val) = self.registry.get_var_for_sort(&path, sort) {
                let defined = self.registers[idx].defined.clone();
                let src_path = self.registers[idx].source_path.clone();
                self.registers[idx] = SymRegister {
                    value: sym_val,
                    defined,
                    source_path: src_path,
                };
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Internal enums
// ---------------------------------------------------------------------------

enum InstructionAction<'ctx> {
    Continue,
    Return(SymValue<'ctx>),
    Jump(usize),
}

#[derive(Clone, Copy)]
enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

#[derive(Clone, Copy)]
enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// Typed Z3 value for Contains equality comparisons.
#[derive(Clone)]
enum ContainsZ3Value<'ctx> {
    Bool(Z3Bool<'ctx>),
    Int(Z3Int<'ctx>),
    Real(Z3Real<'ctx>),
    Str(z3::ast::String<'ctx>),
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Convert a Rego Value to a path segment string.
fn value_to_path_segment(v: &Value) -> String {
    match v {
        Value::String(s) => s.to_string(),
        Value::Number(n) => format!("{:?}", n),
        Value::Bool(b) => format!("{}", b),
        _ => format!("{:?}", v),
    }
}
