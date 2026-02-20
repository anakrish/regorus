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

use z3::ast::{
    Ast, Bool as Z3Bool, Int as Z3Int, Real as Z3Real, Regexp as Z3Regexp, String as Z3String,
    BV as Z3BV,
};

use crate::rvm::instructions::{Instruction, LiteralOrRegister};
use crate::rvm::program::{Program, RuleType};
use crate::value::Value;

use super::path_registry::PathRegistry;
use super::types::{
    ComprehensionAccumulator, ComprehensionYieldEntry, Definedness, SymRegister, SymSetElement,
    SymValue, ValueSort,
};
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

    /// Stack of active comprehension accumulators.
    /// Pushed at ComprehensionBegin, popped after the body completes.
    comprehension_stack: Vec<ComprehensionAccumulator<'ctx>>,
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
        let num_regs = program
            .dispatch_window_size
            .max(program.max_rule_window_size);
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
            comprehension_stack: Vec::new(),
        }
    }

    /// Take the accumulated PC → path-condition map (consumes it).
    pub fn take_pc_path_conditions(&mut self) -> HashMap<usize, Z3Bool<'ctx>> {
        core::mem::take(&mut self.pc_path_conditions)
    }

    /// Translate starting from an entry point PC.
    /// Returns the symbolic result (value of register 0 at Halt).
    pub fn translate_entry_point(&mut self, entry_pc: usize) -> anyhow::Result<SymValue<'ctx>> {
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
            Add { dest, left, right } => self.translate_arithmetic(dest, left, right, ArithOp::Add),
            Sub { dest, left, right } => self.translate_arithmetic(dest, left, right, ArithOp::Sub),
            Mul { dest, left, right } => self.translate_arithmetic(dest, left, right, ArithOp::Mul),
            Div { dest, left, right } => self.translate_arithmetic(dest, left, right, ArithOp::Div),
            Mod { dest, left, right } => self.translate_arithmetic(dest, left, right, ArithOp::Mod),

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
            Index {
                dest,
                container,
                key,
            } => self.translate_index(dest, container, key),
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
                self.path_condition = Z3Bool::and(self.ctx, &[&self.path_condition, &def_cond]);
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
            ObjectCreate { params_index } => self.translate_object_create(params_index),
            ArrayCreate { params_index } => self.translate_array_create(params_index),
            SetCreate { params_index } => self.translate_set_create(params_index),
            ObjectSet { obj, key, value } => {
                // Mutate the object in place: insert key→value.
                let key_reg = self.get_register(key).clone();
                let val_reg = self.get_register(value).clone();
                let obj_reg = self.get_register(obj).clone();

                // If the object is a concrete object and the key is concrete,
                // insert the value (even if value is symbolic, record what we can).
                if let SymValue::Concrete(Value::Object(ref o)) = obj_reg.value {
                    if let SymValue::Concrete(ref k) = key_reg.value {
                        if key_reg.source_path.is_none() {
                            let mut new_obj = (**o).clone();
                            if let SymValue::Concrete(ref v) = val_reg.value {
                                if val_reg.source_path.is_none() {
                                    new_obj.insert(k.clone(), v.clone());
                                } else {
                                    // Symbolic value — insert Undefined placeholder.
                                    new_obj.insert(k.clone(), Value::Undefined);
                                }
                            } else {
                                new_obj.insert(k.clone(), Value::Undefined);
                            }
                            self.set_register_concrete(obj, Value::Object(crate::Rc::new(new_obj)));
                            return Ok(InstructionAction::Continue);
                        }
                    }
                }
                // Fallback: can't track symbolic key mutations.
                self.warnings.push(format!(
                    "PC {}: ObjectSet with symbolic key/object — limited precision",
                    self.pc
                ));
                Ok(InstructionAction::Continue)
            }
            ArrayPush { arr, value } => {
                // Mutate the array in place: push the value.
                let val_reg = self.get_register(value).clone();
                let arr_reg = self.get_register(arr).clone();

                if let SymValue::Concrete(Value::Array(ref a)) = arr_reg.value {
                    if let SymValue::Concrete(ref v) = val_reg.value {
                        if val_reg.source_path.is_none() {
                            let mut new_arr = (**a).clone();
                            new_arr.push(v.clone());
                            self.set_register_concrete(arr, Value::Array(crate::Rc::new(new_arr)));
                            return Ok(InstructionAction::Continue);
                        }
                    }
                    // Symbolic value — push Undefined placeholder to preserve length.
                    let mut new_arr = (**a).clone();
                    new_arr.push(Value::Undefined);
                    self.set_register_concrete(arr, Value::Array(crate::Rc::new(new_arr)));
                } else {
                    self.warnings.push(format!(
                        "PC {}: ArrayPush on non-concrete array — limited precision",
                        self.pc
                    ));
                }
                Ok(InstructionAction::Continue)
            }
            SetAdd { set, value } => {
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
                            reg.source_path
                                .as_ref()
                                .map(|p| (p.clone(), reg.value.sort()))
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
                    // Outside partial set body — mutate the set register directly.
                    let val_reg = self.get_register(value).clone();
                    let set_reg = self.get_register(set).clone();

                    if let SymValue::Concrete(Value::Set(ref s)) = set_reg.value {
                        if let SymValue::Concrete(ref v) = val_reg.value {
                            if val_reg.source_path.is_none() {
                                let mut new_set = (**s).clone();
                                new_set.insert(v.clone());
                                self.set_register_concrete(
                                    set,
                                    Value::Set(crate::Rc::new(new_set)),
                                );
                                return Ok(InstructionAction::Continue);
                            }
                        }
                    }
                    self.warnings.push(format!(
                        "PC {}: SetAdd with symbolic value/set — limited precision",
                        self.pc
                    ));
                }
                Ok(InstructionAction::Continue)
            }
            Contains {
                dest,
                collection,
                value,
            } => self.translate_contains(dest, collection, value),
            Count { dest, collection } => self.translate_count(dest, collection),

            // -- Loops (Phase 3 stubs) --
            LoopStart { params_index } => self.translate_loop_start(params_index),
            LoopNext {
                body_start: _,
                loop_end: _,
            } => {
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

            // -- Comprehensions --
            ComprehensionBegin { params_index } => self.translate_comprehension(params_index),
            ComprehensionYield { value_reg, key_reg } => {
                if !self.comprehension_stack.is_empty() {
                    let value = self.get_register(value_reg).clone();
                    let key = key_reg.map(|kr| self.get_register(kr).clone());
                    let condition = self.path_condition.clone();
                    let acc = self.comprehension_stack.last_mut().unwrap();
                    acc.yields.push(ComprehensionYieldEntry {
                        value,
                        key,
                        condition,
                    });
                }
                Ok(InstructionAction::Continue)
            }
            ComprehensionEnd {} => {
                // When inside a comprehension body, return to signal the
                // body is done.  The actual result-building happens in
                // translate_comprehension after translate_block returns.
                if !self.comprehension_stack.is_empty() {
                    Ok(InstructionAction::Return(SymValue::Concrete(
                        Value::Undefined,
                    )))
                } else {
                    Ok(InstructionAction::Continue)
                }
            }

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
            self.set_register_sym(
                dest,
                SymValue::Concrete(Value::Undefined),
                Definedness::Undefined,
                None,
            );
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
                    self.set_register_sym(
                        dest,
                        SymValue::Concrete(Value::Undefined),
                        Definedness::Undefined,
                        None,
                    );
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
            self.set_register_sym(
                dest,
                SymValue::Concrete(Value::Undefined),
                Definedness::Undefined,
                None,
            );
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
            self.set_register_sym(
                dest,
                SymValue::Concrete(Value::Undefined),
                Definedness::Undefined,
                None,
            );
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
            self.set_register_sym(
                dest,
                SymValue::Concrete(Value::Undefined),
                Definedness::Undefined,
                None,
            );
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
                        self.set_register_sym(
                            dest,
                            SymValue::Bool(result),
                            Definedness::Defined,
                            None,
                        );
                    }
                    SymValue::Concrete(Value::Undefined) => {
                        // Path placeholder that wasn't promoted (shouldn't happen after promotion above).
                        // `not undefined` → true.
                        self.set_register_concrete(dest, Value::Bool(true));
                    }
                    _ => {
                        let val = a.value.to_z3_bool(self.ctx)?;
                        let result = def_bool.ite(&val.not(), &Z3Bool::from_bool(self.ctx, true));
                        self.set_register_sym(
                            dest,
                            SymValue::Bool(result),
                            Definedness::Defined,
                            None,
                        );
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
            .ok_or_else(|| anyhow::anyhow!("Invalid chained index params index {}", params_index))?
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
                    LiteralOrRegister::Literal(idx) => self.program.literals[*idx as usize].clone(),
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
        self.registers
            .resize_with(num_regs.max(self.registers.len()), SymRegister::undefined);
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
                let destr_ok =
                    if let Some(Some(destr_pc)) = rule_info.destructuring_blocks.get(def_idx) {
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
                                self.constraints
                                    .push(both_active.implies(&v_i._eq(&v_j).not()));
                            }
                            (Some(ValueSort::Int), Some(ValueSort::Int)) => {
                                let v_i = self.registry.get_int(path_i);
                                let v_j = self.registry.get_int(path_j);
                                self.constraints
                                    .push(both_active.implies(&v_i._eq(&v_j).not()));
                            }
                            (Some(ValueSort::Bool), Some(ValueSort::Bool)) => {
                                let v_i = self.registry.get_bool(path_i);
                                let v_j = self.registry.get_bool(path_j);
                                self.constraints
                                    .push(both_active.implies(&v_i._eq(&v_j).not()));
                            }
                            (Some(ValueSort::Real), Some(ValueSort::Real)) => {
                                let v_i = self.registry.get_real(path_i);
                                let v_j = self.registry.get_real(path_j);
                                self.constraints
                                    .push(both_active.implies(&v_i._eq(&v_j).not()));
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
            self.constraints
                .push(cardinality.ge(&Z3Int::from_i64(self.ctx, 0)));

            let result_value =
                if collected_partial_set_elements.is_empty() {
                    self.warnings.push(format!(
                    "PC {}: Partial set rule {} → {} body conds, no element paths → SetCardinality",
                    self.pc, rule_index, body_results.len()
                ));
                    SymValue::SetCardinality(cardinality)
                } else {
                    self.warnings.push(format!(
                        "PC {}: Partial set rule {} → {} body conds, {} element(s) → SymbolicSet",
                        self.pc,
                        rule_index,
                        body_results.len(),
                        collected_partial_set_elements.len()
                    ));
                    SymValue::SymbolicSet {
                        cardinality,
                        elements: collected_partial_set_elements,
                    }
                };

            if !is_function {
                self.rule_cache
                    .insert(rule_index, (result_value.clone(), Definedness::Defined));
            }

            self.set_register_sym(dest, result_value, Definedness::Defined, None);
            return Ok(InstructionAction::Continue);
        }

        // -------------------------------------------------------------------
        // Complete rules: combine body results.
        // -------------------------------------------------------------------
        let (final_value, final_defined) = if body_results.is_empty() {
            // No bodies → Undefined.
            (SymValue::Concrete(Value::Undefined), Definedness::Undefined)
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
                Definedness::Undefined => (SymValue::Concrete(default_val), Definedness::Defined),
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
                RuleType::PartialObject if final_defined.is_undefined() => (
                    SymValue::Concrete(Value::new_object()),
                    Definedness::Defined,
                ),
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
            // Check if all values (and keys for non-literal fields) are concrete.
            let all_concrete = params.literal_key_field_pairs().iter().all(|&(_, vr)| {
                let reg = self.get_register(vr);
                reg.value.is_concrete() && reg.source_path.is_none()
            }) && params.field_pairs().iter().all(|&(kr, vr)| {
                let k = self.get_register(kr);
                let v = self.get_register(vr);
                k.value.is_concrete()
                    && k.source_path.is_none()
                    && v.value.is_concrete()
                    && v.source_path.is_none()
            });

            if all_concrete {
                // Build a concrete object with actual values from registers.
                let mut obj = alloc::collections::BTreeMap::new();

                // Literal key fields: look up the key from the program's literals table.
                for &(lit_key_idx, value_reg) in params.literal_key_field_pairs() {
                    if let Some(key) = self.program.literals.get(lit_key_idx as usize) {
                        if let SymValue::Concrete(v) = &self.get_register(value_reg).value {
                            obj.insert(key.clone(), v.clone());
                        }
                    }
                }

                // Non-literal key fields.
                for &(key_reg, value_reg) in params.field_pairs() {
                    if let (SymValue::Concrete(k), SymValue::Concrete(v)) = (
                        &self.get_register(key_reg).value,
                        &self.get_register(value_reg).value,
                    ) {
                        obj.insert(k.clone(), v.clone());
                    }
                }

                self.set_register_concrete(params.dest, Value::Object(crate::Rc::new(obj)));
            } else {
                // Some values are symbolic — fall back to template but populate
                // the concrete fields we can.
                let template = self
                    .program
                    .literals
                    .get(params.template_literal_idx as usize)
                    .cloned()
                    .unwrap_or_else(Value::new_object);

                let mut obj = match template {
                    Value::Object(o) => (*o).clone(),
                    _ => alloc::collections::BTreeMap::new(),
                };

                for &(lit_key_idx, value_reg) in params.literal_key_field_pairs() {
                    if let Some(key) = self.program.literals.get(lit_key_idx as usize) {
                        let reg = self.get_register(value_reg);
                        if reg.value.is_concrete() && reg.source_path.is_none() {
                            if let SymValue::Concrete(v) = &reg.value {
                                obj.insert(key.clone(), v.clone());
                            }
                        }
                        // Symbolic values left as Undefined in template for now.
                    }
                }

                self.set_register_concrete(params.dest, Value::Object(crate::Rc::new(obj)));
            }
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
            // Check if all elements are truly concrete (not path placeholders).
            let all_concrete = params.element_registers().iter().all(|&r| {
                let reg = self.get_register(r);
                reg.value.is_concrete() && reg.source_path.is_none()
            });

            if all_concrete {
                let mut elements = Vec::new();
                for &reg in params.element_registers() {
                    if let SymValue::Concrete(v) = &self.get_register(reg).value {
                        elements.push(v.clone());
                    }
                }
                self.set_register_concrete(params.dest, Value::from_array(elements));
            } else {
                // Build a SymbolicSet so Contains and Count work on arrays
                // with symbolic elements.
                let mut sym_elements = Vec::new();
                for (i, &reg) in params.element_registers().iter().enumerate() {
                    let r = self.get_register(reg);
                    let elem_path = r
                        .source_path
                        .clone()
                        .unwrap_or_else(|| format!("arr_create_{}_{}", self.pc, i));
                    let elem_sort = if r.source_path.is_some() {
                        self.registry
                            .get(elem_path.as_str())
                            .map(|e| e.sort)
                            .unwrap_or(r.value.sort())
                    } else {
                        r.value.sort()
                    };
                    let cond = r.defined.to_z3_bool(self.ctx);
                    sym_elements.push(SymSetElement {
                        condition: cond,
                        element_path: elem_path.clone(),
                        key_path: elem_path,
                        element_sort: elem_sort,
                    });
                }

                let zero = Z3Int::from_i64(self.ctx, 0);
                let one = Z3Int::from_i64(self.ctx, 1);
                let mut sum = Z3Int::from_i64(self.ctx, 0);
                for elem in &sym_elements {
                    let contrib = elem.condition.ite(&one, &zero);
                    sum = Z3Int::add(self.ctx, &[&sum, &contrib]);
                }

                self.set_register_sym(
                    params.dest,
                    SymValue::SymbolicSet {
                        cardinality: sum,
                        elements: sym_elements,
                    },
                    Definedness::Defined,
                    None,
                );
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
            // Check if all elements are truly concrete (not path placeholders).
            let all_concrete = params.element_registers().iter().all(|&r| {
                let reg = self.get_register(r);
                reg.value.is_concrete() && reg.source_path.is_none()
            });

            if all_concrete {
                let mut set = alloc::collections::BTreeSet::new();
                for &reg in params.element_registers() {
                    if let SymValue::Concrete(v) = &self.get_register(reg).value {
                        set.insert(v.clone());
                    }
                }
                self.set_register_concrete(params.dest, Value::Set(crate::Rc::new(set)));
            } else {
                // Build a SymbolicSet so Contains and Count work.
                let mut sym_elements = Vec::new();
                for (i, &reg) in params.element_registers().iter().enumerate() {
                    let r = self.get_register(reg);
                    let elem_path = r
                        .source_path
                        .clone()
                        .unwrap_or_else(|| format!("set_create_{}_{}", self.pc, i));
                    let elem_sort = if r.source_path.is_some() {
                        self.registry
                            .get(elem_path.as_str())
                            .map(|e| e.sort)
                            .unwrap_or(r.value.sort())
                    } else {
                        r.value.sort()
                    };
                    let cond = r.defined.to_z3_bool(self.ctx);
                    sym_elements.push(SymSetElement {
                        condition: cond,
                        element_path: elem_path.clone(),
                        key_path: elem_path,
                        element_sort: elem_sort,
                    });
                }

                let zero = Z3Int::from_i64(self.ctx, 0);
                let one = Z3Int::from_i64(self.ctx, 1);
                let mut sum = Z3Int::from_i64(self.ctx, 0);
                for elem in &sym_elements {
                    let contrib = elem.condition.ite(&one, &zero);
                    sum = Z3Int::add(self.ctx, &[&sum, &contrib]);
                }

                self.set_register_sym(
                    params.dest,
                    SymValue::SymbolicSet {
                        cardinality: sum,
                        elements: sym_elements,
                    },
                    Definedness::Defined,
                    None,
                );
            }
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

                self.set_register_sym(dest, SymValue::Bool(result), result_defined.clone(), None);
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
                    let eq = self.build_path_equality(&elem.key_path, cmp_sort, &val_z3)?;
                    disjuncts.push(Z3Bool::and(self.ctx, &[&elem.condition, &eq]));
                }

                let result = if disjuncts.is_empty() {
                    Z3Bool::from_bool(self.ctx, false)
                } else {
                    let refs: Vec<&Z3Bool> = disjuncts.iter().collect();
                    Z3Bool::or(self.ctx, &refs)
                };

                self.set_register_sym(dest, SymValue::Bool(result), result_defined.clone(), None);
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
                    Value::Object(o) => o.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                    Value::Set(s) => s.iter().map(|v| (v.clone(), v.clone())).collect(),
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
                self.path_condition =
                    Z3Bool::and(self.ctx, &[&saved_path_cond, &element.condition]);

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
    // Comprehensions
    // -----------------------------------------------------------------------

    fn translate_comprehension(
        &mut self,
        params_index: u16,
    ) -> anyhow::Result<InstructionAction<'ctx>> {
        use crate::rvm::instructions::ComprehensionMode;

        let params = self
            .program
            .instruction_data
            .get_comprehension_begin_params(params_index)
            .ok_or_else(|| anyhow::anyhow!("Invalid comprehension params index {}", params_index))?
            .clone();

        let body_start = params.body_start as usize;
        let compr_end = params.comprehension_end as usize;
        let mode = params.mode.clone();
        let result_reg = params.result_reg;

        // Push an accumulator for this comprehension.
        self.comprehension_stack.push(ComprehensionAccumulator {
            mode: mode.clone(),
            result_reg,
            yields: Vec::new(),
        });

        // Save outer state.
        let saved_path_cond = self.path_condition.clone();

        // Translate the body. The body contains LoopStart (which unrolls
        // iterations) and ComprehensionYield (which records elements).
        // ComprehensionEnd returns Return to stop the block cleanly.
        let _result = self.translate_block(body_start);

        // Pop the accumulator with all recorded yields.
        let acc = self
            .comprehension_stack
            .pop()
            .expect("comprehension stack underflow");

        // Restore path condition — comprehensions always produce a result
        // (possibly empty), so they don't narrow the path condition.
        self.path_condition = saved_path_cond;

        // Build the result based on mode and yields.
        match mode {
            ComprehensionMode::Set => {
                self.build_set_comprehension_result(result_reg, &acc)?;
            }
            ComprehensionMode::Array => {
                self.build_array_comprehension_result(result_reg, &acc)?;
            }
            ComprehensionMode::Object => {
                self.build_object_comprehension_result(result_reg, &acc)?;
            }
        }

        self.warnings.push(format!(
            "PC {}: Comprehension ({:?}) with {} yield(s)",
            self.pc,
            acc.mode,
            acc.yields.len()
        ));

        Ok(InstructionAction::Jump(compr_end))
    }

    /// Build a SymbolicSet from set-comprehension yields.
    fn build_set_comprehension_result(
        &mut self,
        result_reg: u8,
        acc: &ComprehensionAccumulator<'ctx>,
    ) -> anyhow::Result<()> {
        if acc.yields.is_empty() {
            // Empty comprehension → empty set.
            self.set_register_concrete(result_reg, Value::new_set());
            return Ok(());
        }

        // Check if all yields are truly concrete (not path placeholders).
        let all_concrete = acc
            .yields
            .iter()
            .all(|y| y.value.value.is_concrete() && y.value.source_path.is_none());
        if all_concrete {
            // Build a concrete set.
            let mut set = alloc::collections::BTreeSet::new();
            for entry in &acc.yields {
                if let SymValue::Concrete(v) = &entry.value.value {
                    if *v != Value::Undefined {
                        set.insert(v.clone());
                    }
                }
            }
            self.set_register_concrete(result_reg, Value::Set(crate::Rc::new(set)));
            return Ok(());
        }

        // Build a SymbolicSet from symbolic yields.
        let mut elements = Vec::new();
        for entry in &acc.yields {
            let elem_path = entry
                .value
                .source_path
                .clone()
                .unwrap_or_else(|| format!("compr_set_{}_{}", self.pc, elements.len()));
            // Get sort from the registry if the value is a path placeholder.
            let elem_sort = if entry.value.source_path.is_some() {
                self.registry
                    .get(elem_path.as_str())
                    .map(|e| e.sort)
                    .unwrap_or(entry.value.value.sort())
            } else {
                entry.value.value.sort()
            };
            elements.push(SymSetElement {
                condition: entry.condition.clone(),
                element_path: elem_path.clone(),
                key_path: elem_path,
                element_sort: elem_sort,
            });
        }

        // Compute cardinality: count of elements whose condition is true.
        // For set semantics, group by key_path and count distinct groups.
        let zero = Z3Int::from_i64(self.ctx, 0);
        let one = Z3Int::from_i64(self.ctx, 1);
        let mut sum = Z3Int::from_i64(self.ctx, 0);
        for elem in &elements {
            let contrib = elem.condition.ite(&one, &zero);
            sum = Z3Int::add(self.ctx, &[&sum, &contrib]);
        }

        self.set_register_sym(
            result_reg,
            SymValue::SymbolicSet {
                cardinality: sum,
                elements,
            },
            Definedness::Defined,
            None,
        );
        Ok(())
    }

    /// Build a concrete or symbolic array from array-comprehension yields.
    fn build_array_comprehension_result(
        &mut self,
        result_reg: u8,
        acc: &ComprehensionAccumulator<'ctx>,
    ) -> anyhow::Result<()> {
        if acc.yields.is_empty() {
            self.set_register_concrete(result_reg, Value::new_array());
            return Ok(());
        }

        // Check if all yields are truly concrete (not path placeholders).
        let all_concrete = acc
            .yields
            .iter()
            .all(|y| y.value.value.is_concrete() && y.value.source_path.is_none());
        if all_concrete {
            let mut arr = Vec::new();
            for entry in &acc.yields {
                if let SymValue::Concrete(v) = &entry.value.value {
                    if *v != Value::Undefined {
                        arr.push(v.clone());
                    }
                }
            }
            self.set_register_concrete(result_reg, Value::Array(crate::Rc::new(arr)));
            return Ok(());
        }

        // For symbolic arrays, model as a SymbolicSet (supports Contains
        // and count). Array ordering is not tracked symbolically.
        let mut elements = Vec::new();
        for (i, entry) in acc.yields.iter().enumerate() {
            let elem_path = entry
                .value
                .source_path
                .clone()
                .unwrap_or_else(|| format!("compr_arr_{}_{}", self.pc, i));
            let elem_sort = if entry.value.source_path.is_some() {
                self.registry
                    .get(elem_path.as_str())
                    .map(|e| e.sort)
                    .unwrap_or(entry.value.value.sort())
            } else {
                entry.value.value.sort()
            };
            elements.push(SymSetElement {
                condition: entry.condition.clone(),
                element_path: elem_path.clone(),
                key_path: elem_path,
                element_sort: elem_sort,
            });
        }

        let zero = Z3Int::from_i64(self.ctx, 0);
        let one = Z3Int::from_i64(self.ctx, 1);
        let mut sum = Z3Int::from_i64(self.ctx, 0);
        for elem in &elements {
            let contrib = elem.condition.ite(&one, &zero);
            sum = Z3Int::add(self.ctx, &[&sum, &contrib]);
        }

        self.set_register_sym(
            result_reg,
            SymValue::SymbolicSet {
                cardinality: sum,
                elements,
            },
            Definedness::Defined,
            None,
        );
        Ok(())
    }

    /// Build a concrete or symbolic object from object-comprehension yields.
    fn build_object_comprehension_result(
        &mut self,
        result_reg: u8,
        acc: &ComprehensionAccumulator<'ctx>,
    ) -> anyhow::Result<()> {
        if acc.yields.is_empty() {
            self.set_register_concrete(
                result_reg,
                Value::Object(crate::Rc::new(alloc::collections::BTreeMap::new())),
            );
            return Ok(());
        }

        // Check if all yields (keys and values) are truly concrete (not path placeholders).
        let all_concrete = acc.yields.iter().all(|y| {
            y.value.value.is_concrete()
                && y.value.source_path.is_none()
                && y.key
                    .as_ref()
                    .map_or(true, |k| k.value.is_concrete() && k.source_path.is_none())
        });
        if all_concrete {
            let mut obj = alloc::collections::BTreeMap::new();
            for entry in &acc.yields {
                if let (SymValue::Concrete(v), Some(k_reg)) = (&entry.value.value, &entry.key) {
                    if let SymValue::Concrete(k) = &k_reg.value {
                        if *k != Value::Undefined && *v != Value::Undefined {
                            obj.insert(k.clone(), v.clone());
                        }
                    }
                }
            }
            self.set_register_concrete(result_reg, Value::Object(crate::Rc::new(obj)));
            return Ok(());
        }

        // For symbolic objects, model similarly to a SymbolicSet.
        // The elements represent key-value pairs; consumers can iterate or
        // check membership based on keys.
        let mut elements = Vec::new();
        for (i, entry) in acc.yields.iter().enumerate() {
            let elem_path = entry
                .value
                .source_path
                .clone()
                .unwrap_or_else(|| format!("compr_obj_{}_{}", self.pc, i));
            let elem_sort = if entry.value.source_path.is_some() {
                self.registry
                    .get(elem_path.as_str())
                    .map(|e| e.sort)
                    .unwrap_or(entry.value.value.sort())
            } else {
                entry.value.value.sort()
            };
            elements.push(SymSetElement {
                condition: entry.condition.clone(),
                element_path: elem_path.clone(),
                key_path: elem_path,
                element_sort: elem_sort,
            });
        }

        let zero = Z3Int::from_i64(self.ctx, 0);
        let one = Z3Int::from_i64(self.ctx, 1);
        let mut sum = Z3Int::from_i64(self.ctx, 0);
        for elem in &elements {
            let contrib = elem.condition.ite(&one, &zero);
            sum = Z3Int::add(self.ctx, &[&sum, &contrib]);
        }

        self.set_register_sym(
            result_reg,
            SymValue::SymbolicSet {
                cardinality: sum,
                elements,
            },
            Definedness::Defined,
            None,
        );
        Ok(())
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
            .ok_or_else(|| anyhow::anyhow!("Builtin index {} out of bounds", params.builtin_index))?
            .clone();

        let builtin_name = builtin_info.name.as_str();

        // Handle well-known builtins with proper Z3 semantics.
        match builtin_name {
            // ---------------------------------------------------------------
            // count — special handling (SetCardinality, concrete, string len)
            // ---------------------------------------------------------------
            "count" => {
                self.translate_builtin_count(&params)?;
            }

            // ---------------------------------------------------------------
            // trace — always returns true
            // ---------------------------------------------------------------
            "trace" => {
                self.set_register_concrete(params.dest, Value::Bool(true));
            }

            // ---------------------------------------------------------------
            // String builtins with Z3 string theory semantics
            // ---------------------------------------------------------------
            "startswith" => {
                self.translate_builtin_string_bool(&params, builtin_name, |s, arg| {
                    // Z3: arg.prefix(&s) checks if arg is a prefix of s
                    // OPA: startswith(s, prefix) → prefix.prefix(&s)
                    arg.prefix(&s)
                })?;
            }
            "endswith" => {
                self.translate_builtin_string_bool(&params, builtin_name, |s, arg| {
                    // OPA: endswith(s, suffix) → suffix.suffix(&s)
                    arg.suffix(&s)
                })?;
            }
            "contains" => {
                self.translate_builtin_string_bool(&params, builtin_name, |s, arg| {
                    // OPA: contains(s, substr) → s.contains(&substr)
                    s.contains(&arg)
                })?;
            }
            "indexof" => {
                self.translate_builtin_indexof(&params)?;
            }
            "replace" => {
                self.translate_builtin_replace(&params)?;
            }
            "substring" => {
                self.translate_builtin_substring(&params)?;
            }
            "trim_prefix" => {
                self.translate_builtin_trim_prefix(&params)?;
            }
            "trim_suffix" => {
                self.translate_builtin_trim_suffix(&params)?;
            }

            // ---------------------------------------------------------------
            // abs — ite(x >= 0, x, -x)
            // ---------------------------------------------------------------
            "abs" => {
                self.translate_builtin_abs(&params)?;
            }

            // ---------------------------------------------------------------
            // is_* type checks — resolve from sort when possible
            // ---------------------------------------------------------------
            "is_string" => {
                self.translate_builtin_is_type(&params, builtin_name, ValueSort::String)?;
            }
            "is_number" => {
                // Numbers can be Int or Real.
                self.translate_builtin_is_number(&params)?;
            }
            "is_boolean" => {
                self.translate_builtin_is_type(&params, builtin_name, ValueSort::Bool)?;
            }
            "is_array" | "is_set" | "is_object" | "is_null" => {
                // These types don't have a corresponding ValueSort in our model.
                // For concrete values, we can check directly; otherwise unconstrained.
                self.translate_builtin_is_collection_type(&params, builtin_name)?;
            }

            // ---------------------------------------------------------------
            // bits.* — Z3 bitvector theory (64-bit)
            // ---------------------------------------------------------------
            "bits.and" => {
                self.translate_builtin_bitwise_binop(&params, builtin_name, |a, b| a.bvand(&b))?;
            }
            "bits.or" => {
                self.translate_builtin_bitwise_binop(&params, builtin_name, |a, b| a.bvor(&b))?;
            }
            "bits.xor" => {
                self.translate_builtin_bitwise_binop(&params, builtin_name, |a, b| a.bvxor(&b))?;
            }
            "bits.negate" => {
                self.translate_builtin_bitwise_unop(&params, builtin_name, |a| a.bvnot())?;
            }
            "bits.lsh" => {
                self.translate_builtin_bitwise_binop(&params, builtin_name, |a, b| a.bvshl(&b))?;
            }
            "bits.rsh" => {
                self.translate_builtin_bitwise_binop(&params, builtin_name, |a, b| a.bvlshr(&b))?;
            }

            // ---------------------------------------------------------------
            // Cedar builtins
            // ---------------------------------------------------------------
            "cedar.like" => {
                self.translate_builtin_cedar_like(&params)?;
            }
            "cedar.is" => {
                self.translate_builtin_cedar_is(&params)?;
            }
            "cedar.in" => {
                self.translate_builtin_cedar_in(&params)?;
            }
            "cedar.in_set" => {
                self.translate_builtin_cedar_in_set(&params)?;
            }
            "cedar.has" => {
                self.translate_builtin_cedar_has(&params)?;
            }
            "cedar.attr" => {
                self.translate_builtin_cedar_attr(&params)?;
            }

            // ---------------------------------------------------------------
            // Boolean-returning builtins (unconstrained)
            // ---------------------------------------------------------------
            "regex.match"
            | "io.jwt.verify_rs256"
            | "io.jwt.verify_rs384"
            | "io.jwt.verify_rs512"
            | "io.jwt.verify_es256"
            | "io.jwt.verify_es384"
            | "io.jwt.verify_es512"
            | "io.jwt.verify_hs256"
            | "io.jwt.verify_hs384"
            | "io.jwt.verify_hs512" => {
                self.warnings.push(format!(
                    "PC {}: Builtin '{}' modeled as unconstrained Bool",
                    self.pc, builtin_name
                ));
                let name = format!("builtin_{}_{}", builtin_name.replace('.', "_"), self.pc);
                let var = Z3Bool::new_const(self.ctx, name.as_str());
                self.set_register_sym(params.dest, SymValue::Bool(var), Definedness::Defined, None);
            }

            // ---------------------------------------------------------------
            // Numeric-returning builtins (unconstrained)
            // ---------------------------------------------------------------
            "to_number" => {
                self.translate_builtin_to_number(&params)?;
            }
            "sum" | "product" | "min" | "max" | "ceil" | "floor" | "round" => {
                self.warnings.push(format!(
                    "PC {}: Builtin '{}' modeled as unconstrained Int",
                    self.pc, builtin_name
                ));
                let name = format!("builtin_{}_{}", builtin_name.replace('.', "_"), self.pc);
                let var = Z3Int::new_const(self.ctx, name.as_str());
                self.set_register_sym(params.dest, SymValue::Int(var), Definedness::Defined, None);
            }

            // ---------------------------------------------------------------
            // Default: string return (most builtins return strings or complex values)
            // ---------------------------------------------------------------
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

    // ===================================================================
    // Builtin implementation helpers
    // ===================================================================

    /// `count(x)` — returns the cardinality/length of a collection or string.
    fn translate_builtin_count(
        &mut self,
        params: &crate::rvm::instructions::BuiltinCallParams,
    ) -> anyhow::Result<()> {
        if params.arg_count() >= 1 {
            let arg_reg = params.args[0];
            let arg = self.get_register(arg_reg).clone();

            // SymbolicSet / SetCardinality → extract the Z3 Int directly.
            if let Some(card) = arg.value.as_set_cardinality() {
                self.set_register_sym(
                    params.dest,
                    SymValue::Int(card.clone()),
                    Definedness::Defined,
                    None,
                );
                return Ok(());
            }

            // Concrete collection → concrete count.
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
                    return Ok(());
                }
            }

            // Symbolic string → Z3 str.len via z3-sys FFI.
            if let Ok(z3_str) = arg.value.to_z3_string(self.ctx) {
                let str_len = self.z3_string_length(&z3_str);
                self.set_register_sym(
                    params.dest,
                    SymValue::Int(str_len),
                    Definedness::Defined,
                    None,
                );
                return Ok(());
            }

            // Path placeholder for a string → look up in registry.
            if let Some(path) = &arg.source_path {
                let sort = self.registry.get_sort(path);
                if sort == Some(ValueSort::String) {
                    let z3_str = self.registry.get_string(path);
                    let str_len = self.z3_string_length(&z3_str);
                    self.set_register_sym(
                        params.dest,
                        SymValue::Int(str_len),
                        Definedness::Defined,
                        None,
                    );
                    return Ok(());
                }
            }
        }
        // Fallback: fresh non-negative Int.
        self.warnings.push(format!(
            "PC {}: Builtin 'count' on symbolic collection → unconstrained Int",
            self.pc
        ));
        let name = format!("builtin_count_{}", self.pc);
        let var = Z3Int::new_const(self.ctx, name.as_str());
        let zero = Z3Int::from_i64(self.ctx, 0);
        self.constraints.push(var.ge(&zero));
        self.set_register_sym(params.dest, SymValue::Int(var), Definedness::Defined, None);
        Ok(())
    }

    /// Resolve a builtin argument to a Z3 String, handling concrete values,
    /// symbolic strings, and path-placeholder registers.
    fn resolve_arg_as_z3_string(&mut self, reg: u8) -> Option<Z3String<'ctx>> {
        let r = self.get_register(reg).clone();
        // Direct Z3 string or concrete string.
        if let Ok(s) = r.value.to_z3_string(self.ctx) {
            return Some(s);
        }
        // Path placeholder → look up in registry.
        if let Some(path) = &r.source_path {
            let sort = self.registry.get_sort(path);
            if sort == Some(ValueSort::String) || sort.is_none() || sort == Some(ValueSort::Unknown)
            {
                // Get or create as String (reasonable default for string builtins).
                return Some(self.registry.get_string(path));
            }
        }
        None
    }

    /// Resolve a builtin argument to a Z3 Int, handling concrete values,
    /// symbolic ints, and path-placeholder registers.
    fn resolve_arg_as_z3_int(&mut self, reg: u8) -> Option<Z3Int<'ctx>> {
        let r = self.get_register(reg).clone();
        if let Ok(i) = r.value.to_z3_int(self.ctx) {
            return Some(i);
        }
        if let Some(path) = &r.source_path {
            let sort = self.registry.get_sort(path);
            if sort == Some(ValueSort::Int) || sort.is_none() || sort == Some(ValueSort::Unknown) {
                return Some(self.registry.get_int(path));
            }
        }
        None
    }

    /// Helper for 2-arg string→bool builtins (startswith, endswith, contains).
    ///
    /// If both args can be promoted to Z3 strings, applies `f(arg0, arg1)` to
    /// produce a Z3 Bool. If either concrete string is involved and the other
    /// is also concrete, evaluates directly. Falls back to unconstrained Bool.
    fn translate_builtin_string_bool(
        &mut self,
        params: &crate::rvm::instructions::BuiltinCallParams,
        name: &str,
        f: impl FnOnce(Z3String<'ctx>, Z3String<'ctx>) -> Z3Bool<'ctx>,
    ) -> anyhow::Result<()> {
        if params.arg_count() >= 2 {
            // Try concrete evaluation first.
            let a0 = self.get_register(params.args[0]).clone();
            let a1 = self.get_register(params.args[1]).clone();
            if let (SymValue::Concrete(Value::String(s0)), SymValue::Concrete(Value::String(s1))) =
                (&a0.value, &a1.value)
            {
                let result = match name {
                    "startswith" => s0.starts_with(s1.as_ref()),
                    "endswith" => s0.ends_with(s1.as_ref()),
                    "contains" => s0.contains(s1.as_ref()),
                    _ => false,
                };
                self.set_register_concrete(params.dest, Value::Bool(result));
                return Ok(());
            }

            // Try Z3 string theory.
            let z0 = self.resolve_arg_as_z3_string(params.args[0]);
            let z1 = self.resolve_arg_as_z3_string(params.args[1]);
            if let (Some(s0), Some(s1)) = (z0, z1) {
                let result = f(s0, s1);
                self.set_register_sym(
                    params.dest,
                    SymValue::Bool(result),
                    Definedness::Defined,
                    None,
                );
                return Ok(());
            }
        }
        // Fallback: unconstrained Bool.
        self.warnings.push(format!(
            "PC {}: Builtin '{}' — cannot resolve args, unconstrained Bool",
            self.pc, name
        ));
        let vname = format!("builtin_{}_{}", name, self.pc);
        let var = Z3Bool::new_const(self.ctx, vname.as_str());
        self.set_register_sym(params.dest, SymValue::Bool(var), Definedness::Defined, None);
        Ok(())
    }

    /// `indexof(s, substr)` → Z3 `str.indexof(s, substr, 0)`.
    /// Returns Int; -1 if not found.
    fn translate_builtin_indexof(
        &mut self,
        params: &crate::rvm::instructions::BuiltinCallParams,
    ) -> anyhow::Result<()> {
        if params.arg_count() >= 2 {
            // Concrete evaluation.
            let a0 = self.get_register(params.args[0]).clone();
            let a1 = self.get_register(params.args[1]).clone();
            if let (SymValue::Concrete(Value::String(s0)), SymValue::Concrete(Value::String(s1))) =
                (&a0.value, &a1.value)
            {
                let idx = s0.find(s1.as_ref()).map(|i| i as i64).unwrap_or(-1);
                self.set_register_concrete(params.dest, Value::from(idx));
                return Ok(());
            }

            let z0 = self.resolve_arg_as_z3_string(params.args[0]);
            let z1 = self.resolve_arg_as_z3_string(params.args[1]);
            if let (Some(s0), Some(s1)) = (z0, z1) {
                let zero = Z3Int::from_i64(self.ctx, 0);
                let result = self.z3_string_indexof(&s0, &s1, &zero);
                self.set_register_sym(
                    params.dest,
                    SymValue::Int(result),
                    Definedness::Defined,
                    None,
                );
                return Ok(());
            }
        }
        // Fallback: unconstrained Int.
        self.warnings.push(format!(
            "PC {}: Builtin 'indexof' — cannot resolve args, unconstrained Int",
            self.pc
        ));
        let name = format!("builtin_indexof_{}", self.pc);
        let var = Z3Int::new_const(self.ctx, name.as_str());
        self.set_register_sym(params.dest, SymValue::Int(var), Definedness::Defined, None);
        Ok(())
    }

    /// `replace(s, old, new)` → Z3 `str.replace(s, old, new)`.
    /// Replaces first occurrence.
    fn translate_builtin_replace(
        &mut self,
        params: &crate::rvm::instructions::BuiltinCallParams,
    ) -> anyhow::Result<()> {
        if params.arg_count() >= 3 {
            // Concrete evaluation.
            let a0 = self.get_register(params.args[0]).clone();
            let a1 = self.get_register(params.args[1]).clone();
            let a2 = self.get_register(params.args[2]).clone();
            if let (
                SymValue::Concrete(Value::String(s0)),
                SymValue::Concrete(Value::String(s1)),
                SymValue::Concrete(Value::String(s2)),
            ) = (&a0.value, &a1.value, &a2.value)
            {
                let result = s0.replacen(s1.as_ref(), s2.as_ref(), 1);
                self.set_register_concrete(params.dest, Value::String(result.into()));
                return Ok(());
            }

            let z0 = self.resolve_arg_as_z3_string(params.args[0]);
            let z1 = self.resolve_arg_as_z3_string(params.args[1]);
            let z2 = self.resolve_arg_as_z3_string(params.args[2]);
            if let (Some(s0), Some(s1), Some(s2)) = (z0, z1, z2) {
                let result = self.z3_string_replace(&s0, &s1, &s2);
                self.set_register_sym(
                    params.dest,
                    SymValue::Str(result),
                    Definedness::Defined,
                    None,
                );
                return Ok(());
            }
        }
        // Fallback: unconstrained String.
        self.warnings.push(format!(
            "PC {}: Builtin 'replace' — cannot resolve args, unconstrained String",
            self.pc
        ));
        let name = format!("builtin_replace_{}", self.pc);
        let var = Z3String::new_const(self.ctx, name.as_str());
        self.set_register_sym(params.dest, SymValue::Str(var), Definedness::Defined, None);
        Ok(())
    }

    /// `substring(s, offset, length)` → Z3 `str.substr(s, offset, length)`.
    /// OPA semantics: if length < 0, take to end of string.
    fn translate_builtin_substring(
        &mut self,
        params: &crate::rvm::instructions::BuiltinCallParams,
    ) -> anyhow::Result<()> {
        if params.arg_count() >= 3 {
            // Concrete evaluation.
            let a0 = self.get_register(params.args[0]).clone();
            let a1 = self.get_register(params.args[1]).clone();
            let a2 = self.get_register(params.args[2]).clone();
            if let (
                SymValue::Concrete(Value::String(s0)),
                SymValue::Concrete(Value::Number(n1)),
                SymValue::Concrete(Value::Number(n2)),
            ) = (&a0.value, &a1.value, &a2.value)
            {
                let offset = n1.as_i64().unwrap_or(0) as usize;
                let length = n2.as_i64().unwrap_or(-1);
                let s = s0.as_ref();
                let result = if offset >= s.len() {
                    ""
                } else if length < 0 {
                    &s[offset..]
                } else {
                    let end = (offset + length as usize).min(s.len());
                    &s[offset..end]
                };
                self.set_register_concrete(params.dest, Value::String(result.into()));
                return Ok(());
            }

            let z0 = self.resolve_arg_as_z3_string(params.args[0]);
            let z1 = self.resolve_arg_as_z3_int(params.args[1]);
            let z2 = self.resolve_arg_as_z3_int(params.args[2]);
            if let (Some(s0), Some(i_offset), Some(i_length)) = (z0, z1, z2) {
                // For negative length, use str.len(s) - offset as the length.
                // We use ite: if length < 0 then str.len(s) - offset else length
                let zero = Z3Int::from_i64(self.ctx, 0);
                let str_len = self.z3_string_length(&s0);
                let effective_len = i_length
                    .lt(&zero)
                    .ite(&Z3Int::sub(self.ctx, &[&str_len, &i_offset]), &i_length);
                let result = self.z3_string_extract(&s0, &i_offset, &effective_len);
                self.set_register_sym(
                    params.dest,
                    SymValue::Str(result),
                    Definedness::Defined,
                    None,
                );
                return Ok(());
            }
        }
        // Fallback: unconstrained String.
        self.warnings.push(format!(
            "PC {}: Builtin 'substring' — cannot resolve args, unconstrained String",
            self.pc
        ));
        let name = format!("builtin_substring_{}", self.pc);
        let var = Z3String::new_const(self.ctx, name.as_str());
        self.set_register_sym(params.dest, SymValue::Str(var), Definedness::Defined, None);
        Ok(())
    }

    /// `trim_prefix(s, prefix)` → if startswith(s, prefix): substr(s, len(prefix), len(s)-len(prefix)) else s
    fn translate_builtin_trim_prefix(
        &mut self,
        params: &crate::rvm::instructions::BuiltinCallParams,
    ) -> anyhow::Result<()> {
        if params.arg_count() >= 2 {
            // Concrete evaluation.
            let a0 = self.get_register(params.args[0]).clone();
            let a1 = self.get_register(params.args[1]).clone();
            if let (SymValue::Concrete(Value::String(s0)), SymValue::Concrete(Value::String(s1))) =
                (&a0.value, &a1.value)
            {
                let result = s0.strip_prefix(s1.as_ref()).unwrap_or(s0.as_ref());
                self.set_register_concrete(params.dest, Value::String(result.into()));
                return Ok(());
            }

            let z0 = self.resolve_arg_as_z3_string(params.args[0]);
            let z1 = self.resolve_arg_as_z3_string(params.args[1]);
            if let (Some(s0), Some(prefix)) = (z0, z1) {
                let has_prefix = prefix.prefix(&s0);
                let s_len = self.z3_string_length(&s0);
                let p_len = self.z3_string_length(&prefix);
                let remaining_len = Z3Int::sub(self.ctx, &[&s_len, &p_len]);
                let trimmed = self.z3_string_extract(&s0, &p_len, &remaining_len);
                // ite(startswith(s, prefix), substr(s, len(prefix), ...), s)
                let result = has_prefix.ite(&trimmed, &s0);
                self.set_register_sym(
                    params.dest,
                    SymValue::Str(result),
                    Definedness::Defined,
                    None,
                );
                return Ok(());
            }
        }
        self.warnings.push(format!(
            "PC {}: Builtin 'trim_prefix' — cannot resolve args, unconstrained String",
            self.pc
        ));
        let name = format!("builtin_trim_prefix_{}", self.pc);
        let var = Z3String::new_const(self.ctx, name.as_str());
        self.set_register_sym(params.dest, SymValue::Str(var), Definedness::Defined, None);
        Ok(())
    }

    /// `trim_suffix(s, suffix)` → if endswith(s, suffix): substr(s, 0, len(s)-len(suffix)) else s
    fn translate_builtin_trim_suffix(
        &mut self,
        params: &crate::rvm::instructions::BuiltinCallParams,
    ) -> anyhow::Result<()> {
        if params.arg_count() >= 2 {
            // Concrete evaluation.
            let a0 = self.get_register(params.args[0]).clone();
            let a1 = self.get_register(params.args[1]).clone();
            if let (SymValue::Concrete(Value::String(s0)), SymValue::Concrete(Value::String(s1))) =
                (&a0.value, &a1.value)
            {
                let result = s0.strip_suffix(s1.as_ref()).unwrap_or(s0.as_ref());
                self.set_register_concrete(params.dest, Value::String(result.into()));
                return Ok(());
            }

            let z0 = self.resolve_arg_as_z3_string(params.args[0]);
            let z1 = self.resolve_arg_as_z3_string(params.args[1]);
            if let (Some(s0), Some(suffix)) = (z0, z1) {
                let has_suffix = suffix.suffix(&s0);
                let s_len = self.z3_string_length(&s0);
                let sfx_len = self.z3_string_length(&suffix);
                let prefix_len = Z3Int::sub(self.ctx, &[&s_len, &sfx_len]);
                let zero = Z3Int::from_i64(self.ctx, 0);
                let trimmed = self.z3_string_extract(&s0, &zero, &prefix_len);
                let result = has_suffix.ite(&trimmed, &s0);
                self.set_register_sym(
                    params.dest,
                    SymValue::Str(result),
                    Definedness::Defined,
                    None,
                );
                return Ok(());
            }
        }
        self.warnings.push(format!(
            "PC {}: Builtin 'trim_suffix' — cannot resolve args, unconstrained String",
            self.pc
        ));
        let name = format!("builtin_trim_suffix_{}", self.pc);
        let var = Z3String::new_const(self.ctx, name.as_str());
        self.set_register_sym(params.dest, SymValue::Str(var), Definedness::Defined, None);
        Ok(())
    }

    /// `abs(x)` → ite(x >= 0, x, -x)
    fn translate_builtin_abs(
        &mut self,
        params: &crate::rvm::instructions::BuiltinCallParams,
    ) -> anyhow::Result<()> {
        if params.arg_count() >= 1 {
            // Concrete evaluation.
            let a0 = self.get_register(params.args[0]).clone();
            if let SymValue::Concrete(Value::Number(n)) = &a0.value {
                if let Some(i) = n.as_i64() {
                    self.set_register_concrete(params.dest, Value::from(i.abs()));
                    return Ok(());
                }
            }

            if let Some(z) = self.resolve_arg_as_z3_int(params.args[0]) {
                let zero = Z3Int::from_i64(self.ctx, 0);
                let neg = z.unary_minus();
                let result = z.ge(&zero).ite(&z, &neg);
                self.set_register_sym(
                    params.dest,
                    SymValue::Int(result),
                    Definedness::Defined,
                    None,
                );
                return Ok(());
            }
        }
        // Fallback: fresh non-negative Int (abs always ≥ 0).
        self.warnings.push(format!(
            "PC {}: Builtin 'abs' — cannot resolve arg, unconstrained non-negative Int",
            self.pc
        ));
        let name = format!("builtin_abs_{}", self.pc);
        let var = Z3Int::new_const(self.ctx, name.as_str());
        let zero = Z3Int::from_i64(self.ctx, 0);
        self.constraints.push(var.ge(&zero));
        self.set_register_sym(params.dest, SymValue::Int(var), Definedness::Defined, None);
        Ok(())
    }

    /// `is_string`, `is_boolean` — resolves from concrete type or known sort.
    fn translate_builtin_is_type(
        &mut self,
        params: &crate::rvm::instructions::BuiltinCallParams,
        name: &str,
        expected_sort: ValueSort,
    ) -> anyhow::Result<()> {
        if params.arg_count() >= 1 {
            let arg = self.get_register(params.args[0]).clone();

            // Concrete value → check directly.
            if let SymValue::Concrete(v) = &arg.value {
                let result = match (name, v) {
                    ("is_string", Value::String(_)) => true,
                    ("is_boolean", Value::Bool(_)) => true,
                    _ => false,
                };
                self.set_register_concrete(params.dest, Value::Bool(result));
                return Ok(());
            }

            // Symbolic value with known sort.
            let known_sort = arg.value.sort();
            if known_sort != ValueSort::Unknown {
                let result = known_sort == expected_sort;
                self.set_register_concrete(params.dest, Value::Bool(result));
                return Ok(());
            }

            // Path placeholder → check sort from registry.
            if let Some(path) = &arg.source_path {
                if let Some(sort) = self.registry.get_sort(path) {
                    if sort != ValueSort::Unknown {
                        let result = sort == expected_sort;
                        self.set_register_concrete(params.dest, Value::Bool(result));
                        return Ok(());
                    }
                }
            }
        }

        // Fallback: unconstrained Bool.
        self.warnings.push(format!(
            "PC {}: Builtin '{}' — unknown sort, unconstrained Bool",
            self.pc, name
        ));
        let vname = format!("builtin_{}_{}", name, self.pc);
        let var = Z3Bool::new_const(self.ctx, vname.as_str());
        self.set_register_sym(params.dest, SymValue::Bool(var), Definedness::Defined, None);
        Ok(())
    }

    /// `is_number` — true for both Int and Real sorts.
    fn translate_builtin_is_number(
        &mut self,
        params: &crate::rvm::instructions::BuiltinCallParams,
    ) -> anyhow::Result<()> {
        if params.arg_count() >= 1 {
            let arg = self.get_register(params.args[0]).clone();

            if let SymValue::Concrete(v) = &arg.value {
                let result = matches!(v, Value::Number(_));
                self.set_register_concrete(params.dest, Value::Bool(result));
                return Ok(());
            }

            let known_sort = arg.value.sort();
            if known_sort == ValueSort::Int || known_sort == ValueSort::Real {
                self.set_register_concrete(params.dest, Value::Bool(true));
                return Ok(());
            }
            if known_sort == ValueSort::Bool || known_sort == ValueSort::String {
                self.set_register_concrete(params.dest, Value::Bool(false));
                return Ok(());
            }

            if let Some(path) = &arg.source_path {
                if let Some(sort) = self.registry.get_sort(path) {
                    if sort == ValueSort::Int || sort == ValueSort::Real {
                        self.set_register_concrete(params.dest, Value::Bool(true));
                        return Ok(());
                    }
                    if sort == ValueSort::Bool || sort == ValueSort::String {
                        self.set_register_concrete(params.dest, Value::Bool(false));
                        return Ok(());
                    }
                }
            }
        }

        self.warnings.push(format!(
            "PC {}: Builtin 'is_number' — unknown sort, unconstrained Bool",
            self.pc
        ));
        let name = format!("builtin_is_number_{}", self.pc);
        let var = Z3Bool::new_const(self.ctx, name.as_str());
        self.set_register_sym(params.dest, SymValue::Bool(var), Definedness::Defined, None);
        Ok(())
    }

    /// `is_array`, `is_set`, `is_object`, `is_null` — concrete value checks.
    /// These types don't map to Z3 sorts, so we can only resolve concrete values.
    fn translate_builtin_is_collection_type(
        &mut self,
        params: &crate::rvm::instructions::BuiltinCallParams,
        name: &str,
    ) -> anyhow::Result<()> {
        if params.arg_count() >= 1 {
            let arg = self.get_register(params.args[0]).clone();

            if let SymValue::Concrete(v) = &arg.value {
                let result = match name {
                    "is_array" => matches!(v, Value::Array(_)),
                    "is_set" => matches!(v, Value::Set(_)),
                    "is_object" => matches!(v, Value::Object(_)),
                    "is_null" => matches!(v, Value::Null),
                    _ => false,
                };
                self.set_register_concrete(params.dest, Value::Bool(result));
                return Ok(());
            }

            // For symbolic values with known sorts: if the sort is String/Bool/Int/Real,
            // then is_array/is_set/is_object/is_null are all false.
            let known_sort = arg.value.sort();
            if known_sort == ValueSort::String
                || known_sort == ValueSort::Bool
                || known_sort == ValueSort::Int
                || known_sort == ValueSort::Real
            {
                self.set_register_concrete(params.dest, Value::Bool(false));
                return Ok(());
            }

            if let Some(path) = &arg.source_path {
                if let Some(sort) = self.registry.get_sort(path) {
                    if sort == ValueSort::String
                        || sort == ValueSort::Bool
                        || sort == ValueSort::Int
                        || sort == ValueSort::Real
                    {
                        self.set_register_concrete(params.dest, Value::Bool(false));
                        return Ok(());
                    }
                }
            }
        }

        self.warnings.push(format!(
            "PC {}: Builtin '{}' — unknown type, unconstrained Bool",
            self.pc, name
        ));
        let vname = format!("builtin_{}_{}", name, self.pc);
        let var = Z3Bool::new_const(self.ctx, vname.as_str());
        self.set_register_sym(params.dest, SymValue::Bool(var), Definedness::Defined, None);
        Ok(())
    }

    /// Binary bitwise operation: `bits.and`, `bits.or`, `bits.xor`, `bits.lsh`, `bits.rsh`.
    /// Uses 64-bit BV theory with Int↔BV conversion.
    fn translate_builtin_bitwise_binop(
        &mut self,
        params: &crate::rvm::instructions::BuiltinCallParams,
        name: &str,
        op: impl FnOnce(Z3BV<'ctx>, Z3BV<'ctx>) -> Z3BV<'ctx>,
    ) -> anyhow::Result<()> {
        if params.arg_count() >= 2 {
            // Concrete evaluation.
            let a0 = self.get_register(params.args[0]).clone();
            let a1 = self.get_register(params.args[1]).clone();
            if let (SymValue::Concrete(Value::Number(n0)), SymValue::Concrete(Value::Number(n1))) =
                (&a0.value, &a1.value)
            {
                if let (Some(i0), Some(i1)) = (n0.as_i64(), n1.as_i64()) {
                    let result = match name {
                        "bits.and" => i0 & i1,
                        "bits.or" => i0 | i1,
                        "bits.xor" => i0 ^ i1,
                        "bits.lsh" => i0.wrapping_shl(i1 as u32),
                        "bits.rsh" => i0.wrapping_shr(i1 as u32),
                        _ => i0,
                    };
                    self.set_register_concrete(params.dest, Value::from(result));
                    return Ok(());
                }
            }

            let z0 = self.resolve_arg_as_z3_int(params.args[0]);
            let z1 = self.resolve_arg_as_z3_int(params.args[1]);
            if let (Some(i0), Some(i1)) = (z0, z1) {
                let bv0 = Z3BV::from_int(&i0, 64);
                let bv1 = Z3BV::from_int(&i1, 64);
                let bv_result = op(bv0, bv1);
                let int_result = bv_result.to_int(true); // signed
                self.set_register_sym(
                    params.dest,
                    SymValue::Int(int_result),
                    Definedness::Defined,
                    None,
                );
                return Ok(());
            }
        }
        // Fallback: unconstrained Int.
        self.warnings.push(format!(
            "PC {}: Builtin '{}' — cannot resolve args, unconstrained Int",
            self.pc, name
        ));
        let vname = format!("builtin_{}_{}", name.replace('.', "_"), self.pc);
        let var = Z3Int::new_const(self.ctx, vname.as_str());
        self.set_register_sym(params.dest, SymValue::Int(var), Definedness::Defined, None);
        Ok(())
    }

    /// Unary bitwise operation: `bits.negate`.
    fn translate_builtin_bitwise_unop(
        &mut self,
        params: &crate::rvm::instructions::BuiltinCallParams,
        name: &str,
        op: impl FnOnce(Z3BV<'ctx>) -> Z3BV<'ctx>,
    ) -> anyhow::Result<()> {
        if params.arg_count() >= 1 {
            // Concrete evaluation.
            let a0 = self.get_register(params.args[0]).clone();
            if let SymValue::Concrete(Value::Number(n)) = &a0.value {
                if let Some(i) = n.as_i64() {
                    self.set_register_concrete(params.dest, Value::from(!i));
                    return Ok(());
                }
            }

            if let Some(z) = self.resolve_arg_as_z3_int(params.args[0]) {
                let bv = Z3BV::from_int(&z, 64);
                let bv_result = op(bv);
                let int_result = bv_result.to_int(true);
                self.set_register_sym(
                    params.dest,
                    SymValue::Int(int_result),
                    Definedness::Defined,
                    None,
                );
                return Ok(());
            }
        }
        self.warnings.push(format!(
            "PC {}: Builtin '{}' — cannot resolve arg, unconstrained Int",
            self.pc, name
        ));
        let vname = format!("builtin_{}_{}", name.replace('.', "_"), self.pc);
        let var = Z3Int::new_const(self.ctx, vname.as_str());
        self.set_register_sym(params.dest, SymValue::Int(var), Definedness::Defined, None);
        Ok(())
    }

    // ===================================================================
    // to_number — converts bool/string/number to Int
    // ===================================================================

    /// `to_number(x)` — convert a value to a number.
    ///
    /// Critical for Cedar: the Cedar compiler emits `to_number(permit_bool)`
    /// at the end to convert the boolean authorization decision to 0/1.
    /// If the argument is a Z3 Bool, we produce `ite(bool, 1, 0)`.
    fn translate_builtin_to_number(
        &mut self,
        params: &crate::rvm::instructions::BuiltinCallParams,
    ) -> anyhow::Result<()> {
        if params.arg_count() >= 1 {
            let a0 = self.get_register(params.args[0]).clone();
            let a0_defined = a0.defined.clone();

            // Concrete evaluation.
            match &a0.value {
                SymValue::Concrete(Value::Bool(b)) => {
                    let n = if *b { 1i64 } else { 0i64 };
                    self.set_register_concrete(params.dest, Value::from(n));
                    return Ok(());
                }
                SymValue::Concrete(Value::Number(n)) => {
                    self.set_register_concrete(params.dest, Value::Number(n.clone()));
                    return Ok(());
                }
                SymValue::Concrete(Value::String(s)) => {
                    if let Ok(n) = s.as_ref().parse::<i64>() {
                        self.set_register_concrete(params.dest, Value::from(n));
                        return Ok(());
                    }
                }
                _ => {}
            }

            // Z3 Bool → ite(bool, 1, 0).
            if let Ok(z_bool) = a0.value.to_z3_bool(self.ctx) {
                let one = Z3Int::from_i64(self.ctx, 1);
                let zero = Z3Int::from_i64(self.ctx, 0);
                let result = z_bool.ite(&one, &zero);
                self.set_register_sym(params.dest, SymValue::Int(result), a0_defined.clone(), None);
                return Ok(());
            }

            // Z3 Int — pass through.
            if let Ok(z_int) = a0.value.to_z3_int(self.ctx) {
                self.set_register_sym(params.dest, SymValue::Int(z_int), a0_defined.clone(), None);
                return Ok(());
            }
        }

        self.warnings.push(format!(
            "PC {}: Builtin 'to_number' — cannot resolve arg, unconstrained Int",
            self.pc
        ));
        let vname = format!("builtin_to_number_{}", self.pc);
        let var = Z3Int::new_const(self.ctx, vname.as_str());
        self.set_register_sym(params.dest, SymValue::Int(var), Definedness::Defined, None);
        Ok(())
    }

    // ===================================================================
    // Cedar builtins
    // ===================================================================

    /// `cedar.like(input, pattern)` — wildcard pattern matching using Z3 regex theory.
    ///
    /// Cedar's `like` operator treats `*` as matching zero or more arbitrary
    /// characters (like shell glob `*`). We translate this to Z3's regex
    /// theory: each literal segment becomes `Regexp::literal`, each `*`
    /// becomes `Regexp::full` (Σ*), and segments are concatenated.
    fn translate_builtin_cedar_like(
        &mut self,
        params: &crate::rvm::instructions::BuiltinCallParams,
    ) -> anyhow::Result<()> {
        if params.arg_count() >= 2 {
            // Concrete fast path.
            let a0 = self.get_register(params.args[0]).clone();
            let a0_defined = a0.defined.clone();
            let a1 = self.get_register(params.args[1]).clone();
            if let (SymValue::Concrete(Value::String(s)), SymValue::Concrete(Value::String(p))) =
                (&a0.value, &a1.value)
            {
                let result = cedar_wildcard_match(s.as_ref(), p.as_ref());
                self.set_register_concrete(params.dest, Value::Bool(result));
                return Ok(());
            }

            // If the pattern is concrete, we can build a precise regex.
            let pattern_concrete = match &a1.value {
                SymValue::Concrete(Value::String(p)) => Some(p.clone()),
                _ => None,
            };

            if let Some(pattern) = pattern_concrete {
                if let Some(input_z3) = self.resolve_arg_as_z3_string(params.args[0]) {
                    let re = cedar_pattern_to_z3_regexp(self.ctx, pattern.as_ref());
                    let result = input_z3.regex_matches(&re);
                    self.set_register_sym(params.dest, SymValue::Bool(result), a0_defined, None);
                    return Ok(());
                }
            }

            // If input is concrete but pattern is symbolic, we can't build a regex.
            // Fall through to unconstrained.
        }

        self.warnings.push(format!(
            "PC {}: Builtin 'cedar.like' — cannot model symbolically, unconstrained Bool",
            self.pc
        ));
        let vname = format!("builtin_cedar_like_{}", self.pc);
        let var = Z3Bool::new_const(self.ctx, vname.as_str());
        self.set_register_sym(params.dest, SymValue::Bool(var), Definedness::Defined, None);
        Ok(())
    }

    /// `cedar.is(entity, type_name)` — entity type check.
    ///
    /// Cedar entities are represented as `"TypeName::id"` strings. The `is`
    /// builtin checks whether the entity's type prefix matches `type_name`.
    /// When the entity is a concrete string or object, we evaluate directly.
    /// When symbolic, we use Z3 `str.prefixof`.
    fn translate_builtin_cedar_is(
        &mut self,
        params: &crate::rvm::instructions::BuiltinCallParams,
    ) -> anyhow::Result<()> {
        if params.arg_count() >= 2 {
            let a0 = self.get_register(params.args[0]).clone();
            let a0_defined = a0.defined.clone();
            let a1 = self.get_register(params.args[1]).clone();

            // Both concrete: evaluate directly.
            if let (SymValue::Concrete(entity), SymValue::Concrete(Value::String(type_name))) =
                (&a0.value, &a1.value)
            {
                let result = match entity {
                    Value::String(s) => {
                        let entity_type = s.as_ref().split("::").next().unwrap_or("");
                        entity_type == type_name.as_ref()
                    }
                    Value::Object(obj) => {
                        let type_key = Value::from("type");
                        matches!(obj.get(&type_key), Some(Value::String(t)) if t.as_ref() == type_name.as_ref())
                    }
                    _ => false,
                };
                self.set_register_concrete(params.dest, Value::Bool(result));
                return Ok(());
            }

            // Symbolic entity string, concrete type_name: use str.prefixof
            if let SymValue::Concrete(Value::String(type_name)) = &a1.value {
                if let Some(entity_z3) = self.resolve_arg_as_z3_string(params.args[0]) {
                    let prefix = format!("{}::", type_name.as_ref());
                    let prefix_z3 = Z3String::from_str(self.ctx, &prefix).unwrap();
                    let result = prefix_z3.prefix(&entity_z3);
                    self.set_register_sym(params.dest, SymValue::Bool(result), a0_defined, None);
                    return Ok(());
                }
            }
        }

        self.warnings.push(format!(
            "PC {}: Builtin 'cedar.is' — cannot model symbolically, unconstrained Bool",
            self.pc
        ));
        let vname = format!("builtin_cedar_is_{}", self.pc);
        let var = Z3Bool::new_const(self.ctx, vname.as_str());
        self.set_register_sym(params.dest, SymValue::Bool(var), Definedness::Defined, None);
        Ok(())
    }

    /// `cedar.in(entity, target, entities)` — entity hierarchy membership.
    ///
    /// This performs BFS over the entity hierarchy graph, which is always
    /// concrete (passed as the third argument). When entity and target are
    /// both concrete, we evaluate directly. When entity is symbolic but
    /// target and entities are concrete, we enumerate matching entity keys
    /// and constrain the symbolic entity to be one of them.
    fn translate_builtin_cedar_in(
        &mut self,
        params: &crate::rvm::instructions::BuiltinCallParams,
    ) -> anyhow::Result<()> {
        if params.arg_count() >= 3 {
            let a0 = self.get_register(params.args[0]).clone();
            let a0_defined = a0.defined.clone();
            let a1 = self.get_register(params.args[1]).clone();
            let a2 = self.get_register(params.args[2]).clone();

            // Extract concrete entities map.
            let entities = match &a2.value {
                SymValue::Concrete(Value::Object(e)) => Some(e.clone()),
                _ => None,
            };

            // Extract concrete target.
            let target = match &a1.value {
                SymValue::Concrete(v) if !matches!(v, Value::Undefined) => Some(v.clone()),
                _ => None,
            };

            if let (Some(entities), Some(target)) = (entities, target) {
                // Check if entity is truly concrete (not a path placeholder).
                let entity_concrete = match &a0.value {
                    SymValue::Concrete(v)
                        if !matches!(v, Value::Undefined) && a0.source_path.is_none() =>
                    {
                        Some(v.clone())
                    }
                    _ => None,
                };

                if let Some(entity) = entity_concrete {
                    // Both concrete: evaluate directly.
                    let result = concrete_cedar_in(&entity, &target, &entities);
                    self.set_register_concrete(params.dest, Value::Bool(result));
                    return Ok(());
                }

                // Entity is symbolic — enumerate which entity keys satisfy `in(E, target)`.
                let matching_keys = enumerate_cedar_in_keys(&target, &entities);
                if let Some(entity_z3) = self.resolve_arg_as_z3_string(params.args[0]) {
                    if matching_keys.is_empty() {
                        // No entity can satisfy this — always false.
                        self.set_register_concrete(params.dest, Value::Bool(false));
                    } else {
                        let mut disjuncts: Vec<Z3Bool<'ctx>> = Vec::new();
                        for key in &matching_keys {
                            let key_z3 = Z3String::from_str(self.ctx, key).unwrap();
                            disjuncts.push(entity_z3._eq(&key_z3));
                        }
                        let refs: Vec<&Z3Bool<'ctx>> = disjuncts.iter().collect();
                        let result = Z3Bool::or(self.ctx, &refs);
                        self.set_register_sym(
                            params.dest,
                            SymValue::Bool(result),
                            a0_defined.clone(),
                            None,
                        );
                    }
                    return Ok(());
                }
            }
        }

        self.warnings.push(format!(
            "PC {}: Builtin 'cedar.in' — entity/target not concrete, unconstrained Bool",
            self.pc
        ));
        let vname = format!("builtin_cedar_in_{}", self.pc);
        let var = Z3Bool::new_const(self.ctx, vname.as_str());
        self.set_register_sym(params.dest, SymValue::Bool(var), Definedness::Defined, None);
        Ok(())
    }

    /// `cedar.in_set(entity, targets, entities)` — membership in set of targets.
    ///
    /// Like `cedar.in` but checks multiple targets (an array). Returns true
    /// if `cedar.in` succeeds for any target in the array.
    fn translate_builtin_cedar_in_set(
        &mut self,
        params: &crate::rvm::instructions::BuiltinCallParams,
    ) -> anyhow::Result<()> {
        if params.arg_count() >= 3 {
            let a0 = self.get_register(params.args[0]).clone();
            let a0_defined = a0.defined.clone();
            let a1 = self.get_register(params.args[1]).clone();
            let a2 = self.get_register(params.args[2]).clone();

            let entities = match &a2.value {
                SymValue::Concrete(Value::Object(e)) => Some(e.clone()),
                _ => None,
            };
            let targets = match &a1.value {
                SymValue::Concrete(Value::Array(t)) => Some(t.clone()),
                _ => None,
            };

            if let (Some(entities), Some(targets)) = (entities, targets) {
                // Entity truly concrete?
                let entity_concrete = match &a0.value {
                    SymValue::Concrete(v)
                        if !matches!(v, Value::Undefined) && a0.source_path.is_none() =>
                    {
                        Some(v.clone())
                    }
                    _ => None,
                };

                if let Some(entity) = entity_concrete {
                    let mut result = false;
                    for target in targets.iter() {
                        if concrete_cedar_in(&entity, target, &entities) {
                            result = true;
                            break;
                        }
                    }
                    self.set_register_concrete(params.dest, Value::Bool(result));
                    return Ok(());
                }

                // Entity symbolic — enumerate matching keys over all targets.
                let mut all_matching = alloc::collections::BTreeSet::new();
                for target in targets.iter() {
                    for key in enumerate_cedar_in_keys(target, &entities) {
                        all_matching.insert(key);
                    }
                }
                if let Some(entity_z3) = self.resolve_arg_as_z3_string(params.args[0]) {
                    if all_matching.is_empty() {
                        self.set_register_concrete(params.dest, Value::Bool(false));
                    } else {
                        let mut disjuncts: Vec<Z3Bool<'ctx>> = Vec::new();
                        for key in &all_matching {
                            let key_z3 = Z3String::from_str(self.ctx, key).unwrap();
                            disjuncts.push(entity_z3._eq(&key_z3));
                        }
                        let refs: Vec<&Z3Bool<'ctx>> = disjuncts.iter().collect();
                        let result = Z3Bool::or(self.ctx, &refs);
                        self.set_register_sym(
                            params.dest,
                            SymValue::Bool(result),
                            a0_defined.clone(),
                            None,
                        );
                    }
                    return Ok(());
                }
            }
        }

        self.warnings.push(format!(
            "PC {}: Builtin 'cedar.in_set' — not fully concrete, unconstrained Bool",
            self.pc
        ));
        let vname = format!("builtin_cedar_in_set_{}", self.pc);
        let var = Z3Bool::new_const(self.ctx, vname.as_str());
        self.set_register_sym(params.dest, SymValue::Bool(var), Definedness::Defined, None);
        Ok(())
    }

    /// `cedar.has(entity, attr_name, entities)` — attribute existence check.
    ///
    /// Checks if an entity has a given attribute. When entity is symbolic,
    /// we enumerate which entity keys have the attribute and create a
    /// disjunction constraint.
    fn translate_builtin_cedar_has(
        &mut self,
        params: &crate::rvm::instructions::BuiltinCallParams,
    ) -> anyhow::Result<()> {
        if params.arg_count() >= 3 {
            let a0 = self.get_register(params.args[0]).clone();
            let a0_defined = a0.defined.clone();
            let a1 = self.get_register(params.args[1]).clone();
            let a2 = self.get_register(params.args[2]).clone();

            let entities = match &a2.value {
                SymValue::Concrete(Value::Object(e)) => Some(e.clone()),
                _ => None,
            };
            let attr = match &a1.value {
                SymValue::Concrete(Value::String(s)) => Some(s.clone()),
                _ => None,
            };

            if let (Some(entities), Some(attr)) = (entities, attr) {
                // Entity truly concrete?
                let entity_concrete = match &a0.value {
                    SymValue::Concrete(v)
                        if !matches!(v, Value::Undefined) && a0.source_path.is_none() =>
                    {
                        Some(v.clone())
                    }
                    _ => None,
                };

                if let Some(entity) = entity_concrete {
                    let result = concrete_cedar_has(&entity, attr.as_ref(), &entities);
                    self.set_register_concrete(params.dest, Value::Bool(result));
                    return Ok(());
                }

                // Entity symbolic — enumerate keys that have this attribute.
                let matching_keys = enumerate_cedar_has_keys(attr.as_ref(), &entities);
                if let Some(entity_z3) = self.resolve_arg_as_z3_string(params.args[0]) {
                    if matching_keys.is_empty() {
                        self.set_register_concrete(params.dest, Value::Bool(false));
                    } else {
                        let mut disjuncts: Vec<Z3Bool<'ctx>> = Vec::new();
                        for key in &matching_keys {
                            let key_z3 = Z3String::from_str(self.ctx, key).unwrap();
                            disjuncts.push(entity_z3._eq(&key_z3));
                        }
                        let refs: Vec<&Z3Bool<'ctx>> = disjuncts.iter().collect();
                        let result = Z3Bool::or(self.ctx, &refs);
                        self.set_register_sym(
                            params.dest,
                            SymValue::Bool(result),
                            a0_defined.clone(),
                            None,
                        );
                    }
                    return Ok(());
                }
            }
        }

        self.warnings.push(format!(
            "PC {}: Builtin 'cedar.has' — not fully concrete, unconstrained Bool",
            self.pc
        ));
        let vname = format!("builtin_cedar_has_{}", self.pc);
        let var = Z3Bool::new_const(self.ctx, vname.as_str());
        self.set_register_sym(params.dest, SymValue::Bool(var), Definedness::Defined, None);
        Ok(())
    }

    /// `cedar.attr(entity, attr_name, entities)` — attribute value lookup.
    ///
    /// When entity is symbolic, we create an ITE chain mapping each
    /// possible entity key to its attribute value. When fully concrete,
    /// we evaluate directly.
    fn translate_builtin_cedar_attr(
        &mut self,
        params: &crate::rvm::instructions::BuiltinCallParams,
    ) -> anyhow::Result<()> {
        if params.arg_count() >= 3 {
            let a0 = self.get_register(params.args[0]).clone();
            let a0_defined = a0.defined.clone();
            let a1 = self.get_register(params.args[1]).clone();
            let a2 = self.get_register(params.args[2]).clone();

            let entities = match &a2.value {
                SymValue::Concrete(Value::Object(e)) => Some(e.clone()),
                _ => None,
            };
            let attr = match &a1.value {
                SymValue::Concrete(Value::String(s)) => Some(s.clone()),
                _ => None,
            };

            if let (Some(entities), Some(attr)) = (entities, attr) {
                // Entity truly concrete?
                let entity_concrete = match &a0.value {
                    SymValue::Concrete(v)
                        if !matches!(v, Value::Undefined) && a0.source_path.is_none() =>
                    {
                        Some(v.clone())
                    }
                    _ => None,
                };

                if let Some(entity) = entity_concrete {
                    let result = concrete_cedar_attr(&entity, attr.as_ref(), &entities);
                    self.set_register_concrete(params.dest, result);
                    return Ok(());
                }

                // Entity is symbolic. Build ITE chain over possible entity keys.
                // Collect (entity_key_str, attr_value) pairs.
                let attr_map = enumerate_cedar_attr_values(attr.as_ref(), &entities);
                if !attr_map.is_empty() {
                    if let Some(entity_z3) = self.resolve_arg_as_z3_string(params.args[0]) {
                        // Determine result sort from the first value.
                        let first_val = &attr_map[0].1;
                        match first_val {
                            Value::String(_) => {
                                // Build ITE chain of string values.
                                let default = Z3String::from_str(self.ctx, "").unwrap();
                                let mut result = default;
                                for (key, val) in attr_map.iter().rev() {
                                    let key_z3 = Z3String::from_str(self.ctx, key).unwrap();
                                    let cond = entity_z3._eq(&key_z3);
                                    let val_str = match val {
                                        Value::String(s) => s.as_ref().to_string(),
                                        _ => format!("{}", val),
                                    };
                                    let val_z3 = Z3String::from_str(self.ctx, &val_str).unwrap();
                                    result = cond.ite(&val_z3, &result);
                                }
                                self.set_register_sym(
                                    params.dest,
                                    SymValue::Str(result),
                                    a0_defined.clone(),
                                    None,
                                );
                                return Ok(());
                            }
                            Value::Object(_) | Value::Array(_) => {
                                // Complex values — return as concrete if only one option.
                                if attr_map.len() == 1 {
                                    self.set_register_concrete(params.dest, attr_map[0].1.clone());
                                    return Ok(());
                                }
                                // Multiple complex values — fall through to unconstrained.
                            }
                            _ => {
                                // Other scalar types — fall through.
                            }
                        }
                    }
                }

                // If entity is a path placeholder pointing to a context-like
                // object, treat it as a symbolic object where attr access
                // creates a sub-path. E.g., input.context accessing "ip"
                // → input.context.ip (symbolic string).
                if let Some(path) = &a0.source_path {
                    let sub_path = format!("{}.{}", path, attr.as_ref());
                    let _entry =
                        self.registry
                            .get_or_create(&sub_path, ValueSort::Unknown, true, self.pc);
                    let defined = self.registry.get(&sub_path).unwrap().defined.clone();
                    self.set_register_sym(
                        params.dest,
                        SymValue::Concrete(Value::Undefined),
                        Definedness::Symbolic(defined),
                        Some(sub_path),
                    );
                    return Ok(());
                }
            }
        }

        // Attribute lookup returns a value of unknown type — model as
        // unconstrained String (could be any type; String is the safest default).
        self.warnings.push(format!(
            "PC {}: Builtin 'cedar.attr' — not fully concrete, unconstrained String",
            self.pc
        ));
        let vname = format!("builtin_cedar_attr_{}", self.pc);
        let var = Z3String::new_const(self.ctx, vname.as_str());
        self.set_register_sym(params.dest, SymValue::Str(var), Definedness::Defined, None);
        Ok(())
    }

    // ===================================================================
    // Z3 string theory FFI helpers
    // ===================================================================

    /// Z3 `str.len(s)` — returns a Z3 Int representing the length of a Z3 String.
    fn z3_string_length(&self, s: &Z3String<'ctx>) -> Z3Int<'ctx> {
        #[allow(unsafe_code)]
        unsafe {
            let ctx_ptr: *const z3::Context = self.ctx;
            let raw_ctx: z3_sys::Z3_context = *(ctx_ptr as *const z3_sys::Z3_context);
            let len_ast = z3_sys::Z3_mk_seq_length(raw_ctx, s.get_z3_ast());
            Z3Int::wrap(self.ctx, len_ast)
        }
    }

    /// Z3 `str.indexof(s, substr, offset)` — returns Int (-1 if not found).
    fn z3_string_indexof(
        &self,
        s: &Z3String<'ctx>,
        substr: &Z3String<'ctx>,
        offset: &Z3Int<'ctx>,
    ) -> Z3Int<'ctx> {
        #[allow(unsafe_code)]
        unsafe {
            let ctx_ptr: *const z3::Context = self.ctx;
            let raw_ctx: z3_sys::Z3_context = *(ctx_ptr as *const z3_sys::Z3_context);
            let ast = z3_sys::Z3_mk_seq_index(
                raw_ctx,
                s.get_z3_ast(),
                substr.get_z3_ast(),
                offset.get_z3_ast(),
            );
            Z3Int::wrap(self.ctx, ast)
        }
    }

    /// Z3 `str.replace(s, src, dst)` — replaces first occurrence.
    fn z3_string_replace(
        &self,
        s: &Z3String<'ctx>,
        src: &Z3String<'ctx>,
        dst: &Z3String<'ctx>,
    ) -> Z3String<'ctx> {
        #[allow(unsafe_code)]
        unsafe {
            let ctx_ptr: *const z3::Context = self.ctx;
            let raw_ctx: z3_sys::Z3_context = *(ctx_ptr as *const z3_sys::Z3_context);
            let ast = z3_sys::Z3_mk_seq_replace(
                raw_ctx,
                s.get_z3_ast(),
                src.get_z3_ast(),
                dst.get_z3_ast(),
            );
            Z3String::wrap(self.ctx, ast)
        }
    }

    /// Z3 `str.substr(s, offset, length)` — extracts a substring.
    fn z3_string_extract(
        &self,
        s: &Z3String<'ctx>,
        offset: &Z3Int<'ctx>,
        length: &Z3Int<'ctx>,
    ) -> Z3String<'ctx> {
        #[allow(unsafe_code)]
        unsafe {
            let ctx_ptr: *const z3::Context = self.ctx;
            let raw_ctx: z3_sys::Z3_context = *(ctx_ptr as *const z3_sys::Z3_context);
            let ast = z3_sys::Z3_mk_seq_extract(
                raw_ctx,
                s.get_z3_ast(),
                offset.get_z3_ast(),
                length.get_z3_ast(),
            );
            Z3String::wrap(self.ctx, ast)
        }
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
            .ok_or_else(|| anyhow::anyhow!("Invalid VDDL params index {}", params_index))?
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
            self.warnings
                .push(format!("PC {}: VDDL with symbolic path component", self.pc));
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
            self.registers.resize_with(idx + 1, SymRegister::undefined);
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
            self.registers.resize_with(idx + 1, SymRegister::undefined);
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
        // Check if this path has a concrete value injected via config.
        // For example, `input.entities` in Cedar analysis should be concrete.
        if let Some(suffix) = path.strip_prefix("input.") {
            // Only match top-level keys (no dots in the suffix).
            if !suffix.contains('.') {
                if let Some(concrete_val) = self.config.concrete_input.get(suffix) {
                    self.set_register_concrete(dest, concrete_val.clone());
                    return Ok(InstructionAction::Continue);
                }
            }
        }

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
    pub(crate) fn ensure_register_sort(&mut self, reg: u8, sort: ValueSort) -> anyhow::Result<()> {
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

// ---------------------------------------------------------------------------
// Cedar builtin helpers (free functions)
// ---------------------------------------------------------------------------

/// Convert a Cedar `like` wildcard pattern to a Z3 `Regexp`.
///
/// The pattern uses `*` to match zero or more arbitrary characters.
/// We split on `*`, create `Regexp::literal` for each literal segment,
/// and `Regexp::full` (Σ*) for each `*`, then concatenate.
fn cedar_pattern_to_z3_regexp<'ctx>(ctx: &'ctx z3::Context, pattern: &str) -> Z3Regexp<'ctx> {
    let segments: Vec<&str> = pattern.split('*').collect();

    if segments.len() == 1 {
        // No wildcards — exact literal match.
        return Z3Regexp::literal(ctx, pattern);
    }

    let mut parts: Vec<Z3Regexp<'ctx>> = Vec::new();
    for (i, seg) in segments.iter().enumerate() {
        if !seg.is_empty() {
            parts.push(Z3Regexp::literal(ctx, seg));
        }
        // Between segments (i.e. where each `*` was), insert Σ*.
        if i < segments.len() - 1 {
            parts.push(Z3Regexp::full(ctx));
        }
    }

    if parts.len() == 1 {
        return parts.into_iter().next().unwrap();
    }

    let refs: Vec<&Z3Regexp<'ctx>> = parts.iter().collect();
    Z3Regexp::concat(ctx, &refs)
}

/// Cedar wildcard match (concrete evaluation, mirrors `builtins/cedar.rs`).
fn cedar_wildcard_match(input: &str, pattern: &str) -> bool {
    let (mut i, mut p) = (0_usize, 0_usize);
    let mut star_idx: Option<usize> = None;
    let mut match_idx = 0_usize;
    let input_bytes = input.as_bytes();
    let pattern_bytes = pattern.as_bytes();

    while i < input_bytes.len() {
        if p < pattern_bytes.len()
            && (pattern_bytes[p] == b'?' || pattern_bytes[p] == input_bytes[i])
        {
            i += 1;
            p += 1;
        } else if p < pattern_bytes.len() && pattern_bytes[p] == b'*' {
            star_idx = Some(p);
            match_idx = i;
            p += 1;
        } else if let Some(star) = star_idx {
            p = star + 1;
            match_idx += 1;
            i = match_idx;
        } else {
            return false;
        }
    }

    while p < pattern_bytes.len() && pattern_bytes[p] == b'*' {
        p += 1;
    }

    p == pattern_bytes.len()
}

/// Concrete `cedar.in` — BFS over entity hierarchy.
fn concrete_cedar_in(
    entity: &Value,
    target: &Value,
    entities: &alloc::collections::BTreeMap<Value, Value>,
) -> bool {
    use alloc::collections::{BTreeSet, VecDeque};

    let entity_key = concrete_entity_key(entity);
    let target_key = concrete_entity_key(target);

    if entity_key == target_key {
        return true;
    }

    let mut queue = VecDeque::new();
    let mut visited = BTreeSet::new();

    queue.push_back(entity_key.clone());
    visited.insert(entity_key);

    while let Some(current) = queue.pop_front() {
        if current == target_key {
            return true;
        }

        let Some(Value::Object(node)) = entities.get(&current) else {
            continue;
        };

        let parents_key = Value::from("parents");
        let Some(Value::Array(parents)) = node.get(&parents_key) else {
            continue;
        };

        for parent in parents.iter() {
            let parent_val = match parent {
                Value::String(_) => parent.clone(),
                _ => continue,
            };
            if visited.insert(parent_val.clone()) {
                queue.push_back(parent_val);
            }
        }
    }

    false
}

/// Extract entity key from a Value (string or object with type/id).
fn concrete_entity_key(value: &Value) -> Value {
    match value {
        Value::String(_) => value.clone(),
        Value::Object(obj) => {
            let type_key = Value::from("type");
            let id_key = Value::from("id");
            if let (Some(Value::String(t)), Some(Value::String(id))) =
                (obj.get(&type_key), obj.get(&id_key))
            {
                Value::String(format!("{}::{}", t.as_ref(), id.as_ref()).into())
            } else {
                value.clone()
            }
        }
        _ => value.clone(),
    }
}

/// Concrete `cedar.has` — check if entity has an attribute.
fn concrete_cedar_has(
    entity: &Value,
    attr: &str,
    entities: &alloc::collections::BTreeMap<Value, Value>,
) -> bool {
    let attr_key = Value::String(attr.into());

    // If entity is already an object, check directly.
    if let Value::Object(obj) = entity {
        return obj.contains_key(&attr_key);
    }

    // Look up entity in entities map.
    let entity_key = concrete_entity_key(entity);
    let Some(Value::Object(entity_record)) = entities.get(&entity_key) else {
        return false;
    };

    // Check direct keys first.
    if entity_record.contains_key(&attr_key) {
        return true;
    }

    // Check in attrs sub-object.
    let attrs_field = Value::from("attrs");
    matches!(entity_record.get(&attrs_field), Some(Value::Object(attrs)) if attrs.contains_key(&attr_key))
}

/// Concrete `cedar.attr` — look up attribute value on an entity.
fn concrete_cedar_attr(
    entity: &Value,
    attr: &str,
    entities: &alloc::collections::BTreeMap<Value, Value>,
) -> Value {
    let attr_key = Value::String(attr.into());

    // If entity is already an object, look up directly.
    if let Value::Object(obj) = entity {
        if let Some(v) = obj.get(&attr_key) {
            return v.clone();
        }
        let attrs_field = Value::from("attrs");
        if let Some(Value::Object(attrs)) = obj.get(&attrs_field) {
            return attrs.get(&attr_key).cloned().unwrap_or(Value::Undefined);
        }
        return Value::Undefined;
    }

    // Look up entity in entities map.
    let entity_key = concrete_entity_key(entity);
    let Some(Value::Object(entity_record)) = entities.get(&entity_key) else {
        return Value::Undefined;
    };

    // Check direct keys.
    if let Some(v) = entity_record.get(&attr_key) {
        return v.clone();
    }

    // Check in attrs sub-object.
    let attrs_field = Value::from("attrs");
    match entity_record.get(&attrs_field) {
        Some(Value::Object(attrs)) => attrs.get(&attr_key).cloned().unwrap_or(Value::Undefined),
        _ => Value::Undefined,
    }
}

/// Enumerate all entity key strings that satisfy `cedar.in(key, target, entities)`.
///
/// This computes the reverse membership set: all keys K such that BFS from K
/// reaches `target` in the entity hierarchy.
fn enumerate_cedar_in_keys(
    target: &Value,
    entities: &alloc::collections::BTreeMap<Value, Value>,
) -> Vec<std::string::String> {
    let target_key = concrete_entity_key(target);
    let mut result = Vec::new();

    // The target itself always matches (entity == target).
    if let Value::String(s) = &target_key {
        result.push(s.as_ref().to_string());
    }

    // Check every entity in the map.
    for entity_key in entities.keys() {
        if entity_key == &target_key {
            continue; // Already added.
        }
        if concrete_cedar_in(entity_key, &target_key, entities) {
            if let Value::String(s) = entity_key {
                result.push(s.as_ref().to_string());
            }
        }
    }

    result
}

/// Enumerate all entity key strings that have the given attribute.
fn enumerate_cedar_has_keys(
    attr: &str,
    entities: &alloc::collections::BTreeMap<Value, Value>,
) -> Vec<std::string::String> {
    let mut result = Vec::new();
    for (key, _) in entities.iter() {
        if let Value::String(s) = key {
            if concrete_cedar_has(&Value::String(s.clone()), attr, entities) {
                result.push(s.as_ref().to_string());
            }
        }
    }
    result
}

/// Enumerate (entity_key_string, attr_value) pairs for all entities that have
/// the given attribute.
fn enumerate_cedar_attr_values(
    attr: &str,
    entities: &alloc::collections::BTreeMap<Value, Value>,
) -> Vec<(std::string::String, Value)> {
    let mut result = Vec::new();
    for (key, _) in entities.iter() {
        if let Value::String(s) = key {
            let val = concrete_cedar_attr(&Value::String(s.clone()), attr, entities);
            if !matches!(val, Value::Undefined) {
                result.push((s.as_ref().to_string(), val));
            }
        }
    }
    result
}
