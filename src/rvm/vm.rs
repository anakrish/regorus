use crate::rvm::instructions::{Instruction, LoopMode};
use crate::rvm::program::Program;
use crate::value::Value;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use anyhow::{bail, Result};

extern crate alloc;

/// Loop execution context for managing iteration state
#[derive(Debug, Clone)]
pub struct LoopContext {
    pub mode: LoopMode,
    pub iteration_state: IterationState,
    pub key_reg: u16,
    pub value_reg: u16,
    pub result_reg: u16,
    pub body_start: u16,
    pub loop_end: u16,
    pub loop_next_pc: u16, // PC of the LoopNext instruction to avoid searching
    pub success_count: usize,
    pub total_iterations: usize,
    pub current_iteration_failed: bool, // Track if current iteration had condition failures
}

/// Iterator state for different collection types
#[derive(Debug, Clone)]
pub enum IterationState {
    Array {
        items: Arc<Vec<Value>>,
        index: usize,
    },
    Object {
        obj: Arc<BTreeMap<Value, Value>>,
        current_key: Option<Value>,
        first_iteration: bool,
    },
    Set {
        items: Arc<std::collections::BTreeSet<Value>>,
        current_item: Option<Value>,
        first_iteration: bool,
    },
}

impl IterationState {
    fn advance(&mut self) {
        match self {
            IterationState::Array { index, .. } => {
                *index += 1;
            }
            IterationState::Object {
                first_iteration, ..
            } => {
                *first_iteration = false;
            }
            IterationState::Set {
                first_iteration, ..
            } => {
                *first_iteration = false;
            }
        }
    }
}

/// Actions that can be taken after processing a loop iteration
#[derive(Debug, Clone)]
enum LoopAction {
    ExitWithSuccess,
    ExitWithFailure,
    Continue,
}

#[allow(unused)]
#[derive(Debug, Clone)]
pub struct CallRuleContext {
    pub return_pc: usize,
    pub dest_reg: u16,
    pub result_reg: u16,
    pub rule_index: u16,
    pub rule_type: crate::rvm::program::RuleType,
    pub current_definition_index: usize,
    pub current_body_index: usize,
}

/// Parameters for loop execution
struct LoopParams {
    collection: u16,
    key_reg: u16,
    value_reg: u16,
    result_reg: u16,
    body_start: u16,
    loop_end: u16,
}

/// The RVM Virtual Machine
pub struct RegoVM {
    /// Registers for storing values during execution
    registers: Vec<Value>,

    /// Program counter
    pc: usize,

    /// The compiled program containing instructions, literals, and metadata
    program: Arc<Program>,

    /// Rule execution cache: rule_index -> (computed: bool, result: Value)
    rule_cache: Vec<(bool, Value)>,

    /// Global data object
    data: Value,

    /// Global input object
    input: Value,

    /// Loop execution stack
    loop_stack: Vec<LoopContext>,

    /// Call rule execution stack for managing nested rule calls
    call_rule_stack: Vec<CallRuleContext>,

    /// Maximum number of instructions to execute (default: 5000)
    max_instructions: usize,

    /// Current count of executed instructions
    executed_instructions: usize,

    /// Interactive debugger for step-by-step execution analysis
    #[cfg(feature = "rvm-debug")]
    debugger: crate::rvm::debugger::InteractiveDebugger,
}

impl Default for RegoVM {
    fn default() -> Self {
        Self::new()
    }
}

impl RegoVM {
    /// Create a new virtual machine
    pub fn new() -> Self {
        let vm = RegoVM {
            registers: Vec::new(), // Start with no registers - will be resized when program is loaded
            pc: 0,
            program: Arc::new(Program::default()),
            rule_cache: Vec::new(),
            data: Value::Null,
            input: Value::Null,
            loop_stack: Vec::new(),
            call_rule_stack: Vec::new(),
            max_instructions: 5000, // Default maximum instruction limit
            executed_instructions: 0,
            #[cfg(feature = "rvm-debug")]
            debugger: crate::rvm::debugger::InteractiveDebugger::new(),
        };

        vm
    }

    /// Load a complete program for execution
    pub fn load_program(&mut self, program: Arc<Program>) {
        self.program = program.clone();

        // Resize registers to match program requirements
        // Ensure at least 1 register is allocated for safety
        let required_registers = std::cmp::max(1, program.num_registers);
        self.registers.clear();
        self.registers.resize(required_registers, Value::Null);

        // Initialize rule cache
        self.rule_cache = vec![(false, Value::Undefined); program.rule_infos.len()];

        // Set PC to main entry point
        self.pc = program.main_entry_point;
        self.executed_instructions = 0; // Reset instruction counter

        // Debug: Print the program received by VM
        std::println!(
            "Debug: VM received program with {} instructions, {} literals, {} rules, {} registers:",
            program.instructions.len(),
            program.literals.len(),
            program.rule_infos.len(),
            required_registers
        );
        for (i, literal) in program.literals.iter().enumerate() {
            std::println!("  VM literal_idx {}: {:?}", i, literal);
        }

        // Debug: Print rule definitions
        std::println!("Debug: VM rule infos:");
        for (rule_idx, rule_info) in program.rule_infos.iter().enumerate() {
            std::println!(
                "  VM Rule {}: {} definitions",
                rule_idx,
                rule_info.definitions.len()
            );
            for (def_idx, bodies) in rule_info.definitions.iter().enumerate() {
                std::println!(
                    "    VM Definition {}: {} bodies at entry points {:?}",
                    def_idx,
                    bodies.len(),
                    bodies
                );
            }
        }
    }

    /// Set the maximum number of instructions that can be executed
    pub fn set_max_instructions(&mut self, max: usize) {
        self.max_instructions = max;
    }

    /// Set the global data object
    pub fn set_data(&mut self, data: Value) {
        self.data = data;
    }

    /// Set the global input object
    pub fn set_input(&mut self, input: Value) {
        self.input = input;
    }

    pub fn execute(&mut self) -> Result<Value> {
        // Reset execution state for each execution
        self.executed_instructions = 0;
        self.pc = 0;

        self.jump_to(0)
    }

    // Public getters for visualization
    pub fn get_pc(&self) -> usize {
        self.pc
    }

    pub fn get_registers(&self) -> &Vec<Value> {
        &self.registers
    }

    pub fn get_program(&self) -> &Arc<Program> {
        &self.program
    }

    pub fn get_call_stack(&self) -> &Vec<CallRuleContext> {
        &self.call_rule_stack
    }

    pub fn get_loop_stack(&self) -> &Vec<LoopContext> {
        &self.loop_stack
    }

    /// Execute the loaded program
    pub fn jump_to(&mut self, target: usize) -> Result<Value> {
        let program = self.program.clone();
        self.pc = target;
        while self.pc < program.instructions.len() {
            // Check instruction execution limit
            if self.executed_instructions >= self.max_instructions {
                bail!(
                    "Execution stopped: exceeded maximum instruction limit of {}",
                    self.max_instructions
                );
            }

            self.executed_instructions += 1;
            let instruction = program.instructions[self.pc].clone();

            // Debugger integration
            #[cfg(feature = "rvm-debug")]
            if self.debugger.should_break(self.pc, &instruction) {
                let debug_ctx = crate::rvm::debugger::DebugContext {
                    pc: self.pc,
                    instruction: &instruction,
                    registers: &self.registers,
                    call_rule_stack: &self.call_rule_stack,
                    loop_stack: &self.loop_stack,
                    executed_instructions: self.executed_instructions,
                    program: &program,
                };
                self.debugger.debug_prompt(&debug_ctx);
            }

            // Debug excessive instruction execution
            if self.executed_instructions > 4990 {
                std::println!(
                    "Debug: instruction #{} at PC {}: {:?}",
                    self.executed_instructions,
                    self.pc,
                    instruction
                );
            }

            match instruction {
                Instruction::Load { dest, literal_idx } => {
                    if let Some(value) = program.literals.get(literal_idx as usize) {
                        std::println!(
                            "Debug: Load instruction - dest={}, literal_idx={}, value={:?}",
                            dest,
                            literal_idx,
                            value
                        );
                        self.registers[dest as usize] = value.clone();
                        std::println!(
                            "Debug: After Load - register[{}] = {:?}",
                            dest,
                            self.registers[dest as usize]
                        );
                    } else {
                        bail!("Literal index {} out of bounds", literal_idx);
                    }
                }

                Instruction::LoadTrue { dest } => {
                    self.registers[dest as usize] = Value::Bool(true);
                }

                Instruction::LoadFalse { dest } => {
                    self.registers[dest as usize] = Value::Bool(false);
                }

                Instruction::LoadNull { dest } => {
                    std::println!("Debug: LoadNull instruction - dest={}", dest);
                    self.registers[dest as usize] = Value::Null;
                    std::println!("Debug: After LoadNull - register[{}] = Null", dest);
                }

                Instruction::LoadBool { dest, value } => {
                    self.registers[dest as usize] = Value::Bool(value);
                }

                Instruction::LoadData { dest } => {
                    self.registers[dest as usize] = self.data.clone();
                }

                Instruction::LoadInput { dest } => {
                    self.registers[dest as usize] = self.input.clone();
                }

                Instruction::Move { dest, src } => {
                    std::println!("Debug: Move instruction - dest={}, src={}", dest, src);
                    std::println!(
                        "Debug: Before Move - src register {} contains: {:?}",
                        src,
                        self.registers[src as usize]
                    );
                    self.registers[dest as usize] = self.registers[src as usize].clone();
                    std::println!(
                        "Debug: After Move - dest register {} contains: {:?}",
                        dest,
                        self.registers[dest as usize]
                    );
                }

                Instruction::Add { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];
                    self.registers[dest as usize] = self.add_values(a, b)?;
                }

                Instruction::Sub { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];
                    self.registers[dest as usize] = self.sub_values(a, b)?;
                }

                Instruction::Mul { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];
                    std::println!("Debug: Mul instruction - left_reg={} contains {:?}, right_reg={} contains {:?}", 
                                 left, a, right, b);
                    self.registers[dest as usize] = self.mul_values(a, b)?;
                }

                Instruction::Div { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];
                    self.registers[dest as usize] = self.div_values(a, b)?;
                }

                Instruction::Mod { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];
                    self.registers[dest as usize] = self.mod_values(a, b)?;
                }

                Instruction::Eq { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];
                    self.registers[dest as usize] = Value::Bool(a == b);
                }

                Instruction::Ne { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];
                    self.registers[dest as usize] = Value::Bool(a != b);
                }

                Instruction::Lt { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];

                    // If either operand is undefined, result is undefined
                    if a == &Value::Undefined || b == &Value::Undefined {
                        self.registers[dest as usize] = Value::Undefined;
                    } else {
                        self.registers[dest as usize] = Value::Bool(self.compare_values(a, b)? < 0);
                    }
                }

                Instruction::Le { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];

                    // If either operand is undefined, result is undefined
                    if a == &Value::Undefined || b == &Value::Undefined {
                        self.registers[dest as usize] = Value::Undefined;
                    } else {
                        self.registers[dest as usize] =
                            Value::Bool(self.compare_values(a, b)? <= 0);
                    }
                }

                Instruction::Gt { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];

                    // If either operand is undefined, result is undefined
                    if a == &Value::Undefined || b == &Value::Undefined {
                        self.registers[dest as usize] = Value::Undefined;
                    } else {
                        self.registers[dest as usize] = Value::Bool(self.compare_values(a, b)? > 0);
                    }
                }

                Instruction::Ge { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];

                    // If either operand is undefined, result is undefined
                    if a == &Value::Undefined || b == &Value::Undefined {
                        self.registers[dest as usize] = Value::Undefined;
                    } else {
                        self.registers[dest as usize] =
                            Value::Bool(self.compare_values(a, b)? >= 0);
                    }
                }

                Instruction::And { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];
                    let a_bool = self.to_bool(a);
                    let b_bool = self.to_bool(b);
                    self.registers[dest as usize] = Value::Bool(a_bool && b_bool);
                }

                Instruction::Or { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];
                    let a_bool = self.to_bool(a);
                    let b_bool = self.to_bool(b);
                    self.registers[dest as usize] = Value::Bool(a_bool || b_bool);
                }

                Instruction::Not { dest, operand } => {
                    let a = &self.registers[operand as usize];
                    let a_bool = self.to_bool(a);
                    self.registers[dest as usize] = Value::Bool(!a_bool);
                }

                Instruction::BuiltinCall { params_index } => {
                    let params =
                        &self.program.instruction_data.builtin_call_params[params_index as usize];
                    let builtin_info =
                        &self.program.builtin_info_table[params.builtin_index as usize];

                    let mut args = Vec::new();
                    for &arg_reg in params.arg_registers() {
                        args.push(self.registers[arg_reg as usize].clone());
                    }

                    // Check argument count constraints
                    if (args.len() as u16) != builtin_info.num_args {
                        bail!(
                            "Builtin function {} expects exactly {} arguments, got {}",
                            builtin_info.name,
                            builtin_info.num_args,
                            args.len()
                        );
                    }

                    // Use resolved builtin from program via vector indexing
                    if let Some(builtin_fcn) = self.program.get_resolved_builtin(params.builtin_index) {
                        // Create a dummy span for the VM context
                        let dummy_source = crate::lexer::Source::from_contents(String::new(), String::new())?;
                        let dummy_span = crate::lexer::Span {
                            source: dummy_source,
                            line: 0,
                            col: 0,
                            start: 0,
                            end: 0,
                        };
                        let dummy_exprs: Vec<crate::ast::Ref<crate::ast::Expr>> = Vec::new();
                        
                        let result = (builtin_fcn.0)(&dummy_span, &dummy_exprs, &args, true)?;
                        self.registers[params.dest as usize] = result;
                    } else {
                        bail!("Builtin function not resolved: {}", builtin_info.name);
                    }
                }

                Instruction::FunctionCall { params_index } => {
                    let params =
                        &self.program.instruction_data.function_call_params[params_index as usize];
                    if let Value::String(func_name) = &self.registers[params.func as usize] {
                        let mut args = Vec::new();
                        for &arg_reg in params.arg_registers() {
                            args.push(self.registers[arg_reg as usize].clone());
                        }

                        // This would eventually call user-defined function rules
                        // For now, just return an error as this is not implemented yet
                        bail!("Function rule calls not yet implemented: {}", func_name);
                    } else {
                        bail!("Function name must be a string");
                    }
                }

                Instruction::Return { value } => {
                    return Ok(self.registers[value as usize].clone());
                }

                Instruction::CallRule { dest, rule_index } => {
                    self.execute_call_rule(dest, rule_index)?;
                }

                Instruction::RuleInit {
                    result_reg,
                    rule_index,
                } => {
                    self.execute_rule_init(result_reg, rule_index)?;
                }

                Instruction::RuleReturn {} => {
                    self.execute_rule_return()?;
                    break;
                }

                Instruction::ObjectNew { dest } => {
                    use std::collections::BTreeMap;
                    let empty_object = Value::Object(Arc::new(BTreeMap::new()));
                    self.registers[dest as usize] = empty_object;
                }

                Instruction::ObjectSet { obj, key, value } => {
                    let key_value = self.registers[key as usize].clone();
                    let value_value = self.registers[value as usize].clone();

                    // Swap the value from the register with Null, modify it, and put it back
                    let mut obj_value =
                        std::mem::replace(&mut self.registers[obj as usize], Value::Null);

                    if let Ok(obj_mut) = obj_value.as_object_mut() {
                        obj_mut.insert(key_value, value_value);
                        self.registers[obj as usize] = obj_value;
                    } else {
                        // Restore the original value and bail
                        self.registers[obj as usize] = obj_value;
                        bail!("ObjectSet: register {} does not contain an object", obj);
                    }
                }

                Instruction::Index {
                    dest,
                    container,
                    key,
                } => {
                    let key_value = &self.registers[key as usize];
                    let container_value = &self.registers[container as usize];

                    // Use Value's built-in indexing - this handles objects, arrays, and sets efficiently
                    let result = container_value[key_value].clone();
                    self.registers[dest as usize] = result;
                }

                Instruction::ArrayNew { dest } => {
                    let empty_array = Value::Array(Arc::new(Vec::new()));
                    self.registers[dest as usize] = empty_array;
                }

                Instruction::ArrayPush { arr, value } => {
                    let value_to_push = self.registers[value as usize].clone();

                    // Swap the value from the register with Null, modify it, and put it back
                    let mut arr_value =
                        std::mem::replace(&mut self.registers[arr as usize], Value::Null);

                    if let Ok(arr_mut) = arr_value.as_array_mut() {
                        arr_mut.push(value_to_push);
                        self.registers[arr as usize] = arr_value;
                    } else {
                        // Restore the original value and bail
                        self.registers[arr as usize] = arr_value;
                        bail!("ArrayPush: register {} does not contain an array", arr);
                    }
                }

                Instruction::SetNew { dest } => {
                    use std::collections::BTreeSet;
                    let empty_set = Value::Set(Arc::new(BTreeSet::new()));
                    self.registers[dest as usize] = empty_set;
                }

                Instruction::SetAdd { set, value } => {
                    let value_to_add = self.registers[value as usize].clone();

                    // Swap the value from the register with Null, modify it, and put it back
                    let mut set_value =
                        std::mem::replace(&mut self.registers[set as usize], Value::Null);

                    if let Ok(set_mut) = set_value.as_set_mut() {
                        set_mut.insert(value_to_add);
                        self.registers[set as usize] = set_value;
                    } else {
                        // Restore the original value and bail
                        self.registers[set as usize] = set_value;
                        bail!("SetAdd: register {} does not contain a set", set);
                    }
                }

                Instruction::Contains {
                    dest,
                    collection,
                    value,
                } => {
                    let value_to_check = &self.registers[value as usize];
                    let collection_value = &self.registers[collection as usize];

                    let result = match collection_value {
                        Value::Set(set_elements) => {
                            // Check if set contains the value
                            Value::Bool(set_elements.contains(value_to_check))
                        }
                        Value::Array(array_items) => {
                            // Check if array contains the value
                            Value::Bool(array_items.contains(value_to_check))
                        }
                        Value::Object(object_fields) => {
                            // Check if object contains the value as a key or value
                            Value::Bool(
                                object_fields.contains_key(value_to_check)
                                    || object_fields.values().any(|v| v == value_to_check),
                            )
                        }
                        _ => {
                            // For other types, return false
                            Value::Bool(false)
                        }
                    };

                    self.registers[dest as usize] = result;
                }

                Instruction::AssertCondition { condition } => {
                    let value = &self.registers[condition as usize];
                    std::println!(
                        "Debug: AssertCondition - condition_reg={} contains {:?}",
                        condition,
                        value
                    );

                    // Check if condition is false or undefined
                    match value {
                        Value::Bool(false) | Value::Undefined => {
                            let condition_type = match value {
                                Value::Bool(false) => "false",
                                Value::Undefined => "undefined",
                                _ => unreachable!(),
                            };
                            std::println!(
                                "Debug: AssertCondition failed ({}) - in loop: {}",
                                condition_type,
                                !self.loop_stack.is_empty()
                            );
                            if !self.loop_stack.is_empty() {
                                // In a loop - behavior depends on loop mode
                                // Get the loop context values we need before mutable borrow
                                let (loop_mode, loop_next_pc, loop_end, result_reg) = {
                                    let loop_ctx = self.loop_stack.last().unwrap();
                                    (
                                        loop_ctx.mode.clone(),
                                        loop_ctx.loop_next_pc,
                                        loop_ctx.loop_end,
                                        loop_ctx.result_reg,
                                    )
                                };

                                match loop_mode {
                                    LoopMode::Any => {
                                        // For SomeIn (existential): mark iteration failed and continue to next iteration
                                        if let Some(loop_ctx_mut) = self.loop_stack.last_mut() {
                                            loop_ctx_mut.current_iteration_failed = true;
                                        }
                                        std::println!("Debug: AssertCondition failed in Any loop - jumping to loop_end={}", loop_end);

                                        // Jump directly to the LoopNext instruction
                                        self.pc = loop_next_pc as usize - 1; // -1 because PC will be incremented
                                    }
                                    LoopMode::Every => {
                                        // For Every (universal): condition failure means entire loop fails
                                        // Jump beyond the loop body to loop_end
                                        std::println!("Debug: AssertCondition failed in Every loop - jumping to loop_end={}", loop_end);
                                        self.loop_stack.pop(); // Remove loop context
                                        self.pc = loop_end as usize - 1; // -1 because PC will be incremented
                                                                         // Set result to false since Every failed
                                        self.registers[result_reg as usize] = Value::Bool(false);
                                    }
                                    _ => {
                                        // For comprehensions: mark iteration failed and continue
                                        if let Some(loop_ctx_mut) = self.loop_stack.last_mut() {
                                            loop_ctx_mut.current_iteration_failed = true;
                                        }
                                        // Jump directly to the LoopNext instruction
                                        self.pc = loop_next_pc as usize - 1; // -1 because PC will be incremented
                                    }
                                }
                            } else {
                                // Outside of loop context, failed assertion means this body/definition fails
                                std::println!(
                                    "Debug: AssertCondition failed outside loop - body failed"
                                );
                                return Err(anyhow::anyhow!("Assertion failed"));
                            }
                        }
                        Value::Null => {
                            std::println!("Debug: AssertCondition failed (null)");
                            return Ok(Value::Undefined); // Null is falsy in Rego
                        }
                        _ => {
                            std::println!("Debug: AssertCondition passed - {:?}", value);
                            // For other values, check if they're truthy
                            // In Rego, only false, undefined, and null are falsy
                            // Everything else (including 0, empty strings, empty arrays) is truthy
                        }
                    }
                }

                Instruction::LoopStart { params_index } => {
                    let loop_params =
                        &self.program.instruction_data.loop_params[params_index as usize];
                    let mode = loop_params.mode.clone();
                    let params = LoopParams {
                        collection: loop_params.collection,
                        key_reg: loop_params.key_reg,
                        value_reg: loop_params.value_reg,
                        result_reg: loop_params.result_reg,
                        body_start: loop_params.body_start,
                        loop_end: loop_params.loop_end,
                    };
                    self.execute_loop_start(&mode, params)?;
                }

                Instruction::LoopNext {
                    body_start,
                    loop_end,
                } => {
                    self.execute_loop_next(body_start, loop_end)?;
                }

                Instruction::Halt => {
                    return Ok(self.registers[0].clone());
                }
            }

            self.pc += 1;
        }

        // If we reach here, return register 0
        Ok(self.registers[0].clone())
    }

    /// Execute CallRule instruction with caching and call stack support
    fn execute_call_rule(&mut self, dest: u16, rule_index: u16) -> Result<()> {
        std::println!(
            "Debug: CallRule execution - dest={}, rule_index={}",
            dest,
            rule_index
        );
        let rule_idx = rule_index as usize;

        // Check bounds
        if rule_idx >= self.rule_cache.len() {
            bail!("Rule index {} out of bounds", rule_index);
        }

        // Check cache first
        let (computed, cached_result) = &self.rule_cache[rule_idx];
        if *computed {
            // Cache hit - return cached result
            std::println!(
                "Debug: Cache hit for rule {} - result: {:?}",
                rule_index,
                cached_result
            );
            self.registers[dest as usize] = cached_result.clone();
            return Ok(());
        }

        let rule_info = self
            .program
            .rule_infos
            .get(rule_idx)
            .ok_or_else(|| anyhow::anyhow!("Rule index {} has no info", rule_index))?
            .clone();

        let rule_type = rule_info.rule_type.clone();
        let rule_definitions = rule_info.definitions.clone();

        if rule_definitions.is_empty() {
            // No definitions - return undefined
            std::println!(
                "Debug: Rule {} has no definitions - returning Undefined",
                rule_index
            );
            let result = Value::Undefined;
            self.rule_cache[rule_idx] = (true, result.clone());
            self.registers[dest as usize] = result;
            return Ok(());
        }

        // Save current PC to return to after rule execution
        self.call_rule_stack.push(CallRuleContext {
            return_pc: self.pc,
            dest_reg: dest,
            result_reg: dest,
            rule_index,
            rule_type,
            current_definition_index: 0,
            current_body_index: 0,
        });
        self.registers[dest as usize] = Value::Undefined; // Initialize destination register

        std::println!(
            "Debug: CallRule executing rule {} with {} definitions",
            rule_index,
            rule_definitions.len()
        );

        for (def_idx, definition_bodies) in rule_definitions.iter().enumerate() {
            for (body_entry_point_idx, body_entry_point) in definition_bodies.iter().enumerate() {
                if let Some(ctx) = self.call_rule_stack.last_mut() {
                    ctx.current_body_index = body_entry_point_idx;
                    ctx.current_definition_index = def_idx;
                }
                std::println!(
                    "Debug: Executing rule definition {} at body {}, entry point {}",
                    def_idx,
                    body_entry_point_idx,
                    body_entry_point
                );

                // Execute the body
                match self.jump_to(*body_entry_point) {
                    Ok(_) => {
                        std::println!("Debug:  Body {} completed", body_entry_point_idx);
                    }
                    Err(e) => {
                        std::println!("Debug:  Body {} failed: {:?}", body_entry_point_idx, e);
                        // Body failed - skip this definition
                        continue;
                    }
                }
                std::println!(
                    "Debug: Body {} completed successfully for definition {} of {} definitions",
                    body_entry_point_idx,
                    def_idx,
                    rule_definitions.len()
                );
            }
        }

        // Return from the call
        let call_context = self.call_rule_stack.pop().expect("Call stack underflow");
        self.pc = call_context.return_pc;
        std::println!(
            "Debug: CallRule returning from rule {} to PC {}",
            rule_index,
            self.pc
        );

        // For partial set/object rules, if all definitions failed and we still have Undefined,
        // set the appropriate empty collection as the default
        if self.registers[dest as usize] == Value::Undefined {
            match call_context.rule_type {
                crate::rvm::program::RuleType::PartialSet => {
                    std::println!(
                        "Debug: All definitions failed for PartialSet rule - using empty set"
                    );
                    self.registers[dest as usize] = Value::new_set();
                }
                crate::rvm::program::RuleType::PartialObject => {
                    std::println!(
                        "Debug: All definitions failed for PartialObject rule - using empty object"
                    );
                    self.registers[dest as usize] = Value::new_object();
                }
                crate::rvm::program::RuleType::Complete => {
                    // For complete rules, Undefined is the correct result when all definitions fail
                    std::println!(
                        "Debug: All definitions failed for Complete rule - keeping Undefined"
                    );
                }
            }
        }

        // Cache the final result
        let result = self.registers[dest as usize].clone();
        std::println!("Debug: Set rule final result: {:?}", result);
        self.rule_cache[rule_idx] = (true, result.clone());

        std::println!(
            "Debug: CallRule completed - dest register {} set to {:?}",
            dest,
            self.registers[dest as usize]
        );
        Ok(())
    }

    /// Execute RuleInit instruction
    fn execute_rule_init(&mut self, result_reg: u16, _rule_index: u16) -> Result<()> {
        let current_ctx = self
            .call_rule_stack
            .last_mut()
            .expect("Call stack underflow");
        current_ctx.result_reg = result_reg;
        match current_ctx.rule_type {
            crate::rvm::program::RuleType::Complete => {
                self.registers[result_reg as usize] = Value::Undefined;
            }
            crate::rvm::program::RuleType::PartialSet => {
                if current_ctx.current_definition_index == 0 {
                    self.registers[result_reg as usize] = Value::new_set();
                }
                std::println!(
                    "Debug: RuleInit for PartialSet - set value: {:?}",
                    self.registers[result_reg as usize]
                );
            }
            crate::rvm::program::RuleType::PartialObject => {
                if current_ctx.current_definition_index == 0 {
                    self.registers[result_reg as usize] = Value::new_object();
                }
            }
        }
        Ok(())
    }

    /// Execute RuleReturn
    fn execute_rule_return(&mut self) -> Result<()> {
        let current_ctx = self
            .call_rule_stack
            .last_mut()
            .expect("Call stack underflow");
        let result_reg = current_ctx.result_reg;
        let dest_reg = current_ctx.dest_reg;
        self.registers[dest_reg as usize] = self.registers[result_reg as usize].clone();
        Ok(())
    }

    /// Add two values
    fn add_values(&self, a: &Value, b: &Value) -> Result<Value> {
        match (a, b) {
            (Value::Number(x), Value::Number(y)) => {
                if let (Some(x_f64), Some(y_f64)) = (x.as_f64(), y.as_f64()) {
                    Ok(Value::from(x_f64 + y_f64))
                } else {
                    bail!("Cannot add these numbers");
                }
            }
            _ => bail!("Cannot add {:?} and {:?}", a, b),
        }
    }

    /// Subtract two values
    fn sub_values(&self, a: &Value, b: &Value) -> Result<Value> {
        match (a, b) {
            (Value::Number(x), Value::Number(y)) => {
                if let (Some(x_f64), Some(y_f64)) = (x.as_f64(), y.as_f64()) {
                    Ok(Value::from(x_f64 - y_f64))
                } else {
                    bail!("Cannot subtract these numbers");
                }
            }
            _ => bail!("Cannot subtract {:?} and {:?}", a, b),
        }
    }

    /// Multiply two values
    fn mul_values(&self, a: &Value, b: &Value) -> Result<Value> {
        match (a, b) {
            (Value::Number(x), Value::Number(y)) => {
                if let (Some(x_f64), Some(y_f64)) = (x.as_f64(), y.as_f64()) {
                    Ok(Value::from(x_f64 * y_f64))
                } else {
                    bail!("Cannot multiply these numbers");
                }
            }
            _ => bail!("Cannot multiply {:?} and {:?}", a, b),
        }
    }

    /// Divide two values
    fn div_values(&self, a: &Value, b: &Value) -> Result<Value> {
        match (a, b) {
            (Value::Number(x), Value::Number(y)) => {
                if let (Some(x_f64), Some(y_f64)) = (x.as_f64(), y.as_f64()) {
                    if y_f64 == 0.0 {
                        bail!("Division by zero");
                    }
                    Ok(Value::from(x_f64 / y_f64))
                } else {
                    bail!("Cannot divide these numbers");
                }
            }
            _ => bail!("Cannot divide {:?} and {:?}", a, b),
        }
    }

    fn mod_values(&self, a: &Value, b: &Value) -> Result<Value> {
        match (a, b) {
            (Value::Number(x), Value::Number(y)) => {
                if let (Some(x_f64), Some(y_f64)) = (x.as_f64(), y.as_f64()) {
                    if y_f64 == 0.0 {
                        bail!("Modulo by zero");
                    }
                    Ok(Value::from(x_f64 % y_f64))
                } else {
                    bail!("Cannot modulo these numbers");
                }
            }
            _ => bail!("Cannot modulo {:?} and {:?}", a, b),
        }
    }

    fn to_bool(&self, value: &Value) -> bool {
        match value {
            Value::Bool(b) => *b,
            Value::Null => false,
            Value::Number(n) => {
                if let Some(f) = n.as_f64() {
                    f != 0.0
                } else {
                    true
                }
            }
            Value::String(s) => !s.is_empty(),
            Value::Array(arr) => !arr.is_empty(),
            Value::Object(obj) => !obj.is_empty(),
            Value::Set(set) => !set.is_empty(),
            _ => true,
        }
    }

    /// Compare two values (-1, 0, 1)
    fn compare_values(&self, a: &Value, b: &Value) -> Result<i32> {
        // Handle undefined values specially - they should be handled at higher level
        if a == &Value::Undefined || b == &Value::Undefined {
            bail!("undefined comparison should be handled at higher level");
        }

        // Use Value's derived PartialOrd implementation which follows the correct ordering:
        // 1. null, 2. bool, 3. number, 4. string, 5. Array, 6. Set, 7. Object
        match a.partial_cmp(b) {
            Some(std::cmp::Ordering::Less) => Ok(-1),
            Some(std::cmp::Ordering::Equal) => Ok(0),
            Some(std::cmp::Ordering::Greater) => Ok(1),
            None => bail!("Cannot compare {:?} and {:?}", a, b),
        }
    }

    /// Execute LoopStart instruction
    fn execute_loop_start(&mut self, mode: &LoopMode, params: LoopParams) -> Result<()> {
        // Initialize result container based on mode
        let initial_result = match mode {
            LoopMode::Any | LoopMode::Every | LoopMode::ForEach => Value::Bool(false),
            LoopMode::ArrayComprehension => Value::new_array(),
            LoopMode::SetComprehension => Value::new_set(),
            LoopMode::ObjectComprehension => Value::Object(Arc::new(BTreeMap::new())),
        };
        self.registers[params.result_reg as usize] = initial_result;

        let collection_value = self.registers[params.collection as usize].clone();

        // Validate collection is iterable and create iteration state
        let iteration_state = match &collection_value {
            Value::Array(items) => {
                if items.is_empty() {
                    self.handle_empty_collection(mode, params.result_reg, params.loop_end)?;
                    return Ok(());
                }
                IterationState::Array {
                    items: items.clone(),
                    index: 0,
                }
            }
            Value::Object(obj) => {
                if obj.is_empty() {
                    self.handle_empty_collection(mode, params.result_reg, params.loop_end)?;
                    return Ok(());
                }
                IterationState::Object {
                    obj: obj.clone(),
                    current_key: None,
                    first_iteration: true,
                }
            }
            Value::Set(set) => {
                if set.is_empty() {
                    self.handle_empty_collection(mode, params.result_reg, params.loop_end)?;
                    return Ok(());
                }
                IterationState::Set {
                    items: set.clone(),
                    current_item: None,
                    first_iteration: true,
                }
            }
            _ => {
                bail!("Cannot iterate over {:?}", collection_value);
            }
        };

        // Set up first iteration
        let has_next =
            self.setup_next_iteration(&iteration_state, params.key_reg, params.value_reg)?;
        if !has_next {
            self.pc = params.loop_end as usize;
            return Ok(());
        }

        // Create loop context
        // The LoopNext instruction is positioned immediately before loop_end
        let loop_next_pc = params.loop_end - 1;

        let loop_context = LoopContext {
            mode: mode.clone(),
            iteration_state,
            key_reg: params.key_reg,
            value_reg: params.value_reg,
            result_reg: params.result_reg,
            body_start: params.body_start,
            loop_end: params.loop_end,
            loop_next_pc,
            success_count: 0,
            total_iterations: 0,
            current_iteration_failed: false,
        };

        self.loop_stack.push(loop_context);
        self.pc = params.body_start as usize - 1; // -1 because PC will be incremented after instruction
        Ok(())
    }

    /// Execute LoopNext instruction
    fn execute_loop_next(&mut self, _body_start: u16, _loop_end: u16) -> Result<()> {
        // Ignore the parameters and use the loop context instead
        if let Some(mut loop_ctx) = self.loop_stack.pop() {
            let body_start = loop_ctx.body_start;
            let loop_end = loop_ctx.loop_end;

            std::println!(
                "Debug: LoopNext - body_start={}, loop_end={} (from context)",
                body_start,
                loop_end
            );

            loop_ctx.total_iterations += 1;
            std::println!(
                "Debug: LoopNext - total_iterations={}",
                loop_ctx.total_iterations
            );

            // Check iteration result
            let iteration_succeeded = self.check_iteration_success(&loop_ctx)?;
            std::println!(
                "Debug: LoopNext - iteration_succeeded={}",
                iteration_succeeded
            );

            if iteration_succeeded {
                loop_ctx.success_count += 1;
                std::println!("Debug: LoopNext - success_count={}", loop_ctx.success_count);
            }

            // Handle mode-specific logic
            let action = self.determine_loop_action(&loop_ctx.mode, iteration_succeeded);
            std::println!("Debug: LoopNext - action={:?}", action);

            match action {
                LoopAction::ExitWithSuccess => {
                    self.registers[loop_ctx.result_reg as usize] = Value::Bool(true);
                    // Set PC to loop_end - 1 because main loop will increment it
                    self.pc = loop_end as usize - 1;
                    return Ok(());
                }
                LoopAction::ExitWithFailure => {
                    self.registers[loop_ctx.result_reg as usize] = Value::Bool(false);
                    // Set PC to loop_end - 1 because main loop will increment it
                    self.pc = loop_end as usize - 1;
                    return Ok(());
                }
                LoopAction::Continue => {
                    // Just continue to next iteration
                }
            }

            // Advance to next iteration
            // Store current key/item before advancing for Object and Set iteration
            if let IterationState::Object {
                ref mut current_key,
                ..
            } = &mut loop_ctx.iteration_state
            {
                // Get the key from the key register to store as current_key
                if loop_ctx.key_reg != u16::MAX {
                    *current_key = Some(self.registers[loop_ctx.key_reg as usize].clone());
                }
            } else if let IterationState::Set {
                ref mut current_item,
                ..
            } = &mut loop_ctx.iteration_state
            {
                // Get the item from the value register to store as current_item
                *current_item = Some(self.registers[loop_ctx.value_reg as usize].clone());
            }

            loop_ctx.iteration_state.advance();
            std::println!("Debug: LoopNext - advanced to next iteration");
            let has_next = self.setup_next_iteration(
                &loop_ctx.iteration_state,
                loop_ctx.key_reg,
                loop_ctx.value_reg,
            )?;
            std::println!("Debug: LoopNext - has_next={}", has_next);

            if has_next {
                loop_ctx.current_iteration_failed = false; // Reset for next iteration
                self.loop_stack.push(loop_ctx);
                self.pc = body_start as usize - 1; // Jump to body_start, which will be incremented to body_start
                std::println!(
                    "Debug: LoopNext - continuing to next iteration, PC set to {}",
                    self.pc
                );
            } else {
                std::println!("Debug: LoopNext - loop finished, calculating final result");
                // Loop finished - determine final result
                let final_result = match loop_ctx.mode {
                    LoopMode::Any => {
                        let result = Value::Bool(loop_ctx.success_count > 0);
                        std::println!(
                            "Debug: LoopNext - Any final result: {:?} (success_count={})",
                            result,
                            loop_ctx.success_count
                        );
                        result
                    }
                    LoopMode::Every => {
                        Value::Bool(loop_ctx.success_count == loop_ctx.total_iterations)
                    }
                    LoopMode::ForEach => {
                        let result = Value::Bool(loop_ctx.success_count > 0);
                        std::println!(
                            "Debug: LoopNext - ForEach final result: {:?} (success_count={})",
                            result,
                            loop_ctx.success_count
                        );
                        result
                    }
                    LoopMode::ArrayComprehension
                    | LoopMode::SetComprehension
                    | LoopMode::ObjectComprehension => {
                        // Result is already accumulated in result_reg
                        self.registers[loop_ctx.result_reg as usize].clone()
                    }
                };

                self.registers[loop_ctx.result_reg as usize] = final_result;
                std::println!(
                    "Debug: LoopNext - final result stored in register {}: {:?}",
                    loop_ctx.result_reg,
                    self.registers[loop_ctx.result_reg as usize]
                );
                self.pc = loop_end as usize - 1; // -1 because PC will be incremented
            }

            Ok(())
        } else {
            // No active loop context - this happens when the collection was empty
            // and handle_empty_collection was called. Just continue past loop_end.
            std::println!(
                "Debug: LoopNext - no active loop (empty collection), jumping past loop_end"
            );
            self.pc = _loop_end as usize; // Jump past LoopNext instruction
            Ok(())
        }
    }

    /// Handle empty collection based on loop mode
    fn handle_empty_collection(
        &mut self,
        mode: &LoopMode,
        result_reg: u16,
        loop_end: u16,
    ) -> Result<()> {
        let result = match mode {
            LoopMode::Any => Value::Bool(false),
            LoopMode::Every => Value::Bool(true), // Every element of empty set satisfies condition
            LoopMode::ForEach => Value::Bool(false),
            LoopMode::ArrayComprehension => Value::new_array(),
            LoopMode::SetComprehension => Value::new_set(),
            LoopMode::ObjectComprehension => Value::Object(Arc::new(BTreeMap::new())),
        };

        self.registers[result_reg as usize] = result;
        // Set PC to loop_end - 1 because the main loop will increment it by 1
        self.pc = (loop_end as usize).saturating_sub(1);
        Ok(())
    }

    /// Set up the next iteration values
    fn setup_next_iteration(
        &mut self,
        state: &IterationState,
        key_reg: u16,
        value_reg: u16,
    ) -> Result<bool> {
        match state {
            IterationState::Array { items, index } => {
                if *index < items.len() {
                    if key_reg != u16::MAX {
                        let key_value = Value::from(*index as f64);
                        self.registers[key_reg as usize] = key_value;
                    }
                    let item_value = items[*index].clone();
                    self.registers[value_reg as usize] = item_value;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            IterationState::Object {
                obj,
                current_key,
                first_iteration,
            } => {
                if *first_iteration {
                    // First iteration: get the first key-value pair
                    if let Some((key, value)) = obj.iter().next() {
                        if key_reg != u16::MAX {
                            self.registers[key_reg as usize] = key.clone();
                        }
                        self.registers[value_reg as usize] = value.clone();
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                } else {
                    // Subsequent iterations: use range starting after current_key
                    if let Some(ref current) = current_key {
                        // Use range to get next key after current
                        let mut range_iter = obj.range((
                            std::ops::Bound::Excluded(current),
                            std::ops::Bound::Unbounded,
                        ));
                        if let Some((key, value)) = range_iter.next() {
                            if key_reg != u16::MAX {
                                self.registers[key_reg as usize] = key.clone();
                            }
                            self.registers[value_reg as usize] = value.clone();
                            Ok(true)
                        } else {
                            Ok(false)
                        }
                    } else {
                        Ok(false)
                    }
                }
            }
            IterationState::Set {
                items,
                current_item,
                first_iteration,
            } => {
                if *first_iteration {
                    // First iteration: get the first item
                    if let Some(item) = items.iter().next() {
                        if key_reg != u16::MAX {
                            // For sets, key and value are the same
                            self.registers[key_reg as usize] = item.clone();
                        }
                        self.registers[value_reg as usize] = item.clone();
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                } else {
                    // Subsequent iterations: use range starting after current_item
                    if let Some(ref current) = current_item {
                        // Use range to get next item after current
                        let mut range_iter = items.range((
                            std::ops::Bound::Excluded(current),
                            std::ops::Bound::Unbounded,
                        ));
                        if let Some(item) = range_iter.next() {
                            if key_reg != u16::MAX {
                                // For sets, key and value are the same
                                self.registers[key_reg as usize] = item.clone();
                            }
                            self.registers[value_reg as usize] = item.clone();
                            Ok(true)
                        } else {
                            Ok(false)
                        }
                    } else {
                        Ok(false)
                    }
                }
            }
        }
    }

    /// Check if current iteration succeeded
    fn check_iteration_success(&self, loop_ctx: &LoopContext) -> Result<bool> {
        // Check if the current iteration had any condition failures
        std::println!(
            "Debug: check_iteration_success - current_iteration_failed={}",
            loop_ctx.current_iteration_failed
        );
        Ok(!loop_ctx.current_iteration_failed)
    }

    /// Determine what action to take based on loop mode and iteration result
    fn determine_loop_action(&self, mode: &LoopMode, success: bool) -> LoopAction {
        match (mode, success) {
            (LoopMode::Any, true) => LoopAction::ExitWithSuccess,
            (LoopMode::Every, false) => LoopAction::ExitWithFailure,
            // For ForEach mode and comprehensions, let explicit accumulation instructions handle the results
            (LoopMode::ForEach, _) => LoopAction::Continue,
            (LoopMode::ArrayComprehension, _) => LoopAction::Continue,
            (LoopMode::SetComprehension, _) => LoopAction::Continue,
            (LoopMode::ObjectComprehension, _) => LoopAction::Continue,
            _ => LoopAction::Continue,
        }
    }
}
