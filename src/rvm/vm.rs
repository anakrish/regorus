use crate::rvm::instructions::{Instruction, LoopMode};
use crate::value::Value;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use anyhow::{bail, Result};

extern crate alloc;

/// Loop execution context for managing iteration state
#[derive(Debug, Clone)]
struct LoopContext {
    mode: LoopMode,
    iteration_state: IterationState,
    key_reg: u16,
    value_reg: u16,
    result_reg: u16,
    body_start: u16,
    loop_end: u16,
    loop_next_pc: u16, // PC of the LoopNext instruction to avoid searching
    success_count: usize,
    total_iterations: usize,
    current_iteration_failed: bool, // Track if current iteration had condition failures
}

/// Iterator state for different collection types
#[derive(Debug, Clone)]
enum IterationState {
    Array {
        items: Arc<Vec<Value>>,
        index: usize,
    },
    Object {
        obj: Arc<BTreeMap<Value, Value>>,
        keys: Vec<Value>,
        index: usize,
    },
    Set {
        items: Vec<Value>,
        index: usize,
    },
}

impl IterationState {
    fn advance(&mut self) {
        match self {
            IterationState::Array { index, .. } => {
                *index += 1;
            }
            IterationState::Object { index, .. } => *index += 1,
            IterationState::Set { index, .. } => *index += 1,
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

/// The RVM Virtual Machine
pub struct RegoVM {
    /// Registers for storing values during execution
    registers: Vec<Value>,

    /// Literal table
    literals: Vec<Value>,

    /// Program counter
    pc: usize,

    /// The bytecode instructions
    instructions: Vec<Instruction>,

    /// Global data object
    data: Value,

    /// Global input object
    input: Value,

    /// Built-in functions
    builtins: BTreeMap<String, fn(&[Value]) -> Result<Value>>,

    /// Loop execution stack
    loop_stack: Vec<LoopContext>,

    /// Maximum number of instructions to execute (default: 5000)
    max_instructions: usize,

    /// Current count of executed instructions
    executed_instructions: usize,
}

impl RegoVM {
    /// Create a new virtual machine
    pub fn new() -> Self {
        let mut vm = RegoVM {
            registers: {
                let mut regs = Vec::new();
                for _ in 0..65536 {
                    // u16 allows up to 65536 registers
                    regs.push(Value::Null);
                }
                regs
            },
            literals: Vec::new(),
            pc: 0,
            instructions: Vec::new(),
            data: Value::Null,
            input: Value::Null,
            builtins: BTreeMap::new(),
            loop_stack: Vec::new(),
            max_instructions: 5000, // Default maximum instruction limit
            executed_instructions: 0,
        };

        // Register built-in functions
        vm.register_builtins();
        vm
    }

    /// Load instructions into the VM
    pub fn load(&mut self, instructions: Vec<Instruction>) {
        self.instructions = instructions;
        self.literals = Vec::new();
        self.pc = 0;
        self.executed_instructions = 0; // Reset instruction counter
    }

    /// Load a complete program with instructions and literals
    pub fn load_program(&mut self, instructions: Vec<Instruction>, literals: Vec<Value>) {
        self.instructions = instructions;
        self.literals = literals.clone();
        self.pc = 0;
        self.executed_instructions = 0; // Reset instruction counter

        // Debug: Print the literals received by VM
        std::println!("Debug: VM received {} literals:", self.literals.len());
        for (i, literal) in self.literals.iter().enumerate() {
            std::println!("  VM literal_idx {}: {:?}", i, literal);
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

    /// Execute the loaded instructions
    pub fn execute(&mut self) -> Result<Value> {
        // Reset execution state for each execution
        self.executed_instructions = 0;
        self.pc = 0;

        while self.pc < self.instructions.len() {
            // Check instruction execution limit
            if self.executed_instructions >= self.max_instructions {
                bail!(
                    "Execution stopped: exceeded maximum instruction limit of {}",
                    self.max_instructions
                );
            }

            self.executed_instructions += 1;
            let instruction = self.instructions[self.pc].clone();

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
                    if let Some(value) = self.literals.get(literal_idx as usize) {
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

                Instruction::Concat { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];
                    self.registers[dest as usize] = self.concat_values(a, b)?;
                }

                Instruction::Call {
                    dest,
                    func,
                    args_start,
                    args_count,
                } => {
                    if let Value::String(func_name) = &self.registers[func as usize] {
                        let mut args = Vec::new();
                        for i in 0..args_count {
                            args.push(self.registers[(args_start + i) as usize].clone());
                        }

                        if let Some(builtin) = self.builtins.get(func_name.as_ref()) {
                            self.registers[dest as usize] = builtin(&args)?;
                        } else {
                            bail!("Unknown function: {}", func_name);
                        }
                    } else {
                        bail!("Function name must be a string");
                    }
                }

                Instruction::Return { value } => {
                    return Ok(self.registers[value as usize].clone());
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
                                    LoopMode::Existential => {
                                        // For SomeIn (existential): mark iteration failed and continue to next iteration
                                        if let Some(loop_ctx_mut) = self.loop_stack.last_mut() {
                                            loop_ctx_mut.current_iteration_failed = true;
                                        }
                                        // Jump directly to the LoopNext instruction
                                        self.pc = loop_next_pc as usize - 1; // -1 because PC will be incremented
                                    }
                                    LoopMode::Universal => {
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
                                // Outside of loop context, return appropriate value for failed assertion
                                match value {
                                    Value::Bool(false) => return Ok(Value::Bool(false)),
                                    Value::Undefined => return Ok(Value::Undefined),
                                    _ => unreachable!(),
                                }
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

                Instruction::LoopStart {
                    mode,
                    collection,
                    key_reg,
                    value_reg,
                    result_reg,
                    body_start,
                    loop_end,
                } => {
                    self.execute_loop_start(
                        &mode, collection, key_reg, value_reg, result_reg, body_start, loop_end,
                    )?;
                }

                Instruction::LoopNext {
                    body_start,
                    loop_end,
                } => {
                    self.execute_loop_next(body_start, loop_end)?;
                }

                Instruction::LoopAccumulate { value, key } => {
                    self.execute_loop_accumulate(value, key)?;
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

    /// Register built-in functions
    fn register_builtins(&mut self) {
        self.builtins.insert(String::from("count"), builtin_count);
        self.builtins.insert(String::from("sum"), builtin_sum);
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

    fn concat_values(&self, a: &Value, b: &Value) -> Result<Value> {
        match (a, b) {
            (Value::String(x), Value::String(y)) => {
                let mut result = String::new();
                result.push_str(x.as_ref());
                result.push_str(y.as_ref());
                Ok(Value::String(result.into()))
            }
            (Value::String(x), b) => {
                let mut result = String::new();
                result.push_str(x.as_ref());
                result.push_str(&format!("{:?}", b));
                Ok(Value::String(result.into()))
            }
            (a, Value::String(y)) => {
                let mut result = format!("{:?}", a);
                result.push_str(y.as_ref());
                Ok(Value::String(result.into()))
            }
            _ => {
                let result = format!("{:?}{:?}", a, b);
                Ok(Value::String(result.into()))
            }
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
    fn execute_loop_start(
        &mut self,
        mode: &LoopMode,
        collection: u16,
        key_reg: u16,
        value_reg: u16,
        result_reg: u16,
        body_start: u16,
        loop_end: u16,
    ) -> Result<()> {
        // Initialize result container based on mode
        let initial_result = match mode {
            LoopMode::Existential | LoopMode::Universal => Value::Bool(false),
            LoopMode::ArrayComprehension => Value::new_array(),
            LoopMode::SetComprehension => Value::new_set(),
            LoopMode::ObjectComprehension => Value::Object(Arc::new(BTreeMap::new())),
        };
        self.registers[result_reg as usize] = initial_result;

        let collection_value = self.registers[collection as usize].clone();

        // Validate collection is iterable and create iteration state
        let iteration_state = match &collection_value {
            Value::Array(items) => {
                if items.is_empty() {
                    self.handle_empty_collection(mode, result_reg, loop_end)?;
                    return Ok(());
                }
                IterationState::Array {
                    items: items.clone(),
                    index: 0,
                }
            }
            Value::Object(obj) => {
                if obj.is_empty() {
                    self.handle_empty_collection(mode, result_reg, loop_end)?;
                    return Ok(());
                }
                let keys: Vec<Value> = obj.keys().cloned().collect();
                IterationState::Object {
                    obj: obj.clone(),
                    keys,
                    index: 0,
                }
            }
            Value::Set(set) => {
                if set.is_empty() {
                    self.handle_empty_collection(mode, result_reg, loop_end)?;
                    return Ok(());
                }
                let items: Vec<Value> = set.iter().cloned().collect();
                IterationState::Set { items, index: 0 }
            }
            _ => {
                bail!("Cannot iterate over {:?}", collection_value);
            }
        };

        // Set up first iteration
        let has_next = self.setup_next_iteration(&iteration_state, key_reg, value_reg)?;
        if !has_next {
            self.pc = loop_end as usize;
            return Ok(());
        }

        // Create loop context
        // The LoopNext instruction is positioned immediately before loop_end
        let loop_next_pc = loop_end - 1;

        let loop_context = LoopContext {
            mode: mode.clone(),
            iteration_state,
            key_reg,
            value_reg,
            result_reg,
            body_start,
            loop_end,
            loop_next_pc,
            success_count: 0,
            total_iterations: 0,
            current_iteration_failed: false,
        };

        self.loop_stack.push(loop_context);
        self.pc = body_start as usize - 1; // -1 because PC will be incremented after instruction
        Ok(())
    }

    /// Execute LoopNext instruction
    fn execute_loop_next(&mut self, body_start: u16, loop_end: u16) -> Result<()> {
        std::println!(
            "Debug: LoopNext - body_start={}, loop_end={}",
            body_start,
            loop_end
        );
        if let Some(mut loop_ctx) = self.loop_stack.pop() {
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
                    LoopMode::Existential => {
                        let result = Value::Bool(loop_ctx.success_count > 0);
                        std::println!(
                            "Debug: LoopNext - Existential final result: {:?} (success_count={})",
                            result,
                            loop_ctx.success_count
                        );
                        result
                    }
                    LoopMode::Universal => {
                        Value::Bool(loop_ctx.success_count == loop_ctx.total_iterations)
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
            self.pc = loop_end as usize; // Jump past LoopNext instruction
            Ok(())
        }
    }

    /// Execute LoopAccumulate instruction (explicit accumulation control)
    fn execute_loop_accumulate(&mut self, value: u16, key: Option<u16>) -> Result<()> {
        if let Some(loop_ctx) = self.loop_stack.last() {
            let value_to_accumulate = self.registers[value as usize].clone();
            let result_reg = loop_ctx.result_reg;

            let mut result_value =
                std::mem::replace(&mut self.registers[result_reg as usize], Value::Null);

            match &mut result_value {
                Value::Array(_) => {
                    if let Ok(arr_mut) = result_value.as_array_mut() {
                        arr_mut.push(value_to_accumulate);
                    }
                }
                Value::Set(_) => {
                    if let Ok(set_mut) = result_value.as_set_mut() {
                        set_mut.insert(value_to_accumulate);
                    }
                }
                Value::Object(_) => {
                    if let Some(key_reg) = key {
                        let key_value = self.registers[key_reg as usize].clone();
                        if let Ok(obj_mut) = result_value.as_object_mut() {
                            obj_mut.insert(key_value, value_to_accumulate);
                        }
                    } else {
                        self.registers[result_reg as usize] = result_value;
                        bail!("Object comprehension requires key register");
                    }
                }
                _ => {
                    self.registers[result_reg as usize] = result_value;
                    bail!("LoopAccumulate: invalid result type");
                }
            }

            self.registers[result_reg as usize] = result_value;
            Ok(())
        } else {
            bail!("LoopAccumulate without active loop");
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
            LoopMode::Existential => Value::Bool(false),
            LoopMode::Universal => Value::Bool(true), // Every element of empty set satisfies condition
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
            IterationState::Object { obj, keys, index } => {
                if *index < keys.len() {
                    let key = &keys[*index];
                    if key_reg != u16::MAX {
                        self.registers[key_reg as usize] = key.clone();
                    }
                    self.registers[value_reg as usize] = obj[key].clone();
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            IterationState::Set { items, index } => {
                if *index < items.len() {
                    let value = &items[*index];
                    if key_reg != u16::MAX {
                        // For sets, key and value are the same
                        self.registers[key_reg as usize] = value.clone();
                    }
                    self.registers[value_reg as usize] = value.clone();
                    Ok(true)
                } else {
                    Ok(false)
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
            (LoopMode::Existential, true) => LoopAction::ExitWithSuccess,
            (LoopMode::Universal, false) => LoopAction::ExitWithFailure,
            // For comprehensions, let explicit accumulation instructions handle the results
            (LoopMode::ArrayComprehension, _) => LoopAction::Continue,
            (LoopMode::SetComprehension, _) => LoopAction::Continue,
            (LoopMode::ObjectComprehension, _) => LoopAction::Continue,
            _ => LoopAction::Continue,
        }
    }
}

/// Built-in function: count
fn builtin_count(args: &[Value]) -> Result<Value> {
    if args.len() != 1 {
        bail!("count expects 1 argument");
    }

    match &args[0] {
        Value::Array(array_items) => Ok(Value::from(array_items.len() as f64)),
        Value::Object(object_fields) => Ok(Value::from(object_fields.len() as f64)),
        Value::Set(set_elements) => Ok(Value::from(set_elements.len() as f64)),
        Value::String(string_content) => Ok(Value::from(string_content.len() as f64)),
        _ => bail!("count expects array, object, set, or string"),
    }
}

/// Built-in function: sum  
fn builtin_sum(args: &[Value]) -> Result<Value> {
    if args.len() != 1 {
        bail!("sum expects 1 argument");
    }

    match &args[0] {
        Value::Array(array_items) => {
            let mut total = 0.0;
            for item in array_items.iter() {
                if let Value::Number(number_value) = item {
                    if let Some(numeric_value) = number_value.as_f64() {
                        total += numeric_value;
                    } else {
                        bail!("sum: non-numeric value in array");
                    }
                } else {
                    bail!("sum: non-numeric value in array");
                }
            }
            Ok(Value::from(total))
        }
        _ => bail!("sum expects array"),
    }
}
