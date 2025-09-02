use crate::rvm::instructions::Instruction;
use crate::value::Value;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use anyhow::{bail, Result};

extern crate alloc;

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

    /// Built-in functions
    builtins: BTreeMap<String, fn(&[Value]) -> Result<Value>>,
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
            builtins: BTreeMap::new(),
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
    }

    /// Load a complete program with instructions and literals
    pub fn load_program(&mut self, instructions: Vec<Instruction>, literals: Vec<Value>) {
        self.instructions = instructions;
        self.literals = literals;
        self.pc = 0;
    }

    /// Execute the loaded instructions
    pub fn execute(&mut self) -> Result<Value> {
        while self.pc < self.instructions.len() {
            let instruction = self.instructions[self.pc].clone();

            match instruction {
                Instruction::Load { dest, literal_idx } => {
                    if let Some(value) = self.literals.get(literal_idx as usize) {
                        self.registers[dest as usize] = value.clone();
                    } else {
                        bail!("Literal index {} out of bounds", literal_idx);
                    }
                }

                Instruction::Move { dest, src } => {
                    self.registers[dest as usize] = self.registers[src as usize].clone();
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
                    self.registers[dest as usize] = self.mul_values(a, b)?;
                }

                Instruction::Div { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];
                    self.registers[dest as usize] = self.div_values(a, b)?;
                }

                Instruction::Eq { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];
                    self.registers[dest as usize] = Value::Bool(a == b);
                }

                Instruction::Lt { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];
                    self.registers[dest as usize] = Value::Bool(self.compare_values(a, b)? < 0);
                }

                Instruction::Gt { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];
                    self.registers[dest as usize] = Value::Bool(self.compare_values(a, b)? > 0);
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
                    // Check if condition is false or undefined - if so, abort with undefined
                    match value {
                        Value::Bool(false) => return Ok(Value::Undefined),
                        Value::Undefined => return Ok(Value::Undefined),
                        Value::Null => return Ok(Value::Undefined), // Null is falsy in Rego
                        _ => {
                            // For other values, check if they're truthy
                            // In Rego, only false, undefined, and null are falsy
                            // Everything else (including 0, empty strings, empty arrays) is truthy
                        }
                    }
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

    /// Compare two values (-1, 0, 1)
    fn compare_values(&self, a: &Value, b: &Value) -> Result<i32> {
        match (a, b) {
            (Value::Number(x), Value::Number(y)) => {
                if let (Some(x_f64), Some(y_f64)) = (x.as_f64(), y.as_f64()) {
                    if x_f64 < y_f64 {
                        Ok(-1)
                    } else if x_f64 > y_f64 {
                        Ok(1)
                    } else {
                        Ok(0)
                    }
                } else {
                    bail!("Cannot compare these numbers");
                }
            }
            _ => bail!("Cannot compare {:?} and {:?}", a, b),
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
