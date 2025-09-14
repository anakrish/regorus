use crate::rvm::instructions::{Instruction, LoopMode};
use crate::rvm::program::Program;
use crate::rvm::tracing_utils::{debug, info, span, trace};
use crate::value::Value;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use thiserror::Error;

/// VM execution errors
#[derive(Error, Debug)]
pub enum VmError {
    #[error("Execution stopped: exceeded maximum instruction limit of {limit}")]
    InstructionLimitExceeded { limit: usize },
    
    #[error("Literal index {index} out of bounds")]
    LiteralIndexOutOfBounds { index: usize },
    
    #[error("Register {register} does not contain an object")]
    RegisterNotObject { register: u8 },
    
    #[error("ObjectCreate: template is not an object")]
    ObjectCreateInvalidTemplate,
    
    #[error("Register {register} does not contain an array")]
    RegisterNotArray { register: u8 },
    
    #[error("Register {register} does not contain a set")]
    RegisterNotSet { register: u8 },
    
    #[error("Rule index {index} out of bounds")]
    RuleIndexOutOfBounds { index: u16 },
    
    #[error("Rule index {index} has no info")]
    RuleInfoMissing { index: u16 },
    
    #[error("Invalid object create params index: {index}")]
    InvalidObjectCreateParams { index: u16 },
    
    #[error("Invalid template literal index: {index}")]
    InvalidTemplateLiteralIndex { index: u16 },
    
    #[error("Builtin function expects exactly {expected} arguments, got {actual}")]
    BuiltinArgumentMismatch { expected: u16, actual: usize },
    
    #[error("Builtin function not resolved: {name}")]
    BuiltinNotResolved { name: String },
    
    #[error("Cannot add {left:?} and {right:?}")]
    InvalidAddition { left: Value, right: Value },
    
    #[error("Cannot subtract {left:?} and {right:?}")]
    InvalidSubtraction { left: Value, right: Value },
    
    #[error("Cannot multiply {left:?} and {right:?}")]
    InvalidMultiplication { left: Value, right: Value },
    
    #[error("Cannot divide {left:?} and {right:?}")]
    InvalidDivision { left: Value, right: Value },
    
    #[error("modulo on floating-point number")]
    ModuloOnFloat,
    
    #[error("Cannot modulo {left:?} and {right:?}")]
    InvalidModulo { left: Value, right: Value },
    
    #[error("Cannot iterate over {value:?}")]
    InvalidIteration { value: Value },
    
    #[error("Assertion failed")]
    AssertionFailed,
    
    #[error("Arithmetic error: {0}")]
    ArithmeticError(String),
}

impl From<anyhow::Error> for VmError {
    fn from(err: anyhow::Error) -> Self {
        VmError::ArithmeticError(alloc::format!("{}", err))
    }
}

pub type Result<T> = core::result::Result<T, VmError>;

extern crate alloc;

/// Loop execution context for managing iteration state
#[derive(Debug, Clone)]
pub struct LoopContext {
    pub mode: LoopMode,
    pub iteration_state: IterationState,
    pub key_reg: u8,
    pub value_reg: u8,
    pub result_reg: u8,
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
    pub dest_reg: u8,
    pub result_reg: u8,
    pub rule_index: u16,
    pub rule_type: crate::rvm::program::RuleType,
    pub current_definition_index: usize,
    pub current_body_index: usize,
}

/// Parameters for loop execution
struct LoopParams {
    collection: u8,
    key_reg: u8,
    value_reg: u8,
    result_reg: u8,
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

    /// Reference to the compiled policy for default rule access
    compiled_policy: Option<crate::CompiledPolicy>,

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

    /// Register stack for isolated register spaces during rule calls
    register_stack: Vec<Vec<Value>>,

    /// Base register window size for the main execution context
    base_register_count: usize,

    /// Maximum number of instructions to execute (default: 25000)
    max_instructions: usize,

    /// Current count of executed instructions
    executed_instructions: usize,

    /// Interactive debugger for step-by-step execution analysis
    #[cfg(feature = "rvm-debug")]
    debugger: crate::rvm::debugger::InteractiveDebugger,

    /// Span stack for hierarchical tracing
    #[cfg(feature = "rvm-tracing")]
    span_stack: Vec<tracing::span::EnteredSpan>,
}

impl Default for RegoVM {
    fn default() -> Self {
        Self::new()
    }
}

impl RegoVM {
    /// Create a new virtual machine
    pub fn new() -> Self {
        // Initialize tracing if enabled
        crate::rvm::tracing_utils::init_rvm_tracing();

        RegoVM {
            registers: Vec::new(), // Start with no registers - will be resized when program is loaded
            pc: 0,
            program: Arc::new(Program::default()),
            compiled_policy: None,
            rule_cache: Vec::new(),
            data: Value::Null,
            input: Value::Null,
            loop_stack: Vec::new(),
            call_rule_stack: Vec::new(),
            register_stack: Vec::new(),
            base_register_count: 2, // Default to 2 registers for basic operations
            max_instructions: 25000, // Default maximum instruction limit
            executed_instructions: 0,
            #[cfg(feature = "rvm-debug")]
            debugger: crate::rvm::debugger::InteractiveDebugger::new(),
            #[cfg(feature = "rvm-tracing")]
            span_stack: Vec::new(),
        }
    }

    /// Create a new virtual machine with compiled policy for default rule support
    pub fn new_with_policy(compiled_policy: crate::CompiledPolicy) -> Self {
        let mut vm = Self::new();
        vm.compiled_policy = Some(compiled_policy);
        vm
    }

    /// Load a complete program for execution
    pub fn load_program(&mut self, program: Arc<Program>) {
        self.program = program.clone();

        // Resize registers to match program requirements
        // Use the base register count instead of hardcoded value
        self.registers.clear();
        self.registers.resize(self.base_register_count, Value::Null);

        // Initialize rule cache
        self.rule_cache = vec![(false, Value::Undefined); program.rule_infos.len()];

        // Set PC to main entry point
        self.pc = program.main_entry_point;
        self.executed_instructions = 0; // Reset instruction counter

        // Debug: Print the program received by VM
        debug!(
            "VM received program with {} instructions, {} literals, {} rules, {} registers:",
            program.instructions.len(),
            program.literals.len(),
            program.rule_infos.len(),
            self.base_register_count
        );
        #[cfg(feature = "rvm-tracing")]
        {
            for (i, literal) in program.literals.iter().enumerate() {
                debug!("  VM literal_idx {}: {:?}", i, literal);
            }
        }

        // Debug: Print rule definitions
        #[cfg(feature = "rvm-tracing")]
        {
            debug!("VM rule infos:");
            for (rule_idx, rule_info) in program.rule_infos.iter().enumerate() {
                debug!(
                    "  VM Rule {}: {} definitions",
                    rule_idx,
                    rule_info.definitions.len()
                );
                for (def_idx, bodies) in rule_info.definitions.iter().enumerate() {
                    debug!(
                        "    VM Definition {}: {} bodies at entry points {:?}",
                        def_idx,
                        bodies.len(),
                        bodies
                    );
                }
            }
        }
    }

    /// Set the compiled policy for default rule evaluation
    pub fn set_compiled_policy(&mut self, compiled_policy: crate::CompiledPolicy) {
        self.compiled_policy = Some(compiled_policy);
    }

    /// Set the maximum number of instructions that can be executed
    pub fn set_max_instructions(&mut self, max: usize) {
        self.max_instructions = max;
    }

    /// Set the base register count for the main execution context
    /// This determines how many registers are available in the root register window
    pub fn set_base_register_count(&mut self, count: usize) {
        self.base_register_count = count.max(1); // Ensure at least 1 register
                                                 // If registers are already allocated, resize them
        if !self.registers.is_empty() {
            self.registers.resize(self.base_register_count, Value::Null);
        }
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
        let _span = span!(tracing::Level::INFO, "vm_execute");
        info!(
            "Starting VM execution with {} instructions",
            self.program.instructions.len()
        );

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

    /// Push a new span onto the span stack for hierarchical tracing
    #[cfg(feature = "rvm-tracing")]
    fn push_span(&mut self, span: tracing::Span) {
        let entered = span.entered();
        self.span_stack.push(entered);
    }

    /// Pop the current span from the span stack
    #[cfg(feature = "rvm-tracing")]
    fn pop_span(&mut self) {
        if let Some(_span) = self.span_stack.pop() {
            // Span is automatically exited when dropped
        }
    }

    /// Clear all spans from the stack (used for cleanup)
    #[cfg(feature = "rvm-tracing")]
    fn clear_spans(&mut self) {
        self.span_stack.clear();
    }

    /// Execute the loaded program
    pub fn jump_to(&mut self, target: usize) -> Result<Value> {
        #[cfg(feature = "rvm-tracing")]
        {
            let span = span!(tracing::Level::INFO, "vm_execution");
            self.push_span(span);
        }

        info!(target_pc = target, "starting VM execution");

        let program = self.program.clone();
        self.pc = target;
        while self.pc < program.instructions.len() {
            // Check instruction execution limit
            if self.executed_instructions >= self.max_instructions {
                return Err(VmError::InstructionLimitExceeded {
                    limit: self.max_instructions,
                });
            }

            self.executed_instructions += 1;
            let instruction = program.instructions[self.pc].clone();

            // Add hierarchical span for loop body execution
            #[cfg(feature = "rvm-tracing")]
            let _loop_span_guard = if !self.loop_stack.is_empty() {
                let span = span!(tracing::Level::DEBUG, "loop_body_execution");
                Some(span.entered())
            } else {
                None
            };

            // Trace every instruction execution
            trace!(
                pc = self.pc,
                instruction = ?instruction,
                executed_count = self.executed_instructions,
                "executing instruction"
            );

            // Debugger integration
            #[cfg(feature = "rvm-debug")]
            if self
                .debugger
                .should_break(self.pc, &instruction, &self.call_rule_stack, &program)
            {
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
                debug!(
                    instruction_count = self.executed_instructions,
                    pc = self.pc,
                    instruction = ?instruction,
                    "high instruction count reached"
                );
            }

            match instruction {
                Instruction::Load { dest, literal_idx } => {
                    if let Some(value) = program.literals.get(literal_idx as usize) {
                        debug!(
                            "Load instruction - dest={}, literal_idx={}, value={:?}",
                            dest, literal_idx, value
                        );
                        self.registers[dest as usize] = value.clone();
                        debug!(
                            "After Load - register[{}] = {:?}",
                            dest, self.registers[dest as usize]
                        );
                    } else {
                        return Err(VmError::LiteralIndexOutOfBounds {
                            index: literal_idx as usize,
                        });
                    }
                }

                Instruction::LoadTrue { dest } => {
                    self.registers[dest as usize] = Value::Bool(true);
                }

                Instruction::LoadFalse { dest } => {
                    self.registers[dest as usize] = Value::Bool(false);
                }

                Instruction::LoadNull { dest } => {
                    debug!("LoadNull instruction - dest={}", dest);
                    self.registers[dest as usize] = Value::Null;
                    debug!("After LoadNull - register[{}] = Null", dest);
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
                    debug!("Move instruction - dest={}, src={}", dest, src);
                    debug!(
                        "Before Move - src register {} contains: {:?}",
                        src, self.registers[src as usize]
                    );
                    self.registers[dest as usize] = self.registers[src as usize].clone();
                    debug!(
                        "After Move - dest register {} contains: {:?}",
                        dest, self.registers[dest as usize]
                    );
                }

                Instruction::Add { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];
                    debug!(
                        "Add instruction - left[{}]={:?}, right[{}]={:?}",
                        left, a, right, b
                    );

                    // Handle undefined values - treat as failure condition
                    if a == &Value::Undefined || b == &Value::Undefined {
                        debug!("Add failed - undefined operand");
                        self.handle_condition(false)?;
                    } else {
                        self.registers[dest as usize] = self.add_values(a, b)?;
                        debug!(
                            "Add result - dest[{}]={:?}",
                            dest, self.registers[dest as usize]
                        );
                    }
                }

                Instruction::Sub { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];

                    // Handle undefined values - treat as failure condition
                    if a == &Value::Undefined || b == &Value::Undefined {
                        self.handle_condition(false)?;
                    } else {
                        self.registers[dest as usize] = self.sub_values(a, b)?;
                    }
                }

                Instruction::Mul { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];
                    debug!(
                        "Mul instruction - left_reg={} contains {:?}, right_reg={} contains {:?}",
                        left, a, right, b
                    );

                    // Handle undefined values - treat as failure condition
                    if a == &Value::Undefined || b == &Value::Undefined {
                        self.handle_condition(false)?;
                    } else {
                        self.registers[dest as usize] = self.mul_values(a, b)?;
                    }
                }

                Instruction::Div { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];

                    // Handle undefined values - treat as failure condition
                    if a == &Value::Undefined || b == &Value::Undefined {
                        self.handle_condition(false)?;
                    } else {
                        self.registers[dest as usize] = self.div_values(a, b)?;
                    }
                }

                Instruction::Mod { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];

                    // Handle undefined values - treat as failure condition
                    if a == &Value::Undefined || b == &Value::Undefined {
                        self.handle_condition(false)?;
                    } else {
                        self.registers[dest as usize] = self.mod_values(a, b)?;
                    }
                }

                Instruction::Eq { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];

                    // Handle undefined values - treat as failure condition
                    if a == &Value::Undefined || b == &Value::Undefined {
                        self.handle_condition(false)?;
                    } else {
                        self.registers[dest as usize] = Value::Bool(a == b);
                    }
                }

                Instruction::Ne { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];

                    // Handle undefined values - treat as failure condition
                    if a == &Value::Undefined || b == &Value::Undefined {
                        self.handle_condition(false)?;
                    } else {
                        self.registers[dest as usize] = Value::Bool(a != b);
                    }
                }

                Instruction::Lt { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];

                    // Handle undefined values - treat as failure condition
                    if a == &Value::Undefined || b == &Value::Undefined {
                        self.handle_condition(false)?;
                    } else {
                        self.registers[dest as usize] = Value::Bool(a < b);
                    }
                }

                Instruction::Le { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];

                    // Handle undefined values - treat as failure condition
                    if a == &Value::Undefined || b == &Value::Undefined {
                        self.handle_condition(false)?;
                    } else {
                        self.registers[dest as usize] = Value::Bool(a <= b);
                    }
                }

                Instruction::Gt { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];

                    // Handle undefined values - treat as failure condition
                    if a == &Value::Undefined || b == &Value::Undefined {
                        self.handle_condition(false)?;
                    } else {
                        self.registers[dest as usize] = Value::Bool(a > b);
                    }
                }

                Instruction::Ge { dest, left, right } => {
                    let a = &self.registers[left as usize];
                    let b = &self.registers[right as usize];

                    // Handle undefined values - treat as failure condition
                    if a == &Value::Undefined || b == &Value::Undefined {
                        self.handle_condition(false)?;
                    } else {
                        self.registers[dest as usize] = Value::Bool(a >= b);
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
                    self.execute_builtin_call(params_index)?;
                }

                Instruction::FunctionCall { params_index } => {
                    self.execute_function_call(params_index)?;
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
                        // Restore the original value and return error
                        self.registers[obj as usize] = obj_value;
                        return Err(VmError::RegisterNotObject { register: obj });
                    }
                }

                Instruction::ObjectCreate { params_index } => {
                    let params = program
                        .instruction_data
                        .get_object_create_params(params_index)
                        .ok_or_else(|| {
                            VmError::InvalidObjectCreateParams {
                                index: params_index,
                            }
                        })?;

                    // Start with template object (always present)
                    let mut obj_value = program
                        .literals
                        .get(params.template_literal_idx as usize)
                        .ok_or_else(|| {
                            VmError::InvalidTemplateLiteralIndex {
                                index: params.template_literal_idx,
                            }
                        })?
                        .clone();

                    // Set all field values
                    if let Ok(obj_mut) = obj_value.as_object_mut() {
                        // Since literal_key_field_pairs is sorted and obj_mut.iter_mut() is also sorted,
                        // we can do efficient parallel iteration for existing keys
                        let mut literal_updates = params.literal_key_field_pairs().iter();
                        let mut current_literal_update = literal_updates.next();

                        // Update existing keys in the object (from template)
                        for (key, value) in obj_mut.iter_mut() {
                            if let Some(&(literal_idx, value_reg)) = current_literal_update {
                                if let Some(literal_key) =
                                    program.literals.get(literal_idx as usize)
                                {
                                    if key == literal_key {
                                        // Found matching key - update the value
                                        *value = self.registers[value_reg as usize].clone();
                                        current_literal_update = literal_updates.next();
                                    }
                                }
                            } else {
                                // No more literal updates to process
                                break;
                            }
                        }

                        // Insert any remaining literal keys that weren't in the template
                        while let Some(&(literal_idx, value_reg)) = current_literal_update {
                            if let Some(key_value) = program.literals.get(literal_idx as usize) {
                                let value_value = self.registers[value_reg as usize].clone();
                                obj_mut.insert(key_value.clone(), value_value);
                            }
                            current_literal_update = literal_updates.next();
                        }

                        // Insert all non-literal key fields
                        for &(key_reg, value_reg) in params.field_pairs() {
                            let key_value = self.registers[key_reg as usize].clone();
                            let value_value = self.registers[value_reg as usize].clone();
                            obj_mut.insert(key_value, value_value);
                        }
                    } else {
                        return Err(VmError::ObjectCreateInvalidTemplate);
                    }

                    // Store result in destination register
                    self.registers[params.dest as usize] = obj_value;
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

                Instruction::IndexLiteral {
                    dest,
                    container,
                    literal_idx,
                } => {
                    let container_value = &self.registers[container as usize];

                    // Get the literal key value from the program's literal table
                    if let Some(key_value) = self.program.literals.get(literal_idx as usize) {
                        // Use Value's built-in indexing - this handles objects, arrays, and sets efficiently
                        let result = container_value[key_value].clone();
                        self.registers[dest as usize] = result;
                    } else {
                        return Err(VmError::LiteralIndexOutOfBounds {
                            index: literal_idx as usize,
                        });
                    }
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
                        // Restore the original value and return error
                        self.registers[arr as usize] = arr_value;
                        return Err(VmError::RegisterNotArray { register: arr });
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
                        // Restore the original value and return error
                        self.registers[set as usize] = set_value;
                        return Err(VmError::RegisterNotSet { register: set });
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
                    debug!(
                        "AssertCondition - condition_reg={} contains {:?}",
                        condition, value
                    );

                    // Convert value to boolean and handle the condition
                    let condition_result = match value {
                        Value::Bool(b) => *b,
                        Value::Undefined => false,
                        _ => true, // In Rego, only false and undefined are falsy
                    };

                    self.handle_condition(condition_result)?;
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
                    #[cfg(feature = "rvm-tracing")]
                    self.clear_spans();
                    return Ok(self.registers[0].clone());
                }
            }

            self.pc += 1;
        }

        // If we reach here, return register 0
        #[cfg(feature = "rvm-tracing")]
        self.clear_spans();

        Ok(self.registers[0].clone())
    }

    /// Shared rule definition execution logic with consistency checking
    fn execute_rule_definitions_common(
        &mut self,
        rule_definitions: &[Vec<usize>],
        rule_info: &crate::rvm::program::RuleInfo,
        function_call_params: Option<&crate::rvm::instructions::FunctionCallParams>,
    ) -> Result<(Value, bool)> {
        let mut first_successful_result: Option<Value> = None;
        let mut rule_failed_due_to_inconsistency = false;
        let is_function_call = rule_info.function_info.is_some();
        let result_reg = rule_info.result_reg as usize;

        let num_registers = rule_info.num_registers as usize;
        let mut register_window = Vec::with_capacity(num_registers);

        let num_retained_registers = match function_call_params {
            Some(params) => {
                // Return register.
                register_window.push(Value::Undefined);
                for arg in params.args[0..params.num_args as usize].iter() {
                    register_window.push(self.registers[*arg as usize].clone());
                }
                // The return register is also retained in addition to the arguments
                params.num_args as usize + 1
            }
            _ => {
                match rule_info.rule_type {
                    crate::rvm::program::RuleType::PartialSet
                    | crate::rvm::program::RuleType::PartialObject => {
                        // For partial sets and objects, retain the result register
                        // since each definition contributes to it
                        1
                    }
                    crate::rvm::program::RuleType::Complete => {
                        // No registers need to be retained between definitions.
                        0
                    }
                }
            }
        };

        let mut old_registers = Vec::default();
        core::mem::swap(&mut old_registers, &mut self.registers);
        self.register_stack.push(old_registers);
        self.registers = register_window;

        for (def_idx, definition_bodies) in rule_definitions.iter().enumerate() {
            for (body_entry_point_idx, body_entry_point) in definition_bodies.iter().enumerate() {
                // Update call context if we have one
                if let Some(ctx) = self.call_rule_stack.last_mut() {
                    ctx.current_body_index = body_entry_point_idx;
                    ctx.current_definition_index = def_idx;
                }

                debug!(
                    "Executing rule definition {} at body {}, entry point {}",
                    def_idx, body_entry_point_idx, body_entry_point
                );

                // Reset register window while preserving retained registers
                self.registers
                    .resize(num_retained_registers, Value::Undefined);
                self.registers.resize(num_registers, Value::Undefined);

                // Execute the body
                match self.jump_to(*body_entry_point) {
                    Ok(_) => {
                        debug!("Body {} completed", body_entry_point_idx);

                        // For complete rules and functions, check consistency of successful results
                        if matches!(rule_info.rule_type, crate::rvm::program::RuleType::Complete)
                            || is_function_call
                        {
                            let current_result = self.registers[result_reg].clone();
                            if current_result != Value::Undefined {
                                if let Some(ref expected) = first_successful_result {
                                    if *expected != current_result {
                                        debug!(
                                            "Rule consistency check failed - expected {:?}, got {:?}",
                                            expected, current_result
                                        );
                                        // Definitions produced different values - rule fails
                                        rule_failed_due_to_inconsistency = true;
                                        self.registers[result_reg] = Value::Undefined;
                                        break;
                                    } else {
                                        debug!("Rule consistency check passed - result matches expected");
                                    }
                                } else {
                                    // First successful result
                                    first_successful_result = Some(current_result.clone());
                                    debug!(
                                        "Rule - first successful result: {:?}",
                                        first_successful_result
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        #[cfg(feature = "rvm-tracing")]
                        debug!("Body {} failed: {:?}", body_entry_point_idx, e);
                        #[cfg(not(feature = "rvm-tracing"))]
                        let _ = e; // Suppress unused warning
                                   // Body failed - skip this definition
                        continue;
                    }
                }
                debug!(
                    "Body {} completed successfully for definition {} of {} definitions",
                    body_entry_point_idx,
                    def_idx,
                    rule_definitions.len()
                );
            }

            // Break out of definition loop if we had inconsistent results
            if rule_failed_due_to_inconsistency {
                debug!("Rule failed due to inconsistent results");
                break;
            }
        }

        let final_result = if rule_failed_due_to_inconsistency {
            Value::Undefined
        } else if let Some(successful_result) = first_successful_result {
            // Use the first successful result if we have one
            successful_result
        } else {
            // No successful definitions - use current register value (likely Undefined)
            self.registers[result_reg].clone()
        };

        if let Some(old_registers) = self.register_stack.pop() {
            self.registers = old_registers;
        }

        Ok((final_result, rule_failed_due_to_inconsistency))
    }

    /// Execute calling rule with caching and call stack support
    fn execute_call_rule_common(
        &mut self,
        dest: u8,
        rule_index: u16,
        function_call_params: Option<&crate::rvm::instructions::FunctionCallParams>,
    ) -> Result<()> {
        debug!(
            "CallRule execution - dest={}, rule_index={}",
            dest, rule_index
        );
        let rule_idx = rule_index as usize;

        // Check bounds
        if rule_idx >= self.rule_cache.len() {
            return Err(VmError::RuleIndexOutOfBounds { index: rule_index });
        }

        // Check cache first
        let (computed, cached_result) = &self.rule_cache[rule_idx];
        if *computed {
            // Cache hit - return cached result
            debug!(
                "Cache hit for rule {} - result: {:?}",
                rule_index, cached_result
            );
            self.registers[dest as usize] = cached_result.clone();
            return Ok(());
        }

        let rule_info = self
            .program
            .rule_infos
            .get(rule_idx)
            .ok_or_else(|| VmError::RuleInfoMissing { index: rule_index })?
            .clone();

        let rule_type = rule_info.rule_type.clone();
        let rule_definitions = rule_info.definitions.clone();

        if rule_definitions.is_empty() {
            // No definitions - return undefined
            debug!(
                "Rule {} has no definitions - returning Undefined",
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
            result_reg: rule_info.result_reg,
            rule_index,
            rule_type: rule_type.clone(),
            current_definition_index: 0,
            current_body_index: 0,
        });

        // Execute all rule definitions with consistency checking
        debug!(
            "CallRule executing rule {} with {} definitions",
            rule_index,
            rule_definitions.len()
        );

        let (final_result, rule_failed_due_to_inconsistency) = self
            .execute_rule_definitions_common(&rule_definitions, &rule_info, function_call_params)?;

        self.registers[dest as usize] = Value::Undefined; // Initialize destination register

        // Return from the call
        let call_context = self.call_rule_stack.pop().expect("Call stack underflow");
        self.pc = call_context.return_pc;
        debug!(
            "CallRule returning from rule {} to PC {}",
            rule_index, self.pc
        );

        // Copy result from the actual result_reg (from call_context) to dest_reg
        // The call_context.result_reg gets updated by RuleInit during execution
        let result_from_rule = if !rule_failed_due_to_inconsistency {
            final_result
        } else {
            Value::Undefined
        };

        // Store the result in the destination register of the calling context
        self.registers[dest as usize] = result_from_rule.clone();

        // For partial set/object rules, if all definitions failed and we still have Undefined,
        // set the appropriate empty collection as the default
        // For complete rules that failed due to inconsistency, keep Undefined
        if self.registers[dest as usize] == Value::Undefined && !rule_failed_due_to_inconsistency {
            match call_context.rule_type {
                crate::rvm::program::RuleType::PartialSet => {
                    debug!("All definitions failed for PartialSet rule - using empty set");
                    self.registers[dest as usize] = Value::new_set();
                }
                crate::rvm::program::RuleType::PartialObject => {
                    debug!("All definitions failed for PartialObject rule - using empty object");
                    self.registers[dest as usize] = Value::new_object();
                }
                crate::rvm::program::RuleType::Complete => {
                    // For complete rules, check if there's a default literal value
                    if let Some(rule_info) = self
                        .program
                        .rule_infos
                        .get(call_context.rule_index as usize)
                    {
                        if let Some(default_literal_index) = rule_info.default_literal_index {
                            if let Some(default_value) =
                                self.program.literals.get(default_literal_index as usize)
                            {
                                debug!(
                                    "All definitions failed for Complete rule - using default literal value: {:?}",
                                    default_value
                                );
                                self.registers[dest as usize] = default_value.clone();
                            } else {
                                debug!(
                                    "All definitions failed for Complete rule - default literal index {} not found, keeping Undefined",
                                    default_literal_index
                                );
                            }
                        } else {
                            debug!(
                                "All definitions failed for Complete rule - no default literal, keeping Undefined"
                            );
                        }
                    } else {
                        debug!(
                            "All definitions failed for Complete rule - rule info not found, keeping Undefined"
                        );
                    }
                }
            }
        }

        // Cache the final result
        let final_result = self.registers[dest as usize].clone();
        debug!("Set rule final result: {:?}", final_result);
        self.rule_cache[rule_idx] = (true, final_result);

        debug!(
            "CallRule completed - dest register {} set to {:?}",
            dest, self.registers[dest as usize]
        );
        Ok(())
    }

    /// Execute CallRule instruction with caching and call stack support
    fn execute_call_rule(&mut self, dest: u8, rule_index: u16) -> Result<()> {
        self.execute_call_rule_common(dest, rule_index, None)
    }

    /// Execute a function call to a user-defined function rule
    fn execute_function_call(&mut self, params_index: u16) -> Result<()> {
        #[cfg(feature = "rvm-tracing")]
        {
            let span = span!(tracing::Level::DEBUG, "execute_function_call");
            self.push_span(span);
        }

        debug!(
            "Executing function call with params_index: {}",
            params_index
        );

        // Get parameters and extract needed values
        let params =
            self.program.instruction_data.function_call_params[params_index as usize].clone();
        self.execute_call_rule_common(params.dest, params.func_rule_index, Some(&params))
    }

    /// Execute a function rule call with arguments
    /// Execute a builtin function call
    fn execute_builtin_call(&mut self, params_index: u16) -> Result<()> {
        let _span = span!(tracing::Level::DEBUG, "execute_builtin_call");
        let _enter = _span.enter();
        debug!("Executing builtin call with params_index: {}", params_index);

        let params = &self.program.instruction_data.builtin_call_params[params_index as usize];
        let builtin_info = &self.program.builtin_info_table[params.builtin_index as usize];

        debug!(
            "Builtin: {} (index: {}), dest_reg: {}",
            builtin_info.name, params.builtin_index, params.dest
        );

        let mut args = Vec::new();
        #[cfg(feature = "rvm-tracing")]
        for (i, &arg_reg) in params.arg_registers().iter().enumerate() {
            let arg_value = self.registers[arg_reg as usize].clone();
            debug!("Builtin arg {}: register {} = {:?}", i, arg_reg, arg_value);
            args.push(arg_value);
        }
        #[cfg(not(feature = "rvm-tracing"))]
        for &arg_reg in params.arg_registers().iter() {
            let arg_value = self.registers[arg_reg as usize].clone();
            args.push(arg_value);
        }

        // Check argument count constraints
        if (args.len() as u16) != builtin_info.num_args {
            debug!(
                "Argument count mismatch for builtin {}: expected {}, got {}",
                builtin_info.name,
                builtin_info.num_args,
                args.len()
            );
            return Err(VmError::BuiltinArgumentMismatch {
                expected: builtin_info.num_args,
                actual: args.len(),
            });
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

            // Create dummy expressions for each argument
            let mut dummy_exprs: Vec<crate::ast::Ref<crate::ast::Expr>> = Vec::new();
            for _ in 0..args.len() {
                let dummy_expr = crate::ast::Expr::Null {
                    span: dummy_span.clone(),
                    value: Value::Null,
                    eidx: 0,
                };
                dummy_exprs.push(crate::ast::Ref::new(dummy_expr));
            }

            let result = (builtin_fcn.0)(&dummy_span, &dummy_exprs, &args, true)?;
            debug!("Builtin {} result: {:?}", builtin_info.name, result);
            self.registers[params.dest as usize] = result.clone();
            debug!("Stored builtin result in register {}", params.dest);
        } else {
            debug!("Builtin function not resolved: {}", builtin_info.name);
            return Err(VmError::BuiltinNotResolved {
                name: builtin_info.name.clone(),
            });
        }

        Ok(())
    }

    /// Execute RuleInit instruction
    fn execute_rule_init(&mut self, result_reg: u8, _rule_index: u16) -> Result<()> {
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
                if current_ctx.current_definition_index == 0 && current_ctx.current_body_index == 0
                {
                    self.registers[result_reg as usize] = Value::new_set();
                }
                debug!(
                    "RuleInit for PartialSet - set value: {:?}",
                    self.registers[result_reg as usize]
                );
            }
            crate::rvm::program::RuleType::PartialObject => {
                if current_ctx.current_definition_index == 0 && current_ctx.current_body_index == 0
                {
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

        let _result_reg = current_ctx.result_reg;

        // RuleReturn just signals completion - the result is already in result_reg
        // The copying to dest_reg happens when we return from CallRule
        debug!(
            "RuleReturn - rule completed with result in result_reg {}: {:?}",
            _result_reg, self.registers[_result_reg as usize]
        );
        Ok(())
    }

    /// Add two values using interpreter's arithmetic logic
    fn add_values(&self, a: &Value, b: &Value) -> Result<Value> {
        match (a, b) {
            (Value::Number(x), Value::Number(y)) => Ok(Value::from(x.add(y)?)),
            _ => Err(VmError::InvalidAddition {
                left: a.clone(),
                right: b.clone(),
            }),
        }
    }

    /// Subtract two values using interpreter's arithmetic logic
    fn sub_values(&self, a: &Value, b: &Value) -> Result<Value> {
        match (a, b) {
            (Value::Number(x), Value::Number(y)) => Ok(Value::from(x.sub(y)?)),
            _ => Err(VmError::InvalidSubtraction {
                left: a.clone(),
                right: b.clone(),
            }),
        }
    }

    /// Multiply two values using interpreter's arithmetic logic
    fn mul_values(&self, a: &Value, b: &Value) -> Result<Value> {
        match (a, b) {
            (Value::Number(x), Value::Number(y)) => Ok(Value::from(x.mul(y)?)),
            _ => Err(VmError::InvalidMultiplication {
                left: a.clone(),
                right: b.clone(),
            }),
        }
    }

    /// Divide two values using interpreter's arithmetic logic
    fn div_values(&self, a: &Value, b: &Value) -> Result<Value> {
        use crate::number::Number;

        match (a, b) {
            (Value::Number(x), Value::Number(y)) => {
                // Handle division by zero like the interpreter (return Undefined in non-strict mode)
                if *y == Number::from(0u64) {
                    return Ok(Value::Undefined);
                }

                Ok(Value::from(x.clone().divide(y)?))
            }
            _ => Err(VmError::InvalidDivision {
                left: a.clone(),
                right: b.clone(),
            }),
        }
    }

    /// Modulo two values using interpreter's arithmetic logic  
    fn mod_values(&self, a: &Value, b: &Value) -> Result<Value> {
        use crate::number::Number;

        match (a, b) {
            (Value::Number(x), Value::Number(y)) => {
                // Handle modulo by zero like the interpreter (return Undefined in non-strict mode)
                if *y == Number::from(0u64) {
                    return Ok(Value::Undefined);
                }

                // Check for integer requirement like the interpreter
                if !x.is_integer() || !y.is_integer() {
                    return Err(VmError::ModuloOnFloat);
                }

                Ok(Value::from(x.clone().modulo(y)?))
            }
            _ => Err(VmError::InvalidModulo {
                left: a.clone(),
                right: b.clone(),
            }),
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

    /// Execute LoopStart instruction
    fn execute_loop_start(&mut self, mode: &LoopMode, params: LoopParams) -> Result<()> {
        #[cfg(feature = "rvm-tracing")]
        {
            let span = span!(tracing::Level::DEBUG, "execute_loop_start", mode = ?mode);
            self.push_span(span);
        }

        debug!(
            "Starting loop: mode={:?}, collection_reg={}, key_reg={}, value_reg={}, result_reg={}",
            mode, params.collection, params.key_reg, params.value_reg, params.result_reg
        );

        // Initialize result container based on mode
        let initial_result = match mode {
            LoopMode::Any | LoopMode::Every | LoopMode::ForEach => Value::Bool(false),
            LoopMode::ArrayComprehension => Value::new_array(),
            LoopMode::SetComprehension => Value::new_set(),
            LoopMode::ObjectComprehension => Value::Object(Arc::new(BTreeMap::new())),
        };
        self.registers[params.result_reg as usize] = initial_result.clone();
        debug!(
            "Initialized result register {} with: {:?}",
            params.result_reg, initial_result
        );

        let collection_value = self.registers[params.collection as usize].clone();
        debug!("Loop collection: {:?}", collection_value);

        // Validate collection is iterable and create iteration state
        let iteration_state = match &collection_value {
            Value::Array(items) => {
                if items.is_empty() {
                    debug!("Empty array collection, handling empty case");
                    self.handle_empty_collection(mode, params.result_reg, params.loop_end)?;
                    return Ok(());
                }
                debug!("Array collection with {} items", items.len());
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
                return Err(VmError::InvalidIteration {
                    value: collection_value.clone(),
                });
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

        // Add span for the first iteration
        #[cfg(feature = "rvm-tracing")]
        {
            let iteration_span = span!(
                tracing::Level::DEBUG,
                "loop_iteration",
                iteration = 1,
                mode = ?mode
            );
            self.push_span(iteration_span);
        }

        self.pc = params.body_start as usize - 1; // -1 because PC will be incremented after instruction

        Ok(())
    }

    /// Execute LoopNext instruction
    fn execute_loop_next(&mut self, _body_start: u16, _loop_end: u16) -> Result<()> {
        // Ignore the parameters and use the loop context instead
        if let Some(mut loop_ctx) = self.loop_stack.pop() {
            let body_start = loop_ctx.body_start;
            let loop_end = loop_ctx.loop_end;

            #[cfg(feature = "rvm-tracing")]
            {
                // Pop the iteration span first
                self.pop_span();
                // Then push the LoopNext processing span
                let span = span!(tracing::Level::DEBUG, "execute_loop_next");
                self.push_span(span);
            }

            debug!(
                "LoopNext - body_start={}, loop_end={} (from context)",
                body_start, loop_end
            );

            loop_ctx.total_iterations += 1;
            debug!(
                "LoopNext - iteration {}, mode={:?}",
                loop_ctx.total_iterations, loop_ctx.mode
            );

            // Check iteration result
            let iteration_succeeded = self.check_iteration_success(&loop_ctx)?;
            debug!("LoopNext - iteration_succeeded={}", iteration_succeeded);

            if iteration_succeeded {
                loop_ctx.success_count += 1;
                debug!("LoopNext - success_count={}", loop_ctx.success_count);
            }

            // Handle mode-specific logic
            let action = self.determine_loop_action(&loop_ctx.mode, iteration_succeeded);
            debug!("LoopNext - action={:?}", action);

            match action {
                LoopAction::ExitWithSuccess => {
                    debug!("Loop exiting with success, setting result to true");
                    self.registers[loop_ctx.result_reg as usize] = Value::Bool(true);
                    // Set PC to loop_end - 1 because main loop will increment it
                    self.pc = loop_end as usize - 1;

                    #[cfg(feature = "rvm-tracing")]
                    self.pop_span();

                    return Ok(());
                }
                LoopAction::ExitWithFailure => {
                    debug!("Loop exiting with failure, setting result to false");
                    self.registers[loop_ctx.result_reg as usize] = Value::Bool(false);
                    // Set PC to loop_end - 1 because main loop will increment it
                    self.pc = loop_end as usize - 1;

                    #[cfg(feature = "rvm-tracing")]
                    self.pop_span();

                    return Ok(());
                }
                LoopAction::Continue => {}
            }

            // Advance to next iteration
            // Store current key/item before advancing for Object and Set iteration
            if let IterationState::Object {
                ref mut current_key,
                ..
            } = &mut loop_ctx.iteration_state
            {
                // Get the key from the key register to store as current_key
                if loop_ctx.key_reg != loop_ctx.value_reg {
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
            debug!("LoopNext - advanced to next iteration");
            let has_next = self.setup_next_iteration(
                &loop_ctx.iteration_state,
                loop_ctx.key_reg,
                loop_ctx.value_reg,
            )?;
            debug!("LoopNext - has_next={}", has_next);

            if has_next {
                loop_ctx.current_iteration_failed = false; // Reset for next iteration

                self.loop_stack.push(loop_ctx);
                self.pc = body_start as usize - 1; // Jump to body_start, which will be incremented to body_start
                debug!(
                    "LoopNext - continuing to next iteration, PC set to {}",
                    self.pc
                );
            } else {
                debug!("LoopNext - loop finished, calculating final result");
                // Loop finished - determine final result
                let final_result = match loop_ctx.mode {
                    LoopMode::Any => {
                        let result = Value::Bool(loop_ctx.success_count > 0);
                        #[cfg(feature = "rvm-tracing")]
                        debug!(
                            "LoopNext - Any final result: {:?} (success_count={})",
                            result, loop_ctx.success_count
                        );
                        result
                    }
                    LoopMode::Every => {
                        Value::Bool(loop_ctx.success_count == loop_ctx.total_iterations)
                    }
                    LoopMode::ForEach => {
                        let result = Value::Bool(loop_ctx.success_count > 0);
                        #[cfg(feature = "rvm-tracing")]
                        debug!(
                            "LoopNext - ForEach final result: {:?} (success_count={})",
                            result, loop_ctx.success_count
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
                debug!(
                    "LoopNext - final result stored in register {}: {:?}",
                    loop_ctx.result_reg, self.registers[loop_ctx.result_reg as usize]
                );

                self.pc = loop_end as usize - 1; // -1 because PC will be incremented

                #[cfg(feature = "rvm-tracing")]
                self.pop_span();
            }

            Ok(())
        } else {
            // No active loop context - this happens when the collection was empty
            // and handle_empty_collection was called. Just continue past loop_end.
            debug!("LoopNext - no active loop (empty collection), jumping past loop_end");
            self.pc = _loop_end as usize; // Jump past LoopNext instruction
            Ok(())
        }
    }

    /// Handle empty collection based on loop mode
    fn handle_empty_collection(
        &mut self,
        mode: &LoopMode,
        result_reg: u8,
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

        #[cfg(feature = "rvm-tracing")]
        self.pop_span();

        Ok(())
    }

    /// Set up the next iteration values
    fn setup_next_iteration(
        &mut self,
        state: &IterationState,
        key_reg: u8,
        value_reg: u8,
    ) -> Result<bool> {
        match state {
            IterationState::Array { items, index } => {
                if *index < items.len() {
                    if key_reg != value_reg {
                        let key_value = Value::from(*index as f64);
                        debug!(
                            "Setting array iteration: key[{}] = {}, value[{}] = {:?}",
                            key_reg, index, value_reg, items[*index]
                        );
                        self.registers[key_reg as usize] = key_value;
                    }
                    let item_value = items[*index].clone();
                    self.registers[value_reg as usize] = item_value.clone();
                    debug!(
                        "Array iteration setup complete: index={}, value={:?}",
                        index, item_value
                    );
                    Ok(true)
                } else {
                    debug!(
                        "Array iteration complete: reached end of {} items",
                        items.len()
                    );
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
                        if key_reg != value_reg {
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
                            if key_reg != value_reg {
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
                        if key_reg != value_reg {
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
                            if key_reg != value_reg {
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
        debug!(
            "check_iteration_success - current_iteration_failed={}",
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

    /// Handle condition evaluation result (for assertions and other conditions)
    fn handle_condition(&mut self, condition_passed: bool) -> Result<()> {
        if condition_passed {
            debug!("Condition passed");
            return Ok(());
        }

        debug!(
            "Condition failed - in loop: {}",
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
                    debug!(
                        "Condition failed in Any loop - jumping to loop_end={}",
                        loop_end
                    );

                    // Jump directly to the LoopNext instruction
                    self.pc = loop_next_pc as usize - 1; // -1 because PC will be incremented
                    #[cfg(feature = "rvm-tracing")]
                    self.pop_span();
                }
                LoopMode::Every => {
                    // For Every (universal): condition failure means entire loop fails
                    // Jump beyond the loop body to loop_end
                    debug!(
                        "Condition failed in Every loop - jumping to loop_end={}",
                        loop_end
                    );
                    self.loop_stack.pop(); // Remove loop context
                    self.pc = loop_end as usize - 1; // -1 because PC will be incremented
                                                     // Set result to false since Every failed
                    self.registers[result_reg as usize] = Value::Bool(false);
                    #[cfg(feature = "rvm-tracing")]
                    self.pop_span();
                }
                _ => {
                    // For comprehensions: mark iteration failed and continue
                    if let Some(loop_ctx_mut) = self.loop_stack.last_mut() {
                        loop_ctx_mut.current_iteration_failed = true;
                    }
                    // Jump directly to the LoopNext instruction
                    self.pc = loop_next_pc as usize - 1; // -1 because PC will be incremented
                    #[cfg(feature = "rvm-tracing")]
                    self.pop_span();
                }
            }
        } else {
            // Outside of loop context, failed condition means this body/definition fails
            debug!("Condition failed outside loop - body failed");
            return Err(VmError::AssertionFailed);
        }

        Ok(())
    }
}
