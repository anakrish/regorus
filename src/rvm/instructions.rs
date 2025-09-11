use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Loop parameters stored in program's instruction data table
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopStartParams {
    /// Loop mode (Existential/Universal/Comprehension types)
    pub mode: LoopMode,
    /// Register containing the collection to iterate over
    pub collection: u8,
    /// Register to store current key (same as value_reg if key not needed)
    pub key_reg: u8,
    /// Register to store current value
    pub value_reg: u8,
    /// Register to store final result
    pub result_reg: u8,
    /// Jump target for loop body start
    pub body_start: u16,
    /// Jump target for loop end
    pub loop_end: u16,
}

/// Builtin function call parameters stored in program's instruction data table
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuiltinCallParams {
    /// Destination register to store the result
    pub dest: u8,
    /// Index into program's builtin_info_table
    pub builtin_index: u16,
    /// Number of arguments actually used
    pub num_args: u8,
    /// Argument register numbers (unused slots contain undefined values)
    pub args: [u8; 8],
}

impl BuiltinCallParams {
    /// Get the number of arguments actually used
    pub fn arg_count(&self) -> usize {
        self.num_args as usize
    }

    /// Get argument register numbers as a slice
    pub fn arg_registers(&self) -> &[u8] {
        &self.args[..self.num_args as usize]
    }
}

/// Function rule call parameters stored in program's instruction data table
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCallParams {
    /// Destination register to store the result
    pub dest: u8,
    /// Rule index of the function to call
    pub func_rule_index: u16,
    /// Number of arguments actually used
    pub num_args: u8,
    /// Argument register numbers (unused slots contain undefined values)
    pub args: [u8; 8],
}

impl FunctionCallParams {
    /// Get the number of arguments actually used
    pub fn arg_count(&self) -> usize {
        self.num_args as usize
    }

    /// Get argument register numbers as a slice
    pub fn arg_registers(&self) -> &[u8] {
        &self.args[..self.num_args as usize]
    }
}

/// Instruction data container for complex instruction parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionData {
    /// Loop parameter table for LoopStart instructions
    pub loop_params: Vec<LoopStartParams>,
    /// Builtin function call parameter table for BuiltinCall instructions
    pub builtin_call_params: Vec<BuiltinCallParams>,
    /// Function rule call parameter table for FunctionCall instructions
    pub function_call_params: Vec<FunctionCallParams>,
}

impl InstructionData {
    /// Create a new empty instruction data container
    pub fn new() -> Self {
        Self {
            loop_params: Vec::new(),
            builtin_call_params: Vec::new(),
            function_call_params: Vec::new(),
        }
    }

    /// Add loop parameters and return the index
    pub fn add_loop_params(&mut self, params: LoopStartParams) -> u16 {
        let index = self.loop_params.len();
        self.loop_params.push(params);
        index as u16
    }

    /// Add builtin call parameters and return the index
    pub fn add_builtin_call_params(&mut self, params: BuiltinCallParams) -> u16 {
        let index = self.builtin_call_params.len();
        self.builtin_call_params.push(params);
        index as u16
    }

    /// Add function call parameters and return the index
    pub fn add_function_call_params(&mut self, params: FunctionCallParams) -> u16 {
        let index = self.function_call_params.len();
        self.function_call_params.push(params);
        index as u16
    }

    /// Get loop parameters by index
    pub fn get_loop_params(&self, index: u16) -> Option<&LoopStartParams> {
        self.loop_params.get(index as usize)
    }

    /// Get builtin call parameters by index
    pub fn get_builtin_call_params(&self, index: u16) -> Option<&BuiltinCallParams> {
        self.builtin_call_params.get(index as usize)
    }

    /// Get function call parameters by index
    pub fn get_function_call_params(&self, index: u16) -> Option<&FunctionCallParams> {
        self.function_call_params.get(index as usize)
    }

    /// Get mutable reference to loop parameters by index
    pub fn get_loop_params_mut(&mut self, index: u16) -> Option<&mut LoopStartParams> {
        self.loop_params.get_mut(index as usize)
    }
}

impl Default for InstructionData {
    fn default() -> Self {
        Self::new()
    }
}

/// Loop execution modes for different Rego iteration constructs
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoopMode {
    /// Any quantification: some x in arr, x := arr[_], etc.
    /// Succeeds if ANY iteration succeeds, exits early on first success
    Any,

    /// Every quantification: every x in arr  
    /// Succeeds only if ALL iterations succeed, exits early on first failure
    Every,

    /// ForEach processing: processes all elements without early exit
    /// Used for set membership rules (contains), object rules, and complete rules
    /// where all candidates must be evaluated. Determined by output constness.
    ForEach,

    /// Array comprehension: [expr | ...]
    /// Collects successful iterations into an array
    ArrayComprehension,

    /// Set comprehension: {expr | ...}
    /// Collects unique successful iterations into a set
    SetComprehension,

    /// Object comprehension: {key: value | ...}
    /// Collects successful key-value pairs into an object
    ObjectComprehension,
}

/// RVM Instructions - simplified enum-based design
#[repr(C)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Instruction {
    /// Load literal value from literal table into register
    Load {
        dest: u8,
        literal_idx: u16,
    },

    /// Load true value into register
    LoadTrue {
        dest: u8,
    },

    /// Load false value into register
    LoadFalse {
        dest: u8,
    },

    /// Load null value into register
    LoadNull {
        dest: u8,
    },

    /// Load boolean value into register
    LoadBool {
        dest: u8,
        value: bool,
    },

    /// Load global data object into register
    LoadData {
        dest: u8,
    },

    /// Load global input object into register
    LoadInput {
        dest: u8,
    },

    /// Move value from one register to another
    Move {
        dest: u8,
        src: u8,
    },

    /// Arithmetic operations
    Add {
        dest: u8,
        left: u8,
        right: u8,
    },
    Sub {
        dest: u8,
        left: u8,
        right: u8,
    },
    Mul {
        dest: u8,
        left: u8,
        right: u8,
    },
    Div {
        dest: u8,
        left: u8,
        right: u8,
    },
    Mod {
        dest: u8,
        left: u8,
        right: u8,
    },

    /// Comparison operations
    Eq {
        dest: u8,
        left: u8,
        right: u8,
    },
    Ne {
        dest: u8,
        left: u8,
        right: u8,
    },
    Lt {
        dest: u8,
        left: u8,
        right: u8,
    },
    Le {
        dest: u8,
        left: u8,
        right: u8,
    },
    Gt {
        dest: u8,
        left: u8,
        right: u8,
    },
    Ge {
        dest: u8,
        left: u8,
        right: u8,
    },

    /// Logical operations
    And {
        dest: u8,
        left: u8,
        right: u8,
    },
    Or {
        dest: u8,
        left: u8,
        right: u8,
    },
    Not {
        dest: u8,
        operand: u8,
    },

    /// Builtin function calls - optimized for builtin functions
    BuiltinCall {
        /// Index into program's instruction_data.builtin_call_params table
        params_index: u16,
    },

    /// Function rule calls - for user-defined function rules  
    FunctionCall {
        /// Index into program's instruction_data.function_call_params table
        params_index: u16,
    },

    /// Return result
    Return {
        value: u8,
    },

    /// Create empty object
    ObjectNew {
        dest: u8,
    },

    /// Set object field
    ObjectSet {
        obj: u8,
        key: u8,
        value: u8,
    },

    /// Index into container (object, array, set)
    Index {
        dest: u8,
        container: u8,
        key: u8,
    },

    /// Index into container using literal key (optimization for Load + Index)
    IndexLiteral {
        dest: u8,
        container: u8,
        literal_idx: u16,
    },

    /// Create empty array
    ArrayNew {
        dest: u8,
    },

    /// Push element to array
    ArrayPush {
        arr: u8,
        value: u8,
    },

    /// Create empty set
    SetNew {
        dest: u8,
    },

    /// Add element to set
    SetAdd {
        set: u8,
        value: u8,
    },

    /// Check if collection contains value (for membership testing)
    Contains {
        dest: u8,
        collection: u8,
        value: u8,
    },

    /// Assert condition - if register contains false or undefined, return undefined immediately
    AssertCondition {
        condition: u8,
    },

    /// Start a loop over a collection with specified semantics - uses parameter table
    LoopStart {
        /// Index into program's instruction_data.loop_params table
        params_index: u16,
    },

    /// Continue to next iteration or exit loop
    LoopNext {
        /// Jump target back to loop body
        body_start: u16,
        /// Jump target for loop end
        loop_end: u16,
    },

    /// Call rule with caching - checks cache first, executes rule if needed, supports call stack
    CallRule {
        /// Destination register to store the result of the rule call
        dest: u8,
        /// Rule index to execute
        rule_index: u16,
    },

    /// Initialize a rule
    RuleInit {
        /// The register where rule's result is accumulated.
        result_reg: u8,

        /// The rule number of the rule
        rule_index: u16,
    },

    /// Return from rule execution
    RuleReturn {},

    /// Stop execution
    Halt,
}

impl Instruction {
    /// Create a new LoopStart instruction with parameter table index
    pub fn loop_start(params_index: u16) -> Self {
        Self::LoopStart { params_index }
    }

    /// Create a new BuiltinCall instruction with parameter table index
    pub fn builtin_call(params_index: u16) -> Self {
        Self::BuiltinCall { params_index }
    }

    /// Create a new FunctionCall instruction with parameter table index
    pub fn function_call(params_index: u16) -> Self {
        Self::FunctionCall { params_index }
    }

    /// Get detailed display string with parameter resolution for debugging
    pub fn display_with_params(&self, instruction_data: &InstructionData) -> String {
        match self {
            Instruction::LoopStart { params_index } => {
                if let Some(params) = instruction_data.get_loop_params(*params_index) {
                    format!(
                        "LOOP_START {:?} R({}) R({}) R({}) R({}) {} {}",
                        params.mode,
                        params.collection,
                        params.key_reg,
                        params.value_reg,
                        params.result_reg,
                        params.body_start,
                        params.loop_end
                    )
                } else {
                    format!("LOOP_START P({}) [INVALID INDEX]", params_index)
                }
            }
            Instruction::BuiltinCall { params_index } => {
                if let Some(params) = instruction_data.get_builtin_call_params(*params_index) {
                    let args_str = params
                        .arg_registers()
                        .iter()
                        .map(|&r| format!("R({})", r))
                        .collect::<Vec<_>>()
                        .join(" ");
                    format!(
                        "BUILTIN_CALL R({}) B({}) [{}]",
                        params.dest, params.builtin_index, args_str
                    )
                } else {
                    format!("BUILTIN_CALL P({}) [INVALID INDEX]", params_index)
                }
            }
            Instruction::FunctionCall { params_index } => {
                if let Some(params) = instruction_data.get_function_call_params(*params_index) {
                    let args_str = params
                        .arg_registers()
                        .iter()
                        .map(|&r| format!("R({})", r))
                        .collect::<Vec<_>>()
                        .join(" ");
                    format!(
                        "FUNCTION_CALL R({}) RULE({}) [{}]",
                        params.dest, params.func_rule_index, args_str
                    )
                } else {
                    format!("FUNCTION_CALL P({}) [INVALID INDEX]", params_index)
                }
            }
            _ => self.to_string(),
        }
    }
}

impl std::fmt::Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Instruction::Load { dest, literal_idx } => {
                format!("LOAD R({}) L({})", dest, literal_idx)
            }
            Instruction::LoadTrue { dest } => format!("LOAD_TRUE R({})", dest),
            Instruction::LoadFalse { dest } => format!("LOAD_FALSE R({})", dest),
            Instruction::LoadNull { dest } => format!("LOAD_NULL R({})", dest),
            Instruction::LoadBool { dest, value } => format!("LOAD_BOOL R({}) {}", dest, value),
            Instruction::LoadData { dest } => format!("LOAD_DATA R({})", dest),
            Instruction::LoadInput { dest } => format!("LOAD_INPUT R({})", dest),
            Instruction::Move { dest, src } => format!("MOVE R({}) R({})", dest, src),
            Instruction::Add { dest, left, right } => {
                format!("ADD R({}) R({}) R({})", dest, left, right)
            }
            Instruction::Sub { dest, left, right } => {
                format!("SUB R({}) R({}) R({})", dest, left, right)
            }
            Instruction::Mul { dest, left, right } => {
                format!("MUL R({}) R({}) R({})", dest, left, right)
            }
            Instruction::Div { dest, left, right } => {
                format!("DIV R({}) R({}) R({})", dest, left, right)
            }
            Instruction::Mod { dest, left, right } => {
                format!("MOD R({}) R({}) R({})", dest, left, right)
            }
            Instruction::Eq { dest, left, right } => {
                format!("EQ R({}) R({}) R({})", dest, left, right)
            }
            Instruction::Ne { dest, left, right } => {
                format!("NE R({}) R({}) R({})", dest, left, right)
            }
            Instruction::Lt { dest, left, right } => {
                format!("LT R({}) R({}) R({})", dest, left, right)
            }
            Instruction::Le { dest, left, right } => {
                format!("LE R({}) R({}) R({})", dest, left, right)
            }
            Instruction::Gt { dest, left, right } => {
                format!("GT R({}) R({}) R({})", dest, left, right)
            }
            Instruction::Ge { dest, left, right } => {
                format!("GE R({}) R({}) R({})", dest, left, right)
            }
            Instruction::And { dest, left, right } => {
                format!("AND R({}) R({}) R({})", dest, left, right)
            }
            Instruction::Or { dest, left, right } => {
                format!("OR R({}) R({}) R({})", dest, left, right)
            }
            Instruction::Not { dest, operand } => {
                format!("NOT R({}) R({})", dest, operand)
            }
            Instruction::BuiltinCall { params_index } => {
                format!("BUILTIN_CALL P({})", params_index)
            }
            Instruction::FunctionCall { params_index } => {
                format!("FUNCTION_CALL P({})", params_index)
            }
            Instruction::Return { value } => format!("RETURN R({})", value),
            Instruction::ObjectNew { dest } => format!("OBJECT_NEW R({})", dest),
            Instruction::ObjectSet { obj, key, value } => {
                format!("OBJECT_SET R({}) R({}) R({})", obj, key, value)
            }
            Instruction::Index {
                dest,
                container,
                key,
            } => format!("INDEX R({}) R({}) R({})", dest, container, key),
            Instruction::IndexLiteral {
                dest,
                container,
                literal_idx,
            } => format!("INDEX_LITERAL R({}) R({}) L({})", dest, container, literal_idx),
            Instruction::ArrayNew { dest } => format!("ARRAY_NEW R({})", dest),
            Instruction::ArrayPush { arr, value } => format!("ARRAY_PUSH R({}) R({})", arr, value),
            Instruction::SetNew { dest } => format!("SET_NEW R({})", dest),
            Instruction::SetAdd { set, value } => format!("SET_ADD R({}) R({})", set, value),
            Instruction::Contains {
                dest,
                collection,
                value,
            } => format!("CONTAINS R({}) R({}) R({})", dest, collection, value),
            Instruction::AssertCondition { condition } => {
                format!("ASSERT_CONDITION R({})", condition)
            }
            Instruction::LoopStart { params_index } => {
                format!("LOOP_START P({})", params_index)
            }
            Instruction::LoopNext {
                body_start,
                loop_end,
            } => {
                format!("LOOP_NEXT {} {}", body_start, loop_end)
            }
            Instruction::CallRule { dest, rule_index } => {
                format!("CALL_RULE R({}) {}", dest, rule_index)
            }
            Instruction::RuleReturn {} => String::from("RULE_RETURN"),

            Instruction::RuleInit {
                result_reg,
                rule_index,
            } => {
                format!("RULE_INIT R({}) {}", result_reg, rule_index)
            }
            Instruction::Halt => String::from("HALT"),
        };
        write!(f, "{}", text)
    }
}
