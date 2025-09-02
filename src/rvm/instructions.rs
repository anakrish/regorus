use alloc::format;
use alloc::string::String;

/// Loop execution modes for different Rego iteration constructs
#[derive(Debug, Clone)]
pub enum LoopMode {
    /// Existential quantification: some x in arr, x := arr[_], etc.
    /// Succeeds if ANY iteration succeeds, exits early on first success
    Existential,

    /// Universal quantification: every x in arr  
    /// Succeeds only if ALL iterations succeed, exits early on first failure
    Universal,

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
#[derive(Debug, Clone)]
pub enum Instruction {
    /// Load literal value from literal table into register
    Load {
        dest: u16,
        literal_idx: u16,
    },

    /// Load true value into register
    LoadTrue {
        dest: u16,
    },

    /// Load false value into register
    LoadFalse {
        dest: u16,
    },

    /// Load null value into register
    LoadNull {
        dest: u16,
    },

    /// Load boolean value into register
    LoadBool {
        dest: u16,
        value: bool,
    },

    /// Move value from one register to another
    Move {
        dest: u16,
        src: u16,
    },

    /// Arithmetic operations
    Add {
        dest: u16,
        left: u16,
        right: u16,
    },
    Sub {
        dest: u16,
        left: u16,
        right: u16,
    },
    Mul {
        dest: u16,
        left: u16,
        right: u16,
    },
    Div {
        dest: u16,
        left: u16,
        right: u16,
    },
    Mod {
        dest: u16,
        left: u16,
        right: u16,
    },

    /// Comparison operations
    Eq {
        dest: u16,
        left: u16,
        right: u16,
    },
    Ne {
        dest: u16,
        left: u16,
        right: u16,
    },
    Lt {
        dest: u16,
        left: u16,
        right: u16,
    },
    Le {
        dest: u16,
        left: u16,
        right: u16,
    },
    Gt {
        dest: u16,
        left: u16,
        right: u16,
    },
    Ge {
        dest: u16,
        left: u16,
        right: u16,
    },

    /// Logical operations
    And {
        dest: u16,
        left: u16,
        right: u16,
    },
    Or {
        dest: u16,
        left: u16,
        right: u16,
    },
    Not {
        dest: u16,
        operand: u16,
    },

    /// String operations
    Concat {
        dest: u16,
        left: u16,
        right: u16,
    },

    /// Function calls
    Call {
        dest: u16,
        func: u16,
        args_start: u16,
        args_count: u16,
    },

    /// Return result
    Return {
        value: u16,
    },

    /// Create empty object
    ObjectNew {
        dest: u16,
    },

    /// Set object field
    ObjectSet {
        obj: u16,
        key: u16,
        value: u16,
    },

    /// Index into container (object, array, set)
    Index {
        dest: u16,
        container: u16,
        key: u16,
    },

    /// Create empty array
    ArrayNew {
        dest: u16,
    },

    /// Push element to array
    ArrayPush {
        arr: u16,
        value: u16,
    },

    /// Create empty set
    SetNew {
        dest: u16,
    },

    /// Add element to set
    SetAdd {
        set: u16,
        value: u16,
    },

    /// Check if collection contains value (for membership testing)
    Contains {
        dest: u16,
        collection: u16,
        value: u16,
    },

    /// Assert condition - if register contains false or undefined, return undefined immediately
    AssertCondition {
        condition: u16,
    },

    /// Start a loop over a collection with specified semantics
    LoopStart {
        /// Loop mode (Existential/Universal/Comprehension types)
        mode: LoopMode,
        /// Register containing the collection to iterate over
        collection: u16,
        /// Register to store current key (u16::MAX if not needed)
        key_reg: u16,
        /// Register to store current value
        value_reg: u16,
        /// Register to store final result
        result_reg: u16,
        /// Jump target for loop body start
        body_start: u16,
        /// Jump target for loop end
        loop_end: u16,
    },

    /// Continue to next iteration or exit loop
    LoopNext {
        /// Jump target back to loop body
        body_start: u16,
        /// Jump target for loop end
        loop_end: u16,
    },

    /// Accumulate result for comprehension modes (optional explicit control)
    LoopAccumulate {
        /// Register containing value to accumulate
        value: u16,
        /// Register containing key (for object comprehensions only)
        key: Option<u16>,
    },

    /// Stop execution
    Halt,
}

impl Instruction {
    /// Get a human-readable representation of the instruction
    pub fn to_string(&self) -> String {
        match self {
            Instruction::Load { dest, literal_idx } => {
                format!("LOAD R({}) L({})", dest, literal_idx)
            }
            Instruction::LoadTrue { dest } => format!("LOAD_TRUE R({})", dest),
            Instruction::LoadFalse { dest } => format!("LOAD_FALSE R({})", dest),
            Instruction::LoadNull { dest } => format!("LOAD_NULL R({})", dest),
            Instruction::LoadBool { dest, value } => format!("LOAD_BOOL R({}) {}", dest, value),
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
            Instruction::Concat { dest, left, right } => {
                format!("CONCAT R({}) R({}) R({})", dest, left, right)
            }
            Instruction::Call {
                dest,
                func,
                args_start,
                args_count,
            } => format!(
                "CALL R({}) R({}) R({}) {}",
                dest, func, args_start, args_count
            ),
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
            Instruction::LoopStart {
                mode,
                collection,
                key_reg,
                value_reg,
                result_reg,
                body_start,
                loop_end,
            } => format!(
                "LOOP_START {:?} R({}) R({}) R({}) R({}) {} {}",
                mode, collection, key_reg, value_reg, result_reg, body_start, loop_end
            ),
            Instruction::LoopNext {
                body_start,
                loop_end,
            } => {
                format!("LOOP_NEXT {} {}", body_start, loop_end)
            }
            Instruction::LoopAccumulate { value, key } => {
                if let Some(key_reg) = key {
                    format!("LOOP_ACCUMULATE R({}) R({})", value, key_reg)
                } else {
                    format!("LOOP_ACCUMULATE R({})", value)
                }
            }
            Instruction::Halt => String::from("HALT"),
        }
    }
}
