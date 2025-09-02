use crate::value::Value;
use alloc::format;
use alloc::string::String;

/// RVM Instructions - simplified enum-based design
#[derive(Debug, Clone)]
pub enum Instruction {
    /// Load literal value from literal table into register
    Load {
        dest: u16,
        literal_idx: u16,
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

    /// Comparison operations
    Eq {
        dest: u16,
        left: u16,
        right: u16,
    },
    Lt {
        dest: u16,
        left: u16,
        right: u16,
    },
    Gt {
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
            Instruction::Eq { dest, left, right } => {
                format!("EQ R({}) R({}) R({})", dest, left, right)
            }
            Instruction::Lt { dest, left, right } => {
                format!("LT R({}) R({}) R({})", dest, left, right)
            }
            Instruction::Gt { dest, left, right } => {
                format!("GT R({}) R({}) R({})", dest, left, right)
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
            Instruction::Halt => String::from("HALT"),
        }
    }
}
