// RVM - Rego Virtual Machine
// A register-based virtual machine for executing Rego policies

pub mod compiler;
pub mod debugger;
pub mod instructions;
pub mod program;
pub mod vm;

#[cfg(test)]
mod instruction_parser;

#[cfg(test)]
mod tests;

pub use compiler::Compiler;
pub use debugger::InteractiveDebugger;
pub use instructions::Instruction;
pub use program::Program;
pub use vm::RegoVM;
