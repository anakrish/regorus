// RVM - Rego Virtual Machine
// A register-based virtual machine for executing Rego policies

pub mod compiler;
pub mod instructions;
pub mod program;
pub mod vm;

#[cfg(test)]
mod instruction_parser;

#[cfg(test)]
mod program_test;

#[cfg(test)]
pub mod tests;

#[cfg(test)]
mod vm_tests;

pub use compiler::Compiler;
pub use instructions::Instruction;
pub use program::Program;
pub use vm::RegoVM;
