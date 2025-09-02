// RVM - Rego Virtual Machine
// A register-based virtual machine for executing Rego policies

pub mod compiler;
pub mod instructions;
pub mod vm;

#[cfg(test)]
pub mod tests;

pub use compiler::Compiler;
pub use instructions::Instruction;
pub use vm::RegoVM;
