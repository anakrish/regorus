// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod core;
mod emit;
mod error;
mod expr;
mod helpers;
mod scope;

pub use core::Compiler;
pub use error::{CompilerError, Result, SpannedCompilerError};

use crate::languages::cedar::ast::{Expr, Policy};
use crate::rvm::program::Program;
use crate::rvm::Instruction;
use alloc::format;
use alloc::string::String;
pub fn compile_to_program(policies: &[Policy]) -> Result<Program> {
    Compiler::new().compile(policies)
}

pub fn compile_expr_to_program(expr: &Expr) -> Result<Program> {
    let mut compiler = Compiler::new();
    let result_reg = compiler.compile_expr(expr)?;
    compiler.emit_instruction(Instruction::Return { value: result_reg });

    compiler.program.main_entry_point = 0;
    compiler.program.dispatch_window_size = compiler.next_reg;
    compiler.program.max_rule_window_size = compiler.next_reg;
    compiler
        .program
        .entry_points
        .insert(String::from("cedar.evaluate"), 0);

    if !compiler.program.builtin_info_table.is_empty() {
        compiler
            .program
            .initialize_resolved_builtins()
            .map_err(|err| {
                SpannedCompilerError::from(CompilerError::General {
                    message: format!("{err}"),
                })
            })?;
    }

    compiler
        .program
        .validate_limits()
        .map_err(|message| SpannedCompilerError::from(CompilerError::General { message }))?;

    Ok(compiler.program)
}
