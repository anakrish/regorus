// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::Program;
use crate::rvm::compiler::Compiler;
use crate::Engine;

impl Program {
    /// Compile a partial deserialized program to a complete one
    ///
    /// This method takes a partial program (containing only entry_points and sources)
    /// and recompiles it to create a complete program with all instructions and data.
    pub fn compile_from_partial(partial_program: Program) -> Result<Program, String> {
        if partial_program.entry_points.is_empty() {
            return Err("Partial program must contain entry points".to_string());
        }
        if partial_program.sources.is_empty() {
            return Err("Partial program must contain sources".to_string());
        }

        let mut engine = Engine::new();
        engine.set_rego_v0(partial_program.rego_v0);

        for source_file in &partial_program.sources {
            engine
                .add_policy(source_file.name.clone(), source_file.content.clone())
                .map_err(|e| format!("Failed to add policy '{}': {}", source_file.name, e))?;
        }

        let entry_point_names: Vec<&str> = partial_program
            .entry_points
            .keys()
            .map(|s| s.as_str())
            .collect();

        if entry_point_names.is_empty() {
            return Err("No entry points found in partial program".to_string());
        }

        let first_entry_point = crate::Rc::from(entry_point_names[0]);
        let compiled_policy = engine
            .compile_with_entrypoint(&first_entry_point)
            .map_err(|e| {
                format!(
                    "Failed to compile policy with entry point '{}': {}",
                    entry_point_names[0], e
                )
            })?;

        let arc_program = Compiler::compile_from_policy(&compiled_policy, &entry_point_names)
            .map_err(|e| format!("Failed to compile RVM program: {}", e))?;

        let mut complete_program = Arc::try_unwrap(arc_program)
            .map_err(|_| "Failed to extract program from Arc".to_string())?;

        complete_program.rego_v0 = partial_program.rego_v0;

        Ok(complete_program)
    }
}
