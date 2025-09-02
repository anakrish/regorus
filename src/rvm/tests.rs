#[cfg(test)]
mod tests {
    use crate::rvm::vm::RegoVM;
    use crate::rvm::compiler::Compiler;
    use crate::value::Value;
    use crate::tests::common::{check_output, value_or_vec_to_vec, YamlTest};
    use alloc::string::ToString;
    use alloc::format;
    use alloc::vec;
    use test_generator::test_resources;
    
    extern crate alloc;
    extern crate std;

    /// Compile a CompiledPolicy to RVM bytecode and execute it
    fn compile_and_run_rvm(compiled_policy: &crate::CompiledPolicy, entrypoint: &str) -> anyhow::Result<Value> {
        std::println!("Debug: Compiling entrypoint: {}", entrypoint);
        
        // Compile the policy to RVM instructions
        let compiled_program = Compiler::compile_from_policy(compiled_policy, entrypoint)?;
        
        std::println!("Debug: Generated {} instructions, {} literals", compiled_program.instructions.len(), compiled_program.literals.len());
        for (i, instr) in compiled_program.instructions.iter().enumerate() {
            std::println!("  {}: {:?}", i, instr);
        }
        std::println!("Literals:");
        for (i, literal) in compiled_program.literals.iter().enumerate() {
            std::println!("  {}: {:?}", i, literal);
        }
        
        // Create a VM and load the instructions and literals
        let mut vm = RegoVM::new();
        vm.load_program(compiled_program.instructions, compiled_program.literals);
        
        // Run the VM
        let result = vm.execute()?;
        std::println!("Debug: VM result: {:?}", result);
        Ok(result)
    }

    fn yaml_test_impl(file: &str) -> anyhow::Result<()> {
        let yaml_str = std::fs::read_to_string(file)?;
        let test: YamlTest = serde_yaml::from_str(&yaml_str)?;

        std::println!("running {file}");

        for case in test.cases {
            std::print!("case {} ", case.note);
            
            if case.skip == Some(true) {
                std::println!("skipped");
                continue;
            }

            // Create and compile the Rego policy
            let mut engine = crate::Engine::new();
            
            // Add modules
            for (idx, module) in case.modules.iter().enumerate() {
                engine.add_policy(format!("rego_{}", idx), module.clone())?;
            }

            // Add data if provided
            if let Some(data) = case.data {
                engine.add_data(data)?;
            }

            // Set input if provided (RVM tests use simple input, not ValueOrVec)
            if let Some(input) = case.input {
                if let crate::tests::common::ValueOrVec::Single(input_value) = input {
                    engine.set_input(input_value);
                }
            }

            // Compile to get the compiled policy
            let entrypoint_ref = crate::Rc::from(case.query.as_str());
            let compiled_policy = engine.compile_with_entrypoint(&entrypoint_ref)?;

            match (&case.want_result, &case.want_error) {
                (Some(expected_result), None) => {
                    // Test expects a successful result
                    match compile_and_run_rvm(&compiled_policy, &case.query) {
                        Ok(actual_result) => {
                            // Convert ValueOrVec to Vec<Value> for compatibility
                            let expected_results = value_or_vec_to_vec(expected_result.clone());
                            let actual_results = vec![actual_result];
                            
                            // Use the shared check_output function which handles #undefined
                            check_output(&actual_results, &expected_results)?;
                        }
                        Err(e) => {
                            panic!("Test case '{}' expected success but got error: {}", case.note, e);
                        }
                    }
                }
                (None, Some(expected_error)) => {
                    // Test expects an error
                    match compile_and_run_rvm(&compiled_policy, &case.query) {
                        Ok(result) => {
                            panic!(
                                "Test case '{}' expected error '{}' but got result: {}",
                                case.note,
                                expected_error,
                                serde_json::to_string_pretty(&result)?
                            );
                        }
                        Err(actual_error) => {
                            let actual_error_str = actual_error.to_string();
                            if !actual_error_str.contains(expected_error) {
                                panic!(
                                    "Error message mismatch for case '{}':\nExpected to contain: {}\nActual: {}",
                                    case.note, expected_error, actual_error_str
                                );
                            }
                        }
                    }
                }
                _ => {
                    panic!("Test case '{}' must specify either want_result or want_error", case.note);
                }
            }

            std::println!("passed");
        }

        Ok(())
    }

    #[test_resources("tests/rvm/compiler/cases/*.yaml")]
    fn run_compiler_test_file(file: &str) {
        yaml_test_impl(file).unwrap()
    }
}
