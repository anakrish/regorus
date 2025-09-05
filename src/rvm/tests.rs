#[cfg(test)]
mod tests {
    use crate::rvm::compiler::Compiler;
    use crate::rvm::vm::RegoVM;
    use crate::tests::common::{check_output, value_or_vec_to_vec, YamlTest};
    use crate::value::Value;
    use alloc::format;
    use alloc::string::ToString;
    use alloc::vec;
    use test_generator::test_resources;

    extern crate alloc;
    extern crate std;

    /// Compile a CompiledPolicy to RVM bytecode and execute it
    fn compile_and_run_rvm(
        compiled_policy: &crate::CompiledPolicy,
        entrypoint: &str,
        data: &Value,
        input: &Value,
    ) -> anyhow::Result<Value> {
        std::println!("Debug: Compiling entrypoint: {}", entrypoint);

        // Compile the policy to RVM instructions
        let program = Compiler::compile_from_policy(compiled_policy, entrypoint)?;

        std::println!(
            "Debug: Generated {} instructions, {} literals",
            program.instructions.len(),
            program.literals.len()
        );
        for (i, instr) in program.instructions.iter().enumerate() {
            std::println!("  {}: {:?}", i, instr);
        }
        std::println!("Literals:");
        for (i, literal) in program.literals.iter().enumerate() {
            std::println!("  {}: {:?}", i, literal);
        }

        // Create a VM and load the program
        let mut vm = RegoVM::new();
        vm.load_program(program);

        // Set data and input in the VM
        vm.set_data(data.clone());
        vm.set_input(input.clone());

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

            // Extract input for both engine and RVM, and set it in engine if provided
            let input_value = case
                .input
                .clone()
                .map(|i| match i {
                    crate::tests::common::ValueOrVec::Single(v) => v,
                    crate::tests::common::ValueOrVec::Many(_) => Value::Null, // Fallback for multiple inputs
                })
                .unwrap_or(Value::Null);

            // Set input in engine if provided
            if case.input.is_some() {
                engine.set_input(input_value.clone());
            }

            // Compile to get the compiled policy
            let entrypoint_ref = crate::Rc::from(case.query.as_str());
            let compiled_policy = engine.compile_with_entrypoint(&entrypoint_ref)?;

            // Extract data for RVM execution
            let data = engine.get_data();

            // Get interpreter result for comparison with RVM
            let interpreter_result = engine.eval_rule(case.query.clone());

            match (&case.want_result, &case.want_error) {
                (Some(expected_result), None) => {
                    // Test expects a successful result
                    match compile_and_run_rvm(&compiled_policy, &case.query, &data, &input_value) {
                        Ok(actual_result) => {
                            // First, assert that RVM result matches interpreter result
                            match &interpreter_result {
                                Ok(interpreter_value) => {
                                    if actual_result != *interpreter_value {
                                        panic!(
                                            "RVM result does not match interpreter result for case '{}':\nRVM result: {:?}\nInterpreter result: {:?}",
                                            case.note, actual_result, interpreter_value
                                        );
                                    }
                                    std::println!(
                                        "✓ RVM matches interpreter for case '{}'",
                                        case.note
                                    );
                                }
                                Err(interpreter_error) => {
                                    panic!(
                                        "Interpreter failed for case '{}' but RVM succeeded:\nRVM result: {:?}\nInterpreter error: {}",
                                        case.note, actual_result, interpreter_error
                                    );
                                }
                            }

                            // Convert ValueOrVec to Vec<Value> for compatibility
                            let expected_results = value_or_vec_to_vec(expected_result.clone());
                            let actual_results = vec![actual_result];

                            // Use the shared check_output function which handles #undefined
                            check_output(&actual_results, &expected_results)?;
                        }
                        Err(e) => {
                            // RVM failed - check if interpreter also failed
                            match &interpreter_result {
                                Ok(interpreter_value) => {
                                    panic!(
                                        "RVM failed for case '{}' but interpreter succeeded:\nRVM error: {}\nInterpreter result: {:?}",
                                        case.note, e, interpreter_value
                                    );
                                }
                                Err(_interpreter_error) => {
                                    // Both failed - this could be expected, but for success cases it's not
                                    panic!(
                                        "Test case '{}' expected success but both RVM and interpreter failed:\nRVM error: {}",
                                        case.note, e
                                    );
                                }
                            }
                        }
                    }
                }
                (None, Some(expected_error)) => {
                    // Test expects an error
                    match compile_and_run_rvm(&compiled_policy, &case.query, &data, &input_value) {
                        Ok(result) => {
                            // RVM succeeded - check if interpreter also succeeded
                            match &interpreter_result {
                                Ok(interpreter_value) => {
                                    // Both succeeded, but test expected error
                                    panic!(
                                        "Test case '{}' expected error '{}' but both RVM and interpreter succeeded:\nRVM result: {}\nInterpreter result: {:?}",
                                        case.note,
                                        expected_error,
                                        serde_json::to_string_pretty(&result)?,
                                        interpreter_value
                                    );
                                }
                                Err(_interpreter_error) => {
                                    panic!(
                                        "Test case '{}' expected error '{}' but RVM succeeded while interpreter failed:\nRVM result: {}",
                                        case.note,
                                        expected_error,
                                        serde_json::to_string_pretty(&result)?
                                    );
                                }
                            }
                        }
                        Err(actual_error) => {
                            // RVM failed - check if interpreter also failed consistently
                            match &interpreter_result {
                                Ok(interpreter_value) => {
                                    panic!(
                                        "RVM failed for case '{}' but interpreter succeeded:\nRVM error: {}\nInterpreter result: {:?}",
                                        case.note, actual_error, interpreter_value
                                    );
                                }
                                Err(_interpreter_error) => {
                                    // Both failed - check if RVM error matches expected
                                    let actual_error_str = actual_error.to_string();
                                    if !actual_error_str.contains(expected_error) {
                                        panic!(
                                            "Error message mismatch for case '{}':\nExpected to contain: {}\nActual: {}",
                                            case.note, expected_error, actual_error_str
                                        );
                                    }
                                    std::println!(
                                        "✓ RVM error matches expected for case '{}'",
                                        case.note
                                    );
                                }
                            }
                        }
                    }
                }
                _ => {
                    panic!(
                        "Test case '{}' must specify either want_result or want_error",
                        case.note
                    );
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
