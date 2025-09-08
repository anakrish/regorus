#[cfg(test)]
mod tests {
    use crate::rvm::instruction_parser::{parse_instruction, parse_loop_mode};
    use crate::rvm::vm::RegoVM;
    use crate::tests::interpreter::process_value;
    use crate::value::Value;
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use anyhow::Result;
    use serde::{Deserialize, Serialize};
    use std::fs;
    use test_generator::test_resources;

    extern crate alloc;
    extern crate std;

    #[derive(Debug, Deserialize, Serialize)]
    struct VmTestCase {
        note: String,
        #[serde(default)]
        description: Option<String>,
        #[serde(default)]
        example_rego: Option<String>,
        #[serde(default)]
        data: Option<crate::Value>,
        #[serde(default)]
        input: Option<crate::Value>,
        literals: Vec<crate::Value>,
        #[serde(default)]
        instruction_params: Option<InstructionParamsSpec>,
        instructions: Vec<String>,
        #[serde(default, deserialize_with = "deserialize_optional_value")]
        want_result: Option<crate::Value>,
        #[serde(default)]
        want_error: Option<String>,
    }

    fn deserialize_optional_value<'de, D>(deserializer: D) -> Result<Option<crate::Value>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // If the field is present, always return Some, even if the value is null
        crate::Value::deserialize(deserializer).map(Some)
    }

    #[derive(Debug, Deserialize, Serialize, Default)]
    struct InstructionParamsSpec {
        #[serde(default)]
        loop_params: Vec<LoopStartParamsSpec>,
        #[serde(default)]
        call_params: Vec<CallParamsSpec>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct LoopStartParamsSpec {
        mode: String,
        collection: u16,
        key_reg: u16,
        value_reg: u16,
        result_reg: u16,
        body_start: u16,
        loop_end: u16,
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct CallParamsSpec {
        dest: u16,
        func: u16,
        args_start: u16,
        args_count: u16,
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct VmTestSuite {
        cases: Vec<VmTestCase>,
    }

    /// Execute VM instructions directly from parsed instructions and literals
    fn execute_vm_instructions(
        instructions: Vec<crate::rvm::instructions::Instruction>,
        literals: Vec<Value>,
        instruction_params: Option<InstructionParamsSpec>,
        data: Option<Value>,
        input: Option<Value>,
    ) -> Result<Value> {
        let mut vm = RegoVM::new();

        // Set global data and input if provided
        if let Some(data_value) = data {
            vm.set_data(data_value);
        }
        if let Some(input_value) = input {
            vm.set_input(input_value);
        }

        // Create a Program from instructions and literals
        let mut program = crate::rvm::program::Program::new();
        program.instructions = instructions;
        program.literals = literals;

        // Build instruction data from params specification
        if let Some(params_spec) = instruction_params {
            // Convert loop params
            for loop_param_spec in params_spec.loop_params {
                let mode = parse_loop_mode(&loop_param_spec.mode)?;
                let loop_params = crate::rvm::instructions::LoopStartParams {
                    mode,
                    collection: loop_param_spec.collection,
                    key_reg: loop_param_spec.key_reg,
                    value_reg: loop_param_spec.value_reg,
                    result_reg: loop_param_spec.result_reg,
                    body_start: loop_param_spec.body_start,
                    loop_end: loop_param_spec.loop_end,
                };
                program.add_loop_params(loop_params);
            }

            // Convert call params
            // Legacy call_params support removed - use builtin_call_params or function_call_params instead
            for _call_param_spec in params_spec.call_params {
                // Legacy call parameters are no longer supported
                // Convert to BuiltinCall or FunctionCall instructions instead
                panic!("Legacy call_params are no longer supported. Use builtin_call_params or function_call_params instead.");
            }
        }

        program.main_entry_point = 0;

        // Set a reasonable default for register count in VM tests
        // Most tests use registers 0-10, so we'll allocate 256 registers to be safe
        program.num_registers = 256;

        let program = Arc::new(program);

        // Load program
        vm.load_program(program);

        // Execute
        vm.execute()
    }

    fn run_vm_test_suite(file: &str) -> Result<()> {
        std::println!("Running VM test suite: {}", file);
        let yaml_content = fs::read_to_string(file)?;
        let test_suite: VmTestSuite = serde_yaml::from_str(&yaml_content)?;

        for test_case in test_suite.cases {
            std::println!("Running VM test case: {}", test_case.note);

            // Literals are already parsed as crate::Value, so we can use them directly
            let literals = test_case.literals;

            // Parse instructions
            let mut instructions = Vec::new();
            for instruction_str in &test_case.instructions {
                let instruction = parse_instruction(instruction_str)?;
                instructions.push(instruction);
            }

            // Execute the VM instructions
            let execution_result = execute_vm_instructions(
                instructions,
                literals,
                test_case.instruction_params,
                test_case.data,
                test_case.input,
            );

            // Check if we expect an error
            if let Some(expected_error) = &test_case.want_error {
                match execution_result {
                    Err(e) => {
                        let error_msg = std::format!("{}", e);
                        if !error_msg.contains(expected_error) {
                            std::println!("Test case '{}' failed:", test_case.note);
                            std::println!("  Expected error containing: '{}'", expected_error);
                            std::println!("  Actual error: '{}'", error_msg);
                            panic!("VM test case failed: {}", test_case.note);
                        }
                    }
                    Ok(result) => {
                        std::println!("Test case '{}' failed:", test_case.note);
                        std::println!("  Expected error containing: '{}'", expected_error);
                        std::println!("  But got successful result: {:?}", result);
                        panic!("VM test case failed: {}", test_case.note);
                    }
                }
            } else if let Some(want_result) = &test_case.want_result {
                // Parse expected result and process special encodings like sets
                let expected_result = process_value(want_result)?;

                let actual_result = match execution_result {
                    Ok(result) => result,
                    Err(e) => {
                        // Check if this was an assertion failure
                        if std::format!("{}", e).contains("Assertion failed") {
                            // Return undefined value for failed assertions
                            Value::Undefined
                        } else {
                            // For other errors, propagate them
                            return Err(e);
                        }
                    }
                };

                // Compare results
                if actual_result != expected_result {
                    std::println!("Test case '{}' failed:", test_case.note);
                    std::println!("  Expected: {:?}", expected_result);
                    std::println!("  Actual: {:?}", actual_result);
                    panic!("VM test case failed: {}", test_case.note);
                }
            } else {
                panic!(
                    "Test case '{}' must have either want_result or want_error",
                    test_case.note
                );
            }

            std::println!("✓ Test case '{}' passed", test_case.note);
        }
        std::println!("✓ Test suite '{}' completed successfully", file);

        Ok(())
    }

    #[test_resources("tests/rvm/vm/suites/*.yaml")]
    fn run_vm_test_file(file: &str) {
        run_vm_test_suite(file).unwrap()
    }

    #[test_resources("tests/rvm/vm/suites/loops/*.yaml")]
    fn run_loop_test_file(file: &str) {
        run_vm_test_suite(file).unwrap()
    }
}
