#[cfg(test)]
mod tests {
    use crate::rvm::instruction_parser::{parse_instruction, parse_value};
    use crate::rvm::vm::RegoVM;
    use crate::tests::interpreter::process_value;
    use crate::value::Value;
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec;
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
        instructions: Vec<String>,
        want_result: crate::Value,
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct VmTestSuite {
        cases: Vec<VmTestCase>,
    }

    /// Execute VM instructions directly from parsed instructions and literals
    fn execute_vm_instructions(
        instructions: Vec<crate::rvm::instructions::Instruction>,
        literals: Vec<Value>,
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
        program.main_entry_point = 0;
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

            // Parse expected result and process special encodings like sets
            let expected_result = process_value(&test_case.want_result)?;

            // Execute the VM instructions
            let actual_result =
                execute_vm_instructions(instructions, literals, test_case.data, test_case.input)?;

            // Compare results
            if actual_result != expected_result {
                std::println!("Test case '{}' failed:", test_case.note);
                std::println!("  Expected: {:?}", expected_result);
                std::println!("  Actual: {:?}", actual_result);
                panic!("VM test case failed: {}", test_case.note);
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

    // Legacy test for the old monolithic test file (can be removed eventually)
    #[test]
    fn test_instruction_parsing() -> Result<()> {
        // Test basic instruction parsing
        let load_instr = parse_instruction("Load { dest: 0, literal_idx: 1 }")?;
        match load_instr {
            crate::rvm::instructions::Instruction::Load { dest, literal_idx } => {
                assert_eq!(dest, 0);
                assert_eq!(literal_idx, 1);
            }
            _ => panic!("Expected Load instruction"),
        }

        let move_instr = parse_instruction("Move { dest: 2, src: 3 }")?;
        match move_instr {
            crate::rvm::instructions::Instruction::Move { dest, src } => {
                assert_eq!(dest, 2);
                assert_eq!(src, 3);
            }
            _ => panic!("Expected Move instruction"),
        }

        let add_instr = parse_instruction("Add { dest: 4, left: 5, right: 6 }")?;
        match add_instr {
            crate::rvm::instructions::Instruction::Add { dest, left, right } => {
                assert_eq!(dest, 4);
                assert_eq!(left, 5);
                assert_eq!(right, 6);
            }
            _ => panic!("Expected Add instruction"),
        }

        Ok(())
    }

    #[test]
    fn test_simple_existential_debug() -> Result<()> {
        std::println!("Testing simple existential loop...");

        // Test the basic existential test case
        let literals = vec![
            Value::Number(1i64.into()),
            Value::Number(2i64.into()),
            Value::Number(3i64.into()),
            Value::Number(2i64.into()), // comparison value
        ];

        let instruction_strings = vec![
            "ArrayNew { dest: 0 }",
            "Load { dest: 1, literal_idx: 0 }",
            "ArrayPush { arr: 0, value: 1 }",
            "Load { dest: 2, literal_idx: 1 }",
            "ArrayPush { arr: 0, value: 2 }",
            "Load { dest: 3, literal_idx: 2 }",
            "ArrayPush { arr: 0, value: 3 }",
            "LoopStart { mode: Existential, collection: 0, key_reg: 4, value_reg: 5, result_reg: 6, body_start: 8, loop_end: 12 }",
            "Load { dest: 7, literal_idx: 3 }",
            "Gt { dest: 8, left: 5, right: 7 }",
            "AssertCondition { condition: 8 }",
            "LoopNext { body_start: 8, loop_end: 12 }",
            "Return { value: 6 }",
        ];

        // Parse instructions
        let mut instructions = Vec::new();
        for instruction_str in &instruction_strings {
            let instruction = parse_instruction(instruction_str)?;
            std::println!("Parsed: {:?}", instruction);
            instructions.push(instruction);
        }

        // Create VM and execute
        std::println!("Starting execution...");
        let result = execute_vm_instructions(instructions, literals, None, None)?;
        std::println!("Result: {:?}", result);

        assert_eq!(result, Value::Bool(true));
        Ok(())
    }

    #[test]
    fn test_value_parsing() -> Result<()> {
        // Test basic value parsing
        let num = parse_value("Number(42)")?;
        assert_eq!(num, Value::from(42.0));

        let string_val = parse_value("String(\"hello\")")?;
        assert_eq!(string_val, Value::String("hello".into()));

        let bool_val = parse_value("Bool(true)")?;
        assert_eq!(bool_val, Value::Bool(true));

        let null_val = parse_value("Null")?;
        assert_eq!(null_val, Value::Null);

        // Test array parsing
        let array_val = parse_value("Array([Number(1), Number(2), Number(3)])")?;
        let expected_vec = vec![Value::from(1.0), Value::from(2.0), Value::from(3.0)];
        let expected_array = Value::Array(Arc::new(expected_vec));
        assert_eq!(array_val, expected_array);

        Ok(())
    }

    #[test]
    fn test_simple_vm_execution() -> Result<()> {
        // Test a simple Load + Return sequence
        let instructions = vec![
            crate::rvm::instructions::Instruction::Load {
                dest: 0,
                literal_idx: 0,
            },
            crate::rvm::instructions::Instruction::Return { value: 0 },
        ];

        let literals = vec![Value::from(42.0)];

        let result = execute_vm_instructions(instructions, literals, None, None)?;
        assert_eq!(result, Value::from(42.0));

        Ok(())
    }

    #[test]
    fn test_arithmetic_vm_execution() -> Result<()> {
        // Test basic arithmetic: 10 + 5 = 15
        let instructions = vec![
            crate::rvm::instructions::Instruction::Load {
                dest: 0,
                literal_idx: 0,
            },
            crate::rvm::instructions::Instruction::Load {
                dest: 1,
                literal_idx: 1,
            },
            crate::rvm::instructions::Instruction::Add {
                dest: 2,
                left: 0,
                right: 1,
            },
            crate::rvm::instructions::Instruction::Return { value: 2 },
        ];

        let literals = vec![Value::from(10.0), Value::from(5.0)];

        let result = execute_vm_instructions(instructions, literals, None, None)?;
        assert_eq!(result, Value::from(15.0));

        Ok(())
    }
}
