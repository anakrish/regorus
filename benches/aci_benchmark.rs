// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use regorus::rvm::{compiler::Compiler, vm::RegoVM};
use regorus::*;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use core::panic;
use std::path::Path;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct TestCase {
    note: String,
    data: Value,
    input: Value,
    modules: Vec<String>,
    query: String,
    want_result: Value,
    #[serde(default)]
    skip_rvm: bool,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct YamlTest {
    cases: Vec<TestCase>,
}

fn setup_engine(dir: &Path, case: &TestCase) -> Engine {
    let mut engine = Engine::new();
    engine.set_rego_v0(true);

    engine
        .add_data(case.data.clone())
        .expect("failed to add data");
    engine.set_input(case.input.clone());

    for (idx, rego) in case.modules.iter().enumerate() {
        if rego.ends_with(".rego") {
            let path = dir.join(rego);
            let path = path.to_str().expect("not a valid path");
            engine
                .add_policy_from_file(path)
                .expect("failed to add policy");
        } else {
            engine
                .add_policy(format!("rego{idx}.rego"), rego.clone())
                .expect("failed to add policy");
        }
    }

    engine
}

fn aci_policy_eval(c: &mut Criterion) {
    let dir = Path::new("tests/aci");
    for entry in WalkDir::new(dir)
        .sort_by_file_name()
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.to_string_lossy().ends_with(".yaml") {
            continue;
        }

        let yaml = std::fs::read(path).expect("failed to read yaml test");
        let yaml = String::from_utf8_lossy(&yaml);
        let test: YamlTest = serde_yaml::from_str(&yaml).expect("failed to deserialize yaml test");

        for case in &test.cases {
            // Setup engine once per test case
            let mut engine = setup_engine(dir, case);

            // Validate interpreter result matches want_result before benchmarking
            // Note: this also ensures that the engine is prepared by the first eval call
            // The first eval-call is always expensive due to various preparations.
            let interpreter_result = engine
                .eval_rule(case.query.clone())
                .expect("interpreter eval failed");
            let interpreter_value = Value::from_json_str(&interpreter_result.to_string())
                .expect("failed to convert interpreter result");

            if interpreter_value != case.want_result {
                panic!(
                    "Interpreter result mismatch for {}: expected {:?}, got {:?}",
                    case.note, case.want_result, interpreter_value
                );
            }

            // Benchmark interpreter (reusing the same engine setup)
            c.bench_with_input(
                BenchmarkId::new("interpreter", &case.note),
                &case,
                |b, case| {
                    b.iter_batched(
                        || engine.clone(),
                        |mut engine| engine.eval_rule(case.query.clone()).unwrap(),
                        BatchSize::SmallInput,
                    )
                },
            );

            // Skip RVM benchmark if marked to skip
            if case.skip_rvm {
                continue;
            }

            // Prepare RVM setup using the same engine instance
            let input = case.input.clone();
            let data = case.data.clone();

            // Create CompiledPolicy first
            let rule = Rc::from(case.query.as_str());
            let compiled_policy = engine
                .compile_with_entrypoint(&rule)
                .expect("compilation failed");

            // Use RVM compiler to create a program
            let program = Compiler::compile_from_policy(&compiled_policy, &[&case.query])
                .expect("RVM compilation failed");

            // Create RVM and load the program for validation
            let mut vm = RegoVM::new();
            vm.load_program(program.clone());
            vm.set_data(data.clone()).expect("Failed to set data");
            vm.set_input(input.clone());

            // Execute on RVM and validate result
            let rvm_result = vm.execute().expect("RVM execution failed");
            let rvm_value = Value::from_json_str(&rvm_result.to_string())
                .expect("failed to convert RVM result");

            if rvm_value != case.want_result {
                panic!(
                    "RVM result mismatch for {}: expected {:?}, got {:?}",
                    case.note, case.want_result, rvm_value
                );
            }

            // Benchmark RVM (reusing compiled program)
            c.bench_with_input(
                BenchmarkId::new("rvm_eval_only", &case.note),
                &case,
                |b, case| {
                    b.iter_batched(
                        || {
                            let mut vm = RegoVM::new();
                            vm.load_program(program.clone());
                            vm.set_data(data.clone()).expect("Failed to set data");
                            (vm, case.input.clone())
                        },
                        |(mut vm, input)| {
                            vm.set_input(input);
                            vm.execute().unwrap()
                        },
                        BatchSize::SmallInput,
                    )
                },
            );

            // Benchmark program serialization
            c.bench_with_input(
                BenchmarkId::new("program_serialize", &case.note),
                &program,
                |b, program| b.iter(|| program.serialize_binary().expect("Serialization failed")),
            );

            // Pre-serialize for deserialization benchmark
            let serialized_program = program
                .serialize_binary()
                .expect("Pre-serialization failed");

            // Benchmark program deserialization
            c.bench_with_input(
                BenchmarkId::new("program_deserialize", &case.note),
                &serialized_program,
                |b, serialized_data| {
                    b.iter(|| {
                        match regorus::rvm::program::Program::deserialize_binary(serialized_data)
                            .expect("Deserialization failed")
                        {
                            regorus::rvm::program::DeserializationResult::Complete(program)
                            | regorus::rvm::program::DeserializationResult::Partial(program) => {
                                program
                            }
                        }
                    })
                },
            );
        }
    }
}

fn aci_multi_entrypoint_serialization(c: &mut Criterion) {
    let dir = Path::new("tests/aci");

    // Define the framework delegation rules as entry points
    let framework_entrypoints = [
        "data.policy.mount_device",
        "data.policy.unmount_device",
        "data.policy.mount_overlay",
        "data.policy.unmount_overlay",
        "data.policy.create_container",
        "data.policy.exec_in_container",
        "data.policy.exec_external",
        "data.policy.shutdown_container",
        "data.policy.signal_container_process",
        "data.policy.plan9_mount",
        "data.policy.plan9_unmount",
        "data.policy.get_properties",
        "data.policy.dump_stacks",
        "data.policy.runtime_logging",
        "data.policy.load_fragment",
        "data.policy.scratch_mount",
        "data.policy.scratch_unmount",
    ];

    // Load the ACI test cases to get proper setup
    let yaml_path = dir.join("aci.yaml");
    let yaml = std::fs::read(&yaml_path).expect("failed to read aci.yaml test");
    let yaml = String::from_utf8_lossy(&yaml);
    let test: YamlTest = serde_yaml::from_str(&yaml).expect("failed to deserialize aci.yaml test");

    // Use the first test case as a representative setup (mount_device)
    let representative_case = &test.cases[0];

    // Setup engine using the existing function with all necessary modules and data
    let mut engine = setup_engine(dir, representative_case);

    // Create CompiledPolicy using the first entrypoint
    let first_entrypoint = Rc::from(framework_entrypoints[0]);
    let compiled_policy = engine
        .compile_with_entrypoint(&first_entrypoint)
        .expect("compilation failed");

    // Create RVM program with multiple entry points
    let program = Compiler::compile_from_policy(&compiled_policy, &framework_entrypoints)
        .expect("RVM compilation with multiple entrypoints failed");

    // Benchmark multi-entrypoint program serialization
    c.bench_function("multi_entrypoint_serialize", |b| {
        b.iter(|| {
            program
                .serialize_binary()
                .expect("Multi-entrypoint serialization failed")
        })
    });

    // Pre-serialize for deserialization benchmark
    let serialized_program = program
        .serialize_binary()
        .expect("Multi-entrypoint pre-serialization failed");

    std::fs::write("target/original_program.bin", &serialized_program)
        .expect("Failed to write original program");

    // Benchmark multi-entrypoint program deserialization
    c.bench_with_input(
        BenchmarkId::new("multi_entrypoint_deserialize", "framework_rules"),
        &serialized_program,
        |b, serialized_data| {
            b.iter(|| {
                match regorus::rvm::program::Program::deserialize_binary(serialized_data)
                    .expect("Multi-entrypoint deserialization failed")
                {
                    regorus::rvm::program::DeserializationResult::Complete(program)
                    | regorus::rvm::program::DeserializationResult::Partial(program) => program,
                }
            })
        },
    );

    // Create a corrupted version to force partial deserialization
    let mut corrupted_program = serialized_program.clone();

    // Just corrupt the end of the data
    let end = corrupted_program.len();
    for i in (end - 10)..end {
        corrupted_program[i] = 0xFF;
    }

    // Verify that our corruption actually triggers partial deserialization
    match regorus::rvm::program::Program::deserialize_binary(&corrupted_program) {
        Ok(regorus::rvm::program::DeserializationResult::Partial(partial_program)) => {
            // Good! Corruption worked and we got partial deserialization
            // Recompile from partial program
            let recompiled_program =
                regorus::rvm::program::Program::compile_from_partial(partial_program)
                    .expect("failed to recompile partially deserialized program");

            let reserialized_program = recompiled_program
                .serialize_binary()
                .expect("Multi-entrypoint pre-serialization failed");
            if serialized_program != reserialized_program {
                // Dump program to files for analysis
                std::fs::write("target/reserialized_program.bin", &reserialized_program)
                    .expect("Failed to write reserialized program");

                println!("Original program size: {}", serialized_program.len());
                println!("Reserialized program size: {}", reserialized_program.len());

                // Dump the entry points for comparison
                println!("Original entry points: {:?}", &program.entry_points);
                println!(
                    "Recompiled entry points: {:?}",
                    &recompiled_program.entry_points
                );

                // Find the first difference
                for (i, (a, b)) in serialized_program
                    .iter()
                    .zip(reserialized_program.iter())
                    .enumerate()
                {
                    if a != b {
                        println!("First difference at byte {}: original=0x{:02x} ('{}'), reserialized=0x{:02x} ('{}')", 
                                i, a, *a as char, b, *b as char);
                        break;
                    }
                }

                panic!("Reserialized program after recompilation does not match original (files dumped to target/)");
            }
        }
        Ok(regorus::rvm::program::DeserializationResult::Complete(_)) => {
            // Corruption didn't work as expected, but we can still benchmark
            panic!("Corruption didn't trigger partial deserialization");
        }
        Err(_) => {
            // Complete failure - corruption was too aggressive
            panic!("Corruption caused complete deserialization failure");
        }
    }

    // Benchmark recompilation from partial deserialization
    c.bench_with_input(
        BenchmarkId::new("multi_entrypoint_recompile", "framework_rules"),
        &corrupted_program,
        |b, corrupted_data| {
            b.iter_batched(
                || {
                    // Try to deserialize the corrupted program
                    match regorus::rvm::program::Program::deserialize_binary(corrupted_data) {
                        Ok(result) => Some(result),
                        Err(_) => {
                            // If deserialization fails completely (e.g., artifact section corrupted),
                            // we can't benchmark recompilation, so skip this iteration
                            None
                        }
                    }
                },
                |deserialization_result_opt| {
                    if let Some(deserialization_result) = deserialization_result_opt {
                        match deserialization_result {
                            regorus::rvm::program::DeserializationResult::Complete(_) => {
                                panic!("Expecting partial deserialization.")
                            }
                            regorus::rvm::program::DeserializationResult::Partial(
                                partial_program,
                            ) => {
                                // Recompile from partial program
                                regorus::rvm::program::Program::compile_from_partial(
                                    partial_program,
                                )
                                .unwrap_or_else(|_| {
                                    // If recompilation fails, return a new program as fallback
                                    regorus::rvm::program::Program::new()
                                })
                            }
                        }
                    } else {
                        // Deserialization failed completely, return a new program as fallback
                        regorus::rvm::program::Program::new()
                    }
                },
                BatchSize::SmallInput,
            )
        },
    );

    // Benchmark program loading and execution with multiple entrypoints
    let test_data = representative_case.data.clone();
    let test_input = representative_case.input.clone();

    // Benchmark full flow: deserialize -> recompile (if partial) -> execute
    c.bench_with_input(
        BenchmarkId::new(
            "multi_entrypoint_full_flow",
            "deserialize_recompile_execute",
        ),
        &corrupted_program,
        |b, serialized_data| {
            let data = test_data.clone();
            let input = test_input.clone();
            b.iter(|| {
                // Deserialize the program
                let deserialized_program =
                    match regorus::rvm::program::Program::deserialize_binary(serialized_data)
                        .expect("Multi-entrypoint deserialization failed")
                    {
                        regorus::rvm::program::DeserializationResult::Complete(_) => {
                            panic!("Expecting partial deserialization.")
                        }
                        regorus::rvm::program::DeserializationResult::Partial(partial_program) => {
                            // Recompile from partial program
                            regorus::rvm::program::Program::compile_from_partial(partial_program)
                                .expect("Recompilation from partial program failed")
                        }
                    };

                // Execute the program
                let mut vm = RegoVM::new();
                vm.load_program(std::sync::Arc::new(deserialized_program));
                vm.set_data(data.clone()).expect("Failed to set data");
                vm.set_input(input.clone());
                vm.execute().expect("Multi-entrypoint execution failed")
            })
        },
    );
    c.bench_function("multi_entrypoint_execution", |b| {
        b.iter_batched(
            || {
                let mut vm = RegoVM::new();
                vm.load_program(program.clone());
                vm.set_data(test_data.clone()).expect("Failed to set data");
                vm
            },
            |mut vm| {
                // Execute one of the framework rules as an example
                vm.set_input(test_input.clone());
                vm.execute().expect("Multi-entrypoint execution failed")
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    aci_benches,
    aci_policy_eval,
    aci_multi_entrypoint_serialization
);
criterion_main!(aci_benches);
