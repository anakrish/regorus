// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use regorus::rvm::{compiler::Compiler, vm::RegoVM};
use regorus::*;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

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
            let program = Compiler::compile_from_policy(&compiled_policy, &case.query)
                .expect("RVM compilation failed");

            // Create RVM and load the program for validation
            let mut vm = RegoVM::new();
            vm.load_program(program.clone());
            vm.set_data(data.clone());
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
                            vm.set_data(data.clone());
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
        }
    }
}

criterion_group!(aci_benches, aci_policy_eval);
criterion_main!(aci_benches);
