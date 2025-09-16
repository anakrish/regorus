// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use regorus::rvm::test_utils::test_round_trip_serialization;
use regorus::rvm::{compiler::Compiler, vm::RegoVM};
use regorus::*;

use std::path::Path;
use std::time::Instant;

use anyhow::Result;
use clap::Parser;
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

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

fn setup_engine(dir: &Path, case: &TestCase) -> Result<Engine> {
    let mut engine = Engine::new();
    engine.set_rego_v0(true);

    engine.add_data(case.data.clone())?;
    engine.set_input(case.input.clone());

    for (idx, rego) in case.modules.iter().enumerate() {
        if rego.ends_with(".rego") {
            let path = dir.join(rego);
            let path = path.to_str().expect("not a valid path");
            engine.add_policy_from_file(path.to_string())?;
        } else {
            engine.add_policy(format!("rego{idx}.rego"), rego.clone())?;
        }
    }

    Ok(engine)
}

fn eval_test_case_interpreter(dir: &Path, case: &TestCase) -> Result<Value> {
    let mut engine = setup_engine(dir, case)?;

    // Use eval_rule instead of eval_query since we're evaluating specific rules
    let result = engine.eval_rule(case.query.clone())?;

    // Make result json compatible. (E.g: avoid sets).
    Value::from_json_str(&result.to_string())
}

fn eval_test_case_rvm(dir: &Path, case: &TestCase) -> Result<Value> {
    let mut engine = setup_engine(dir, case)?;

    // Convert input and data for RVM
    let input = case.input.clone();
    let data = case.data.clone();

    // Create CompiledPolicy first (needed for RVM compiler)
    let rule = Rc::from(case.query.as_str());
    let compiled_policy = engine.compile_with_entrypoint(&rule)?;

    // Use RVM compiler to create a program
    let program = Compiler::compile_from_policy(&compiled_policy, &case.query)?;

    // Test round-trip serialization
    test_round_trip_serialization(program.as_ref()).map_err(|e| {
        anyhow::anyhow!(
            "Round-trip serialization test failed for case '{}': {}",
            case.note,
            e
        )
    })?;

    // Create RVM and load the program
    let mut vm = RegoVM::new();
    vm.load_program(program);
    vm.set_data(data)?;
    vm.set_input(input);

    // Execute on RVM
    let result = vm.execute()?;

    // Make result json compatible. (E.g: avoid sets).
    Value::from_json_str(&result.to_string())
}

fn run_aci_tests(dir: &Path, filter: Option<&str>) -> Result<()> {
    let mut nfailures = 0;
    for entry in WalkDir::new(dir)
        .sort_by_file_name()
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.to_string_lossy().ends_with(".yaml") {
            continue;
        }

        let yaml = std::fs::read(&path)?;
        let yaml = String::from_utf8_lossy(&yaml);
        let test: YamlTest = serde_yaml::from_str(&yaml)?;

        for case in &test.cases {
            // Apply filter if specified
            if let Some(filter_str) = filter {
                if !case.note.contains(filter_str) {
                    continue;
                }
            }

            print!("{:50}", case.note);

            // Test with interpreter
            let start = Instant::now();
            let interpreter_results = eval_test_case_interpreter(dir, case)?;
            let interpreter_duration = start.elapsed();

            if interpreter_results != case.want_result {
                println!(
                    "INTERPRETER DIFF {}",
                    prettydiff::diff_chars(
                        &serde_yaml::to_string(&case.want_result)?,
                        &serde_yaml::to_string(&interpreter_results)?
                    )
                );
                nfailures += 1;
                continue;
            }
            if case.skip_rvm {
                println!("skipped rvm");
                continue;
            }

            // Test with RVM
            let start = Instant::now();
            let rvm_results = eval_test_case_rvm(dir, case)?;
            let rvm_duration = start.elapsed();

            if interpreter_results != rvm_results {
                println!("INTERPRETER RESULT:");
                println!("{}", serde_yaml::to_string(&interpreter_results)?);
                println!("RVM RESULT:");
                println!("{}", serde_yaml::to_string(&rvm_results)?);
                println!(
                    "INTERPRETER vs RVM DIFF {}",
                    prettydiff::diff_chars(
                        &serde_yaml::to_string(&interpreter_results)?,
                        &serde_yaml::to_string(&rvm_results)?
                    )
                );
                nfailures += 1;
                continue;
            }

            print!(
                "Interp: {:?}, RVM: {:?}\n",
                interpreter_duration, rvm_duration
            );
        }
    }
    assert!(nfailures == 0);

    Ok(())
}

#[cfg(feature = "coverage")]
fn run_aci_tests_coverage(dir: &Path) -> Result<()> {
    let mut engine = Engine::new();
    engine.set_rego_v0(true);
    engine.set_enable_coverage(true);

    let mut added = std::collections::BTreeSet::new();

    for entry in WalkDir::new(dir)
        .sort_by_file_name()
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.to_string_lossy().ends_with(".yaml") {
            continue;
        }

        let yaml = std::fs::read(&path)?;
        let yaml = String::from_utf8_lossy(&yaml);
        let test: YamlTest = serde_yaml::from_str(&yaml)?;

        for case in &test.cases {
            for (idx, rego) in case.modules.iter().enumerate() {
                if rego.ends_with(".rego") {
                    let path = dir.join(rego);
                    let path = path.to_str().expect("not a valid path");
                    let path = path.to_string();
                    if !added.contains(&path) {
                        engine.add_policy_from_file(path.to_string())?;
                        added.insert(path);
                    }
                } else {
                    engine.add_policy(format!("rego{idx}.rego"), rego.clone())?;
                }
            }

            engine.clear_data();
            engine.add_data(case.data.clone())?;
            engine.set_input(case.input.clone());
            let _query_results = engine.eval_query(case.query.clone(), true)?;
        }
    }

    //let report = engine.get_coverage_report()?;
    //println!("{}", report.to_string_pretty()?);

    Ok(())
}

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to ACI test suite.
    #[arg(long, short)]
    #[clap(default_value = "tests/aci")]
    test_dir: String,

    /// Filter to run only specific test cases (by note field, e.g., "create_container")
    #[arg(long, short)]
    filter: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    #[cfg(feature = "coverage")]
    run_aci_tests_coverage(&Path::new(&cli.test_dir))?;

    run_aci_tests(&Path::new(&cli.test_dir), cli.filter.as_deref())
}
