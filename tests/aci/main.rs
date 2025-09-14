// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
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

    // Convert input to Value for compiled policy evaluation
    let input = case.input.clone();

    // Compile with entrypoint and evaluate using compiled policy
    let rule = Rc::from(case.query.as_str());
    let compiled = engine.compile_with_entrypoint(&rule)?;
    let result = compiled.eval_with_input(input)?;

    // Make result json compatible. (E.g: avoid sets).
    Value::from_json_str(&result.to_string())
}

fn run_aci_tests(dir: &Path) -> Result<()> {
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
            print!("{:50}", case.note);

            // Test with interpreter
            let start = Instant::now();
            let interpreter_results = eval_test_case_interpreter(dir, case);
            let interpreter_duration = start.elapsed();

            // Test with RVM
            let start = Instant::now();
            let rvm_results = eval_test_case_rvm(dir, case);
            let rvm_duration = start.elapsed();

            match (interpreter_results, rvm_results) {
                (Ok(interpreter_actual), Ok(rvm_actual)) => {
                    // First check interpreter against expected result
                    if interpreter_actual != case.want_result {
                        println!(
                            "INTERPRETER DIFF {}",
                            prettydiff::diff_chars(
                                &serde_yaml::to_string(&case.want_result)?,
                                &serde_yaml::to_string(&interpreter_actual)?
                            )
                        );
                        nfailures += 1;
                        continue;
                    }

                    // Then check RVM against expected result
                    if rvm_actual != case.want_result {
                        println!(
                            "RVM DIFF {}",
                            prettydiff::diff_chars(
                                &serde_yaml::to_string(&case.want_result)?,
                                &serde_yaml::to_string(&rvm_actual)?
                            )
                        );
                        nfailures += 1;
                        continue;
                    }

                    // Finally, assert that interpreter and RVM produce identical results
                    if interpreter_actual != rvm_actual {
                        println!(
                            "INTERPRETER vs RVM DIFF {}",
                            prettydiff::diff_chars(
                                &serde_yaml::to_string(&interpreter_actual)?,
                                &serde_yaml::to_string(&rvm_actual)?
                            )
                        );
                        nfailures += 1;
                        continue;
                    }

                    println!(
                        "passed    interp: {:?}, rvm: {:?}",
                        interpreter_duration, rvm_duration
                    );
                }
                (Ok(_), Err(rvm_error)) => {
                    println!("RVM failed    {:?}", rvm_duration);
                    println!("RVM error: {rvm_error}");
                    nfailures += 1;
                }
                (Err(interpreter_error), Ok(_)) => {
                    println!("INTERPRETER failed    {:?}", interpreter_duration);
                    println!("Interpreter error: {interpreter_error}");
                    nfailures += 1;
                }
                (Err(interpreter_error), Err(rvm_error)) => {
                    println!(
                        "BOTH failed    interp: {:?}, rvm: {:?}",
                        interpreter_duration, rvm_duration
                    );
                    println!("Interpreter error: {interpreter_error}");
                    println!("RVM error: {rvm_error}");
                    nfailures += 1;
                }
            }
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

    let report = engine.get_coverage_report()?;
    println!("{}", report.to_string_pretty()?);

    Ok(())
}

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to ACI test suite.
    #[arg(long, short)]
    #[clap(default_value = "tests/aci")]
    test_dir: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    #[cfg(feature = "coverage")]
    run_aci_tests_coverage(&Path::new(&cli.test_dir))?;

    run_aci_tests(&Path::new(&cli.test_dir))
}
