// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(all(feature = "cedar", feature = "rvm"))]

use regorus::languages::cedar::cache::CedarCache;
use regorus::languages::cedar::compiler::compile_to_program;
use regorus::languages::cedar::parser::Parser;
use regorus::rvm::program::{generate_assembly_listing, AssemblyListingConfig};
use regorus::rvm::vm::RegoVM;
use regorus::{Rc, Source, Value};
use serde::Deserialize;
use std::fs;
use std::sync::Arc;
use test_generator::test_resources;

#[derive(Debug, Deserialize)]
struct CedarTestCase {
    note: String,
    policies: Vec<String>,
    input: Value,
    want_result: Option<String>,
    error: Option<String>,
    skip: Option<bool>,
    #[serde(default = "default_use_cache")]
    use_cache: bool,
}

#[derive(Debug, Deserialize)]
struct YamlTest {
    cases: Vec<CedarTestCase>,
}

fn default_use_cache() -> bool {
    true
}

fn parse_policies(
    policies: &[String],
) -> anyhow::Result<Vec<regorus::languages::cedar::ast::Policy>> {
    let mut out = Vec::new();
    for (idx, policy) in policies.iter().enumerate() {
        let source = Source::from_contents(format!("policy_{idx}.cedar"), policy.clone())?;
        let mut parser = Parser::new(&source).map_err(|err| anyhow::anyhow!(err))?;
        let mut parsed = parser.parse().map_err(|err| anyhow::anyhow!(err))?;
        out.append(&mut parsed);
    }
    Ok(out)
}

fn run_yaml(file: &str) -> anyhow::Result<()> {
    let yaml_str = fs::read_to_string(file)?;
    let test: YamlTest = serde_yaml::from_str(&yaml_str)?;

    for case in test.cases {
        if case.skip == Some(true) {
            continue;
        }

        let policies = match parse_policies(&case.policies) {
            Ok(policies) => policies,
            Err(err) => {
                if let Some(expected) = case.error.as_ref() {
                    let message = err.to_string();
                    if !message.contains(expected) {
                        anyhow::bail!(
                            "case '{}' error '{}' does not contain '{}'",
                            case.note,
                            message,
                            expected
                        );
                    }
                    continue;
                }
                return Err(err);
            }
        };

        let program = match compile_to_program(&policies) {
            Ok(program) => program,
            Err(err) => {
                if let Some(expected) = case.error.as_ref() {
                    let message = err.to_string();
                    if !message.contains(expected) {
                        anyhow::bail!(
                            "case '{}' error '{}' does not contain '{}'",
                            case.note,
                            message,
                            expected
                        );
                    }
                    continue;
                }
                return Err(err.into());
            }
        };

        let listing = generate_assembly_listing(&program, &AssemblyListingConfig::default());
        println!("\n=== Cedar case: {} ===\n{}", case.note, listing);

        let mut vm = RegoVM::new();
        if case.use_cache {
            vm.set_cedar_cache(Some(Rc::new(CedarCache::new())));
        }
        vm.set_strict_builtin_errors(true);
        vm.load_program(Arc::new(program));
        vm.set_input(case.input.clone());

        let result = vm.execute_entry_point_by_name("cedar.authorize");

        match result {
            Ok(value) => match &case.want_result {
                Some(expected) => {
                    let expected_value = match expected.as_str() {
                        "permit" => Value::from(1u64),
                        "deny" => Value::from(0u64),
                        _ => anyhow::bail!(
                            "case '{}' has unsupported want_result '{}'",
                            case.note,
                            expected
                        ),
                    };

                    if value != expected_value {
                        anyhow::bail!(
                            "case '{}' expected {}, got {}",
                            case.note,
                            expected_value,
                            value
                        );
                    }
                }
                None => {
                    anyhow::bail!("case '{}' expected error but got success", case.note);
                }
            },
            Err(err) => match &case.error {
                Some(expected) => {
                    let message = err.to_string();
                    if !message.contains(expected) {
                        anyhow::bail!(
                            "case '{}' error '{}' does not contain '{}'",
                            case.note,
                            message,
                            expected
                        );
                    }
                }
                None => return Err(err.into()),
            },
        }
    }

    Ok(())
}

#[test_resources("tests/rvm/cedar/**/*.yaml")]
fn run(path: &str) {
    run_yaml(path).unwrap();
}
