// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! YAML-driven test suite for Azure Policy parsing and evaluation.
//!
//! Each YAML file in `tests/azure_policy/cases/` contains a list of test cases.
//! Each case specifies a policy rule JSON string and expected evaluation outcomes.
//!
//! Currently, the test runner validates:
//! - Successful parsing of policy rule JSON into the AST
//! - Expected parse failures for malformed inputs
//!
//! As the compiler is implemented, this runner will be extended to also:
//! - Compile the AST to RVM bytecode
//! - Evaluate the compiled policy against the provided resource/parameters
//! - Check `want_effect` / `want_undefined` results

use anyhow::Result;
use regorus::languages::azure_policy::aliases::normalizer;
use regorus::languages::azure_policy::aliases::AliasRegistry;
use regorus::languages::azure_policy::compiler;
use regorus::languages::azure_policy::parser;
use regorus::rvm::RegoVM;
use regorus::Source;
use regorus::Value;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use test_generator::test_resources;

/// A single test case in the YAML file.
#[derive(Serialize, Deserialize, Debug)]
struct TestCase {
    /// Short identifier for the test case.
    pub note: String,

    /// The Azure Policy `policyRule` JSON string.
    #[serde(default)]
    pub policy_rule: Option<String>,

    /// The full Azure Policy definition JSON string (alternative to `policy_rule`).
    #[serde(default)]
    pub policy_definition: Option<String>,

    /// Resource properties to evaluate against (for future evaluation).
    #[serde(default)]
    pub resource: Option<serde_yaml::Value>,

    /// Policy parameters (for future evaluation).
    #[serde(default)]
    pub parameters: Option<serde_yaml::Value>,

    /// Expected effect when the condition matches (for future evaluation).
    #[serde(default)]
    pub want_effect: Option<String>,

    /// If true, the condition is expected to NOT match (for future evaluation).
    #[serde(default)]
    pub want_undefined: Option<bool>,

    /// If true, the policy_rule is expected to fail parsing.
    #[serde(default)]
    pub want_parse_error: Option<bool>,

    /// Optional API version for the resource (e.g., "2023-01-01").
    /// When set, injected as `input.resource.apiVersion` so policies and
    /// alias-versioned path selection can reference it.
    #[serde(default)]
    pub api_version: Option<String>,

    /// Optional custom context object. Overrides the default test context
    /// (resourceGroup, subscription). Useful for testing `resourceGroup()`,
    /// `subscription()`, and other context-dependent expressions.
    #[serde(default)]
    pub context: Option<serde_yaml::Value>,

    /// If true, skip this test case.
    #[serde(default)]
    pub skip: Option<bool>,
}

/// Top-level YAML test file structure.
#[derive(Serialize, Deserialize, Debug)]
struct YamlTest {
    /// Optional path to an aliases JSON file (relative to
    /// `tests/azure_policy/aliases/`). When present, the alias catalog is
    /// loaded into an `AliasRegistry` and each test case's `resource` is
    /// treated as raw ARM JSON and run through the normalizer (root
    /// `properties` flattening + sub-resource array flattening) before
    /// evaluation.
    #[serde(default)]
    pub aliases: Option<String>,

    /// Optional global policy rule JSON string. Used as the default for test
    /// cases that don't specify their own `policy_rule` or `policy_definition`.
    /// Avoids duplicating the same policy across many test cases.
    #[serde(default)]
    pub policy_rule: Option<String>,

    /// Optional global policy definition JSON string (alternative to `policy_rule`).
    #[serde(default)]
    pub policy_definition: Option<String>,

    pub cases: Vec<TestCase>,
}

/// Filter test cases by the `TEST_CASE_FILTER` environment variable.
fn should_run_test_case(case_note: &str) -> bool {
    if let Ok(filter) = std::env::var("TEST_CASE_FILTER") {
        case_note.contains(&filter)
    } else {
        true
    }
}

/// Run all test cases from a YAML file.
fn yaml_test_impl(file: &str) -> Result<()> {
    let yaml_str = fs::read_to_string(file)?;
    let test: YamlTest = serde_yaml::from_str(&yaml_str)?;

    // Load alias registry if an aliases file is specified.
    let alias_registry = if let Some(ref aliases_file) = test.aliases {
        let aliases_dir = Path::new(file)
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("../aliases")
            .join(aliases_file);
        let aliases_json = fs::read_to_string(&aliases_dir).unwrap_or_else(|e| {
            panic!(
                "Failed to load aliases file {}: {}",
                aliases_dir.display(),
                e
            )
        });
        let mut registry = AliasRegistry::new();
        registry.load_from_json(&aliases_json)?;
        Some(registry)
    } else {
        None
    };

    println!("running {file}");
    if let Some(ref reg) = alias_registry {
        println!("  Aliases loaded ({} resource types)", reg.len());
    }
    if let Ok(filter) = std::env::var("TEST_CASE_FILTER") {
        println!("  Test case filter active: '{filter}'");
    }

    let mut executed_count = 0usize;
    let mut skipped_count = 0usize;

    for case in &test.cases {
        if !should_run_test_case(&case.note) {
            println!("  case {} filtered out", case.note);
            skipped_count += 1;
            continue;
        }

        print!("  case {} ", case.note);

        if case.skip == Some(true) {
            println!("skipped");
            skipped_count += 1;
            continue;
        }

        executed_count += 1;

        let expects_parse_error = case.want_parse_error == Some(true);

        // Determine source and parse mode.
        // Case-level policy_definition/policy_rule takes precedence over
        // top-level (global) policy_definition/policy_rule.
        let (source_text, use_definition) = if let Some(ref defn) = case.policy_definition {
            (defn.clone(), true)
        } else if let Some(ref rule) = case.policy_rule {
            (rule.clone(), false)
        } else if let Some(ref defn) = test.policy_definition {
            (defn.clone(), true)
        } else if let Some(ref rule) = test.policy_rule {
            (rule.clone(), false)
        } else {
            panic!(
                "case '{}': must specify either 'policy_rule' or 'policy_definition'",
                case.note
            );
        };

        // Keep a reference for extracting parameter defaults later.
        let source = Source::from_contents(format!("test:{}", case.note), source_text)?;

        // Parse and compile.
        //
        // When the source is a full policy definition we parse to
        // `PolicyDefinition` and compile via `compile_policy_definition*`
        // which bakes parameter `defaultValue`s into the program's literal
        // table.  When it's just a policy rule we parse/compile directly.
        let compile_result: Result<_> = if use_definition {
            match parser::parse_policy_definition(&source) {
                Ok(defn) => {
                    if expects_parse_error {
                        panic!(
                            "case '{}': expected parse error but parsing succeeded",
                            case.note
                        );
                    }
                    if let Some(ref registry) = alias_registry {
                        compiler::compile_policy_definition_with_aliases(
                            &defn,
                            registry.alias_map(),
                        )
                    } else {
                        compiler::compile_policy_definition(&defn)
                    }
                }
                Err(e) => {
                    if expects_parse_error {
                        println!("passed (expected parse error: {})", e);
                        continue;
                    }
                    panic!("case '{}': unexpected parse error: {}", case.note, e);
                }
            }
        } else {
            match parser::parse_policy_rule(&source) {
                Ok(ast) => {
                    if expects_parse_error {
                        panic!(
                            "case '{}': expected parse error but parsing succeeded",
                            case.note
                        );
                    }
                    if let Some(ref registry) = alias_registry {
                        compiler::compile_policy_rule_with_aliases(&ast, registry.alias_map())
                    } else {
                        compiler::compile_policy_rule(&ast)
                    }
                }
                Err(e) => {
                    if expects_parse_error {
                        println!("passed (expected parse error: {})", e);
                        continue;
                    }
                    panic!("case '{}': unexpected parse error: {}", case.note, e);
                }
            }
        };

        let program = compile_result?;

        let mut vm = RegoVM::new();
        vm.load_program(program);
        vm.set_input(make_input(case, alias_registry.as_ref())?);

        let value = vm.execute_entry_point_by_name("main")?;

        if case.want_undefined == Some(true) {
            assert_eq!(
                value,
                Value::Undefined,
                "case '{}': expected undefined, got {}",
                case.note,
                value
            );
            println!("passed (compiled + undefined)");
            continue;
        }

        if let Some(effect) = &case.want_effect {
            let expected = Value::from(effect.clone());
            assert_eq!(
                value, expected,
                "case '{}': expected effect {:?}, got {}",
                case.note, effect, value
            );
            println!("passed (compiled + effect={})", effect);
        } else {
            println!("passed (compiled)");
        }
    }

    println!(
        "  Summary for {}: {} executed, {} skipped",
        file, executed_count, skipped_count
    );

    Ok(())
}

fn make_input(case: &TestCase, alias_registry: Option<&AliasRegistry>) -> Result<Value> {
    let parameters =
        yaml_to_regorus_value(case.parameters.as_ref())?.unwrap_or_else(Value::new_object);

    // Use custom context if provided, otherwise default.
    let context = if let Some(ref ctx) = case.context {
        yaml_to_regorus_value(Some(ctx))?.unwrap_or_else(Value::new_object)
    } else {
        Value::from_json_str(
            r#"{
                "resourceGroup": {
                    "name": "myResourceGroup",
                    "location": "eastus"
                },
                "subscription": {
                    "subscriptionId": "00000000-0000-0000-0000-000000000000"
                }
            }"#,
        )?
    };

    let mut resource = if let Some(registry) = alias_registry {
        // Convert YAML resource → serde_json, resolve aliases for the resource
        // type, run normalizer with sub-resource info, convert to regorus Value.
        let raw_json: serde_json::Value = case
            .resource
            .as_ref()
            .map(|y| serde_json::to_value(y).expect("YAML→JSON conversion failed"))
            .unwrap_or(serde_json::Value::Object(Default::default()));
        let resource_type = raw_json.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let resolved = registry.get(resource_type);
        let normalized_json =
            normalizer::normalize(&raw_json, resolved, case.api_version.as_deref());
        Value::from_json_str(&serde_json::to_string(&normalized_json)?)
            .expect("normalized JSON→Value conversion failed")
    } else {
        yaml_to_regorus_value(case.resource.as_ref())?.unwrap_or_else(Value::new_object)
    };

    // Inject api_version into the resource if specified.
    if let Some(ref api_ver) = case.api_version {
        let map = resource.as_object_mut()?;
        map.insert(Value::from("apiVersion"), Value::from(api_ver.clone()));
    }

    let mut input = Value::new_object();
    let map = input.as_object_mut()?;
    map.insert(Value::from("resource"), resource);
    map.insert(Value::from("parameters"), parameters);
    map.insert(Value::from("context"), context);

    Ok(input)
}

fn yaml_to_regorus_value(value: Option<&serde_yaml::Value>) -> Result<Option<Value>> {
    let Some(value) = value else {
        return Ok(None);
    };

    let json = serde_json::to_string(value)?;
    let regorus_value = Value::from_json_str(&json)?;
    Ok(Some(regorus_value))
}

#[test_resources("tests/azure_policy/cases/*.yaml")]
fn run_azure_policy_yaml(file: &str) {
    yaml_test_impl(file).unwrap();
}

#[test]
fn test_specific_case() {
    if std::env::var("TEST_CASE_FILTER").is_err() {
        println!("Specific case test skipped - no TEST_CASE_FILTER set");
        println!("  Usage: TEST_CASE_FILTER=\"note substring\" cargo test --features azure_policy test_specific_case -- --nocapture");
        return;
    }

    if let Ok(entries) = fs::read_dir("tests/azure_policy/cases") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("yaml") {
                if let Err(e) = yaml_test_impl(path.to_str().unwrap()) {
                    println!("Error in file {}: {}", path.display(), e);
                }
            }
        }
    }
}
