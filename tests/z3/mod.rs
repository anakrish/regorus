// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::Path;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use regorus::z3_integration::Z3PolicyVerifier;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct ExpectedConflict {
    policy1_rule: String,
    policy2_rule: String,
    conflict_type: String,
    expected_conflicting_input: Option<String>,  // JSON input that should trigger the conflict
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct TestCase {
    note: String,
    effects: Option<Vec<String>>,
    policies: Option<Vec<String>>,
    conflict_expected: Option<bool>,
    expected_conflicts: Option<Vec<ExpectedConflict>>,
    error_message: Option<String>,
    panic_expected: Option<bool>,
    panic_message: Option<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct TestCases {
    cases: Vec<TestCase>,
}

fn verify_expected_conflicts(
    actual_conflicts: &[String],
    actual_conflicting_inputs: &[String],
    expected_conflicts: &[ExpectedConflict],
    test_note: &str,
) -> Result<()> {
    if expected_conflicts.is_empty() {
        return Ok(()); // No specific conflicts expected, just check count
    }

    if actual_conflicts.len() != expected_conflicts.len() {
        return Err(anyhow!(
            "Expected {} conflicts but found {} in test: {}",
            expected_conflicts.len(),
            actual_conflicts.len(),
            test_note
        ));
    }

    for (i, expected) in expected_conflicts.iter().enumerate() {
        let actual_conflict = &actual_conflicts[i];
        
        // Check if the actual conflict contains expected patterns
        let contains_policy1 = actual_conflict.contains(&expected.policy1_rule);
        let contains_policy2 = actual_conflict.contains(&expected.policy2_rule);
        let _contains_type = actual_conflict.contains(&expected.conflict_type);

        if !contains_policy1 || !contains_policy2 {
            return Err(anyhow!(
                "Conflict {} doesn't match expected pattern.\nExpected: {} vs {}\nActual: {}\nTest: {}",
                i + 1,
                expected.policy1_rule,
                expected.policy2_rule,
                actual_conflict,
                test_note
            ));
        }

        // Verify conflicting input if expected
        if let Some(ref expected_input) = expected.expected_conflicting_input {
            if i < actual_conflicting_inputs.len() {
                let actual_input = &actual_conflicting_inputs[i];
                
                // Parse both JSON strings to compare semantically
                let expected_json: serde_json::Value = serde_json::from_str(expected_input)
                    .map_err(|e| anyhow!("Failed to parse expected JSON: {}", e))?;
                let actual_json: serde_json::Value = serde_json::from_str(actual_input)
                    .map_err(|e| anyhow!("Failed to parse actual JSON: {}", e))?;
                
                if expected_json != actual_json {
                    return Err(anyhow!(
                        "Conflicting input {} doesn't match expected.\nExpected JSON: {}\nActual JSON: {}\nExpected Raw: {}\nActual Raw: {}\nTest: {}",
                        i + 1,
                        serde_json::to_string_pretty(&expected_json).unwrap_or_default(),
                        serde_json::to_string_pretty(&actual_json).unwrap_or_default(),
                        expected_input,
                        actual_input,
                        test_note
                    ));
                }
                println!("✓ Conflicting input {} matches expected", i + 1);
            } else {
                return Err(anyhow!(
                    "Expected conflicting input {} but only {} inputs generated",
                    i + 1,
                    actual_conflicting_inputs.len()
                ));
            }
        }

        println!("✓ Conflict {} matches expected pattern", i + 1);
    }

    Ok(())
}

fn run_test_case(case: &TestCase) -> Result<()> {
    println!("Running test case: {}", case.note);

    if let Some(ref policies) = case.policies {
        // Create Z3 verifier and add policies
        let mut verifier = Z3PolicyVerifier::new();
        
        for policy in policies {
            match verifier.add_policy(policy) {
                Ok(_) => {}
                Err(e) => {
                    if case.panic_expected == Some(true) {
                        if let Some(ref expected_msg) = case.panic_message {
                            if e.to_string().contains(expected_msg) {
                                println!("✓ Expected panic occurred: {}", e);
                                return Ok(());
                            } else {
                                return Err(anyhow!("Panic occurred but message doesn't match. Expected: '{}', Got: '{}'", expected_msg, e));
                            }
                        } else {
                            println!("✓ Expected panic occurred: {}", e);
                            return Ok(());
                        }
                    } else {
                        return Err(anyhow!("Unexpected error: {}", e));
                    }
                }
            }
        }

        // Check for conflicts
        let effects = case.effects.as_ref()
            .map(|e| e.iter().map(|s| s.as_str()).collect::<Vec<_>>())
            .unwrap_or_else(|| vec!["deny", "audit", "modify", "deployIfNotExists"]);
            
        match verifier.verify_policies_with_effects_detailed(&effects) {
            Ok(result) => {
                let has_conflicts = !result.conflicts.is_empty();
                
                if let Some(expected) = case.conflict_expected {
                    if has_conflicts == expected {
                        // If we expected conflicts and got them, verify specific conflicts if provided
                        if has_conflicts && case.expected_conflicts.is_some() {
                            verify_expected_conflicts(
                                &result.conflicts,
                                &result.conflicting_inputs,
                                case.expected_conflicts.as_ref().unwrap(),
                                &case.note,
                            )?;
                        }
                        println!("✓ Conflict detection result matches expectation: {}", has_conflicts);
                    } else {
                        return Err(anyhow!("Conflict detection mismatch. Expected: {}, Got: {}", expected, has_conflicts));
                    }
                } else {
                    println!("ℹ Conflicts found: {}", has_conflicts);
                    for conflict in result.conflicts {
                        println!("  {}", conflict);
                    }
                }
            }
            Err(e) => {
                if case.panic_expected == Some(true) {
                    if let Some(ref expected_msg) = case.panic_message {
                        if e.to_string().contains(expected_msg) {
                            println!("✓ Expected panic occurred during conflict check: {}", e);
                            return Ok(());
                        } else {
                            return Err(anyhow!("Panic occurred but message doesn't match. Expected: '{}', Got: '{}'", expected_msg, e));
                        }
                    } else {
                        println!("✓ Expected panic occurred during conflict check: {}", e);
                        return Ok(());
                    }
                } else {
                    return Err(anyhow!("Unexpected error during conflict check: {}", e));
                }
            }
        }

        if case.panic_expected == Some(true) {
            return Err(anyhow!("Expected panic but test completed successfully"));
        }
    }

    Ok(())
}

fn test_file_impl(path: &Path) -> Result<()> {
    let contents = std::fs::read_to_string(path)?;
    let test_cases: TestCases = serde_yaml::from_str(&contents)?;

    for case in test_cases.cases {
        run_test_case(&case)?;
    }

    Ok(())
}

pub fn run_z3_tests() -> Result<()> {
    let test_dir = Path::new("tests/z3/cases");
    
    if !test_dir.exists() {
        return Err(anyhow!("Z3 test directory not found: {}", test_dir.display()));
    }

    let mut test_files = Vec::new();
    for entry in std::fs::read_dir(test_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("yaml") {
            test_files.push(path);
        }
    }

    test_files.sort();
    
    for test_file in test_files {
        println!("\n=== Testing {} ===", test_file.display());
        test_file_impl(&test_file)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_z3_yaml_cases() {
        match run_z3_tests() {
            Ok(_) => println!("All Z3 tests passed!"),
            Err(e) => panic!("Z3 tests failed: {}", e),
        }
    }
}
