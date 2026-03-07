// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Core test runner logic.  Compiles each policy definition, evaluates test
//! cases against it, and checks the expected compliance state / effect.

use crate::format;
use anyhow::Result;
use regorus::languages::azure_policy::aliases::{normalizer, AliasRegistry};
use regorus::languages::azure_policy::{compiler, parser};
use regorus::rvm::RegoVM;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Aggregate test statistics.
pub struct Stats {
    pub files: usize,
    pub cases: usize,
    pub pass: usize,
    pub fail: usize,
    pub skip: usize,
    pub file_errors: usize,
    pub failures: Vec<String>,
    pub known_failure_count: usize,
    pub known_failure_msgs: Vec<String>,
}

/// A known test failure: file path substring + optional case substring + reason.
struct KnownFailure {
    file_contains: &'static str,
    case_contains: &'static str,
    reason: &'static str,
}

/// List of known test failures with reasons. These are run but their failures
/// are reported separately and do not cause a non-zero exit code.
const KNOWN_FAILURES: &[KnownFailure] = &[
    KnownFailure {
        file_contains: "ModifyBoolean.Test.yaml",
        case_contains: "",
        reason: "missing external file Modify2.json",
    },
    KnownFailure {
        file_contains: "Policy_VmsizeExistsTest.Test.yaml",
        case_contains: "step2",
        reason: "bare path (no alias) evaluation not yet implemented",
    },
    KnownFailure {
        file_contains: "ASC_Azure_Defender_Containers_Full_Features_DINE.Test.yaml",
        case_contains: "",
        reason: "complex nested extension/gating evaluation not yet supported",
    },
    KnownFailure {
        file_contains: "ValidateDCRDelete.Test.yaml",
        case_contains: "Protected",
        reason: "DenyAction protected-resource detection not yet supported",
    },
];

/// Run all test files and return aggregate statistics.
pub fn run_all(
    test_files: &[PathBuf],
    base_folder: &str,
    alias_registry: Option<&AliasRegistry>,
    verbose: bool,
    stop_on_fail: bool,
) -> Result<Stats> {
    let mut stats = Stats {
        files: 0,
        cases: 0,
        pass: 0,
        fail: 0,
        skip: 0,
        file_errors: 0,
        failures: Vec::new(),
        known_failure_count: 0,
        known_failure_msgs: Vec::new(),
    };

    for test_path in test_files {
        let rel = test_path
            .strip_prefix(base_folder)
            .unwrap_or(test_path)
            .display()
            .to_string();

        stats.files += 1;

        let yaml_str = match std::fs::read_to_string(test_path) {
            Ok(s) => s,
            Err(e) => {
                record_file_error(
                    &mut stats,
                    &rel,
                    format!("{rel}: cannot read file: {e}"),
                    verbose,
                );
                if stop_on_fail {
                    return Ok(stats);
                }
                continue;
            }
        };

        // Use the Deserializer iterator API so that multi-document YAML files
        // (separated by `---`) are handled gracefully — we deserialize each
        // document as a separate TestFile and merge their test cases.
        let test_file: format::TestFile = match parse_yaml_test_file(&yaml_str) {
            Ok(t) => t,
            Err(e) => {
                record_file_error(
                    &mut stats,
                    &rel,
                    format!("{rel}: YAML parse error: {e}"),
                    verbose,
                );
                if stop_on_fail {
                    return Ok(stats);
                }
                continue;
            }
        };

        if verbose {
            println!(
                "\n── {} ({} test{}) ──",
                rel,
                test_file.tests.len(),
                if test_file.tests.len() == 1 { "" } else { "s" }
            );
        }

        // Load file-level policy definition (if any).
        // Returns the original file text (for the lexer) plus the parsed Value
        // (for pointer queries).  This avoids re-serializing the JSON, which
        // would lose the original layout and might exceed the lexer column limit.
        let file_policy = load_file_policy(test_path, &test_file, &rel);
        let file_policy = match file_policy {
            Ok(v) => v,
            Err(msg) => {
                record_file_error(&mut stats, &rel, msg, verbose);
                if stop_on_fail {
                    return Ok(stats);
                }
                continue;
            }
        };

        for case in &test_file.tests {
            stats.cases += 1;
            let label = format!("{rel} / {}", case.name);

            // Determine the policy text (for the lexer) and the parsed JSON
            // value (for pointer queries like details.type extraction).
            let (policy_text, policy_json) = if let Some(ref inline_rule) = case.policy_rule {
                // The YAML folded scalar (>) makes policyRule a JSON string
                // rather than an object.  Parse it if necessary.
                let rule_obj = if let Some(s) = inline_rule.as_str() {
                    match json_lenient(s) {
                        Ok(v) => v,
                        Err(e) => {
                            record_fail(
                                &mut stats,
                                &rel,
                                format!("{label}: inline policyRule JSON error: {e}"),
                                verbose,
                            );
                            if stop_on_fail {
                                return Ok(stats);
                            }
                            continue;
                        }
                    }
                } else {
                    inline_rule.clone()
                };
                // Wrap in a minimal definition.
                let json = serde_json::json!({
                    "properties": {
                        "policyRule": rule_obj,
                        "mode": "All"
                    }
                });
                // Pretty-print so we stay within the lexer column limit.
                let text = serde_json::to_string_pretty(&json).unwrap();
                (text, json)
            } else if let Some((ref file_text, ref file_json)) = file_policy {
                // Use the original file text — preserves formatting and avoids
                // exceeding the lexer column limit from single-line serialization.
                (file_text.clone(), file_json.clone())
            } else {
                if verbose {
                    println!("  SKIP (no policy) {}", case.name);
                }
                stats.skip += 1;
                continue;
            };

            // Parse.
            let source = match regorus::Source::from_contents(label.clone(), policy_text) {
                Ok(s) => s,
                Err(e) => {
                    record_fail(
                        &mut stats,
                        &rel,
                        format!("{label}: source error: {e}"),
                        verbose,
                    );
                    if stop_on_fail {
                        return Ok(stats);
                    }
                    continue;
                }
            };

            let defn = match parser::parse_policy_definition(&source) {
                Ok(d) => d,
                Err(e) => {
                    record_fail(
                        &mut stats,
                        &rel,
                        format!("{label}: parse error: {e}"),
                        verbose,
                    );
                    if stop_on_fail {
                        return Ok(stats);
                    }
                    continue;
                }
            };

            // Compile.
            let program = if let Some(reg) = alias_registry {
                compiler::compile_policy_definition_with_aliases_opts(
                    &defn,
                    reg.alias_map(),
                    reg.alias_modifiable_map(),
                    true, // fallback unknown aliases to raw paths
                )
            } else {
                compiler::compile_policy_definition(&defn)
            };

            let program = match program {
                Ok(p) => p,
                Err(e) => {
                    record_fail(
                        &mut stats,
                        &rel,
                        format!("{label}: compile error: {e}"),
                        verbose,
                    );
                    if stop_on_fail {
                        return Ok(stats);
                    }
                    continue;
                }
            };

            // Extract details.type for AINE/DINE normalization.
            let details_type = policy_json
                .pointer("/properties/policyRule/then/details/type")
                .or_else(|| policy_json.pointer("/then/details/type"))
                .and_then(|v| v.as_str())
                .map(String::from);

            // DenyAction tests use `requests` instead of `resources`.
            if !case.requests.is_empty() {
                // Determine missingTokenAction for requests without token claims.
                // This controls what happens when the RP doesn't provide a
                // validation token.  "Deny" → action fires (Protected);
                // "Audit" → audit only (not blocked).
                let missing_token_action = case
                    .expected
                    .missing_token_action
                    .as_deref()
                    .or_else(|| {
                        // Fall back to the policy parameter default.
                        policy_json
                            .pointer("/properties/parameters/missingTokenAction/defaultValue")
                            .or_else(|| {
                                policy_json.pointer("/parameters/missingTokenAction/defaultValue")
                            })
                            .and_then(|v| v.as_str())
                    })
                    .unwrap_or("Audit");

                let mut case_passed = true;
                for (ri, request) in case.requests.iter().enumerate() {
                    // Parse the existing resource from the request.
                    let raw_resource = if let Some(ref res_str) = request.existing_resource {
                        match json_lenient(res_str.trim()) {
                            Ok(v) => v,
                            Err(e) => {
                                record_fail(
                                    &mut stats,
                                    &rel,
                                    format!(
                                        "{label} [request {ri}]: existingResource JSON error: {e}"
                                    ),
                                    verbose,
                                );
                                case_passed = false;
                                break;
                            }
                        }
                    } else {
                        serde_json::json!({})
                    };

                    // Parse identity and token claims.
                    let identity_claims = request
                        .request_identity_claims
                        .as_deref()
                        .and_then(|s| json_lenient(s.trim()).ok())
                        .unwrap_or(serde_json::json!({}));
                    let token_claims = request
                        .policy_token_claims
                        .as_deref()
                        .and_then(|s| json_lenient(s.trim()).ok());

                    // Missing-token handling: when no token claims are provided
                    // and missingTokenAction is "Deny", the action fires
                    // immediately (without evaluating claims conditions).
                    if token_claims.is_none() && missing_token_action.eq_ignore_ascii_case("Deny") {
                        // Synthesize the effect result that the policy would
                        // produce when the action fires.
                        let effect_name = case
                            .parameters
                            .as_ref()
                            .and_then(|p| p.get("effect"))
                            .and_then(|v| v.as_str())
                            .or_else(|| {
                                policy_json
                                    .pointer("/properties/parameters/effect/defaultValue")
                                    .or_else(|| {
                                        policy_json.pointer("/parameters/effect/defaultValue")
                                    })
                                    .and_then(|v| v.as_str())
                            })
                            .unwrap_or("DenyAction");
                        let synthetic_result = regorus::Value::from_json_str(&format!(
                            r#"{{"effect":"{}"}}"#,
                            effect_name
                        ))
                        .unwrap_or_else(|_| regorus::Value::from("DenyAction"));
                        if let Err(msg) =
                            check_expected(&synthetic_result, &case.expected, &label, ri)
                        {
                            record_fail(&mut stats, &rel, msg, verbose);
                            case_passed = false;
                            break;
                        }
                        continue;
                    }

                    match eval_deny_action_case(
                        &program,
                        &raw_resource,
                        &identity_claims,
                        token_claims.as_ref(),
                        case,
                        alias_registry,
                        &policy_json,
                    ) {
                        Ok(result) => {
                            if let Err(msg) = check_expected(&result, &case.expected, &label, ri) {
                                record_fail(&mut stats, &rel, msg, verbose);
                                case_passed = false;
                                break;
                            }
                        }
                        Err(e) => {
                            record_fail(
                                &mut stats,
                                &rel,
                                format!("{label} [request {ri}]: execution error: {e}"),
                                verbose,
                            );
                            case_passed = false;
                            break;
                        }
                    }
                }

                if case_passed {
                    stats.pass += 1;
                    if verbose {
                        println!("  PASS {}", case.name);
                    }
                } else if stop_on_fail {
                    return Ok(stats);
                }
                continue;
            }

            // Collect resources.
            let resources: Vec<serde_json::Value> = if case.resources.is_empty() {
                vec![serde_json::json!({})]
            } else {
                case.resources
                    .iter()
                    .filter_map(|s| json_lenient(s.trim()).ok())
                    .collect()
            };

            if resources.is_empty() && !case.resources.is_empty() {
                record_fail(
                    &mut stats,
                    &rel,
                    format!("{label}: all resource JSON blocks failed to parse"),
                    verbose,
                );
                if stop_on_fail {
                    return Ok(stats);
                }
                continue;
            }

            // Evaluate each resource.
            let mut case_passed = true;
            for (ri, raw_resource) in resources.iter().enumerate() {
                match eval_case(
                    &program,
                    raw_resource,
                    case,
                    alias_registry,
                    &details_type,
                    &policy_json,
                ) {
                    Ok(result) => {
                        if let Err(msg) = check_expected(&result, &case.expected, &label, ri) {
                            record_fail(&mut stats, &rel, msg, verbose);
                            case_passed = false;
                            break;
                        }
                    }
                    Err(e) => {
                        record_fail(
                            &mut stats,
                            &rel,
                            format!("{label} [resource {ri}]: execution error: {e}"),
                            verbose,
                        );
                        case_passed = false;
                        break;
                    }
                }
            }

            if case_passed {
                stats.pass += 1;
                if verbose {
                    println!("  PASS {}", case.name);
                }
            } else {
                // Already recorded via record_fail above.
                if stop_on_fail {
                    return Ok(stats);
                }
            }
        }
    }

    Ok(stats)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Load the file-level policy JSON (from `policy:` path or None).
/// Returns `(original_text, parsed_value)` so the caller can feed the
/// original text directly into the lexer without re-serializing.
fn load_file_policy(
    yaml_path: &Path,
    test_file: &format::TestFile,
    rel: &str,
) -> Result<Option<(String, serde_json::Value)>, String> {
    let Some(ref pol_path) = test_file.policy else {
        return Ok(None);
    };

    let resolved = pol_path.replace('\\', "/");
    let base = yaml_path.parent().unwrap_or_else(|| Path::new("."));
    let policy_path = base.join(&resolved);

    let text = std::fs::read_to_string(&policy_path).map_err(|e| {
        format!(
            "{rel}: cannot read policy file {}: {e}",
            policy_path.display()
        )
    })?;

    // Strip leading UTF-8 BOM (common in Windows-created files).
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text).to_string();

    let json = json_lenient(&text).map_err(|e| {
        format!(
            "{rel}: policy JSON parse error ({}): {e}",
            policy_path.display()
        )
    })?;

    Ok(Some((text, json)))
}

/// Evaluate a single resource against the compiled program.
fn eval_case(
    program: &Arc<regorus::rvm::Program>,
    raw_resource: &serde_json::Value,
    case: &format::TestCase,
    alias_registry: Option<&AliasRegistry>,
    details_type: &Option<String>,
    policy_json: &serde_json::Value,
) -> Result<regorus::Value> {
    // Normalize the resource.
    // For synthetic test resources (no ARM-style "type" like "Microsoft.X/y"),
    // skip normalisation and just lowercase all keys — the normalizer is
    // designed for real ARM resources and would discard unknown top-level
    // fields like "dict" that csharp-converted tests rely on.
    let is_arm_resource = raw_resource
        .as_object()
        .and_then(|obj| obj.iter().find(|(k, _)| k.eq_ignore_ascii_case("type")))
        .and_then(|(_, v)| v.as_str())
        .map(|t| t.contains('/'))
        .unwrap_or(false);

    let resource_json = if is_arm_resource {
        if let Some(reg) = alias_registry {
            let api_ver = raw_resource
                .as_object()
                .and_then(|obj| {
                    obj.iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("apiVersion"))
                })
                .and_then(|(_, v)| v.as_str())
                .map(String::from);
            normalizer::normalize(raw_resource, Some(reg), api_ver.as_deref())
        } else {
            normalizer::normalize(raw_resource, None, None)
        }
    } else {
        // Synthetic resource — deep-lowercase keys for case-insensitive
        // matching but preserve the full structure.
        lowercase_keys_deep(raw_resource)
    };

    // Debug: print normalized resource when DEBUG_NORM env var is set.
    if std::env::var("DEBUG_NORM").is_ok() {
        eprintln!(
            "DEBUG normalized resource: {}",
            serde_json::to_string_pretty(&resource_json).unwrap_or_default()
        );
    }

    // Build parameters (coerce YAML booleans to match policy parameter types).
    let params = {
        let mut p = case
            .parameters
            .clone()
            .unwrap_or_else(|| serde_json::json!({}));
        coerce_test_parameters(&mut p, policy_json);
        serde_json::to_string(&p).unwrap()
    };
    let params_value = regorus::Value::from_json_str(&params)?;

    // Compute `fullName` from resource `id` and inject it into the resource
    // before converting to regorus::Value.  `fullName` is a virtual field in
    // Azure Policy computed from the resource ID path.
    let resource_json = inject_full_name(resource_json, case);

    // Build resource value.
    let resource_value = regorus::Value::from_json_str(&serde_json::to_string(&resource_json)?)?;

    // Input envelope.
    let mut input = regorus::Value::new_object();
    let map = input.as_object_mut()?;
    map.insert(regorus::Value::from("resource"), resource_value);
    map.insert(regorus::Value::from("parameters"), params_value);

    // Inject parentResource into input envelope (normalised).
    if let Some(ref env) = case.environment {
        if let Some(ref pr_str) = env.parent_resource {
            if let Ok(pr_json) = json_lenient(pr_str.trim()) {
                let pr_norm = if let Some(reg) = alias_registry {
                    normalizer::normalize(&pr_json, Some(reg), None)
                } else {
                    normalizer::normalize(&pr_json, None, None)
                };
                let pr_value = regorus::Value::from_json_str(&serde_json::to_string(&pr_norm)?)?;
                map.insert(regorus::Value::from("parentResource"), pr_value);
            }
        }
    }

    // Context.
    let utc_now = {
        use std::time::SystemTime;
        let d = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = d.as_secs();
        // Compute date components from epoch seconds.
        let days = secs / 86400;
        let time_of_day = secs % 86400;
        let (year, month, day) = epoch_days_to_date(days);
        let hour = time_of_day / 3600;
        let minute = (time_of_day % 3600) / 60;
        let second = time_of_day % 60;
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.0000000Z")
    };
    let mut ctx: serde_json::Value = serde_json::json!({
        "resourceGroup": { "name": "testRG", "location": "eastus" },
        "subscription": { "subscriptionId": "00000000-0000-0000-0000-000000000000" },
        "utcNow": utc_now
    });
    if let Some(ref env) = case.environment {
        if let Some(ref rg_str) = env.resource_group {
            if let Ok(rg) = json_lenient(rg_str.trim()) {
                ctx["resourceGroup"] = rg;
            }
        }
    }
    // Inject requestContext from the resource's apiVersion.
    if let Some(api_ver) = raw_resource.get("apiVersion").and_then(|v| v.as_str()) {
        ctx["requestContext"] = serde_json::json!({ "apiVersion": api_ver });
    }
    let ctx_value = regorus::Value::from_json_str(&serde_json::to_string(&ctx)?)?;

    let mut vm = RegoVM::new();
    vm.load_program(Arc::clone(program));
    vm.set_input(input);
    vm.set_context(ctx_value);

    // Host-await for AINE/DINE: inject related resource or null fallback.
    // When the test provides a relatedResource, normalise it and inject it.
    // Otherwise inject `null` so that AINE/DINE programs get a "resource not
    // found" answer instead of a fatal HostAwait-missing-response error.
    {
        let mut responses: BTreeMap<regorus::Value, Vec<regorus::Value>> = BTreeMap::new();

        let rr_str = case
            .environment
            .as_ref()
            .and_then(|env| env.related_resource.as_deref());

        let rr_value = if let Some(rr_str) = rr_str {
            if let Ok(rr_json) = json_lenient(rr_str.trim()) {
                let rr_norm = if let Some(reg) = alias_registry {
                    let rr_with_type = if let Some(ref dt) = details_type {
                        inject_type(&rr_json, dt)
                    } else {
                        rr_json
                    };
                    normalizer::normalize(&rr_with_type, Some(reg), None)
                } else {
                    normalizer::normalize(&rr_json, None, None)
                };
                regorus::Value::from_json_str(&serde_json::to_string(&rr_norm)?)?
            } else {
                regorus::Value::Null
            }
        } else {
            // No relatedResource → null means "resource not found".
            regorus::Value::Null
        };

        responses
            .entry(regorus::Value::from("azure.policy.existence_check"))
            .or_default()
            .push(rr_value);
        vm.set_host_await_responses(responses);
    }

    Ok(vm.execute_entry_point_by_name("main")?)
}

/// Evaluate a DenyAction request against the compiled program.
///
/// DenyAction policies evaluate whether an ARM request (e.g. DELETE) should be
/// blocked.  The `if` condition is evaluated just like normal policies, but the
/// context is enriched with identity claims (`requestContext().identity`) and
/// policy token claims (`claims()`).
fn eval_deny_action_case(
    program: &Arc<regorus::rvm::Program>,
    raw_resource: &serde_json::Value,
    identity_claims: &serde_json::Value,
    token_claims: Option<&serde_json::Value>,
    case: &format::TestCase,
    alias_registry: Option<&AliasRegistry>,
    policy_json: &serde_json::Value,
) -> Result<regorus::Value> {
    // Normalize the existing resource exactly like normal eval_case.
    let is_arm_resource = raw_resource
        .as_object()
        .and_then(|obj| obj.iter().find(|(k, _)| k.eq_ignore_ascii_case("type")))
        .and_then(|(_, v)| v.as_str())
        .map(|t| t.contains('/'))
        .unwrap_or(false);

    let resource_json = if is_arm_resource {
        if let Some(reg) = alias_registry {
            let api_ver = raw_resource
                .as_object()
                .and_then(|obj| {
                    obj.iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("apiVersion"))
                })
                .and_then(|(_, v)| v.as_str())
                .map(String::from);
            normalizer::normalize(raw_resource, Some(reg), api_ver.as_deref())
        } else {
            normalizer::normalize(raw_resource, None, None)
        }
    } else {
        lowercase_keys_deep(raw_resource)
    };

    let resource_json = inject_full_name(resource_json, case);

    // Build parameters.
    let params = {
        let mut p = case
            .parameters
            .clone()
            .unwrap_or_else(|| serde_json::json!({}));
        coerce_test_parameters(&mut p, policy_json);
        serde_json::to_string(&p).unwrap()
    };
    let params_value = regorus::Value::from_json_str(&params)?;

    // Build resource value.
    let resource_value = regorus::Value::from_json_str(&serde_json::to_string(&resource_json)?)?;

    // Input envelope.
    let mut input = regorus::Value::new_object();
    let map = input.as_object_mut()?;
    map.insert(regorus::Value::from("resource"), resource_value);
    map.insert(regorus::Value::from("parameters"), params_value);

    // Build context with identity and token claims.
    let mut ctx: serde_json::Value = serde_json::json!({
        "resourceGroup": { "name": "testRG", "location": "eastus" },
        "subscription": { "subscriptionId": "00000000-0000-0000-0000-000000000000" },
        "requestContext": {
            "apiVersion": raw_resource.get("apiVersion").and_then(|v| v.as_str()).unwrap_or(""),
            "identity": identity_claims
        }
    });

    // Inject claims() — the policy token claims from the RP validation.
    if let Some(tc) = token_claims {
        ctx["claims"] = tc.clone();
    }

    let ctx_value = regorus::Value::from_json_str(&serde_json::to_string(&ctx)?)?;

    let mut vm = RegoVM::new();
    vm.load_program(Arc::clone(program));
    vm.set_input(input);
    vm.set_context(ctx_value);

    Ok(vm.execute_entry_point_by_name("main")?)
}

/// Check that the evaluation result matches the expected outcome.
fn check_expected(
    result: &regorus::Value,
    expected: &format::Expected,
    label: &str,
    ri: usize,
) -> Result<(), String> {
    let Some(state) = expected.state() else {
        // No expected state → nothing to check.
        return Ok(());
    };

    let is_compliant =
        state.eq_ignore_ascii_case("Compliant") || state.eq_ignore_ascii_case("NotApplicable");
    let is_noncompliant =
        state.eq_ignore_ascii_case("NonCompliant") || state.eq_ignore_ascii_case("Protected");

    if is_compliant {
        if *result != regorus::Value::Undefined {
            return Err(format!(
                "{label} [resource {ri}]: expected {state} (Undefined) but got {result}"
            ));
        }
    } else if is_noncompliant {
        if *result == regorus::Value::Undefined {
            return Err(format!(
                "{label} [resource {ri}]: expected {state} but got Undefined"
            ));
        }

        // Optionally check the effect name.
        if let Some(ref expected_effect) = expected.effect {
            let actual = extract_effect(result);
            if !actual.eq_ignore_ascii_case(expected_effect) {
                return Err(format!(
                    "{label} [resource {ri}]: expected effect '{expected_effect}' but got '{actual}'"
                ));
            }
        }
    }
    // Other states (e.g., "Protected" for DenyAction) — basic pass.

    Ok(())
}

/// Extract the effect name from a VM result value.
fn extract_effect(value: &regorus::Value) -> String {
    if let Ok(obj) = value.as_object() {
        if let Some(e) = obj.get(&regorus::Value::from("effect")) {
            if let Ok(s) = e.as_string() {
                return s.to_string();
            }
        }
    }
    if let Ok(s) = value.as_string() {
        return s.to_string();
    }
    String::new()
}

/// Inject a `type` field into a JSON object (for normalizer resource-type lookup).
fn inject_type(json: &serde_json::Value, resource_type: &str) -> serde_json::Value {
    if let Some(obj) = json.as_object() {
        let mut obj = obj.clone();
        obj.entry("type")
            .or_insert_with(|| serde_json::Value::String(resource_type.to_string()));
        serde_json::Value::Object(obj)
    } else {
        json.clone()
    }
}

/// Compute `fullName` from a resource ID and inject it into the (normalised)
/// resource JSON.
///
/// `fullName` is a virtual field in Azure Policy that represents the resource's
/// name segments relative to its provider.  For example:
///
/// - `.../providers/Microsoft.Rp/parentTypes/parent/childTypes/child` → `parent/child`
/// - `.../resourcegroups/myRg/providers/Microsoft.Rp/types/myRes` → `myRes`
/// - `.../subscriptions/sub-id/resourcegroups/rgName` → `sub-id/rgName`
/// - Extension resource: `.../providers/Microsoft.Ext/types/res` → `res`
///
/// For data-plane resources with a `parentResource`, `fullName` is derived from
/// the parent resource's name + the child resource's `name` field (or the last
/// name segment of the child `id`).
fn inject_full_name(
    mut resource_json: serde_json::Value,
    case: &format::TestCase,
) -> serde_json::Value {
    // Avoid overwriting if the resource already provides fullName.
    if resource_json
        .as_object()
        .map(|o| o.contains_key("fullname"))
        .unwrap_or(false)
    {
        return resource_json;
    }

    let full_name = compute_full_name(&resource_json, case);
    if let Some(name) = full_name {
        if let Some(obj) = resource_json.as_object_mut() {
            // Insert under lowercase key so it matches the normalizer output.
            obj.insert("fullname".to_string(), serde_json::Value::String(name));
        }
    }
    resource_json
}

/// Compute fullName from the resource `id`, with optional `parentResource`
/// context.
fn compute_full_name(resource_json: &serde_json::Value, case: &format::TestCase) -> Option<String> {
    let id = resource_json
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if id.is_empty() {
        // Try parent-based derivation for data-plane resources.
        return compute_full_name_from_parent(resource_json, case);
    }

    // Parse the resource ID into segments.
    let segments: Vec<&str> = id.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return None;
    }

    // Find the LAST "providers" segment.
    let last_provider_idx = segments
        .iter()
        .rposition(|s| s.eq_ignore_ascii_case("providers"));

    if let Some(pi) = last_provider_idx {
        // After "providers" we have: providerNamespace, type1, name1[, type2, name2, ...]
        let after = &segments[pi + 1..]; // skip "providers"
        if after.len() < 3 {
            // Provider + type + name minimum
            return None;
        }
        // Skip the provider namespace (e.g., "Microsoft.Compute"), then names
        // are at odd indices (1, 3, 5, ...).
        let type_name_pairs = &after[1..]; // skip provider namespace
        let names: Vec<&str> = type_name_pairs
            .iter()
            .enumerate()
            .filter(|(i, _)| i % 2 == 1)
            .map(|(_, s)| *s)
            .collect();
        if names.is_empty() {
            return None;
        }
        Some(names.join("/"))
    } else {
        // No "providers" segment — subscription-level resource.
        // e.g., /subscriptions/sub-id/resourcegroups/rgName → sub-id/rgName
        // Collect all "name" segments (odd indices in the id: sub-id, rgName, etc.)
        let names: Vec<&str> = segments
            .iter()
            .enumerate()
            .filter(|(i, _)| i % 2 == 1)
            .map(|(_, s)| *s)
            .collect();
        if names.is_empty() {
            return None;
        }
        Some(names.join("/"))
    }
}

/// Compute fullName from `parentResource` + child `name` for data-plane
/// resources that may lack a full ARM `id`.
fn compute_full_name_from_parent(
    resource_json: &serde_json::Value,
    case: &format::TestCase,
) -> Option<String> {
    let parent_str = case
        .environment
        .as_ref()
        .and_then(|e| e.parent_resource.as_ref())?;
    let parent_json = json_lenient(parent_str.trim()).ok()?;
    let parent_id = parent_json.get("id").and_then(|v| v.as_str())?;

    // Extract the parent's name from its id (last name segment after provider).
    let parent_segments: Vec<&str> = parent_id.split('/').filter(|s| !s.is_empty()).collect();
    let last_provider_idx = parent_segments
        .iter()
        .rposition(|s| s.eq_ignore_ascii_case("providers"))?;
    let after = &parent_segments[last_provider_idx + 1..];
    if after.len() < 3 {
        return None;
    }
    let parent_names: Vec<&str> = after[1..]
        .iter()
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, s)| *s)
        .collect();
    let parent_name = parent_names.last()?;

    // Get child name from the resource's `name` field.
    let child_name = resource_json.get("name").and_then(|v| v.as_str())?;

    Some(format!("{parent_name}/{child_name}"))
}

/// Check if a failure message matches a known failure pattern.
/// Returns the reason string if it matches, None otherwise.
fn find_known_failure(rel: &str, msg: &str) -> Option<&'static str> {
    for kf in KNOWN_FAILURES {
        if rel.contains(kf.file_contains)
            && (kf.case_contains.is_empty() || msg.contains(kf.case_contains))
        {
            return Some(kf.reason);
        }
    }
    None
}

/// Record a case-level failure in stats and optionally print it.
/// If the failure matches a known-failure pattern, it is tracked separately.
fn record_fail(stats: &mut Stats, rel: &str, msg: String, verbose: bool) {
    if let Some(reason) = find_known_failure(rel, &msg) {
        stats.known_failure_count += 1;
        stats
            .known_failure_msgs
            .push(format!("{msg}  [known: {reason}]"));
        if verbose {
            eprintln!("  KNOWN-FAIL {msg}  ({reason})");
        }
    } else {
        if verbose {
            eprintln!("  FAIL {msg}");
        }
        stats.failures.push(msg);
        stats.fail += 1;
    }
}

/// Record a file-level error (YAML parse, missing file, etc.).
///
/// These are tracked separately from case-level failures so that
/// `pass + fail + skip == cases` remains an invariant.
fn record_file_error(stats: &mut Stats, rel: &str, msg: String, verbose: bool) {
    if let Some(reason) = find_known_failure(rel, &msg) {
        stats.known_failure_count += 1;
        stats
            .known_failure_msgs
            .push(format!("{msg}  [known: {reason}]"));
        if verbose {
            eprintln!("  KNOWN-FAIL {msg}  ({reason})");
        }
    } else {
        if verbose {
            eprintln!("  FAIL {msg}");
        }
        stats.failures.push(msg);
        stats.file_errors += 1;
    }
}

/// Convert epoch days (days since 1970-01-01) to (year, month, day).
fn epoch_days_to_date(mut days: u64) -> (u64, u64, u64) {
    // Civil calendar algorithm.
    days += 719_468; // shift epoch to 0000-03-01
    let era = days / 146_097;
    let doe = days % 146_097; // day of era
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Lenient JSON parser that strips trailing commas before `}` and `]`,
/// and also strips a leading UTF-8 BOM if present.
fn json_lenient(s: &str) -> Result<serde_json::Value> {
    // Strip leading BOM (common in Windows-created files).
    let s = s.strip_prefix('\u{feff}').unwrap_or(s);

    // Try strict first.
    if let Ok(v) = serde_json::from_str(s) {
        return Ok(v);
    }

    // Strip trailing commas.
    let mut cleaned = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    let mut i = 0;
    while i < len {
        if chars[i] == ',' {
            let mut j = i + 1;
            while j < len && chars[j].is_whitespace() {
                j += 1;
            }
            if j < len && (chars[j] == '}' || chars[j] == ']') {
                i += 1;
                continue;
            }
        }
        cleaned.push(chars[i]);
        i += 1;
    }
    Ok(serde_json::from_str(&cleaned)?)
}

/// Coerce YAML-deserialized test parameters to match the policy's declared
/// parameter types.  YAML parses unquoted `true` / `false` as booleans, but
/// some policy definitions declare those parameters as `String` with
/// `allowedValues` like `["Yes","No"]`.  This function converts boolean
/// values to the matching allowed-value string.
fn coerce_test_parameters(params: &mut serde_json::Value, policy_json: &serde_json::Value) {
    let params_obj = match params.as_object_mut() {
        Some(o) => o,
        None => return,
    };

    // Locate the policy's parameter definitions.
    let defs = policy_json
        .pointer("/properties/parameters")
        .or_else(|| policy_json.pointer("/parameters"));
    let defs = match defs.and_then(|v| v.as_object()) {
        Some(d) => d,
        None => return,
    };

    for (key, value) in params_obj.iter_mut() {
        let is_bool = value.is_boolean();
        if !is_bool {
            continue;
        }
        let b = value.as_bool().unwrap();

        // Find the matching policy parameter definition (case-insensitive).
        let def = defs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v);
        let def = match def {
            Some(d) => d,
            None => continue,
        };

        // Only coerce when the policy declares it as a String type.
        let ptype = def.get("type").and_then(|v| v.as_str()).unwrap_or_default();
        if !ptype.eq_ignore_ascii_case("string") {
            continue;
        }

        // If there are allowedValues, pick the one matching the boolean.
        if let Some(allowed) = def.get("allowedValues").and_then(|v| v.as_array()) {
            let yes_no: Vec<&str> = allowed.iter().filter_map(|v| v.as_str()).collect();
            // Match common patterns: "Yes"/"No", "Enabled"/"Disabled", etc.
            let replacement = if b {
                yes_no
                    .iter()
                    .find(|s| {
                        s.eq_ignore_ascii_case("yes")
                            || s.eq_ignore_ascii_case("true")
                            || s.eq_ignore_ascii_case("enabled")
                    })
                    .copied()
            } else {
                yes_no
                    .iter()
                    .find(|s| {
                        s.eq_ignore_ascii_case("no")
                            || s.eq_ignore_ascii_case("false")
                            || s.eq_ignore_ascii_case("disabled")
                    })
                    .copied()
            };
            if let Some(s) = replacement {
                *value = serde_json::Value::String(s.to_string());
            } else {
                // Fallback: stringify the boolean.
                *value = serde_json::Value::String(b.to_string());
            }
        } else {
            // No allowedValues — just stringify.
            *value = serde_json::Value::String(b.to_string());
        }
    }
}

/// Recursively lowercase all object keys in a JSON value.
/// Used for synthetic test resources that lack an ARM `type` field.
fn lowercase_keys_deep(val: &serde_json::Value) -> serde_json::Value {
    match val {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                out.insert(k.to_ascii_lowercase(), lowercase_keys_deep(v));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(lowercase_keys_deep).collect())
        }
        other => other.clone(),
    }
}

/// Parse a YAML string that may contain multiple `---`-separated documents.
///
/// `serde_yaml` 0.9 has known issues with:
///   - trailing whitespace after block scalar indicators (`> ` → `>`)
///   - missing final newline
///   - genuine multi-document YAML
///
/// This function works around all three by preprocessing the input and, if the
/// single-document parse still fails with the "more than one document" error,
/// falling back to the multi-document `Deserializer` iterator.
fn parse_yaml_test_file(yaml: &str) -> Result<format::TestFile> {
    use serde::Deserialize;

    // Strip trailing whitespace on block-scalar indicator lines and ensure a
    // final newline — both trigger false "multi-document" errors in serde_yaml.
    // Also strip a leading UTF-8 BOM which some Windows-created files carry.
    let trimmed = yaml.strip_prefix('\u{feff}').unwrap_or(yaml);
    let cleaned: String = trimmed
        .lines()
        .map(|line| line.trim_end())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";

    // Fast path: single-document.
    match serde_yaml::from_str::<format::TestFile>(&cleaned) {
        Ok(t) => return Ok(t),
        Err(e) => {
            let msg = e.to_string();
            if !msg.contains("more than one document") {
                return Err(anyhow::anyhow!("{e}"));
            }
            // Fall through to multi-document parsing.
        }
    }

    // Multi-document fallback: prepend `---` if absent so the iterator
    // recognises the first document boundary.
    let prefixed = if cleaned.starts_with("---") {
        cleaned
    } else {
        format!("---\n{cleaned}")
    };

    let mut merged: Option<format::TestFile> = None;

    for document in serde_yaml::Deserializer::from_str(&prefixed) {
        let doc = format::TestFile::deserialize(document).map_err(|e| anyhow::anyhow!("{e}"))?;

        match merged.as_mut() {
            None => {
                merged = Some(doc);
            }
            Some(base) => {
                if doc.title.is_some() {
                    base.title = doc.title;
                }
                if doc.policy.is_some() {
                    base.policy = doc.policy;
                }
                base.tests.extend(doc.tests);
            }
        }
    }

    merged.ok_or_else(|| anyhow::anyhow!("YAML file contains no documents"))
}
