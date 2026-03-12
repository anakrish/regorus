// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use anyhow::{anyhow, bail, Result};

use regorus::rvm::analysis::{
    generate_input_for_goal, generate_test_suite, policy_diff, policy_subsumes, AnalysisConfig,
    AnalysisGoal,
};

pub fn rego_analyze(
    bundles: &[String],
    files: &[String],
    entrypoint: String,
    output: Option<String>,
    cover_lines: Vec<String>,
    avoid_lines: Vec<String>,
    dump_smt: Option<String>,
    dump_model: Option<String>,
    timeout: u32,
    max_loops: usize,
    input_file: Option<String>,
    schema_file: Option<String>,
    azure_aliases_file: Option<String>,
    model_fetch: Option<String>,
) -> Result<()> {
    let (program, data, cedar_entities) =
        compile_policy_set(bundles, files, &entrypoint, azure_aliases_file.as_ref())?;

    // Parse the expected output value (if given).
    let desired_value: Option<regorus::Value> = match &output {
        Some(json_str) => Some(
            regorus::Value::from_json_str(json_str)
                .map_err(|e| anyhow!("invalid JSON for --output: {e}"))?,
        ),
        None => None,
    };

    // Parse file:line pairs for --cover-line.
    let mut cover: Vec<(String, usize)> = Vec::new();
    for spec in &cover_lines {
        let parts: Vec<&str> = spec.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            bail!("Invalid --cover-line format: '{spec}'. Expected FILE:LINE");
        }
        let line: usize = parts[0]
            .parse()
            .map_err(|_| anyhow!("Invalid line number in '{spec}'"))?;
        let file_name = parts[1].to_string();
        cover.push((file_name, line));
    }

    // Parse file:line pairs for --avoid-line.
    let mut avoid: Vec<(String, usize)> = Vec::new();
    for spec in &avoid_lines {
        let parts: Vec<&str> = spec.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            bail!("Invalid --avoid-line format: '{spec}'. Expected FILE:LINE");
        }
        let line: usize = parts[0]
            .parse()
            .map_err(|_| anyhow!("Invalid line number in '{spec}'"))?;
        let file_name = parts[1].to_string();
        avoid.push((file_name, line));
    }

    let has_lines = !cover.is_empty() || !avoid.is_empty();

    // Build the goal.
    let goal = match (desired_value, has_lines) {
        (Some(v), true) => AnalysisGoal::OutputAndCoverLines {
            expected: v,
            cover,
            avoid,
        },
        (Some(v), false) => AnalysisGoal::ExpectedOutput(v),
        (None, true) => AnalysisGoal::CoverLines { cover, avoid },
        (None, false) => {
            // No output, no lines — find any input that triggers a
            // non-default result.  This handles object-valued rules
            // (e.g. `deny := {"result": true, ...}`) where comparing
            // against `Bool(true)` would always be UNSAT.
            AnalysisGoal::NonDefault
        }
    };

    // Load example input for type seeding (if provided).
    let example_input: Option<regorus::Value> = match &input_file {
        Some(path) => {
            let contents = std::fs::read_to_string(path)
                .map_err(|e| anyhow!("Failed to read input file '{}': {}", path, e))?;
            Some(
                regorus::Value::from_json_str(&contents)
                    .map_err(|e| anyhow!("Failed to parse input file '{}': {}", path, e))?,
            )
        }
        None => None,
    };

    // Load JSON Schema for input constraints (if provided).
    let input_schema: Option<serde_json::Value> = match &schema_file {
        Some(path) => {
            let contents = std::fs::read_to_string(path)
                .map_err(|e| anyhow!("Failed to read schema file '{}': {}", path, e))?;
            Some(
                serde_json::from_str(&contents)
                    .map_err(|e| anyhow!("Failed to parse schema file '{}': {}", path, e))?,
            )
        }
        None => None,
    };

    let mut concrete_input = std::collections::HashMap::new();
    if let Some(entities) = cedar_entities {
        concrete_input.insert("entities".to_string(), entities);
    }

    let config = AnalysisConfig {
        max_loop_depth: max_loops,
        max_rule_depth: 3,
        timeout_ms: timeout,
        dump_smt: dump_smt.is_some(),
        dump_model: dump_model.is_some(),
        example_input,
        input_schema,
        concrete_input,
        fetch_input_path: model_fetch,
    };

    let result = generate_input_for_goal(&program, &data, &entrypoint, &goal, &config)?;

    // Write SMT to file if requested.
    if let (Some(ref path), Some(ref smt)) = (&dump_smt, &result.solver_smt) {
        std::fs::write(path, smt)
            .map_err(|e| anyhow!("Failed to write SMT to '{}': {}", path, e))?;
        eprintln!("SMT assertions written to {path}");
    }

    // Write Z3 model to file if requested.
    if let (Some(ref path), Some(ref model)) = (&dump_model, &result.model_string) {
        std::fs::write(path, model)
            .map_err(|e| anyhow!("Failed to write model to '{}': {}", path, e))?;
        eprintln!("Z3 model written to {path}");
    }

    // Output result as JSON to stdout.
    let output_obj = serde_json::json!({
        "satisfiable": result.satisfiable,
        "input": result.input.map(|v| {
            // Convert regorus::Value to serde_json::Value for pretty printing.
            serde_json::from_str::<serde_json::Value>(
                &v.to_json_str().unwrap_or_else(|_| "null".to_string())
            ).unwrap_or(serde_json::Value::Null)
        }),
        "warnings": result.warnings,
    });
    println!("{}", serde_json::to_string_pretty(&output_obj)?);

    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: compile a set of policy/data files into a Program + data Value.
// ---------------------------------------------------------------------------
fn compile_policy_set(
    bundles: &[String],
    files: &[String],
    entrypoint: &str,
    azure_aliases_file: Option<&String>,
) -> Result<(
    regorus::Rc<regorus::rvm::program::Program>,
    regorus::Value,
    Option<regorus::Value>,
)> {
    let mut engine = regorus::Engine::new();
    let mut cedar_sources: Vec<(String, String)> = Vec::new();
    let mut azure_sources: Vec<(String, String)> = Vec::new();
    let mut cedar_entities: Option<regorus::Value> = None;
    let mut rego_sources_present = false;

    for dir in bundles.iter() {
        let entries =
            std::fs::read_dir(dir).or_else(|e| bail!("failed to read bundle {dir}.\n{e}"))?;
        for entry in entries {
            let entry = entry.or_else(|e| bail!("failed to unwrap entry. {e}"))?;
            let path = entry.path();
            match (path.is_file(), path.extension()) {
                (true, Some(ext)) if ext == "rego" => {}
                _ => continue,
            }
            super::add_policy_from_file(&mut engine, entry.path().display().to_string())?;
            rego_sources_present = true;
        }
    }

    for file in files.iter() {
        if file.ends_with(".rego") {
            super::add_policy_from_file(&mut engine, file.clone())?;
            rego_sources_present = true;
        } else if file.ends_with(".cedar") {
            let contents = std::fs::read_to_string(file)
                .map_err(|e| anyhow!("Failed to read Cedar file '{}': {}", file, e))?;
            cedar_sources.push((file.clone(), contents));
        } else if file.ends_with(".json") {
            let raw = std::fs::read_to_string(file)
                .map_err(|e| anyhow!("Failed to read JSON file '{}': {}", file, e))?;
            if looks_like_azure_policy_definition(&raw) {
                azure_sources.push((file.clone(), raw));
            } else {
                let d = regorus::Value::from_json_str(&raw)
                    .map_err(|e| anyhow!("Failed to parse JSON file '{}': {}", file, e))?;
                if !cedar_sources.is_empty() {
                    cedar_entities = Some(d);
                } else {
                    engine.add_data(d)?;
                }
            }
        } else if file.ends_with(".yaml") {
            let d = super::read_value_from_yaml_file(file)?;
            engine.add_data(d)?;
        } else {
            bail!("Unsupported data file `{file}`. Must be rego, cedar, json or yaml.");
        }
    }

    if !azure_sources.is_empty() && (!cedar_sources.is_empty() || rego_sources_present) {
        bail!(
            "Cannot mix Azure Policy definitions with Rego/Cedar sources in the same command"
        );
    }

    let is_cedar = !cedar_sources.is_empty();
    let is_azure = !azure_sources.is_empty();
    let program = if is_azure {
        if azure_sources.len() != 1 {
            bail!("Exactly one Azure Policy definition JSON file is supported per command");
        }
        let aliases = azure_aliases_file
            .ok_or_else(|| anyhow!("Azure Policy input requires --azure-aliases <aliases.json>"))?;
        let (path, contents) = azure_sources.into_iter().next().unwrap();
        compile_azure_policy_to_program(&path, &contents, aliases)?
    } else if is_cedar {
        regorus::Rc::new(compile_cedar_to_program(&cedar_sources)?)
    } else {
        let ep: regorus::Rc<str> = regorus::Rc::from(entrypoint);
        let compiled = engine.compile_with_entrypoint(&ep)?;
        regorus::languages::rego::compiler::Compiler::compile_from_policy(&compiled, &[entrypoint])?
    };

    let data = engine.get_data();
    Ok((program, data, cedar_entities))
}

fn looks_like_azure_policy_definition(raw_json: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw_json) else {
        return false;
    };
    if v.get("policyRule").is_some() {
        return true;
    }
    v.get("properties")
        .and_then(|p| p.get("policyRule"))
        .is_some()
}

// ---------------------------------------------------------------------------
// Common helpers for loading inputs, schemas, and building AnalysisConfig.
// ---------------------------------------------------------------------------

fn load_example_input(input_file: &Option<String>) -> Result<Option<regorus::Value>> {
    match input_file {
        Some(path) => {
            let contents = std::fs::read_to_string(path)
                .map_err(|e| anyhow!("Failed to read input file '{}': {}", path, e))?;
            Ok(Some(regorus::Value::from_json_str(&contents).map_err(
                |e| anyhow!("Failed to parse input file '{}': {}", path, e),
            )?))
        }
        None => Ok(None),
    }
}

fn load_schema(schema_file: &Option<String>) -> Result<Option<serde_json::Value>> {
    match schema_file {
        Some(path) => {
            let contents = std::fs::read_to_string(path)
                .map_err(|e| anyhow!("Failed to read schema file '{}': {}", path, e))?;
            Ok(Some(serde_json::from_str(&contents).map_err(|e| {
                anyhow!("Failed to parse schema file '{}': {}", path, e)
            })?))
        }
        None => Ok(None),
    }
}

fn parse_desired_output(output: &Option<String>) -> Result<Option<regorus::Value>> {
    match output {
        Some(json_str) => Ok(Some(
            regorus::Value::from_json_str(json_str)
                .map_err(|e| anyhow!("invalid JSON for --output: {e}"))?,
        )),
        None => Ok(None),
    }
}

fn regorus_value_to_json(v: &regorus::Value) -> serde_json::Value {
    serde_json::from_str::<serde_json::Value>(
        &v.to_json_str().unwrap_or_else(|_| "null".to_string()),
    )
    .unwrap_or(serde_json::Value::Null)
}

// ===========================================================================
// Policy Diff
// ===========================================================================

#[allow(clippy::too_many_arguments)]
pub fn rego_diff(
    bundles1: &[String],
    policy1_files: &[String],
    bundles2: &[String],
    policy2_files: &[String],
    entrypoint: String,
    output: Option<String>,
    dump_smt: Option<String>,
    dump_model: Option<String>,
    timeout: u32,
    max_loops: usize,
    input_file: Option<String>,
    schema_file: Option<String>,
    azure_aliases_file: Option<String>,
) -> Result<()> {
    let (program1, data1, cedar_entities1) =
        compile_policy_set(bundles1, policy1_files, &entrypoint, azure_aliases_file.as_ref())?;
    let (program2, _data2, cedar_entities2) =
        compile_policy_set(bundles2, policy2_files, &entrypoint, azure_aliases_file.as_ref())?;

    let example_input = load_example_input(&input_file)?;
    let input_schema = load_schema(&schema_file)?;
    let desired_value = parse_desired_output(&output)?;

    let mut concrete_input = std::collections::HashMap::new();
    // If either policy set has Cedar entities, inject them.
    if let Some(entities) = cedar_entities1.or(cedar_entities2) {
        concrete_input.insert("entities".to_string(), entities);
    }

    let config = AnalysisConfig {
        max_loop_depth: max_loops,
        max_rule_depth: 3,
        timeout_ms: timeout,
        dump_smt: dump_smt.is_some(),
        dump_model: dump_model.is_some(),
        example_input,
        input_schema,
        concrete_input,
        fetch_input_path: None,
    };

    let result = policy_diff(
        &program1,
        &program2,
        &data1,
        &entrypoint,
        desired_value.as_ref(),
        &config,
    )?;

    // Write SMT/model files if requested.
    if let (Some(ref path), Some(ref smt)) = (&dump_smt, &result.solver_smt) {
        std::fs::write(path, smt)
            .map_err(|e| anyhow!("Failed to write SMT to '{}': {}", path, e))?;
        eprintln!("SMT assertions written to {path}");
    }
    if let (Some(ref path), Some(ref model)) = (&dump_model, &result.model_string) {
        std::fs::write(path, model)
            .map_err(|e| anyhow!("Failed to write model to '{}': {}", path, e))?;
        eprintln!("Z3 model written to {path}");
    }

    let output_obj = serde_json::json!({
        "equivalent": result.equivalent,
        "distinguishing_input": result.distinguishing_input.map(|v| regorus_value_to_json(&v)),
        "policy1_output": result.output_policy1,
        "policy2_output": result.output_policy2,
        "warnings": result.warnings,
    });
    println!("{}", serde_json::to_string_pretty(&output_obj)?);

    Ok(())
}

// ===========================================================================
// Policy Subsumption
// ===========================================================================

#[allow(clippy::too_many_arguments)]
pub fn rego_subsumes(
    old_files: &[String],
    new_files: &[String],
    entrypoint: String,
    output: Option<String>,
    dump_smt: Option<String>,
    dump_model: Option<String>,
    timeout: u32,
    max_loops: usize,
    input_file: Option<String>,
    schema_file: Option<String>,
    azure_aliases_file: Option<String>,
) -> Result<()> {
    let (old_program, data, cedar_entities_old) =
        compile_policy_set(&[], old_files, &entrypoint, azure_aliases_file.as_ref())?;
    let (new_program, _data2, cedar_entities_new) =
        compile_policy_set(&[], new_files, &entrypoint, azure_aliases_file.as_ref())?;

    let example_input = load_example_input(&input_file)?;
    let input_schema = load_schema(&schema_file)?;
    let desired_value = parse_desired_output(&output)?.unwrap_or(regorus::Value::Bool(true));

    let mut concrete_input = std::collections::HashMap::new();
    if let Some(entities) = cedar_entities_old.or(cedar_entities_new) {
        concrete_input.insert("entities".to_string(), entities);
    }

    let config = AnalysisConfig {
        max_loop_depth: max_loops,
        max_rule_depth: 3,
        timeout_ms: timeout,
        dump_smt: dump_smt.is_some(),
        dump_model: dump_model.is_some(),
        example_input,
        input_schema,
        concrete_input,
        fetch_input_path: None,
    };

    let result = policy_subsumes(
        &old_program,
        &new_program,
        &data,
        &entrypoint,
        &desired_value,
        &config,
    )?;

    if let (Some(ref path), Some(ref smt)) = (&dump_smt, &result.solver_smt) {
        std::fs::write(path, smt)
            .map_err(|e| anyhow!("Failed to write SMT to '{}': {}", path, e))?;
        eprintln!("SMT assertions written to {path}");
    }
    if let (Some(ref path), Some(ref model)) = (&dump_model, &result.model_string) {
        std::fs::write(path, model)
            .map_err(|e| anyhow!("Failed to write model to '{}': {}", path, e))?;
        eprintln!("Z3 model written to {path}");
    }

    let output_obj = serde_json::json!({
        "subsumes": result.subsumes,
        "counterexample": result.counterexample.map(|v| regorus_value_to_json(&v)),
        "warnings": result.warnings,
    });
    println!("{}", serde_json::to_string_pretty(&output_obj)?);

    Ok(())
}

// ===========================================================================
// Test Suite Generation
// ===========================================================================

#[allow(clippy::too_many_arguments)]
pub fn rego_gen_tests(
    bundles: &[String],
    files: &[String],
    entrypoint: String,
    output: Option<String>,
    dump_smt: Option<String>,
    timeout: u32,
    max_loops: usize,
    max_tests: usize,
    input_file: Option<String>,
    schema_file: Option<String>,
    azure_aliases_file: Option<String>,
    model_fetch: Option<String>,
    condition_coverage: bool,
    format: &str,
) -> Result<()> {
    let (program, data, cedar_entities) =
        compile_policy_set(bundles, files, &entrypoint, azure_aliases_file.as_ref())?;

    let example_input = load_example_input(&input_file)?;
    let input_schema = load_schema(&schema_file)?;
    let desired_value = parse_desired_output(&output)?;

    let mut concrete_input = std::collections::HashMap::new();
    if let Some(entities) = cedar_entities {
        concrete_input.insert("entities".to_string(), entities);
    }

    let config = AnalysisConfig {
        max_loop_depth: max_loops,
        max_rule_depth: 3,
        timeout_ms: timeout,
        dump_smt: dump_smt.is_some(),
        dump_model: false,
        example_input,
        input_schema,
        concrete_input,
        fetch_input_path: model_fetch,
    };

    let result = generate_test_suite(
        &program,
        &data,
        &entrypoint,
        desired_value.as_ref(),
        &config,
        max_tests,
        condition_coverage,
    )?;

    if let (Some(ref path), Some(ref smt)) = (&dump_smt, &result.solver_smt) {
        std::fs::write(path, smt)
            .map_err(|e| anyhow!("Failed to write SMT to '{}': {}", path, e))?;
        eprintln!("SMT assertions written to {path}");
    }

    // Build a cache of source-file lines for annotated output and text fields.
    // Key: filename, Value: Vec of lines (0-indexed).
    let source_cache = build_source_cache(&result);

    // Helper: look up source text for a "file:line" location string.
    // Note: span.line is 1-based (line 0 is a special "default" sentinel).
    let source_text = |loc: &str| -> String {
        if let Some(idx) = loc.rfind(':') {
            let file = &loc[..idx];
            if let Ok(line_no) = loc[idx + 1..].parse::<usize>() {
                if let Some(lines) = source_cache.get(file) {
                    if line_no > 0 && line_no <= lines.len() {
                        return lines[line_no - 1].trim().to_string();
                    }
                }
            }
        }
        String::new()
    };

    match format {
        "annotated" => print_annotated_output(&result, &source_cache)?,
        _ => print_json_output(&result, &source_text)?,
    }

    Ok(())
}

/// Build a cache mapping filenames to their source lines.
fn build_source_cache(
    result: &regorus::rvm::analysis::TestSuiteResult,
) -> std::collections::HashMap<String, Vec<String>> {
    let mut files_needed: std::collections::HashSet<String> = std::collections::HashSet::new();
    for tc in &result.test_cases {
        for (f, _) in &tc.covered_lines {
            files_needed.insert(f.clone());
        }
        for (loc, _) in &tc.condition_coverage {
            if let Some(idx) = loc.rfind(':') {
                files_needed.insert(loc[..idx].to_string());
            }
        }
    }
    let mut cache = std::collections::HashMap::new();
    for file in &files_needed {
        if let Ok(contents) = std::fs::read_to_string(file) {
            let lines: Vec<String> = contents.lines().map(|l| l.to_string()).collect();
            cache.insert(file.clone(), lines);
        }
    }
    cache
}

/// Print JSON format output (default).
fn print_json_output(
    result: &regorus::rvm::analysis::TestSuiteResult,
    source_text: &dyn Fn(&str) -> String,
) -> Result<()> {
    let test_cases_json: Vec<serde_json::Value> = result
        .test_cases
        .iter()
        .map(|tc| {
            let lines: Vec<serde_json::Value> = tc
                .covered_lines
                .iter()
                .map(|(f, l)| {
                    let loc = format!("{}:{}", f, l);
                    let text = source_text(&loc);
                    let mut entry = serde_json::json!({ "location": loc });
                    if !text.is_empty() {
                        entry["text"] = serde_json::json!(text);
                    }
                    entry
                })
                .collect();
            let cond_cov: Vec<serde_json::Value> = tc
                .condition_coverage
                .iter()
                .map(|(loc, val)| {
                    let text = source_text(loc);
                    let mut entry = serde_json::json!({
                        "location": loc,
                        "value": val,
                    });
                    if !text.is_empty() {
                        entry["text"] = serde_json::json!(text);
                    }
                    entry
                })
                .collect();
            let mut obj = serde_json::json!({
                "input": regorus_value_to_json(&tc.input),
                "covered_lines": lines,
            });
            if !cond_cov.is_empty() {
                obj["condition_coverage"] = serde_json::json!(cond_cov);
            }
            obj
        })
        .collect();

    let coverage_pct = if result.coverable_lines > 0 {
        (result.covered_lines as f64 / result.coverable_lines as f64) * 100.0
    } else {
        0.0
    };

    let mut coverage_summary = serde_json::json!({
        "coverable_lines": result.coverable_lines,
        "covered_lines": result.covered_lines,
        "coverage_pct": format!("{:.1}%", coverage_pct),
    });
    if result.condition_goals > 0 {
        coverage_summary["condition_goals"] = serde_json::json!(result.condition_goals);
        coverage_summary["condition_goals_covered"] =
            serde_json::json!(result.condition_goals_covered);
        let cond_pct = (result.condition_goals_covered as f64
            / result.condition_goals as f64)
            * 100.0;
        coverage_summary["condition_coverage_pct"] =
            serde_json::json!(format!("{:.1}%", cond_pct));
    }

    let output_obj = serde_json::json!({
        "test_cases": test_cases_json,
        "coverage_summary": coverage_summary,
        "warnings": result.warnings,
    });
    println!("{}", serde_json::to_string_pretty(&output_obj)?);

    Ok(())
}

/// Print annotated source listing with per-test condition coverage markers.
///
/// For each test case, prints the full policy source with annotations:
///   - Lines covered by that test get a `+` marker
///   - Lines with a condition-coverage goal show `[T]` or `[F]`
///   - Uncovered lines are shown without a marker
fn print_annotated_output(
    result: &regorus::rvm::analysis::TestSuiteResult,
    source_cache: &std::collections::HashMap<String, Vec<String>>,
) -> Result<()> {
    // Collect all source files referenced, in deterministic order.
    let mut all_files: Vec<&String> = source_cache.keys().collect();
    all_files.sort();

    // Build set of all known condition lines across all tests.
    // A line is a "condition line" if it appears in any test's condition_coverage.
    let mut all_condition_lines: std::collections::HashSet<(String, usize)> =
        std::collections::HashSet::new();
    for tc in &result.test_cases {
        for (loc, _) in &tc.condition_coverage {
            if let Some(idx) = loc.rfind(':') {
                let file = loc[..idx].to_string();
                if let Ok(line_no) = loc[idx + 1..].parse::<usize>() {
                    all_condition_lines.insert((file, line_no));
                }
            }
        }
    }

    // Print summary header.
    let coverage_pct = if result.coverable_lines > 0 {
        (result.covered_lines as f64 / result.coverable_lines as f64) * 100.0
    } else {
        0.0
    };
    println!(
        "# Coverage: {}/{} lines ({:.1}%)",
        result.covered_lines, result.coverable_lines, coverage_pct
    );
    if result.condition_goals > 0 {
        let cond_pct = (result.condition_goals_covered as f64
            / result.condition_goals as f64)
            * 100.0;
        println!(
            "# Conditions: {}/{} goals ({:.1}%)",
            result.condition_goals_covered, result.condition_goals, cond_pct
        );
    }
    println!("# Tests: {}", result.test_cases.len());
    println!();

    for (ti, tc) in result.test_cases.iter().enumerate() {
        // Build sets for quick lookup.
        let covered: std::collections::HashSet<(String, usize)> =
            tc.covered_lines.iter().cloned().collect();
        let cond_map: std::collections::HashMap<(String, usize), bool> = tc
            .condition_coverage
            .iter()
            .filter_map(|(loc, val)| {
                if let Some(idx) = loc.rfind(':') {
                    let file = loc[..idx].to_string();
                    if let Ok(line_no) = loc[idx + 1..].parse::<usize>() {
                        return Some(((file, line_no), *val));
                    }
                }
                None
            })
            .collect();

        // Determine what makes this test special.
        let false_conds: Vec<_> = tc
            .condition_coverage
            .iter()
            .filter(|(_, v)| !v)
            .collect();
        let test_label = if false_conds.is_empty() {
            "line coverage".to_string()
        } else {
            false_conds
                .iter()
                .map(|(loc, _)| format!("{} = false", loc))
                .collect::<Vec<_>>()
                .join(", ")
        };

        println!("== Test {} ({}) ==", ti + 1, test_label);
        println!("Input: {}", regorus_value_to_json(&tc.input));
        println!();

        for file in &all_files {
            if let Some(lines) = source_cache.get(*file) {
                for (i, line) in lines.iter().enumerate() {
                    let line_no = i + 1; // 1-based, matching span.line
                    let key = (file.to_string(), line_no);

                    let marker = if let Some(val) = cond_map.get(&key) {
                        // Explicit condition coverage entry for this test.
                        if *val { "true " } else { "false" }
                    } else if all_condition_lines.contains(&key) && covered.contains(&key) {
                        // This is a condition line and was covered (assertion
                        // passed), so the condition was true.
                        "true "
                    } else {
                        "     "
                    };

                    println!(
                        "{} {:>4} | {}",
                        marker,
                        line_no,
                        line,
                    );
                }
            }
        }
        println!();
    }

    if !result.warnings.is_empty() {
        println!("# Warnings:");
        for w in &result.warnings {
            println!("#   {}", w);
        }
    }

    Ok(())
}

#[cfg(feature = "cedar")]
fn compile_cedar_to_program(
    sources: &[(String, String)],
) -> Result<regorus::rvm::program::Program> {
    use regorus::languages::cedar::{compiler, parser::Parser as CedarParser};

    let mut all_policies = Vec::new();
    for (path, contents) in sources {
        let source = regorus::Source::from_contents(path.clone(), contents.clone())
            .map_err(|e| anyhow!("Failed to create source for '{}': {}", path, e))?;
        let mut parser = CedarParser::new(&source)
            .map_err(|e| anyhow!("Failed to parse Cedar file '{}': {}", path, e))?;
        let policies = parser
            .parse()
            .map_err(|e| anyhow!("Failed to parse Cedar file '{}': {}", path, e))?;
        all_policies.extend(policies);
    }
    let program = compiler::compile_to_program(&all_policies)
        .map_err(|e| anyhow!("Failed to compile Cedar policies: {}", e))?;
    Ok(program)
}

#[cfg(feature = "azure_policy")]
fn compile_azure_policy_to_program(
    path: &str,
    contents: &str,
    aliases_file: &str,
) -> Result<regorus::Rc<regorus::rvm::program::Program>> {
    use regorus::languages::azure_policy::{aliases::AliasRegistry, compiler, parser};

    let aliases_json = std::fs::read_to_string(aliases_file)
        .map_err(|e| anyhow!("Failed to read Azure aliases file '{}': {}", aliases_file, e))?;
    let mut registry = AliasRegistry::new();
    registry
        .load_from_json(&aliases_json)
        .map_err(|e| anyhow!("Failed to parse Azure aliases file '{}': {}", aliases_file, e))?;
    let alias_map = registry.alias_map();

    let source = regorus::Source::from_contents(path.to_string(), contents.to_string())
        .map_err(|e| anyhow!("Failed to create source for '{}': {}", path, e))?;

    if let Ok(defn) = parser::parse_policy_definition(&source) {
        return compiler::compile_policy_definition_with_aliases(&defn, alias_map)
            .map_err(|e| anyhow!("Failed to compile Azure Policy definition '{}': {}", path, e));
    }

    let rule = parser::parse_policy_rule(&source)
        .map_err(|e| anyhow!("Failed to parse Azure Policy '{}': {}", path, e))?;
    compiler::compile_policy_rule_with_aliases(&rule, alias_map)
        .map_err(|e| anyhow!("Failed to compile Azure Policy rule '{}': {}", path, e))
}

#[cfg(not(feature = "azure_policy"))]
fn compile_azure_policy_to_program(
    _path: &str,
    _contents: &str,
    _aliases_file: &str,
) -> Result<regorus::Rc<regorus::rvm::program::Program>> {
    bail!("Azure Policy support requires the `azure_policy` feature")
}

#[cfg(not(feature = "cedar"))]
fn compile_cedar_to_program(
    _sources: &[(String, String)],
) -> Result<regorus::rvm::program::Program> {
    bail!("Cedar support requires the `cedar` feature");
}
