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
) -> Result<()> {
    // Create engine and load policies/data.
    let mut engine = regorus::Engine::new();
    let mut cedar_sources: Vec<(String, String)> = Vec::new();
    let mut cedar_entities: Option<regorus::Value> = None;

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
        }
    }

    for file in files.iter() {
        if file.ends_with(".rego") {
            super::add_policy_from_file(&mut engine, file.clone())?;
        } else if file.ends_with(".cedar") {
            let contents = std::fs::read_to_string(file)
                .map_err(|e| anyhow!("Failed to read Cedar file '{}': {}", file, e))?;
            cedar_sources.push((file.clone(), contents));
        } else if file.ends_with(".json") {
            let d = super::read_value_from_json_file(file)?;
            if !cedar_sources.is_empty() {
                // For Cedar policies, JSON files contain entity data.
                // Stash it to inject as concrete input.entities later.
                cedar_entities = Some(d);
            } else {
                engine.add_data(d)?;
            }
        } else if file.ends_with(".yaml") {
            let d = super::read_value_from_yaml_file(file)?;
            engine.add_data(d)?;
        } else {
            bail!("Unsupported data file `{file}`. Must be rego, cedar, json or yaml.");
        }
    }

    // Compile to RVM bytecode — Cedar or Rego path.
    let is_cedar = !cedar_sources.is_empty();
    let (program_owned, program_rc);
    let program: &regorus::rvm::program::Program = if is_cedar {
        program_owned = compile_cedar_to_program(&cedar_sources)?;
        &program_owned
    } else {
        let ep: regorus::Rc<str> = regorus::Rc::from(entrypoint.as_str());
        let compiled = engine.compile_with_entrypoint(&ep)?;
        program_rc = regorus::languages::rego::compiler::Compiler::compile_from_policy(
            &compiled,
            &[entrypoint.as_str()],
        )?;
        &program_rc
    };
    let data = engine.get_data();

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
            // No output, no lines — just check satisfiability.
            AnalysisGoal::ExpectedOutput(regorus::Value::Bool(true))
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
    if is_cedar {
        if let Some(entities) = cedar_entities {
            concrete_input.insert("entities".to_string(), entities);
        }
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
) -> Result<(
    regorus::Rc<regorus::rvm::program::Program>,
    regorus::Value,
    Option<regorus::Value>,
)> {
    let mut engine = regorus::Engine::new();
    let mut cedar_sources: Vec<(String, String)> = Vec::new();
    let mut cedar_entities: Option<regorus::Value> = None;

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
        }
    }

    for file in files.iter() {
        if file.ends_with(".rego") {
            super::add_policy_from_file(&mut engine, file.clone())?;
        } else if file.ends_with(".cedar") {
            let contents = std::fs::read_to_string(file)
                .map_err(|e| anyhow!("Failed to read Cedar file '{}': {}", file, e))?;
            cedar_sources.push((file.clone(), contents));
        } else if file.ends_with(".json") {
            let d = super::read_value_from_json_file(file)?;
            if !cedar_sources.is_empty() {
                cedar_entities = Some(d);
            } else {
                engine.add_data(d)?;
            }
        } else if file.ends_with(".yaml") {
            let d = super::read_value_from_yaml_file(file)?;
            engine.add_data(d)?;
        } else {
            bail!("Unsupported data file `{file}`. Must be rego, cedar, json or yaml.");
        }
    }

    let is_cedar = !cedar_sources.is_empty();
    let program = if is_cedar {
        regorus::Rc::new(compile_cedar_to_program(&cedar_sources)?)
    } else {
        let ep: regorus::Rc<str> = regorus::Rc::from(entrypoint);
        let compiled = engine.compile_with_entrypoint(&ep)?;
        regorus::languages::rego::compiler::Compiler::compile_from_policy(&compiled, &[entrypoint])?
    };

    let data = engine.get_data();
    Ok((program, data, cedar_entities))
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
) -> Result<()> {
    let (program1, data1, cedar_entities1) =
        compile_policy_set(bundles1, policy1_files, &entrypoint)?;
    let (program2, _data2, cedar_entities2) =
        compile_policy_set(bundles2, policy2_files, &entrypoint)?;

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
) -> Result<()> {
    let (old_program, data, cedar_entities_old) = compile_policy_set(&[], old_files, &entrypoint)?;
    let (new_program, _data2, cedar_entities_new) =
        compile_policy_set(&[], new_files, &entrypoint)?;

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
) -> Result<()> {
    let (program, data, cedar_entities) = compile_policy_set(bundles, files, &entrypoint)?;

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
    };

    let result = generate_test_suite(
        &program,
        &data,
        &entrypoint,
        desired_value.as_ref(),
        &config,
        max_tests,
    )?;

    if let (Some(ref path), Some(ref smt)) = (&dump_smt, &result.solver_smt) {
        std::fs::write(path, smt)
            .map_err(|e| anyhow!("Failed to write SMT to '{}': {}", path, e))?;
        eprintln!("SMT assertions written to {path}");
    }

    let test_cases_json: Vec<serde_json::Value> = result
        .test_cases
        .iter()
        .map(|tc| {
            let lines: Vec<String> = tc
                .covered_lines
                .iter()
                .map(|(f, l)| format!("{}:{}", f, l))
                .collect();
            serde_json::json!({
                "input": regorus_value_to_json(&tc.input),
                "covered_lines": lines,
            })
        })
        .collect();

    let coverage_pct = if result.coverable_lines > 0 {
        (result.covered_lines as f64 / result.coverable_lines as f64) * 100.0
    } else {
        0.0
    };

    let output_obj = serde_json::json!({
        "test_cases": test_cases_json,
        "coverage_summary": {
            "coverable_lines": result.coverable_lines,
            "covered_lines": result.covered_lines,
            "coverage_pct": format!("{:.1}%", coverage_pct),
        },
        "warnings": result.warnings,
    });
    println!("{}", serde_json::to_string_pretty(&output_obj)?);

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

#[cfg(not(feature = "cedar"))]
fn compile_cedar_to_program(
    _sources: &[(String, String)],
) -> Result<regorus::rvm::program::Program> {
    bail!("Cedar support requires the `cedar` feature");
}
