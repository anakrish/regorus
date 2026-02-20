// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use anyhow::{anyhow, bail, Result};

use regorus::rvm::analysis::{generate_input_for_goal, AnalysisConfig, AnalysisGoal};

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
