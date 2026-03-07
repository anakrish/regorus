// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use anyhow::{anyhow, bail, Result};
use std::sync::Arc;

#[allow(dead_code)]
fn read_file(path: &String) -> Result<String> {
    std::fs::read_to_string(path).map_err(|_| anyhow!("could not read {path}"))
}

#[allow(unused_variables)]
fn read_value_from_yaml_file(path: &String) -> Result<regorus::Value> {
    #[cfg(feature = "yaml")]
    return regorus::Value::from_yaml_file(path);

    #[cfg(not(feature = "yaml"))]
    bail!("regorus has not been built with yaml support");
}

fn read_value_from_json_file(path: &String) -> Result<regorus::Value> {
    #[cfg(feature = "std")]
    return regorus::Value::from_json_file(path);

    #[cfg(not(feature = "std"))]
    regorus::Value::from_json_str(&read_file(path)?)
}

fn add_policy_from_file(engine: &mut regorus::Engine, path: String) -> Result<String> {
    #[cfg(feature = "std")]
    return engine.add_policy_from_file(path);

    #[cfg(not(feature = "std"))]
    engine.add_policy(path.clone(), read_file(&path)?)
}

#[allow(clippy::too_many_arguments)]
fn rego_eval(
    bundles: &[String],
    files: &[String],
    input: Option<String>,
    query: String,
    enable_tracing: bool,
    non_strict: bool,
    #[cfg(feature = "coverage")] coverage: bool,
    v0: bool,
) -> Result<()> {
    // Create engine.
    let mut engine = regorus::Engine::new();

    engine.set_strict_builtin_errors(!non_strict);

    #[cfg(feature = "coverage")]
    engine.set_enable_coverage(coverage);

    engine.set_rego_v0(v0);

    // Load files from given bundles.
    for dir in bundles.iter() {
        let entries =
            std::fs::read_dir(dir).or_else(|e| bail!("failed to read bundle {dir}.\n{e}"))?;
        // Loop through each entry in the bundle folder.
        for entry in entries {
            let entry = entry.or_else(|e| bail!("failed to unwrap entry. {e}"))?;
            let path = entry.path();

            // Process only .rego files.
            match (path.is_file(), path.extension()) {
                (true, Some(ext)) if ext == "rego" => {}
                _ => continue,
            }

            let _package = add_policy_from_file(&mut engine, entry.path().display().to_string())?;
        }
    }

    // Load given files.
    for file in files.iter() {
        if file.ends_with(".rego") {
            // Read policy file.
            let _package = add_policy_from_file(&mut engine, file.clone())?;
        } else {
            // Read data file.
            let data = if file.ends_with(".json") {
                read_value_from_json_file(file)?
            } else if file.ends_with(".yaml") {
                read_value_from_yaml_file(file)?
            } else {
                bail!("Unsupported data file `{file}`. Must be rego, json or yaml.");
            };

            // Merge given data.
            engine.add_data(data)?;
        }
    }

    if let Some(file) = input {
        let input = if file.ends_with(".json") {
            read_value_from_json_file(&file)?
        } else if file.ends_with(".yaml") {
            read_value_from_yaml_file(&file)?
        } else {
            bail!("Unsupported input file `{file}`. Must be json or yaml.")
        };
        engine.set_input(input);
    }

    // Note: The `eval_query` function is used below since it produces output
    // in the same format as OPA. It also allows evaluating arbitrary statements
    // as queries.
    //
    // Most applications will want to use `eval_rule` instead.
    // It is faster since it does not have to parse the query string.
    // It also returns the value of the rule directly and thus is easier
    // to use.
    let results = engine.eval_query(query, enable_tracing)?;

    println!("{}", serde_json::to_string_pretty(&results)?);

    #[cfg(feature = "coverage")]
    if coverage {
        let report = engine.get_coverage_report()?;
        println!("{}", report.to_string_pretty()?);
    }

    Ok(())
}

fn rego_lex(file: String, verbose: bool) -> Result<()> {
    use regorus::unstable::*;

    // Create source.
    #[cfg(feature = "std")]
    let source = Source::from_file(file)?;

    #[cfg(not(feature = "std"))]
    let source = Source::from_contents(file.clone(), read_file(&file)?)?;

    // Create lexer.
    let mut lexer = Lexer::new(&source);

    // Read tokens until EOF.
    loop {
        let token = lexer.next_token()?;
        if token.0 == TokenKind::Eof {
            break;
        }

        if verbose {
            // Print each token's line and mark with with ^.
            println!("{}", token.1.message("", ""));
        }

        // Print the token.
        println!("{token:?}");
    }
    Ok(())
}

fn rego_parse(file: String, v0: bool) -> Result<()> {
    use regorus::unstable::*;

    // Create source.
    #[cfg(feature = "std")]
    let source = Source::from_file(file)?;

    #[cfg(not(feature = "std"))]
    let source = Source::from_contents(file.clone(), read_file(&file)?)?;

    // Create a parser and parse the source.
    let mut parser = Parser::new(&source)?;

    if !v0 {
        parser.enable_rego_v1()?;
    }

    let ast = parser.parse()?;
    println!("{ast:#?}");

    Ok(())
}

#[allow(unused_variables)]
fn rego_ast(file: String) -> Result<()> {
    #[cfg(feature = "ast")]
    {
        // Create engine.
        let mut engine = regorus::Engine::new();

        // Create source.
        #[cfg(feature = "std")]
        engine.add_policy_from_file(file)?;

        #[cfg(not(feature = "std"))]
        engine.add_policy(file.clone(), read_file(&file)?)?;

        let ast = engine.get_ast_as_json()?;

        println!("{ast}");
        Ok(())
    }

    #[cfg(not(feature = "ast"))]
    {
        bail!("`ast` feature must be enabled");
    }
}

#[derive(clap::Subcommand)]
enum RegorusCommand {
    /// Parse a Rego policy and dump AST.
    Ast {
        /// Rego policy file.
        file: String,
    },

    /// Evaluate a Rego Query.
    Eval {
        /// Directories containing Rego files.
        #[arg(long, short, value_name = "bundle")]
        bundles: Vec<String>,

        /// Policy or data files. Rego, json or yaml.
        #[arg(long, short, value_name = "policy.rego|data.json|data.yaml")]
        data: Vec<String>,

        /// Input file. json or yaml.
        #[arg(long, short, value_name = "input.rego")]
        input: Option<String>,

        /// Query. Rego query block.
        query: String,

        /// Enable tracing.
        #[arg(long, short)]
        trace: bool,

        /// Perform non-strict evaluation. (default behavior of OPA).
        #[arg(long, short)]
        non_strict: bool,

        /// Display coverage information
        #[cfg(feature = "coverage")]
        #[arg(long, short)]
        coverage: bool,

        /// Turn on Rego language v0.
        #[arg(long)]
        v0: bool,
    },

    /// Tokenize a Rego policy.
    Lex {
        /// Rego policy file.
        file: String,

        /// Verbose output.
        #[arg(long, short)]
        verbose: bool,
    },

    /// Parse a Rego policy.
    Parse {
        /// Rego policy file.
        file: String,

        /// Turn on Rego language v0.
        #[arg(long)]
        v0: bool,
    },

    /// Azure Policy operations: compile, evaluate, disassemble.
    #[cfg(feature = "azure_policy")]
    #[command(name = "azure-policy")]
    AzurePolicy {
        #[command(subcommand)]
        command: AzurePolicyCommand,
    },
}

/// Azure Policy subcommands.
#[cfg(feature = "azure_policy")]
#[derive(clap::Subcommand)]
enum AzurePolicyCommand {
    /// Compile a policy definition and dump the RVM program as JSON.
    Compile {
        /// Policy definition JSON file.
        file: String,

        /// Alias catalog JSON file (Get-AzPolicyAlias format).
        #[arg(long, short)]
        aliases: Option<String>,
    },

    /// Compile a policy definition and dump assembly listing.
    Disasm {
        /// Policy definition JSON file.
        file: String,

        /// Alias catalog JSON file.
        #[arg(long, short)]
        aliases: Option<String>,

        /// Show instruction addresses.
        #[arg(long, default_value_t = true)]
        addresses: bool,

        /// Show instruction byte encoding.
        #[arg(long)]
        bytes: bool,
    },

    /// Compile and evaluate a policy against a resource.
    Eval {
        /// Policy definition JSON file.
        file: String,

        /// Input file (JSON or YAML) with structure:
        /// `{ "resource": {...}, "parameters": {...}, "context": {...} }`.
        /// Or a bare resource JSON/YAML object.
        #[arg(long, short)]
        input: Option<String>,

        /// Alias catalog JSON file.
        #[arg(long, short)]
        aliases: Option<String>,

        /// Resource type for alias lookup and normalization
        /// (e.g., "Microsoft.Compute/virtualMachines").
        /// When omitted the normalizer extracts the type from the
        /// resource's "type" field.
        #[arg(long, short = 't')]
        resource_type: Option<String>,
    },

    /// Parse a policy definition and dump the AST.
    Parse {
        /// Policy definition JSON file.
        file: String,
    },

    /// Run an external Azure Policy test suite (YAML format).
    #[command(name = "test-suite")]
    TestSuite {
        /// Root folder containing `*.Test.yaml` files (searched recursively).
        folder: String,

        /// Alias catalog JSON file.
        #[arg(long, short)]
        aliases: Option<String>,

        /// Only run test files whose path contains this substring.
        #[arg(long, short)]
        filter: Option<String>,

        /// Print verbose per-case output.
        #[arg(long, short)]
        verbose: bool,
    },
}

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: RegorusCommand,
}

// ── Azure Policy helpers ──────────────────────────────────────────────────

#[cfg(feature = "azure_policy")]
fn az_load_aliases(
    path: Option<&str>,
) -> Result<Option<regorus::languages::azure_policy::aliases::AliasRegistry>> {
    let Some(path) = path else { return Ok(None) };
    let json = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("could not read alias catalog {path}: {e}"))?;
    let mut registry = regorus::languages::azure_policy::aliases::AliasRegistry::new();
    registry.load_from_json(&json)?;
    eprintln!("Loaded {} resource type(s) from {path}", registry.len());
    Ok(Some(registry))
}

#[cfg(feature = "azure_policy")]
fn az_compile(
    file: &str,
    aliases: Option<&str>,
) -> Result<(
    regorus::Rc<regorus::rvm::Program>,
    Option<regorus::languages::azure_policy::aliases::AliasRegistry>,
)> {
    use regorus::languages::azure_policy::{compiler, parser};

    let source_text =
        std::fs::read_to_string(file).map_err(|e| anyhow!("could not read {file}: {e}"))?;
    let source = regorus::Source::from_contents(file.to_string(), source_text)?;

    let defn = parser::parse_policy_definition(&source).map_err(|e| anyhow!("parse error: {e}"))?;

    let registry = az_load_aliases(aliases)?;

    let program = if let Some(ref reg) = registry {
        compiler::compile_policy_definition_with_aliases(
            &defn,
            reg.alias_map(),
            reg.alias_modifiable_map(),
        )?
    } else {
        compiler::compile_policy_definition(&defn)?
    };

    Ok((program, registry))
}

#[cfg(feature = "azure_policy")]
fn az_policy_compile(file: String, aliases: Option<String>) -> Result<()> {
    let (program, _) = az_compile(&file, aliases.as_deref())?;
    let json = program.serialize_json().map_err(|e| anyhow!("{e}"))?;
    println!("{json}");
    Ok(())
}

#[cfg(feature = "azure_policy")]
fn az_policy_disasm(
    file: String,
    aliases: Option<String>,
    addresses: bool,
    bytes: bool,
) -> Result<()> {
    use regorus::rvm::{generate_assembly_listing, AssemblyListingConfig};

    let (program, _) = az_compile(&file, aliases.as_deref())?;

    let config = AssemblyListingConfig {
        show_addresses: addresses,
        show_bytes: bytes,
        ..AssemblyListingConfig::default()
    };

    let listing = generate_assembly_listing(&program, &config);
    println!("{listing}");
    Ok(())
}

#[cfg(feature = "azure_policy")]
fn az_policy_eval(
    file: String,
    input: Option<String>,
    aliases: Option<String>,
    resource_type: Option<String>,
) -> Result<()> {
    use regorus::languages::azure_policy::aliases::normalizer;
    use regorus::rvm::RegoVM;

    let (program, registry) = az_compile(&file, aliases.as_deref())?;

    // Build input value.
    let input_value = if let Some(ref input_path) = input {
        let raw: serde_json::Value = {
            let text = std::fs::read_to_string(input_path)
                .map_err(|e| anyhow!("could not read {input_path}: {e}"))?;
            if input_path.ends_with(".yaml") || input_path.ends_with(".yml") {
                serde_yaml::from_str(&text)?
            } else {
                serde_json::from_str(&text)?
            }
        };

        // When --resource-type is given, inject it into the resource so the
        // normalizer can look up the right aliases.
        let raw = if let Some(ref rt) = resource_type {
            let mut r = raw.clone();
            if r.is_object() {
                if let Some(res) = r.get_mut("resource") {
                    res["type"] = serde_json::Value::String(rt.clone());
                } else {
                    r["type"] = serde_json::Value::String(rt.clone());
                }
            }
            r
        } else {
            raw
        };

        // Determine if the input already has the envelope structure
        // { "resource": {...}, ... } or is a bare resource object.
        let envelope = if raw.is_object() && raw.get("resource").is_some() {
            // Already an envelope — normalize the resource inside it.
            let mut env = raw;
            if let Some(ref reg) = registry {
                if let Some(resource) = env.get("resource") {
                    let api_version = env
                        .get("resource")
                        .and_then(|r| r.get("apiVersion"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let normalized =
                        normalizer::normalize(resource, Some(reg), api_version.as_deref());
                    env["resource"] = normalized;
                }
            }
            env
        } else {
            // Bare resource — normalize and wrap.
            if let Some(ref reg) = registry {
                reg.normalize_and_wrap(&raw, None, None, None)
            } else {
                normalizer::build_input_envelope(raw, None, None)
            }
        };

        regorus::Value::from_json_str(&serde_json::to_string(&envelope)?)?
    } else {
        // No input — empty envelope.
        regorus::Value::from_json_str(r#"{"resource":{},"parameters":{},"context":{}}"#)?
    };

    // Build a default context if not in the input.
    let context_value = {
        let ctx_json = if let Some(ref input_path) = input {
            let text = std::fs::read_to_string(input_path)?;
            let raw: serde_json::Value =
                if input_path.ends_with(".yaml") || input_path.ends_with(".yml") {
                    serde_yaml::from_str(&text)?
                } else {
                    serde_json::from_str(&text)?
                };
            if let Some(ctx) = raw.get("context") {
                serde_json::to_string(ctx)?
            } else {
                r#"{"resourceGroup":{"name":"default","location":"eastus"},"subscription":{"subscriptionId":"00000000-0000-0000-0000-000000000000"}}"#.to_string()
            }
        } else {
            r#"{"resourceGroup":{"name":"default","location":"eastus"},"subscription":{"subscriptionId":"00000000-0000-0000-0000-000000000000"}}"#.to_string()
        };
        regorus::Value::from_json_str(&ctx_json)?
    };

    // Execute.
    let mut vm = RegoVM::new();
    vm.load_program(Arc::clone(&program));
    vm.set_input(input_value);
    vm.set_context(context_value);

    let result = vm.execute()?;

    // Pretty-print the result.
    let json_str = serde_json::to_string_pretty(&serde_json::from_str::<serde_json::Value>(
        &result.to_json_str()?,
    )?)?;
    println!("{json_str}");

    Ok(())
}

#[cfg(feature = "azure_policy")]
fn az_policy_parse(file: String) -> Result<()> {
    use regorus::languages::azure_policy::parser;

    let source_text =
        std::fs::read_to_string(&file).map_err(|e| anyhow!("could not read {file}: {e}"))?;
    let source = regorus::Source::from_contents(file.to_string(), source_text)?;

    let defn = parser::parse_policy_definition(&source).map_err(|e| anyhow!("parse error: {e}"))?;

    println!("{defn:#?}");
    Ok(())
}

// ── External test-suite runner ────────────────────────────────────────────

/// YAML schema for the external Azure Policy test suite (`*.Test.yaml`).
#[cfg(feature = "azure_policy")]
mod ext_test {
    use serde::Deserialize;

    #[derive(Deserialize, Debug)]
    #[allow(dead_code)]
    pub struct TestFile {
        #[serde(default)]
        pub title: Option<String>,

        /// Path to a policy definition JSON file (relative to the YAML file, may use `\`).
        #[serde(default)]
        pub policy: Option<String>,

        #[serde(default)]
        pub tests: Vec<TestCase>,
    }

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    pub struct TestCase {
        pub name: String,

        #[serde(default)]
        pub parameters: Option<serde_json::Value>,

        /// Inline policy rule (used in `csharp-converted` tests).
        #[serde(default)]
        pub policy_rule: Option<serde_json::Value>,

        pub expected: Expected,

        #[serde(default)]
        pub resources: Vec<String>,

        #[serde(default)]
        pub environment: Option<Environment>,

        /// DenyAction-style tests use `requests` instead of `resources`.
        #[serde(default)]
        pub requests: Vec<serde_json::Value>,
    }

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    #[allow(dead_code)]
    pub struct Expected {
        #[serde(default)]
        pub compliance_state: Option<String>,

        /// Legacy alias for `complianceState`.
        #[serde(default)]
        pub outcome: Option<String>,

        #[serde(default)]
        pub effect: Option<String>,

        #[serde(default)]
        pub fields: Vec<FieldExpectation>,

        #[serde(default)]
        pub deployment: Vec<serde_json::Value>,
    }

    #[derive(Deserialize, Debug)]
    #[allow(dead_code)]
    pub struct FieldExpectation {
        pub path: String,
        pub value: serde_json::Value,
    }

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "camelCase")]
    pub struct Environment {
        #[serde(default)]
        pub related_resource: Option<String>,

        #[serde(default)]
        pub resource_group: Option<String>,
    }

    impl Expected {
        /// Normalised compliance state string.
        pub fn state(&self) -> Option<&str> {
            self.compliance_state.as_deref().or(self.outcome.as_deref())
        }
    }
}

#[cfg(feature = "azure_policy")]
fn az_policy_test_suite(
    folder: String,
    aliases: Option<String>,
    filter: Option<String>,
    verbose: bool,
) -> Result<()> {
    use regorus::languages::azure_policy::aliases::normalizer;
    use regorus::languages::azure_policy::{compiler, parser};
    use regorus::rvm::RegoVM;
    use std::collections::BTreeMap;
    use std::path::Path;

    // Optionally load a shared alias catalog.
    let alias_registry = az_load_aliases(aliases.as_deref())?;

    // Recursively find all *.Test.yaml files.
    let mut test_files = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.ends_with(".Test.yaml") {
                    out.push(path);
                }
            }
        }
    }
    walk(Path::new(&folder), &mut test_files);
    test_files.sort();

    if test_files.is_empty() {
        bail!("No *.Test.yaml files found under {folder}");
    }

    println!("Found {} test file(s) under {}", test_files.len(), folder);

    let mut total_files = 0usize;
    let mut total_cases = 0usize;
    let mut total_pass = 0usize;
    let mut total_fail = 0usize;
    let mut total_skip = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for test_path in &test_files {
        let rel = test_path
            .strip_prefix(&folder)
            .unwrap_or(test_path)
            .display()
            .to_string();

        if let Some(ref f) = filter {
            if !rel.contains(f.as_str()) {
                continue;
            }
        }
        total_files += 1;

        let yaml_str = match std::fs::read_to_string(test_path) {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("{rel}: cannot read file: {e}");
                eprintln!("SKIP {msg}");
                failures.push(msg);
                total_fail += 1;
                continue;
            }
        };

        let test_file: ext_test::TestFile = match serde_yaml::from_str(&yaml_str) {
            Ok(t) => t,
            Err(e) => {
                let msg = format!("{rel}: YAML parse error: {e}");
                eprintln!("SKIP {msg}");
                failures.push(msg);
                total_fail += 1;
                continue;
            }
        };

        if verbose {
            println!("\n── {} ({} tests) ──", rel, test_file.tests.len());
        }

        // Load the file-level policy definition (if any).
        let file_policy_json: Option<serde_json::Value> =
            if let Some(ref pol_path) = test_file.policy {
                // Resolve path relative to the YAML file.  Windows backslashes → forward.
                let resolved = pol_path.replace('\\', "/");
                let base = test_path.parent().unwrap_or_else(|| Path::new("."));
                let policy_path = base.join(&resolved);
                match std::fs::read_to_string(&policy_path) {
                    Ok(text) => match serde_json::from_str(&text) {
                        Ok(v) => Some(v),
                        Err(e) => {
                            // Try stripping trailing commas (common in test JSON).
                            match serde_json_lenient(&text) {
                                Ok(v) => Some(v),
                                Err(_) => {
                                    let msg = format!(
                                        "{rel}: policy JSON parse error ({}): {e}",
                                        policy_path.display()
                                    );
                                    eprintln!("SKIP {msg}");
                                    failures.push(msg);
                                    total_fail += 1;
                                    continue;
                                }
                            }
                        }
                    },
                    Err(e) => {
                        let msg = format!(
                            "{rel}: cannot read policy file {}: {e}",
                            policy_path.display()
                        );
                        eprintln!("SKIP {msg}");
                        failures.push(msg);
                        total_fail += 1;
                        continue;
                    }
                }
            } else {
                None
            };

        for case in &test_file.tests {
            total_cases += 1;
            let label = format!("{rel} / {}", case.name);

            // Skip DenyAction tests (different evaluation model).
            if !case.requests.is_empty() {
                if verbose {
                    println!("  SKIP (DenyAction) {}", case.name);
                }
                total_skip += 1;
                continue;
            }

            // Determine the policy definition JSON for this case.
            let policy_json = if let Some(ref inline_rule) = case.policy_rule {
                // Inline policyRule in the test case → wrap in a minimal definition.
                serde_json::json!({
                    "properties": {
                        "policyRule": inline_rule,
                        "mode": "All"
                    }
                })
            } else if let Some(ref file_json) = file_policy_json {
                file_json.clone()
            } else {
                if verbose {
                    println!("  SKIP (no policy) {}", case.name);
                }
                total_skip += 1;
                continue;
            };

            // Parse the policy definition.
            let policy_text = serde_json::to_string(&policy_json).unwrap();
            let source = match regorus::Source::from_contents(label.clone(), policy_text) {
                Ok(s) => s,
                Err(e) => {
                    let msg = format!("{label}: source error: {e}");
                    if verbose {
                        eprintln!("  FAIL {msg}");
                    }
                    failures.push(msg);
                    total_fail += 1;
                    continue;
                }
            };

            let defn = match parser::parse_policy_definition(&source) {
                Ok(d) => d,
                Err(e) => {
                    let msg = format!("{label}: parse error: {e}");
                    if verbose {
                        eprintln!("  FAIL {msg}");
                    }
                    failures.push(msg);
                    total_fail += 1;
                    continue;
                }
            };

            // Compile.
            let program = if let Some(ref reg) = alias_registry {
                match compiler::compile_policy_definition_with_aliases(
                    &defn,
                    reg.alias_map(),
                    reg.alias_modifiable_map(),
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        let msg = format!("{label}: compile error: {e}");
                        if verbose {
                            eprintln!("  FAIL {msg}");
                        }
                        failures.push(msg);
                        total_fail += 1;
                        continue;
                    }
                }
            } else {
                match compiler::compile_policy_definition(&defn) {
                    Ok(p) => p,
                    Err(e) => {
                        let msg = format!("{label}: compile error: {e}");
                        if verbose {
                            eprintln!("  FAIL {msg}");
                        }
                        failures.push(msg);
                        total_fail += 1;
                        continue;
                    }
                }
            };

            // Extract details.type for AINE/DINE host-await normalization.
            let details_type = policy_json
                .pointer("/properties/policyRule/then/details/type")
                .or_else(|| policy_json.pointer("/then/details/type"))
                .and_then(|v| v.as_str())
                .map(String::from);

            // If no resources provided, evaluate once with empty resource.
            let resources: Vec<serde_json::Value> = if case.resources.is_empty() {
                vec![serde_json::json!({})]
            } else {
                case.resources
                    .iter()
                    .filter_map(|s| {
                        serde_json_lenient(s.trim())
                            .or_else(|_| serde_json::from_str(s.trim()))
                            .ok()
                    })
                    .collect()
            };

            if resources.is_empty() && !case.resources.is_empty() {
                let msg = format!("{label}: all resource JSON blocks failed to parse");
                if verbose {
                    eprintln!("  FAIL {msg}");
                }
                failures.push(msg);
                total_fail += 1;
                continue;
            }

            // Evaluate each resource and check the result.
            let mut case_passed = true;
            for (ri, raw_resource) in resources.iter().enumerate() {
                // Normalize the resource.
                let resource_json = if let Some(ref reg) = alias_registry {
                    let api_ver = raw_resource
                        .get("apiVersion")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    normalizer::normalize(raw_resource, Some(reg), api_ver.as_deref())
                } else {
                    normalizer::normalize(raw_resource, None, None)
                };

                // Build parameters.
                let params = case
                    .parameters
                    .as_ref()
                    .map(|p| serde_json::to_string(p).unwrap())
                    .unwrap_or_else(|| "{}".to_string());
                let params_value = regorus::Value::from_json_str(&params)?;

                // Build resource value.
                let resource_value =
                    regorus::Value::from_json_str(&serde_json::to_string(&resource_json)?)?;

                // Input envelope.
                let mut input = regorus::Value::new_object();
                let map = input.as_object_mut()?;
                map.insert(regorus::Value::from("resource"), resource_value);
                map.insert(regorus::Value::from("parameters"), params_value);

                // Context (resourceGroup, subscription, requestContext).
                let mut ctx: serde_json::Value = serde_json::json!({
                    "resourceGroup": { "name": "testRG", "location": "eastus" },
                    "subscription": { "subscriptionId": "00000000-0000-0000-0000-000000000000" }
                });
                if let Some(ref env) = case.environment {
                    if let Some(ref rg_str) = env.resource_group {
                        if let Ok(rg) = serde_json_lenient(rg_str.trim()) {
                            ctx["resourceGroup"] = rg;
                        }
                    }
                }
                // Inject requestContext from resource apiVersion.
                if let Some(api_ver) = raw_resource.get("apiVersion").and_then(|v| v.as_str()) {
                    ctx["requestContext"] = serde_json::json!({ "apiVersion": api_ver });
                }
                let ctx_value = regorus::Value::from_json_str(&serde_json::to_string(&ctx)?)?;

                let mut vm = RegoVM::new();
                vm.load_program(Arc::clone(&program));
                vm.set_input(input);
                vm.set_context(ctx_value);

                // Host-await for AINE/DINE: related resource.
                if let Some(ref env) = case.environment {
                    if let Some(ref rr_str) = env.related_resource {
                        if let Ok(rr_json) = serde_json_lenient(rr_str.trim()) {
                            // Normalize related resource.
                            let rr_norm = if let Some(ref reg) = alias_registry {
                                let rr_with_type = if let Some(ref dt) = details_type {
                                    let mut rr = rr_json.clone();
                                    if rr.is_object() {
                                        rr.as_object_mut().unwrap().entry("type").or_insert_with(
                                            || serde_json::Value::String(dt.clone()),
                                        );
                                    }
                                    rr
                                } else {
                                    rr_json
                                };
                                normalizer::normalize(&rr_with_type, Some(reg), None)
                            } else {
                                normalizer::normalize(&rr_json, None, None)
                            };

                            let rr_value =
                                regorus::Value::from_json_str(&serde_json::to_string(&rr_norm)?)?;
                            let mut responses: BTreeMap<regorus::Value, Vec<regorus::Value>> =
                                BTreeMap::new();
                            responses
                                .entry(regorus::Value::from("azure.policy.existence_check"))
                                .or_default()
                                .push(rr_value);
                            vm.set_host_await_responses(responses);
                        }
                    }
                }

                let result = match vm.execute_entry_point_by_name("main") {
                    Ok(v) => v,
                    Err(e) => {
                        let msg = format!("{label} [resource {ri}]: execution error: {e}");
                        if verbose {
                            eprintln!("  FAIL {msg}");
                        }
                        failures.push(msg);
                        case_passed = false;
                        break;
                    }
                };

                // Check expected compliance state.
                let expected_state = case.expected.state();
                if let Some(state) = expected_state {
                    let is_compliant = state.eq_ignore_ascii_case("Compliant");
                    let is_noncompliant = state.eq_ignore_ascii_case("NonCompliant")
                        || state.eq_ignore_ascii_case("Protected");

                    if is_compliant {
                        // Compliant → the condition should NOT match (undefined).
                        if result != regorus::Value::Undefined {
                            // Some policies return the effect even when compliant
                            // via existenceCondition match.  Check if the result
                            // has effect matching the expected.
                            let effect_val = extract_effect(&result);
                            if !effect_val.is_empty() {
                                // AINE/DINE compliant: the if-condition matched
                                // but the existenceCondition was satisfied.
                                // Our compiler returns Undefined in that case,
                                // but if it doesn't, still treat as pass if
                                // the state says Compliant.
                            }
                            let msg = format!(
                                "{label} [resource {ri}]: expected Compliant (undefined) but got {}",
                                result
                            );
                            if verbose {
                                eprintln!("  FAIL {msg}");
                            }
                            failures.push(msg);
                            case_passed = false;
                            break;
                        }
                    } else if is_noncompliant {
                        // NonCompliant → the condition should match, producing an effect.
                        if result == regorus::Value::Undefined {
                            let msg = format!(
                                "{label} [resource {ri}]: expected NonCompliant but got undefined"
                            );
                            if verbose {
                                eprintln!("  FAIL {msg}");
                            }
                            failures.push(msg);
                            case_passed = false;
                            break;
                        }

                        // Optionally check the effect name.
                        if let Some(ref expected_effect) = case.expected.effect {
                            let actual = extract_effect(&result);
                            if !actual.eq_ignore_ascii_case(expected_effect) {
                                let msg = format!(
                                    "{label} [resource {ri}]: expected effect '{}' but got '{}'",
                                    expected_effect, actual
                                );
                                if verbose {
                                    eprintln!("  FAIL {msg}");
                                }
                                failures.push(msg);
                                case_passed = false;
                                break;
                            }
                        }
                    }
                    // Other states (e.g., "Protected" for DenyAction) — we only
                    // check if we got a result or not for now.
                }
            }

            if case_passed {
                total_pass += 1;
                if verbose {
                    println!("  PASS {}", case.name);
                }
            } else {
                total_fail += 1;
            }
        }
    }

    // Summary.
    println!("\n══════════════════════════════════════════════════════════");
    println!(
        "Files: {total_files}  Cases: {total_cases}  Pass: {total_pass}  Fail: {total_fail}  Skip: {total_skip}"
    );
    if !failures.is_empty() {
        println!("\nFailures ({}):", failures.len());
        for (i, f) in failures.iter().enumerate() {
            println!("  {}. {f}", i + 1);
        }
    }
    println!("══════════════════════════════════════════════════════════");

    if total_fail > 0 {
        bail!("{total_fail} test(s) failed");
    }

    Ok(())
}

/// Extract the effect name string from a VM result value.
#[cfg(feature = "azure_policy")]
fn extract_effect(value: &regorus::Value) -> String {
    if let Ok(obj) = value.as_object() {
        if let Some(e) = obj.get(&regorus::Value::from("effect")) {
            if let Ok(s) = e.as_string() {
                return s.to_string();
            }
        }
    }
    // Fallback: try to use the value as a plain string.
    if let Ok(s) = value.as_string() {
        return s.to_string();
    }
    String::new()
}

/// Lenient JSON parser that strips trailing commas before values/arrays close.
/// Many test policy JSON files have trailing commas which strict serde_json rejects.
#[cfg(feature = "azure_policy")]
fn serde_json_lenient(s: &str) -> Result<serde_json::Value> {
    // Simple approach: strip trailing commas before } and ].
    let mut cleaned = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    let mut i = 0;
    while i < len {
        if chars[i] == ',' {
            // Look ahead past whitespace for } or ].
            let mut j = i + 1;
            while j < len && chars[j].is_whitespace() {
                j += 1;
            }
            if j < len && (chars[j] == '}' || chars[j] == ']') {
                // Skip the trailing comma.
                i += 1;
                continue;
            }
        }
        cleaned.push(chars[i]);
        i += 1;
    }
    Ok(serde_json::from_str(&cleaned)?)
}

fn main() -> Result<()> {
    use clap::Parser;

    // Parse and dispatch command.
    let cli = Cli::parse();
    match cli.command {
        RegorusCommand::Eval {
            bundles,
            data,
            input,
            query,
            trace,
            non_strict,
            #[cfg(feature = "coverage")]
            coverage,
            v0,
        } => rego_eval(
            &bundles,
            &data,
            input,
            query,
            trace,
            non_strict,
            #[cfg(feature = "coverage")]
            coverage,
            v0,
        ),
        RegorusCommand::Lex { file, verbose } => rego_lex(file, verbose),
        RegorusCommand::Parse { file, v0 } => rego_parse(file, v0),
        RegorusCommand::Ast { file } => rego_ast(file),
        #[cfg(feature = "azure_policy")]
        RegorusCommand::AzurePolicy { command } => match command {
            AzurePolicyCommand::Compile { file, aliases } => az_policy_compile(file, aliases),
            AzurePolicyCommand::Disasm {
                file,
                aliases,
                addresses,
                bytes,
            } => az_policy_disasm(file, aliases, addresses, bytes),
            AzurePolicyCommand::Eval {
                file,
                input,
                aliases,
                resource_type,
            } => az_policy_eval(file, input, aliases, resource_type),
            AzurePolicyCommand::Parse { file } => az_policy_parse(file),
            AzurePolicyCommand::TestSuite {
                folder,
                aliases,
                filter,
                verbose,
            } => az_policy_test_suite(folder, aliases, filter, verbose),
        },
    }
}
