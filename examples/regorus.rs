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
        },
    }
}
