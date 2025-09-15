// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use anyhow::{anyhow, bail, Result};
use regorus::rvm::{
    generate_assembly_listing, generate_tabular_assembly_listing, AssemblyListingConfig, Compiler,
    RegoVM,
};

#[derive(clap::ValueEnum, Clone, Debug)]
enum EvalEngine {
    /// Use the interpreter engine.
    Interpreter,
    /// Use the RVM (Rego Virtual Machine) engine.
    Rvm,
    /// Use the VM engine (alias for RVM).
    Vm,
}

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

fn rego_compile(
    bundles: &[String],
    files: &[String],
    rule_name: String,
    tabular: bool,
    v0: bool,
) -> Result<()> {
    // Create engine.
    let mut engine = regorus::Engine::new();
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

    // Get the compiled policy from the engine
    let rule_name_rc: regorus::Rc<str> = rule_name.clone().into();
    let compiled_policy = engine.compile_with_entrypoint(&rule_name_rc)?;

    // Compile the rule to RVM bytecode
    let program = Compiler::compile_from_policy(&compiled_policy, &rule_name)?;

    // Generate assembly listing
    let config = AssemblyListingConfig::default();
    let listing = if tabular {
        generate_tabular_assembly_listing(&program, &config)
    } else {
        generate_assembly_listing(&program, &config)
    };

    println!("{}", listing);

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn rego_eval(
    bundles: &[String],
    files: &[String],
    input: Option<String>,
    query: String,
    eval_engine: EvalEngine,
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

    // Load input data if provided
    let input_data = if let Some(file) = input {
        let input = if file.ends_with(".json") {
            read_value_from_json_file(&file)?
        } else if file.ends_with(".yaml") {
            read_value_from_yaml_file(&file)?
        } else {
            bail!("Unsupported input file `{file}`. Must be json or yaml.")
        };
        engine.set_input(input.clone());
        Some(input)
    } else {
        None
    };

    // Evaluate based on the selected engine
    match eval_engine {
        EvalEngine::Interpreter => {
            // Use the interpreter engine (existing behavior)
            let results = engine.eval_query(query, enable_tracing)?;
            println!("{}", serde_json::to_string_pretty(&results)?);

            #[cfg(feature = "coverage")]
            if coverage {
                let report = engine.get_coverage_report()?;
                println!("{}", report.to_string_pretty()?);
            }
        }
        EvalEngine::Rvm | EvalEngine::Vm => {
            // Use the RVM/VM engine
            // Compile the policy first
            use std::sync::Arc;
            let rule_rc: Arc<str> = query.clone().into();
            let compiled_policy = engine.compile_with_entrypoint(&rule_rc)?;

            // Compile to RVM program
            let program = Compiler::compile_from_policy(&compiled_policy, &query)?;

            // Create and execute VM
            let mut vm = RegoVM::new();
            vm.load_program(program);
            vm.set_data(engine.get_data());

            // Set input if we have it
            if let Some(input_data) = input_data {
                vm.set_input(input_data);
            }

            let result = vm.execute()?;

            // Format result to match interpreter output structure
            let formatted_result = serde_json::json!({
                "result": [{
                    "expressions": [{
                        "value": result,
                        "text": query,
                        "location": {
                            "row": 1,
                            "col": 1
                        }
                    }]
                }]
            });

            println!("{}", serde_json::to_string_pretty(&formatted_result)?);
        }
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

    /// Compile a Rego query to RVM bytecode and dump assembly listing.
    Compile {
        /// Directories containing Rego files.
        #[arg(long, short, value_name = "bundle")]
        bundles: Vec<String>,

        /// Policy or data files. Rego, json or yaml.
        #[arg(long, short, value_name = "policy.rego|data.json|data.yaml")]
        data: Vec<String>,

        /// Rule name. Rego rule name (e.g., data.example.allow).
        rule_name: String,

        /// Use tabular format for assembly listing.
        #[arg(long, short)]
        tabular: bool,

        /// Turn on Rego language v0.
        #[arg(long)]
        v0: bool,
    },

    /// Debug a Rego query with interactive debugger.
    Debug {
        /// Directories containing Rego files.
        #[arg(long, short, value_name = "bundle")]
        bundles: Vec<String>,

        /// Policy or data files. Rego, json or yaml.
        #[arg(long, short, value_name = "policy.rego|data.json|data.yaml")]
        data: Vec<String>,

        /// Input file. json or yaml.
        #[arg(long, short, value_name = "input.json|input.yaml")]
        input: Option<String>,

        /// Rule name. Rego rule name (e.g., data.example.allow).
        rule_name: String,

        /// Turn on Rego language v0.
        #[arg(long)]
        v0: bool,
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

        /// Engine to use for evaluation.
        #[arg(long, value_enum, default_value = "interpreter")]
        engine: EvalEngine,

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
}

fn rego_debug(
    bundles: &[String],
    files: &[String],
    input: Option<String>,
    rule_name: String,
    v0: bool,
) -> Result<()> {
    // Create engine and compile the policy
    let mut engine = regorus::Engine::new();
    engine.set_rego_v0(v0);

    // Load files from given bundles.
    for dir in bundles.iter() {
        let entries =
            std::fs::read_dir(dir).or_else(|e| bail!("failed to read bundle {dir}.\n{e}"))?;
        for entry in entries {
            let entry = entry.or_else(|e| bail!("failed to read entry {dir}.\n{e}"))?;
            let path = entry.path().to_string_lossy().to_string();
            if path.ends_with(".rego") {
                add_policy_from_file(&mut engine, path)?;
            }
        }
    }

    // Load files.
    for file in files.iter() {
        if file.ends_with(".rego") {
            add_policy_from_file(&mut engine, file.clone())?;
        } else if file.ends_with(".json") {
            let value = read_value_from_json_file(file)?;
            engine.add_data(value)?;
        } else if file.ends_with(".yaml") || file.ends_with(".yml") {
            let value = read_value_from_yaml_file(file)?;
            engine.add_data(value)?;
        } else {
            bail!("unknown file type {file}");
        }
    }

    // Set input if provided
    let input_value = if let Some(input_file) = input {
        if input_file.ends_with(".json") {
            let value = read_value_from_json_file(&input_file)?;
            engine.set_input(value.clone());
            Some(value)
        } else if input_file.ends_with(".yaml") || input_file.ends_with(".yml") {
            let value = read_value_from_yaml_file(&input_file)?;
            engine.set_input(value.clone());
            Some(value)
        } else {
            bail!("unknown input file type {input_file}");
        }
    } else {
        None
    };

    // Compile the rule
    use std::sync::Arc;
    let rule_rc: Arc<str> = rule_name.clone().into();
    let compiled_policy = engine.compile_with_entrypoint(&rule_rc)?;

    // Compile to RVM program
    let program = Compiler::compile_from_policy(&compiled_policy, &rule_name)?;

    // Show assembly listing first
    println!("=== RVM ASSEMBLY LISTING ===");
    let config = AssemblyListingConfig::default();
    let listing = generate_assembly_listing(&program, &config);
    println!("{}", listing);

    println!("\n=== STARTING DEBUG SESSION ===");
    println!("Rule: {}", rule_name);
    println!(
        "Instructions: {}, Literals: {}",
        program.instructions.len(),
        program.literals.len()
    );

    // Set environment variables to enable debugging
    #[cfg(feature = "rvm-debug")]
    {
        std::env::set_var("RVM_INTERACTIVE_DEBUG", "1");
        std::env::set_var("RVM_STEP_MODE", "1");
        println!("Debug mode enabled. The debugger will break on the first instruction.");
        println!("Use debugger commands: (s)tep, (c)ontinue, (l)ist, (asm)embly, (r)egisters, (h)elp, (q)uit");
    }

    #[cfg(not(feature = "rvm-debug"))]
    {
        println!("Note: Interactive debugging requires the 'rvm-debug' feature.");
        println!("Rebuild with: cargo build --example regorus --features rvm-debug");
        println!("Running without interactive debugging...");
    }

    // Create VM (debugger will be automatically configured via environment variables)
    let mut vm = RegoVM::new();

    // Load the program
    vm.load_program(program);

    // Set data and input
    vm.set_data(engine.get_data());
    if let Some(input_data) = input_value {
        vm.set_input(input_data);
    }

    println!("Debug mode enabled. The debugger will break on the first instruction.");
    println!("Use debugger commands: (s)tep, (c)ontinue, (l)ist, (asm)embly, (r)egisters, (h)elp, (q)uit");
    println!();

    // Execute with debugging - the VM will automatically call the debugger
    match vm.execute() {
        Ok(result) => {
            println!("\n=== EXECUTION COMPLETED ===");
            println!("Result: {}", result);
        }
        Err(e) => {
            println!("\n=== EXECUTION ERROR ===");
            println!("Error: {}", e);
        }
    }

    Ok(())
}

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: RegorusCommand,
}

fn main() -> Result<()> {
    use clap::Parser;

    // Parse and dispatch command.
    let cli = Cli::parse();
    match cli.command {
        RegorusCommand::Ast { file } => rego_ast(file),
        RegorusCommand::Compile {
            bundles,
            data,
            rule_name,
            tabular,
            v0,
        } => rego_compile(&bundles, &data, rule_name, tabular, v0),
        RegorusCommand::Debug {
            bundles,
            data,
            input,
            rule_name,
            v0,
        } => rego_debug(&bundles, &data, input, rule_name, v0),
        RegorusCommand::Eval {
            bundles,
            data,
            input,
            query,
            engine,
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
            engine,
            trace,
            non_strict,
            #[cfg(feature = "coverage")]
            coverage,
            v0,
        ),
        RegorusCommand::Lex { file, verbose } => rego_lex(file, verbose),
        RegorusCommand::Parse { file, v0 } => rego_parse(file, v0),
    }
}
