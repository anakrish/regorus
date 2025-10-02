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

#[derive(clap::ValueEnum, Clone, Debug)]
enum SerializationFormat {
    /// MessagePack binary format (compact, cross-language compatible).
    Msgpack,
    /// MessagePack hybrid format (binary structure, JSON literals).
    MsgpackHybrid,
    /// Bincode binary format (Rust-specific, efficient).
    Bincode,
    /// JSON format (human-readable, with proper field names).
    Json,
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
    serialize: Option<SerializationFormat>,
    output: Option<String>,
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
    let program = Compiler::compile_from_policy(&compiled_policy, &[&rule_name])?;

    // Generate assembly listing
    let config = AssemblyListingConfig::default();
    let listing = if tabular {
        generate_tabular_assembly_listing(&program, &config)
    } else {
        generate_assembly_listing(&program, &config)
    };

    println!("{}", listing);

    // Handle serialization if requested
    if let Some(format) = serialize {
        let serialized = match format {
            SerializationFormat::Msgpack => program
                .serialize_messagepack()
                .map_err(|e| anyhow!("messagepack serialization failed: {}", e))?
                .into(),
            SerializationFormat::MsgpackHybrid => program
                .serialize_messagepack_hybrid()
                .map_err(|e| anyhow!("messagepack hybrid serialization failed: {}", e))?
                .into(),
            SerializationFormat::Bincode => bincode::serialize(&program)
                .map_err(|e| anyhow!("bincode serialization failed: {}", e))?,
            SerializationFormat::Json => program
                .serialize_json()
                .map_err(|e| anyhow!("json serialization failed: {}", e))?
                .into_bytes(),
        };

        // Write to output file or stdout
        match output {
            Some(output_file) => {
                std::fs::write(&output_file, &serialized)
                    .map_err(|e| anyhow!("failed to write to {}: {}", output_file, e))?;
                println!("Serialized program written to: {}", output_file);
            }
            None => {
                // Write binary data to stdout (not great for terminal display)
                use std::io::Write;
                std::io::stdout()
                    .write_all(&serialized)
                    .map_err(|e| anyhow!("failed to write to stdout: {}", e))?;
            }
        }
    }

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
            let program = Compiler::compile_from_policy(&compiled_policy, &[&query])?;

            // Create and execute VM
            let mut vm = RegoVM::new();
            vm.load_program(program);
            vm.set_data(engine.get_data())
                .map_err(|e| anyhow::anyhow!("Failed to set data: {}", e))?;

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

        /// Serialize compiled program to file instead of showing assembly.
        #[arg(long, short, value_name = "format", value_enum)]
        serialize: Option<SerializationFormat>,

        /// Output file for serialized program. If not specified, uses stdout for assembly or generates filename for serialization.
        #[arg(long, short, value_name = "file")]
        output: Option<String>,

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

    /// Evaluate an RBAC policy.
    Rbac {
        /// RBAC policy file (JSON).
        #[arg(long, short, value_name = "policy.json")]
        policy: String,

        /// Evaluation context file (JSON).
        #[arg(long, short, value_name = "context.json")]
        context: String,

        /// Show RVM assembly listing.
        #[arg(long, short)]
        assembly: bool,

        /// Use tabular format for assembly listing.
        #[arg(long, short)]
        tabular: bool,

        /// Enable verbose output with execution details.
        #[arg(long, short)]
        verbose: bool,
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
    let program = Compiler::compile_from_policy(&compiled_policy, &[&rule_name])?;

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
    vm.set_data(engine.get_data())
        .map_err(|e| anyhow::anyhow!("Failed to set data: {}", e))?;
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

fn rbac_eval(
    policy_file: &str,
    context_file: &str,
    show_assembly: bool,
    tabular: bool,
    verbose: bool,
) -> Result<()> {
    use regorus::rbac::{RbacCompiler, RbacParser};
    use std::sync::Arc;

    // Read policy file
    let policy_json = std::fs::read_to_string(policy_file)
        .map_err(|e| anyhow!("Failed to read policy file {}: {}", policy_file, e))?;

    // Read context file
    let context_json = std::fs::read_to_string(context_file)
        .map_err(|e| anyhow!("Failed to read context file {}: {}", context_file, e))?;

    if verbose {
        println!("=== RBAC POLICY ===");
        println!("{}", policy_json);
        println!("\n=== EVALUATION CONTEXT ===");
        println!("{}", context_json);
        println!();
    }

    // Parse policy
    let policy = RbacParser::parse_policy(&policy_json)
        .map_err(|e| anyhow!("Failed to parse policy: {}", e))?;

    if verbose {
        println!("=== PARSED POLICY ===");
        println!("Role Definitions: {}", policy.role_definitions.len());
        for role_def in &policy.role_definitions {
            println!("  - {} ({})", role_def.name, role_def.id);
            println!("    Permissions: {}", role_def.permissions.len());
            for perm in &role_def.permissions {
                println!("      Actions: {}", perm.actions.len());
                println!("      Data Actions: {}", perm.data_actions.len());
            }
        }
        println!("Role Assignments: {}", policy.role_assignments.len());
        for assignment in &policy.role_assignments {
            println!(
                "  - Principal {} -> Role {} @ {}",
                assignment.principal_id, assignment.role_definition_id, assignment.scope
            );
            if let Some(condition) = &assignment.condition {
                println!("    Condition: {:?}", condition);
            }
        }
        println!();
    }

    // Parse context
    let context_value: serde_json::Value = serde_json::from_str(&context_json)
        .map_err(|e| anyhow!("Failed to parse context JSON: {}", e))?;

    // Convert to EvaluationContext using the same logic as WASM binding
    let context = parse_evaluation_context(&context_value)
        .map_err(|e| anyhow!("Failed to parse evaluation context: {}", e))?;

    if verbose {
        println!("=== EVALUATION CONTEXT ===");
        println!("Principal: {} ({:?})", context.principal.id, context.principal.principal_type);
        println!("Resource: {} ({})", context.resource.scope, context.resource.resource_type);
        if let Some(action) = &context.action {
            println!("Action: {}", action);
        }
        if let Some(data_action) = &context.request.data_action {
            println!("Data Action: {}", data_action);
        }
        if let Some(action) = &context.request.action {
            println!("Request Action: {}", action);
        }
        println!();
    }

    // Compile to RVM program
    let program = RbacCompiler::compile_to_program(&policy, &context)
        .map_err(|e| anyhow!("Failed to compile RBAC policy: {}", e))?;

    if show_assembly {
        println!("=== RVM ASSEMBLY LISTING ===");
        let config = AssemblyListingConfig::default();
        let listing = if tabular {
            generate_tabular_assembly_listing(&program, &config)
        } else {
            generate_assembly_listing(&program, &config)
        };
        println!("{}", listing);
        println!();
    }

    // Execute the program
    let mut vm = RegoVM::new();
    vm.load_program(Arc::new(program));

    // Build VM input from context
    let vm_input = build_vm_input(&context);
    vm.set_input(vm_input);
    vm.set_data(regorus::Value::new_object())
        .map_err(|e| anyhow!("Failed to set data: {}", e))?;

    let start_time = std::time::Instant::now();
    let result = vm.execute().map_err(|e| anyhow!("Execution failed: {}", e))?;
    let duration = start_time.elapsed();

    // Display results
    println!("=== EVALUATION RESULT ===");
    let allow = match &result {
        regorus::Value::Bool(b) => *b,
        regorus::Value::Undefined => false,
        _ => {
            return Err(anyhow!("Unexpected result type: {:?}", result));
        }
    };

    println!("Decision: {}", if allow { "ALLOW" } else { "DENY" });
    println!("Execution Time: {:.3}ms", duration.as_secs_f64() * 1000.0);

    if verbose {
        println!("Raw Result: {:?}", result);
    }

    Ok(())
}

// Helper function to parse evaluation context (same as WASM binding)
fn parse_evaluation_context(json: &serde_json::Value) -> Result<regorus::rbac::EvaluationContext> {
    use regorus::rbac::*;
    use regorus::Value;

    // Parse principal
    let principal_obj = json
        .get("principal")
        .ok_or_else(|| anyhow!("Missing 'principal' field"))?;

    let principal_id = principal_obj
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Missing or invalid 'principal.id'"))?;

    let principal_type_str = principal_obj
        .get("principalType")
        .and_then(|v| v.as_str())
        .unwrap_or("User");

    let principal_type = match principal_type_str {
        "User" => PrincipalType::User,
        "Group" => PrincipalType::Group,
        "ServicePrincipal" => PrincipalType::ServicePrincipal,
        "ManagedServiceIdentity" => PrincipalType::ManagedServiceIdentity,
        _ => PrincipalType::User,
    };

    let principal_attributes = principal_obj
        .get("attributes")
        .and_then(|v| serde_json::from_value::<Value>(v.clone()).ok())
        .unwrap_or_else(Value::new_object);

    // Parse resource
    let resource_obj = json
        .get("resource")
        .ok_or_else(|| anyhow!("Missing 'resource' field"))?;

    let resource_scope = resource_obj
        .get("scope")
        .and_then(|v| v.as_str())
        .unwrap_or("/");

    let resource_id = resource_obj
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or(resource_scope);

    let resource_type = resource_obj
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("Microsoft.Resources/subscriptions");

    let resource_attributes = resource_obj
        .get("attributes")
        .and_then(|v| serde_json::from_value::<Value>(v.clone()).ok())
        .unwrap_or_else(Value::new_object);

    // Parse action and actionType
    let action_value = json.get("action").and_then(|v| v.as_str()).map(|s| s.to_string());

    let action_type = json.get("actionType").and_then(|v| v.as_str());

    // Determine whether this is a data action or regular action
    let (request_action, request_data_action) = match action_type {
        Some("dataAction") => (None, action_value.clone()),
        _ => (action_value.clone(), None),
    };

    let suboperation = json
        .get("subOperation")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Parse request attributes
    let request_attributes = json
        .get("request")
        .and_then(|req| req.get("attributes"))
        .and_then(|v| serde_json::from_value::<Value>(v.clone()).ok())
        .unwrap_or_else(Value::new_object);

    Ok(EvaluationContext {
        principal: Principal {
            id: principal_id.to_string(),
            principal_type,
            custom_security_attributes: principal_attributes,
        },
        resource: Resource {
            id: resource_id.to_string(),
            resource_type: resource_type.to_string(),
            scope: resource_scope.to_string(),
            attributes: resource_attributes,
        },
        request: RequestContext {
            action: request_action.clone(),
            data_action: request_data_action,
            attributes: request_attributes,
        },
        environment: EnvironmentContext {
            is_private_link: None,
            private_endpoint: None,
            subnet: None,
            utc_now: None,
        },
        action: action_value,
        suboperation,
    })
}

fn build_vm_input(context: &regorus::rbac::EvaluationContext) -> regorus::Value {
    use regorus::Value;
    use std::collections::BTreeMap;

    let mut input_map: BTreeMap<Value, Value> = BTreeMap::new();

    // The RBAC compiler expects input with these fields:
    // - principalId: the principal making the request
    // - resource: the resource being accessed (uses scope)
    // - action: the action being performed
    // - actionType: "dataAction" or "action"

    input_map.insert(
        Value::String("principalId".into()),
        Value::String(context.principal.id.clone().into()),
    );

    input_map.insert(
        Value::String("resource".into()),
        Value::String(context.resource.scope.clone().into()),
    );

    // Determine action and actionType following the same logic as test_runner.rs
    let (action_value, action_type) = if let Some(data_action) = &context.request.data_action {
        (data_action.clone(), "dataAction")
    } else if let Some(action) = &context.request.action {
        (action.clone(), "action")
    } else if let Some(action) = &context.action {
        (action.clone(), "action")
    } else {
        (String::new(), "action")
    };

    input_map.insert(
        Value::String("action".into()),
        Value::String(action_value.into()),
    );

    input_map.insert(
        Value::String("actionType".into()),
        Value::String(action_type.into()),
    );

    Value::from(input_map)
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
            serialize,
            output,
        } => rego_compile(&bundles, &data, rule_name, tabular, v0, serialize, output),
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
        RegorusCommand::Rbac {
            policy,
            context,
            assembly,
            tabular,
            verbose,
        } => rbac_eval(&policy, &context, assembly, tabular, verbose),
    }
}
