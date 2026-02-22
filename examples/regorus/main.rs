// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use anyhow::{anyhow, bail, Result};

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

fn rego_compile(
    bundles: &[String],
    files: &[String],
    entrypoints: &[String],
    output: Option<String>,
    listing: Option<String>,
    listing_output: Option<String>,
) -> Result<()> {
    let mut engine = regorus::Engine::new();

    // Load .rego files from bundle directories.
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
            let _package = add_policy_from_file(&mut engine, entry.path().display().to_string())?;
        }
    }

    // Load files: .rego → policy, .json/.yaml → data.
    for file in files.iter() {
        if file.ends_with(".rego") {
            let _package = add_policy_from_file(&mut engine, file.clone())?;
        } else {
            let data = if file.ends_with(".json") {
                read_value_from_json_file(file)?
            } else if file.ends_with(".yaml") {
                read_value_from_yaml_file(file)?
            } else {
                bail!("Unsupported data file `{file}`. Must be rego, json or yaml.");
            };
            engine.add_data(data)?;
        }
    }

    // Compile to RVM bytecode.
    if entrypoints.is_empty() {
        bail!("at least one --entrypoint is required");
    }
    let ep: regorus::Rc<str> = regorus::Rc::from(entrypoints[0].as_str());
    let compiled = engine.compile_with_entrypoint(&ep)?;
    let ep_strs: Vec<&str> = entrypoints.iter().map(|s| s.as_str()).collect();
    let program =
        regorus::languages::rego::compiler::Compiler::compile_from_policy(&compiled, &ep_strs)?;

    // Generate listing if requested.
    let listing_kind = listing.as_deref().or_else(|| {
        if listing_output.is_some() || output.is_none() {
            Some("standard")
        } else {
            None
        }
    });

    if let Some(listing_kind) = listing_kind {
        let listing_text = match listing_kind {
            "standard" => regorus::rvm::program::generate_assembly_listing(
                &program,
                &regorus::rvm::program::AssemblyListingConfig::default(),
            ),
            "tabular" => regorus::rvm::program::generate_tabular_assembly_listing(
                &program,
                &regorus::rvm::program::AssemblyListingConfig::default(),
            ),
            _ => bail!("unsupported listing format `{listing_kind}`"),
        };

        if let Some(path) = listing_output.as_ref() {
            std::fs::write(path, listing_text)?;
        } else {
            println!("{listing_text}");
        }
    }

    // Write program JSON if requested.
    if let Some(path) = output.as_ref() {
        let serialized = program.serialize_json().map_err(|err| anyhow!(err))?;
        std::fs::write(path, serialized)?;
    }

    Ok(())
}

#[cfg(feature = "z3-analysis")]
mod analyze;

#[cfg(feature = "cedar")]
#[path = "../cedar/cli.rs"]
mod cedar_cli;

#[derive(clap::Subcommand)]
enum RegorusCommand {
    /// Symbolically analyze a Rego policy using Z3.
    ///
    /// Translates the policy into SMT constraints and uses the Z3 solver to
    /// generate a concrete input that satisfies the given goal (expected output,
    /// line coverage, or both).
    #[cfg(feature = "z3-analysis")]
    Analyze {
        /// Directories containing Rego files.
        #[arg(long, short, value_name = "bundle")]
        bundles: Vec<String>,

        /// Policy or data files. Rego, json or yaml.
        #[arg(long, short, value_name = "policy.rego|data.json")]
        data: Vec<String>,

        /// Entry point to analyze (e.g. "data.example.allow").
        #[arg(long, short, value_name = "RULE")]
        entrypoint: String,

        /// Expected output value (JSON literal, e.g. "true", "false", "42", "\"admin\"").
        /// When omitted, the solver only requires the result to be defined.
        #[arg(long, short, value_name = "JSON")]
        output: Option<String>,

        /// Source lines to cover, as "file:line" pairs (e.g. "policy.rego:10").
        /// Multiple lines can be specified.
        #[arg(long, short = 'l', value_name = "FILE:LINE")]
        cover_line: Vec<String>,

        /// Source lines to avoid, as "file:line" pairs (e.g. "policy.rego:10").
        /// The generated input must NOT execute these lines.
        #[arg(long, value_name = "FILE:LINE")]
        avoid_line: Vec<String>,

        /// Dump SMT-LIB2 assertions to the given file.
        #[arg(long, value_name = "FILE")]
        dump_smt: Option<String>,

        /// Dump Z3 model (variable assignments) to the given file.
        #[arg(long, value_name = "FILE")]
        dump_model: Option<String>,

        /// Z3 solver timeout in milliseconds (default: 30000).
        #[arg(long, default_value = "30000")]
        timeout: u32,

        /// Maximum loop unrolling depth (default: 5).
        #[arg(long, default_value = "5")]
        max_loops: usize,

        /// Example input file (JSON). Used to infer types for symbolic
        /// input fields so that comparisons are properly constrained.
        #[arg(long, short, value_name = "input.json")]
        input: Option<String>,

        /// JSON Schema file for input constraints. When provided, Z3
        /// constraints are generated to enforce types, required fields,
        /// minimum lengths, enums, and field uniqueness (`x-unique`).
        #[arg(long, short, value_name = "schema.json")]
        schema: Option<String>,
    },

    /// Find inputs where two policy versions disagree (policy diff).
    ///
    /// Translates both policies into SMT constraints over the same symbolic
    /// input space and asks Z3 for an input where
    /// `policy1(input) XOR policy2(input)`.  If SAT, the model is a
    /// distinguishing input; if UNSAT, the policies are equivalent.
    #[cfg(feature = "z3-analysis")]
    Diff {
        /// Directories containing Rego files for policy 1.
        #[arg(long, value_name = "bundle")]
        bundles1: Vec<String>,

        /// Policy or data files for policy 1. Rego, Cedar, json or yaml.
        #[arg(long, value_name = "FILE", required = true)]
        policy1: Vec<String>,

        /// Directories containing Rego files for policy 2.
        #[arg(long, value_name = "bundle")]
        bundles2: Vec<String>,

        /// Policy or data files for policy 2. Rego, Cedar, json or yaml.
        #[arg(long, value_name = "FILE", required = true)]
        policy2: Vec<String>,

        /// Entry point to analyze (e.g. "data.example.allow").
        #[arg(long, short, value_name = "RULE")]
        entrypoint: String,

        /// Expected output value to compare against (default: true).
        #[arg(long, short, value_name = "JSON")]
        output: Option<String>,

        /// Dump SMT-LIB2 assertions to the given file.
        #[arg(long, value_name = "FILE")]
        dump_smt: Option<String>,

        /// Dump Z3 model (variable assignments) to the given file.
        #[arg(long, value_name = "FILE")]
        dump_model: Option<String>,

        /// Z3 solver timeout in milliseconds (default: 30000).
        #[arg(long, default_value = "30000")]
        timeout: u32,

        /// Maximum loop unrolling depth (default: 5).
        #[arg(long, default_value = "5")]
        max_loops: usize,

        /// Example input file (JSON) for type inference.
        #[arg(long, short, value_name = "input.json")]
        input: Option<String>,

        /// JSON Schema file for input constraints.
        #[arg(long, short, value_name = "schema.json")]
        schema: Option<String>,
    },

    /// Check whether one policy subsumes another.
    ///
    /// Proves whether `new_policy ⊇ old_policy`: every input that old_policy
    /// accepts (produces `desired_output`) is also accepted by new_policy.
    /// If a counterexample exists, it is printed.
    #[cfg(feature = "z3-analysis")]
    Subsumes {
        /// Policy or data files for the OLD policy.
        #[arg(long, value_name = "FILE", required = true)]
        old: Vec<String>,

        /// Policy or data files for the NEW policy.
        #[arg(long, value_name = "FILE", required = true)]
        new: Vec<String>,

        /// Entry point to analyze (e.g. "data.example.allow").
        #[arg(long, short, value_name = "RULE")]
        entrypoint: String,

        /// Expected output value (default: true).
        #[arg(long, short, value_name = "JSON")]
        output: Option<String>,

        /// Dump SMT-LIB2 assertions to the given file.
        #[arg(long, value_name = "FILE")]
        dump_smt: Option<String>,

        /// Dump Z3 model (variable assignments) to the given file.
        #[arg(long, value_name = "FILE")]
        dump_model: Option<String>,

        /// Z3 solver timeout in milliseconds (default: 30000).
        #[arg(long, default_value = "30000")]
        timeout: u32,

        /// Maximum loop unrolling depth (default: 5).
        #[arg(long, default_value = "5")]
        max_loops: usize,

        /// Example input file (JSON) for type inference.
        #[arg(long, short, value_name = "input.json")]
        input: Option<String>,

        /// JSON Schema file for input constraints.
        #[arg(long, short, value_name = "schema.json")]
        schema: Option<String>,
    },

    /// Generate a test suite by covering all reachable source lines.
    ///
    /// Iteratively invokes Z3 to produce one concrete input per reachable
    /// source line.  The output is a JSON array of test cases, each with
    /// the input and the lines it covers.
    #[cfg(feature = "z3-analysis")]
    GenTests {
        /// Directories containing Rego files.
        #[arg(long, short, value_name = "bundle")]
        bundles: Vec<String>,

        /// Policy or data files. Rego, Cedar, json or yaml.
        #[arg(long, short, value_name = "policy.rego|data.json")]
        data: Vec<String>,

        /// Entry point to analyze (e.g. "data.example.allow").
        #[arg(long, short, value_name = "RULE")]
        entrypoint: String,

        /// Expected output value (JSON literal). When omitted, the solver
        /// only requires the result to be defined.
        #[arg(long, short, value_name = "JSON")]
        output: Option<String>,

        /// Dump (base) SMT-LIB2 assertions to the given file.
        #[arg(long, value_name = "FILE")]
        dump_smt: Option<String>,

        /// Z3 solver timeout in milliseconds (default: 30000).
        #[arg(long, default_value = "30000")]
        timeout: u32,

        /// Maximum loop unrolling depth (default: 5).
        #[arg(long, default_value = "5")]
        max_loops: usize,

        /// Maximum number of test cases to generate (default: 100).
        #[arg(long, default_value = "100")]
        max_tests: usize,

        /// Example input file (JSON) for type inference.
        #[arg(long, short, value_name = "input.json")]
        input: Option<String>,

        /// JSON Schema file for input constraints.
        #[arg(long, short, value_name = "schema.json")]
        schema: Option<String>,
    },

    /// Parse a Rego policy and dump AST.
    Ast {
        /// Rego policy file.
        file: String,
    },

    /// Compile Rego policies into an RVM program (bytecode JSON or listing).
    Compile {
        /// Directories containing Rego files.
        #[arg(long, short, value_name = "bundle")]
        bundles: Vec<String>,

        /// Policy or data files. Rego, json or yaml.
        #[arg(long, short, value_name = "policy.rego|data.json")]
        data: Vec<String>,

        /// Entry points to compile (e.g. "data.example.allow").
        #[arg(long, short, value_name = "RULE", required = true)]
        entrypoint: Vec<String>,

        /// Output file for compiled program JSON.
        #[arg(short, long, value_name = "program.json")]
        output: Option<String>,

        /// Assembly listing format (standard or tabular).
        #[arg(long, value_name = "standard|tabular")]
        listing: Option<String>,

        /// Output file for assembly listing.
        #[arg(long, value_name = "listing.txt")]
        listing_output: Option<String>,
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

    /// Cedar policy tools.
    #[cfg(feature = "cedar")]
    Cedar {
        #[command(subcommand)]
        command: cedar_cli::CedarCommand,
    },
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
        RegorusCommand::Compile {
            bundles,
            data,
            entrypoint,
            output,
            listing,
            listing_output,
        } => rego_compile(
            &bundles,
            &data,
            &entrypoint,
            output,
            listing,
            listing_output,
        ),
        #[cfg(feature = "z3-analysis")]
        RegorusCommand::Analyze {
            bundles,
            data,
            entrypoint,
            output,
            cover_line,
            avoid_line,
            dump_smt,
            dump_model,
            timeout,
            max_loops,
            input,
            schema,
        } => analyze::rego_analyze(
            &bundles, &data, entrypoint, output, cover_line, avoid_line, dump_smt, dump_model,
            timeout, max_loops, input, schema,
        ),
        #[cfg(feature = "z3-analysis")]
        RegorusCommand::Diff {
            bundles1,
            policy1,
            bundles2,
            policy2,
            entrypoint,
            output,
            dump_smt,
            dump_model,
            timeout,
            max_loops,
            input,
            schema,
        } => analyze::rego_diff(
            &bundles1, &policy1, &bundles2, &policy2, entrypoint, output, dump_smt, dump_model,
            timeout, max_loops, input, schema,
        ),
        #[cfg(feature = "z3-analysis")]
        RegorusCommand::Subsumes {
            old,
            new,
            entrypoint,
            output,
            dump_smt,
            dump_model,
            timeout,
            max_loops,
            input,
            schema,
        } => analyze::rego_subsumes(
            &old, &new, entrypoint, output, dump_smt, dump_model, timeout, max_loops, input, schema,
        ),
        #[cfg(feature = "z3-analysis")]
        RegorusCommand::GenTests {
            bundles,
            data,
            entrypoint,
            output,
            dump_smt,
            timeout,
            max_loops,
            max_tests,
            input,
            schema,
        } => analyze::rego_gen_tests(
            &bundles, &data, entrypoint, output, dump_smt, timeout, max_loops, max_tests, input,
            schema,
        ),
        #[cfg(feature = "cedar")]
        RegorusCommand::Cedar { command } => cedar_cli::run(command),
    }
}
