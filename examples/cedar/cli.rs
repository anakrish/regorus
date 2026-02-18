// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use anyhow::{anyhow, bail, Result};
use std::sync::Arc;

use super::{read_value_from_json_file, read_value_from_yaml_file};

fn read_value_from_file(path: &String) -> Result<regorus::Value> {
    if path.ends_with(".json") {
        read_value_from_json_file(path)
    } else if path.ends_with(".yaml") || path.ends_with(".yml") {
        read_value_from_yaml_file(path)
    } else {
        bail!("Unsupported file `{path}`. Must be json or yaml.");
    }
}

fn ensure_object(value: &mut regorus::Value, label: &str) -> Result<()> {
    value
        .as_object_mut()
        .map(|_| ())
        .map_err(|_| anyhow!("{label} must be a JSON/YAML object"))
}

fn ensure_object_key(
    value: &mut regorus::Value,
    key: &str,
    default_value: regorus::Value,
) -> Result<()> {
    let map = value.as_object_mut()?;
    let key_value = regorus::Value::from(key);
    map.entry(key_value).or_insert(default_value);
    Ok(())
}

fn ensure_object_field(value: &regorus::Value, key: &str, label: &str) -> Result<()> {
    let map = value.as_object()?;
    if let Some(field) = map.get(&regorus::Value::from(key)) {
        field
            .as_object()
            .map(|_| ())
            .map_err(|_| anyhow!("{label} must be a JSON/YAML object"))?;
    }
    Ok(())
}

#[derive(clap::Args, Debug)]
pub struct CedarInputArgs {
    /// Full input document (includes principal/action/resource/context/entities).
    #[arg(long, value_name = "input.json|input.yaml", conflicts_with_all = [
        "request_json",
        "principal",
        "action",
        "resource",
        "context",
    ])]
    input: Option<String>,

    /// Request JSON document (principal/action/resource/context). Entities are optional.
    #[arg(long = "request-json", value_name = "request.json", conflicts_with_all = [
        "principal",
        "action",
        "resource",
        "context",
    ])]
    request_json: Option<String>,

    /// Principal entity (e.g. User::"alice").
    #[arg(short = 'l', long)]
    principal: Option<String>,

    /// Action entity (e.g. Action::"view").
    #[arg(short = 'a', long)]
    action: Option<String>,

    /// Resource entity (e.g. File::"foo").
    #[arg(short = 'r', long)]
    resource: Option<String>,

    /// Context file (JSON or YAML object).
    #[arg(long, value_name = "context.json|context.yaml")]
    context: Option<String>,
}

fn build_cedar_input(args: &CedarInputArgs) -> Result<regorus::Value> {
    if let Some(path) = args.input.as_ref() {
        let mut input = read_value_from_file(path)?;
        ensure_object(&mut input, "input")?;
        ensure_object_key(&mut input, "context", regorus::Value::new_object())?;
        ensure_object_key(&mut input, "entities", regorus::Value::new_object())?;
        ensure_object_field(&input, "context", "context")?;
        ensure_object_field(&input, "entities", "entities")?;
        return Ok(input);
    }

    if let Some(path) = args.request_json.as_ref() {
        let mut input = read_value_from_file(path)?;
        ensure_object(&mut input, "request-json")?;
        {
            let map = input.as_object()?;
            for key in ["principal", "action", "resource"] {
                if !map.contains_key(&regorus::Value::from(key)) {
                    bail!("request-json missing required field `{key}`");
                }
            }
        }
        ensure_object_key(&mut input, "context", regorus::Value::new_object())?;
        ensure_object_key(&mut input, "entities", regorus::Value::new_object())?;
        ensure_object_field(&input, "context", "context")?;
        ensure_object_field(&input, "entities", "entities")?;
        return Ok(input);
    }

    if args.principal.is_some()
        || args.action.is_some()
        || args.resource.is_some()
        || args.context.is_some()
    {
        let principal = args
            .principal
            .as_ref()
            .ok_or_else(|| anyhow!("--principal is required"))?;
        let action = args
            .action
            .as_ref()
            .ok_or_else(|| anyhow!("--action is required"))?;
        let resource = args
            .resource
            .as_ref()
            .ok_or_else(|| anyhow!("--resource is required"))?;

        let mut input = regorus::Value::new_object();
        let map = input.as_object_mut()?;
        map.insert(
            regorus::Value::from("principal"),
            regorus::Value::from(principal.as_str()),
        );
        map.insert(
            regorus::Value::from("action"),
            regorus::Value::from(action.as_str()),
        );
        map.insert(
            regorus::Value::from("resource"),
            regorus::Value::from(resource.as_str()),
        );

        let context = match args.context.as_ref() {
            Some(path) => {
                let mut ctx = read_value_from_file(path)?;
                ensure_object(&mut ctx, "context")?;
                ctx
            }
            None => regorus::Value::new_object(),
        };

        ensure_object_key(&mut input, "context", context)?;
        ensure_object_key(&mut input, "entities", regorus::Value::new_object())?;
        ensure_object_field(&input, "context", "context")?;
        ensure_object_field(&input, "entities", "entities")?;
        return Ok(input);
    }

    bail!("missing input: use --input, --request-json, or principal/action/resource flags")
}

fn parse_cedar_policies(files: &[String]) -> Result<Vec<regorus::languages::cedar::ast::Policy>> {
    let mut out = Vec::new();
    for file in files {
        #[cfg(feature = "std")]
        let source = regorus::Source::from_file(file)?;

        #[cfg(not(feature = "std"))]
        let source = regorus::Source::from_contents(file.clone(), read_file(file)?)?;

        let mut parser =
            regorus::languages::cedar::parser::Parser::new(&source).map_err(|err| anyhow!(err))?;
        let mut policies = parser.parse().map_err(|err| anyhow!(err))?;
        out.append(&mut policies);
    }
    Ok(out)
}

fn cedar_authorize(args: CedarAuthorizeArgs) -> Result<()> {
    let input = build_cedar_input(&args.input)?;
    let policies = parse_cedar_policies(&args.policies)?;
    let program = regorus::languages::cedar::compiler::compile_to_program(&policies)
        .map_err(|err| anyhow!(err))?;

    let mut vm = regorus::rvm::vm::RegoVM::new();
    vm.set_strict_builtin_errors(true);
    vm.load_program(Arc::new(program));
    vm.set_input(input);

    let result = vm.execute_entry_point_by_name("cedar.authorize")?;
    let decision = result.as_u64()?;
    match decision {
        1 => {
            println!("ALLOW");
            Ok(())
        }
        0 => {
            println!("DENY");
            std::process::exit(2);
        }
        _ => bail!("unexpected authorization result {decision}"),
    }
}

fn cedar_evaluate(args: CedarEvaluateArgs) -> Result<()> {
    let input = build_cedar_input(&args.input)?;
    let source = regorus::Source::from_contents("<cedar-expr>".to_string(), args.expr)?;
    let mut parser =
        regorus::languages::cedar::parser::Parser::new(&source).map_err(|err| anyhow!(err))?;
    let expr = parser.parse_expression().map_err(|err| anyhow!(err))?;

    let program = regorus::languages::cedar::compiler::compile_expr_to_program(&expr)
        .map_err(|err| anyhow!(err))?;

    let mut vm = regorus::rvm::vm::RegoVM::new();
    vm.set_strict_builtin_errors(true);
    vm.load_program(Arc::new(program));
    vm.set_input(input);

    let result = vm.execute_entry_point_by_name("cedar.evaluate")?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn cedar_compile(args: CedarCompileArgs) -> Result<()> {
    let policies = parse_cedar_policies(&args.policies)?;
    let program = regorus::languages::cedar::compiler::compile_to_program(&policies)
        .map_err(|err| anyhow!(err))?;

    let listing_kind = args.listing.as_deref().or_else(|| {
        if args.listing_output.is_some() || args.output.is_none() {
            Some("standard")
        } else {
            None
        }
    });

    if let Some(listing_kind) = listing_kind {
        let listing = match listing_kind {
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

        if let Some(path) = args.listing_output.as_ref() {
            std::fs::write(path, listing)?;
        } else {
            println!("{listing}");
        }
    }

    if let Some(path) = args.output.as_ref() {
        let serialized = program.serialize_json().map_err(|err| anyhow!(err))?;
        std::fs::write(path, serialized)?;
    }
    Ok(())
}

pub fn run(command: CedarCommand) -> Result<()> {
    match command {
        CedarCommand::Authorize(args) => cedar_authorize(args),
        CedarCommand::Evaluate(args) => cedar_evaluate(args),
        CedarCommand::Compile(args) => cedar_compile(args),
    }
}

#[derive(clap::Subcommand)]
pub enum CedarCommand {
    /// Evaluate a Cedar authorization request.
    Authorize(CedarAuthorizeArgs),

    /// Evaluate a Cedar expression.
    Evaluate(CedarEvaluateArgs),

    /// Compile Cedar policies into an RVM program.
    Compile(CedarCompileArgs),
}

#[derive(clap::Args, Debug)]
pub struct CedarAuthorizeArgs {
    /// Cedar policy files.
    #[arg(short, long, value_name = "policy.cedar", required = true)]
    policies: Vec<String>,

    #[command(flatten)]
    input: CedarInputArgs,
}

#[derive(clap::Args, Debug)]
pub struct CedarEvaluateArgs {
    /// Cedar expression.
    #[arg(value_name = "EXPR")]
    expr: String,

    #[command(flatten)]
    input: CedarInputArgs,
}

#[derive(clap::Args, Debug)]
pub struct CedarCompileArgs {
    /// Cedar policy files.
    #[arg(short, long, value_name = "policy.cedar", required = true)]
    policies: Vec<String>,

    /// Output file for compiled program JSON.
    #[arg(short, long, value_name = "program.json")]
    output: Option<String>,

    /// Assembly listing format (standard or tabular).
    #[arg(long, value_name = "standard|tabular")]
    listing: Option<String>,

    /// Output file for assembly listing.
    #[arg(long, value_name = "listing.txt")]
    listing_output: Option<String>,
}
