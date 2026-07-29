// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `compile-rvm` and `eval-rvm` subcommands for the regorus example binary.
//!
//! These two commands are the ahead-of-time half of the RVM story:
//!
//! * `compile-rvm` turns Rego modules (plus optional static data) into a
//!   serialized RVM program artifact on disk.
//! * `eval-rvm` loads such an artifact, supplies `input`/`data`/`context`,
//!   executes one entry point, and prints the result as JSON.
//!
//! The default container is the **portable `RVMP` format**, which is
//! explicitly specified in `docs/rvm/portable-format.md` and is intended to be
//! read by non-Rust runtimes (for example a C# loader).  The legacy `REGO`
//! v6 container produced by `Program::serialize_binary` is still available via
//! `--format legacy`.
//!
//! Usage:
//! ```text
//! cargo run --example regorus -- compile-rvm \
//!     --data policy.rego --data data.json \
//!     --entrypoint data.example.allow \
//!     --output policy.rvmp
//!
//! cargo run --example regorus -- eval-rvm \
//!     --input input.json --data data.json \
//!     --entrypoint data.example.allow \
//!     policy.rvmp
//! ```

use std::fmt;

use anyhow::Result;

use regorus::languages::rego::compiler::Compiler;
use regorus::rvm::program::{
    AssemblyListingConfig, DeserializationResult, PortableError, PortableInfo,
    PortableWriteOptions, Program,
};
use regorus::rvm::RegoVM;
use regorus::{Engine, Value};

// ── Command line value types ─────────────────────────────────────────────────

/// Container format used for an RVM program artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum RvmFormat {
    /// Portable, language-neutral `RVMP` container (default).
    ///
    /// Explicitly specified, deterministic, and readable from non-Rust hosts.
    #[default]
    Portable,

    /// Legacy Rust-shaped `REGO` v6 container.
    ///
    /// Produced by `Program::serialize_binary`.  Kept for compatibility with
    /// existing tooling; not recommended for cross-language consumers.
    Legacy,
}

impl fmt::Display for RvmFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Portable => f.write_str("portable"),
            Self::Legacy => f.write_str("legacy"),
        }
    }
}

// ── Typed errors ─────────────────────────────────────────────────────────────

/// Errors that are specific to the RVM artifact subcommands.
///
/// These are surfaced through `anyhow` (the convention used by the rest of
/// this example) but stay strongly typed so callers can match on them.
#[derive(Debug)]
pub enum RvmCliError {
    /// A file was neither `.rego`, `.json`, nor `.yaml`.
    UnsupportedFileType {
        /// Path that was rejected.
        path: String,
        /// Comma separated list of accepted extensions.
        expected: &'static str,
    },

    /// An artifact file could not be read.
    ArtifactRead {
        /// Path that was being read.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// An artifact file could not be written.
    ArtifactWrite {
        /// Path that was being written.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// The file is neither a portable (`RVMP`) nor a legacy (`REGO`) artifact.
    UnknownArtifactFormat {
        /// Path that was inspected.
        path: String,
        /// First bytes of the file, for diagnosis.
        prefix: String,
    },

    /// A portable artifact failed to decode.
    PortableDecode {
        /// Path that was being decoded.
        path: String,
        /// Typed codec error.
        source: PortableError,
    },

    /// A program could not be encoded in the portable format.
    PortableEncode {
        /// Typed codec error.
        source: PortableError,
    },

    /// A legacy artifact failed to decode.
    LegacyDecode {
        /// Path that was being decoded.
        path: String,
        /// Message reported by the legacy codec.
        message: String,
    },

    /// A program could not be encoded in the legacy format.
    LegacyEncode {
        /// Message reported by the legacy codec.
        message: String,
    },

    /// A legacy artifact only decoded partially and must be recompiled.
    NeedsRecompilation {
        /// Path that was being decoded.
        path: String,
    },

    /// The requested entry point is not present in the artifact.
    EntryPointNotFound {
        /// Entry point requested on the command line.
        name: String,
        /// Entry points the artifact does define.
        available: Vec<String>,
    },

    /// The artifact exposes several entry points and none was selected.
    AmbiguousEntryPoint {
        /// Entry points the artifact defines.
        available: Vec<String>,
    },

    /// The artifact exposes no entry points at all.
    NoEntryPoints {
        /// Path that was inspected.
        path: String,
    },
}

impl fmt::Display for RvmCliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFileType { path, expected } => {
                write!(f, "unsupported file `{path}`; expected one of: {expected}")
            }
            Self::ArtifactRead { path, source } => {
                write!(f, "could not read artifact `{path}`: {source}")
            }
            Self::ArtifactWrite { path, source } => {
                write!(f, "could not write artifact `{path}`: {source}")
            }
            Self::UnknownArtifactFormat { path, prefix } => write!(
                f,
                "`{path}` is not an RVM artifact (expected magic 'RVMP' or 'REGO', found {prefix})"
            ),
            Self::PortableDecode { path, source } => {
                write!(f, "could not load portable artifact `{path}`: {source}")
            }
            Self::PortableEncode { source } => {
                write!(f, "could not write portable artifact: {source}")
            }
            Self::LegacyDecode { path, message } => {
                write!(f, "could not load legacy artifact `{path}`: {message}")
            }
            Self::LegacyEncode { message } => {
                write!(f, "could not write legacy artifact: {message}")
            }
            Self::NeedsRecompilation { path } => write!(
                f,
                "legacy artifact `{path}` decoded only partially and needs recompilation; \
                 recompile it with `compile-rvm`"
            ),
            Self::EntryPointNotFound { name, available } => write!(
                f,
                "entry point `{name}` is not in this artifact; available: [{}]",
                available.join(", ")
            ),
            Self::AmbiguousEntryPoint { available } => write!(
                f,
                "artifact defines {} entry points; select one with --entrypoint: [{}]",
                available.len(),
                available.join(", ")
            ),
            Self::NoEntryPoints { path } => {
                write!(f, "artifact `{path}` does not define any entry point")
            }
        }
    }
}

impl std::error::Error for RvmCliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ArtifactRead { source, .. } | Self::ArtifactWrite { source, .. } => Some(source),
            Self::PortableDecode { source, .. } | Self::PortableEncode { source } => Some(source),
            _ => None,
        }
    }
}

// ── Shared helpers ───────────────────────────────────────────────────────────

const POLICY_OR_DATA_EXTENSIONS: &str = ".rego, .json, .yaml";
const DATA_EXTENSIONS: &str = ".json, .yaml";

fn read_data_file(path: &String) -> Result<Value> {
    if path.ends_with(".json") {
        crate::read_value_from_json_file(path)
    } else if path.ends_with(".yaml") || path.ends_with(".yml") {
        crate::read_value_from_yaml_file(path)
    } else {
        Err(RvmCliError::UnsupportedFileType {
            path: path.clone(),
            expected: DATA_EXTENSIONS,
        }
        .into())
    }
}

/// Merge every `--data` file into a single value using the engine's own
/// (conflict-detecting) merge semantics.
fn merge_data_files(files: &[String]) -> Result<Value> {
    let mut engine = Engine::new();
    for file in files {
        engine.add_data(read_data_file(file)?)?;
    }
    Ok(engine.get_data())
}

/// Collect `*.rego` files from each `--bundle` directory.
fn bundle_policy_files(bundles: &[String]) -> Result<Vec<String>> {
    let mut files = Vec::new();
    for dir in bundles {
        let entries = std::fs::read_dir(dir).map_err(|e| RvmCliError::ArtifactRead {
            path: dir.clone(),
            source: e,
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| RvmCliError::ArtifactRead {
                path: dir.clone(),
                source: e,
            })?;
            let path = entry.path();
            match (path.is_file(), path.extension()) {
                (true, Some(ext)) if ext == "rego" => files.push(path.display().to_string()),
                _ => continue,
            }
        }
    }
    // Directory iteration order is not guaranteed; sort so that compilation
    // (and therefore the artifact bytes) stays deterministic.
    files.sort();
    Ok(files)
}

fn entry_point_names(program: &Program) -> Vec<String> {
    program.entry_points.keys().cloned().collect()
}

// ── compile-rvm ──────────────────────────────────────────────────────────────

/// Compile Rego modules into a serialized RVM program artifact.
#[allow(clippy::too_many_arguments)]
pub fn compile_rvm(
    bundles: &[String],
    files: &[String],
    entrypoints: &[String],
    output: String,
    format: RvmFormat,
    execution_only: bool,
    listing: Option<String>,
    non_strict: bool,
    v0: bool,
) -> Result<()> {
    let mut engine = Engine::new();
    engine.set_strict_builtin_errors(!non_strict);
    engine.set_rego_v0(v0);

    // Policies from bundle directories.
    for file in bundle_policy_files(bundles)? {
        let _package = crate::add_policy_from_file(&mut engine, file)?;
    }

    // Policies and static data given explicitly.
    for file in files {
        if file.ends_with(".rego") {
            let _package = crate::add_policy_from_file(&mut engine, file.clone())?;
        } else if file.ends_with(".json") || file.ends_with(".yaml") || file.ends_with(".yml") {
            engine.add_data(read_data_file(file)?)?;
        } else {
            return Err(RvmCliError::UnsupportedFileType {
                path: file.clone(),
                expected: POLICY_OR_DATA_EXTENSIONS,
            }
            .into());
        }
    }

    // `clap` guarantees at least one entry point, but be explicit anyway.
    let first = entrypoints
        .first()
        .ok_or_else(|| anyhow::anyhow!("at least one --entrypoint is required"))?;

    let compiled = engine.compile_with_entrypoint(&regorus::Rc::from(first.as_str()))?;
    let entry_point_refs: Vec<&str> = entrypoints.iter().map(String::as_str).collect();
    let program = Compiler::compile_from_policy(&compiled, &entry_point_refs)?;

    let bytes = match format {
        RvmFormat::Portable => {
            let options = if execution_only {
                PortableWriteOptions::execution_only()
            } else {
                PortableWriteOptions::all()
            };
            program
                .serialize_portable_with_options(&options)
                .map_err(|source| RvmCliError::PortableEncode { source })?
        }
        RvmFormat::Legacy => program
            .serialize_binary()
            .map_err(|message| RvmCliError::LegacyEncode { message })?,
    };

    std::fs::write(&output, &bytes).map_err(|e| RvmCliError::ArtifactWrite {
        path: output.clone(),
        source: e,
    })?;

    if let Some(listing_path) = listing {
        let text = regorus::rvm::generate_assembly_listing(
            program.as_ref(),
            &AssemblyListingConfig::default(),
        );
        std::fs::write(&listing_path, text).map_err(|e| RvmCliError::ArtifactWrite {
            path: listing_path.clone(),
            source: e,
        })?;
        println!("Wrote assembly listing to {listing_path}");
    }

    println!(
        "Wrote {} artifact to {output} ({} bytes)",
        format,
        bytes.len()
    );
    println!(
        "  instructions: {}, literals: {}, rules: {}, builtins: {}",
        program.instructions.len(),
        program.literals.len(),
        program.rule_infos.len(),
        program.builtin_info_table.len()
    );
    println!("  entry points: [{}]", entrypoints.join(", "));
    if program.has_host_await {
        println!("  note: program uses host-await; evaluation requires suspendable execution");
    }

    Ok(())
}

// ── eval-rvm ─────────────────────────────────────────────────────────────────

/// Load a serialized RVM artifact from disk.
fn load_artifact(path: &String) -> Result<(Program, RvmFormat)> {
    let bytes = std::fs::read(path).map_err(|e| RvmCliError::ArtifactRead {
        path: path.clone(),
        source: e,
    })?;

    if Program::is_portable_artifact(&bytes) {
        let program = Program::deserialize_portable(&bytes).map_err(|source| {
            RvmCliError::PortableDecode {
                path: path.clone(),
                source,
            }
        })?;
        return Ok((program, RvmFormat::Portable));
    }

    if bytes.starts_with(&Program::MAGIC) {
        let program = match Program::deserialize_binary(&bytes).map_err(|message| {
            RvmCliError::LegacyDecode {
                path: path.clone(),
                message,
            }
        })? {
            DeserializationResult::Complete(program) => program,
            DeserializationResult::Partial(_) => {
                return Err(RvmCliError::NeedsRecompilation { path: path.clone() }.into())
            }
        };
        return Ok((program, RvmFormat::Legacy));
    }

    let prefix = bytes
        .iter()
        .take(4)
        .map(|b| format!("{b:#04x}"))
        .collect::<Vec<_>>()
        .join(" ");
    Err(RvmCliError::UnknownArtifactFormat {
        path: path.clone(),
        prefix: if prefix.is_empty() {
            "<empty file>".to_string()
        } else {
            prefix
        },
    }
    .into())
}

fn print_artifact_info(path: &String, program: &Program, format: RvmFormat) -> Result<()> {
    println!("artifact:      {path}");
    println!("format:        {format}");
    if format == RvmFormat::Portable {
        let bytes = std::fs::read(path).map_err(|e| RvmCliError::ArtifactRead {
            path: path.clone(),
            source: e,
        })?;
        let info: PortableInfo =
            Program::inspect_portable(&bytes).map_err(|source| RvmCliError::PortableDecode {
                path: path.clone(),
                source,
            })?;
        println!("version:       {}", info.format_version);
        println!("feature flags: {:#010x}", info.feature_flags);
        println!("sections:      {}", info.section_count);
        println!("total size:    {} bytes", info.total_size);
        println!("debug info:    {}", info.has_debug_info);
        println!("metadata:      {}", info.has_metadata);
        println!("host await:    {}", info.uses_host_await);
        println!("rego v0:       {}", info.rego_v0);
    } else {
        println!("version:       {}", Program::SERIALIZATION_VERSION);
        println!("rego v0:       {}", program.rego_v0);
        println!("host await:    {}", program.has_host_await);
    }
    println!("instructions:  {}", program.instructions.len());
    println!("literals:      {}", program.literals.len());
    println!("rules:         {}", program.rule_infos.len());
    println!("builtins:      {}", program.builtin_info_table.len());
    println!("entry points:");
    for (name, pc) in &program.entry_points {
        println!("  {name} (pc {pc})");
    }
    Ok(())
}

/// Pick the entry point to execute.
fn select_entry_point(program: &Program, path: &str, requested: Option<String>) -> Result<String> {
    let available = entry_point_names(program);
    match requested {
        Some(name) => {
            if program.get_entry_point(&name).is_some() {
                Ok(name)
            } else {
                Err(RvmCliError::EntryPointNotFound { name, available }.into())
            }
        }
        None => match available.len() {
            0 => Err(RvmCliError::NoEntryPoints {
                path: path.to_string(),
            }
            .into()),
            1 => available
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("internal error: missing entry point")),
            _ => Err(RvmCliError::AmbiguousEntryPoint { available }.into()),
        },
    }
}

/// Load an RVM artifact, execute one entry point, and print the result.
#[allow(clippy::too_many_arguments)]
pub fn eval_rvm(
    artifact: String,
    data: &[String],
    input: Option<String>,
    context: Option<String>,
    entrypoint: Option<String>,
    info: bool,
    list_entrypoints: bool,
) -> Result<()> {
    let (program, format) = load_artifact(&artifact)?;

    if list_entrypoints {
        for name in entry_point_names(&program) {
            println!("{name}");
        }
        return Ok(());
    }

    if info {
        return print_artifact_info(&artifact, &program, format);
    }

    let entry_point = select_entry_point(&program, &artifact, entrypoint)?;

    let mut vm = RegoVM::new();
    vm.load_program(std::sync::Arc::new(program));

    if !data.is_empty() {
        vm.set_data(merge_data_files(data)?)?;
    }

    if let Some(file) = input {
        vm.set_input(read_data_file(&file)?);
    }

    if let Some(file) = context {
        vm.set_context(read_data_file(&file)?);
    }

    let result = vm.execute_entry_point_by_name(&entry_point)?;

    if result == Value::Undefined {
        // Rego is three-valued: undefined is not false. Say so explicitly
        // instead of letting it look like a JSON string.
        eprintln!("entry point `{entry_point}` evaluated to undefined");
    }
    println!("{}", serde_json::to_string_pretty(&result)?);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory as _;
        crate::Cli::command().debug_assert();
    }

    #[test]
    fn compile_rvm_arguments_parse() {
        let cli = crate::Cli::parse_from([
            "regorus",
            "compile-rvm",
            "--data",
            "policy.rego",
            "--data",
            "data.json",
            "--entrypoint",
            "data.a.allow",
            "--entrypoint",
            "data.a.deny",
            "--output",
            "out.rvmp",
        ]);
        match cli.command {
            crate::RegorusCommand::CompileRvm {
                data,
                entrypoint,
                output,
                format,
                execution_only,
                listing,
                v0,
                ..
            } => {
                assert_eq!(data, ["policy.rego", "data.json"]);
                assert_eq!(entrypoint, ["data.a.allow", "data.a.deny"]);
                assert_eq!(output, "out.rvmp");
                assert_eq!(format, RvmFormat::Portable, "portable must be the default");
                assert!(!execution_only);
                assert_eq!(listing, None);
                assert!(!v0);
            }
            _ => panic!("expected the compile-rvm subcommand"),
        }
    }

    #[test]
    fn compile_rvm_accepts_the_legacy_format_and_short_flags() {
        let cli = crate::Cli::parse_from([
            "regorus",
            "compile-rvm",
            "-d",
            "policy.rego",
            "-e",
            "data.a.allow",
            "-o",
            "out.rvmb",
            "-f",
            "legacy",
            "--execution-only",
            "--v0",
        ]);
        match cli.command {
            crate::RegorusCommand::CompileRvm {
                format,
                execution_only,
                v0,
                ..
            } => {
                assert_eq!(format, RvmFormat::Legacy);
                assert!(execution_only);
                assert!(v0);
            }
            _ => panic!("expected the compile-rvm subcommand"),
        }
    }

    #[test]
    fn compile_rvm_requires_entrypoint_and_output() {
        assert!(
            crate::Cli::try_parse_from(["regorus", "compile-rvm", "--output", "out.rvmp"]).is_err(),
            "--entrypoint must be required"
        );
        assert!(
            crate::Cli::try_parse_from(["regorus", "compile-rvm", "-e", "data.a.allow"]).is_err(),
            "--output must be required"
        );
    }

    #[test]
    fn eval_rvm_arguments_parse() {
        let cli = crate::Cli::parse_from([
            "regorus",
            "eval-rvm",
            "--data",
            "data.json",
            "--input",
            "input.json",
            "--context",
            "context.json",
            "--entrypoint",
            "data.a.allow",
            "policy.rvmp",
        ]);
        match cli.command {
            crate::RegorusCommand::EvalRvm {
                artifact,
                data,
                input,
                context,
                entrypoint,
                info,
                list_entrypoints,
            } => {
                assert_eq!(artifact, "policy.rvmp");
                assert_eq!(data, ["data.json"]);
                assert_eq!(input.as_deref(), Some("input.json"));
                assert_eq!(context.as_deref(), Some("context.json"));
                assert_eq!(entrypoint.as_deref(), Some("data.a.allow"));
                assert!(!info);
                assert!(!list_entrypoints);
            }
            _ => panic!("expected the eval-rvm subcommand"),
        }
    }

    #[test]
    fn eval_rvm_requires_an_artifact() {
        assert!(crate::Cli::try_parse_from(["regorus", "eval-rvm"]).is_err());
    }

    #[test]
    fn portable_is_the_default_format() {
        assert_eq!(RvmFormat::default(), RvmFormat::Portable);
        assert_eq!(RvmFormat::Portable.to_string(), "portable");
        assert_eq!(RvmFormat::Legacy.to_string(), "legacy");
    }

    #[test]
    fn unsupported_data_file_is_rejected() {
        let err = read_data_file(&"policy.txt".to_string()).unwrap_err();
        assert!(err.to_string().contains("unsupported file `policy.txt`"));
    }

    #[test]
    fn entry_point_selection_reports_alternatives() {
        let mut program = Program::new();
        program.entry_points.insert("data.a.allow".to_string(), 0);
        program.entry_points.insert("data.b.allow".to_string(), 1);

        let path = "test.rvmp";
        let err = select_entry_point(&program, path, Some("data.c.allow".to_string()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("data.a.allow"), "{err}");
        assert!(err.contains("data.b.allow"), "{err}");

        let err = select_entry_point(&program, path, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--entrypoint"), "{err}");

        assert_eq!(
            select_entry_point(&program, path, Some("data.b.allow".to_string())).unwrap(),
            "data.b.allow"
        );
    }

    #[test]
    fn single_entry_point_needs_no_selection() {
        let mut program = Program::new();
        program
            .entry_points
            .insert("data.only.allow".to_string(), 0);
        assert_eq!(
            select_entry_point(&program, "a.rvmp", None).unwrap(),
            "data.only.allow"
        );
    }

    #[test]
    fn unknown_artifact_magic_is_reported() {
        let err = RvmCliError::UnknownArtifactFormat {
            path: "x.bin".to_string(),
            prefix: "0x00 0x01".to_string(),
        }
        .to_string();
        assert!(err.contains("RVMP"), "{err}");
        assert!(err.contains("REGO"), "{err}");
    }
}
