// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Standalone test runner for Azure Policy test suites.
//!
//! Recursively discovers `*.Test.yaml` files under a given folder and evaluates
//! each test case through the regorus Azure Policy compiler + RVM pipeline.
//!
//! # Usage
//!
//! ```text
//! ap-test-runner <FOLDER> [OPTIONS]
//!
//! Arguments:
//!   <FOLDER>  Root folder containing *.Test.yaml files
//!
//! Options:
//!   -a, --aliases <PATH>   Alias catalog JSON file or directory (repeatable)
//!   -f, --filter <STRING>  Only run files whose path contains this substring
//!   -v, --verbose          Print per-case pass/fail output
//!   -s, --stop-on-fail     Stop at the first failure
//!       --list             List discovered test files without running them
//! ```

mod format;
mod runner;

use anyhow::{bail, Result};
use clap::Parser;
use std::path::Path;

#[derive(Parser)]
#[command(
    name = "ap-test-runner",
    about = "Run Azure Policy test suites (*.Test.yaml)"
)]
struct Cli {
    /// Root folder containing *.Test.yaml files (searched recursively).
    folder: String,

    /// Alias catalog JSON file or directory (repeatable; directories are
    /// scanned recursively for *.json files).  All use Get-AzPolicyAlias format.
    #[arg(long, short)]
    aliases: Vec<String>,

    /// Data policy manifest directory or file (repeatable; directories are
    /// scanned recursively for *.json files).  These describe data-plane
    /// aliases (e.g., Microsoft.KeyVault.Data).
    #[arg(long, short = 'd')]
    data_manifests: Vec<String>,

    /// Only run test files whose path contains this substring.
    #[arg(long, short)]
    filter: Option<String>,

    /// Print verbose per-case output.
    #[arg(long, short)]
    verbose: bool,

    /// Stop at the first failure.
    #[arg(long, short)]
    stop_on_fail: bool,

    /// List discovered test files without running them.
    #[arg(long)]
    list: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load alias catalogs (optional, repeatable).
    let has_aliases = !cli.aliases.is_empty();
    let has_data_manifests = !cli.data_manifests.is_empty();

    // Auto-discover control-plane alias catalog from test folder if not explicitly given.
    let alias_paths = if has_aliases {
        cli.aliases.clone()
    } else {
        let auto_file = Path::new(&cli.folder).join("builtin/Prod/ResourceTypesAndAliases.json");
        if auto_file.is_file() {
            vec![auto_file.display().to_string()]
        } else {
            vec![]
        }
    };

    // Auto-discover data manifests from test folder if not explicitly given.
    let data_manifest_paths = if has_data_manifests {
        cli.data_manifests.clone()
    } else {
        let auto_dir = Path::new(&cli.folder).join("dataPolicyManifests/Prod");
        if auto_dir.is_dir() {
            vec![auto_dir.display().to_string()]
        } else {
            vec![]
        }
    };

    let alias_registry = if !alias_paths.is_empty() || !data_manifest_paths.is_empty() {
        let mut reg = regorus::languages::azure_policy::aliases::AliasRegistry::new();

        // Load control-plane alias catalogs.
        if !alias_paths.is_empty() {
            let json_files = collect_alias_files(&alias_paths)?;
            let mut loaded = 0usize;
            for file in &json_files {
                let json = std::fs::read_to_string(file).map_err(|e| {
                    anyhow::anyhow!("Cannot read alias file {}: {e}", file.display())
                })?;
                match reg.load_from_json(&json) {
                    Ok(()) => loaded += 1,
                    Err(e) => {
                        if cli.verbose {
                            eprintln!("  skip alias file {} (parse error: {})", file.display(), e);
                        }
                    }
                }
            }
            if loaded == 0 {
                eprintln!(
                    "Warning: {} alias path(s) given but no valid catalog files found",
                    alias_paths.len()
                );
            } else {
                println!(
                    "Alias catalog loaded: {} resource types from {} file(s)",
                    reg.len(),
                    loaded
                );
            }
        }

        // Load data-plane manifests.
        if !data_manifest_paths.is_empty() {
            let json_files = collect_alias_files(&data_manifest_paths)?;
            let mut loaded = 0usize;
            let before = reg.len();
            for file in &json_files {
                let json = std::fs::read_to_string(file).map_err(|e| {
                    anyhow::anyhow!("Cannot read manifest file {}: {e}", file.display())
                })?;
                match reg.load_data_policy_manifest_json(&json) {
                    Ok(()) => loaded += 1,
                    Err(e) => {
                        if cli.verbose {
                            eprintln!(
                                "  skip data manifest {} (parse error: {})",
                                file.display(),
                                e
                            );
                        }
                    }
                }
            }
            let added = reg.len() - before;
            if loaded > 0 {
                println!(
                    "Data manifests loaded: {} data-plane resource types from {} file(s)",
                    added, loaded
                );
            }
        }

        if reg.is_empty() {
            None
        } else {
            Some(reg)
        }
    } else {
        None
    };

    // Discover test files.
    let mut test_files = Vec::new();
    discover_test_files(Path::new(&cli.folder), &mut test_files);
    test_files.sort();

    if test_files.is_empty() {
        bail!("No *.Test.yaml files found under {}", cli.folder);
    }

    // Apply filter.
    let test_files: Vec<_> = test_files
        .into_iter()
        .filter(|p| {
            if let Some(ref f) = cli.filter {
                let rel = p
                    .strip_prefix(&cli.folder)
                    .unwrap_or(p)
                    .display()
                    .to_string();
                rel.contains(f.as_str())
            } else {
                true
            }
        })
        .collect();

    if cli.list {
        println!("Discovered {} test file(s):", test_files.len());
        for f in &test_files {
            println!("  {}", f.display());
        }
        return Ok(());
    }

    println!(
        "Found {} test file(s) under {}",
        test_files.len(),
        cli.folder
    );

    // Run.
    let stats = runner::run_all(
        &test_files,
        &cli.folder,
        alias_registry.as_ref(),
        cli.verbose,
        cli.stop_on_fail,
    )?;

    // Summary.
    println!("\n══════════════════════════════════════════════════════════");
    let total_errors = stats.fail + stats.file_errors;
    if stats.file_errors > 0 || stats.known_failure_count > 0 {
        println!(
            "Files: {}  Cases: {}  Pass: {}  Fail: {}  Known-fail: {}  Skip: {}  File-errors: {}",
            stats.files,
            stats.cases,
            stats.pass,
            stats.fail,
            stats.known_failure_count,
            stats.skip,
            stats.file_errors
        );
    } else {
        println!(
            "Files: {}  Cases: {}  Pass: {}  Fail: {}  Skip: {}",
            stats.files, stats.cases, stats.pass, stats.fail, stats.skip
        );
    }
    if !stats.failures.is_empty() {
        println!("\nFailures ({}):", stats.failures.len());
        for (i, f) in stats.failures.iter().enumerate() {
            println!("  {}. {f}", i + 1);
        }
    }
    if !stats.known_failure_msgs.is_empty() {
        println!("\nKnown failures ({}):", stats.known_failure_msgs.len());
        for (i, f) in stats.known_failure_msgs.iter().enumerate() {
            println!("  {}. {f}", i + 1);
        }
    }
    println!("══════════════════════════════════════════════════════════");

    if total_errors > 0 {
        bail!("{} test(s) failed", total_errors);
    }

    Ok(())
}

/// Expand a list of alias paths (files or directories) into concrete JSON file paths.
///
/// Each entry in `paths` is either:
/// - A file path → used directly
/// - A directory → scanned recursively for `*.json` files
fn collect_alias_files(paths: &[String]) -> Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    for p in paths {
        let path = std::path::PathBuf::from(p);
        if path.is_dir() {
            discover_json_files(&path, &mut files);
        } else if path.is_file() {
            files.push(path);
        } else {
            bail!("Alias path does not exist: {p}");
        }
    }
    files.sort();
    Ok(files)
}

/// Recursively find all `*.json` files under `dir`.
fn discover_json_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            discover_json_files(&path, out);
        } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.ends_with(".json") {
                out.push(path);
            }
        }
    }
}

/// Recursively find all `*.Test.yaml` files under `dir`.
fn discover_test_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            discover_test_files(&path, out);
        } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.ends_with(".Test.yaml") {
                out.push(path);
            }
        }
    }
}
