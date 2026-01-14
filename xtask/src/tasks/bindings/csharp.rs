// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::VecDeque;
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;

use super::ffi;
use crate::tasks::util::{dotnet_host_arch, format_command, run_command, workspace_root};
use zip::read::ZipArchive;

/// Builds the Regorus C# NuGet package from local sources.
#[derive(Args, Clone)]
pub struct BuildNugetCommand {
    /// Build the Rust FFI artefacts for the provided target triple (defaults to the host).
    #[arg(long = "target", value_name = "TRIPLE")]
    pub targets: Vec<String>,

    /// Build the package in release mode (defaults to debug).
    #[arg(long)]
    pub release: bool,

    /// Override the directory that contains compiled regorus FFI artefacts.
    #[arg(long, value_name = "PATH")]
    pub artifacts_dir: Option<PathBuf>,

    /// Require all platform artefacts to exist before packing.
    #[arg(long)]
    pub enforce_artifacts: bool,
}

/// Parsed build options shared across tasks that need a NuGet package.
#[derive(Clone, Debug)]
pub struct BuildNugetConfig {
    pub targets: Vec<String>,
    pub release: bool,
    pub artifacts_dir: Option<PathBuf>,
    pub enforce_artifacts: bool,
}

/// Result of a NuGet build, including generated artefacts.
#[derive(Debug)]
pub struct BuildNugetResult {
    pub package_dir: PathBuf,
    pub packages: Vec<PathBuf>,
}

/// Builds (or rebuilds) the C# NuGet package with the supplied configuration.
pub fn build_nuget_package(config: &BuildNugetConfig) -> Result<BuildNugetResult> {
    let workspace_root = workspace_root();
    let configuration = if config.release { "Release" } else { "Debug" };
    let profile = ffi::profile_dir(config.release);

    let base_artifacts_dir = if let Some(dir) = &config.artifacts_dir {
        if !config.targets.is_empty() {
            println!("Skipping FFI build for specified targets because --artifacts-dir is set.");
        }
        dir.clone()
    } else {
        let targets = ffi::resolve_targets(config.targets.clone())?;
        ffi::build_targets(&workspace_root, &targets, config.release)?;

        workspace_root.join("bindings/ffi/target")
    };

    let artifacts_dir = base_artifacts_dir.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize FFI artefacts directory at {}",
            base_artifacts_dir.display()
        )
    })?;

    let package_dir = invoke_dotnet_pack(
        &workspace_root,
        &artifacts_dir,
        configuration,
        &profile,
        !config.enforce_artifacts,
    )?;

    let packages = find_packages(&package_dir)?;

    Ok(BuildNugetResult {
        package_dir,
        packages,
    })
}

/// Returns all NuGet packages currently present in the given directory.
pub fn find_packages(package_dir: &Path) -> Result<Vec<PathBuf>> {
    if !package_dir.exists() {
        return Ok(Vec::new());
    }

    let mut packages = Vec::new();
    let entries = fs::read_dir(package_dir).with_context(|| {
        format!(
            "failed to enumerate NuGet artefacts under {}",
            package_dir.display()
        )
    })?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path
            .extension()
            .and_then(|ext| ext.to_str())
            .map_or(false, |ext| ext.eq_ignore_ascii_case("nupkg"))
        {
            packages.push(path);
        }
    }

    packages.sort();
    Ok(packages)
}
fn invoke_dotnet_pack(
    root: &Path,
    artifacts_dir: &Path,
    configuration: &str,
    profile: &str,
    ignore_missing: bool,
) -> Result<PathBuf> {
    let project_dir = root.join("bindings/csharp/Regorus");
    let artifacts_dir_str = artifacts_dir
        .to_str()
        .ok_or_else(|| anyhow!("artefact directory path contains invalid UTF-8"))?;

    let profile_arg = format!("/p:RegorusFFIArtifactsProfile={}", profile);
    let dir_arg = format!("/p:RegorusFFIArtifactsDir={}", artifacts_dir_str);

    let mut restore = Command::new("dotnet");
    restore.current_dir(&project_dir);
    restore.arg("restore");
    run_command(restore, "dotnet restore")?;

    let mut build = Command::new("dotnet");
    build.current_dir(&project_dir);
    build.arg("build");
    build.arg("--no-restore");
    build.arg("-c");
    build.arg(configuration);
    build.arg("--verbosity");
    build.arg("minimal");
    build.arg(&dir_arg);
    build.arg(&profile_arg);
    if ignore_missing {
        build.arg("/p:IgnoreMissingArtifacts=true");
    }
    let mut build_log_path = None;
    if let Some(dir) = env::var_os("CODEQL_EXTRACTOR_CSHARP_LOG_DIR") {
        let log_dir = PathBuf::from(dir);
        if fs::create_dir_all(&log_dir).is_ok() {
            let log_path = log_dir.join("xtask-dotnet-build.log");
            let _ = fs::remove_file(&log_path);
            build.arg(format!(
                "/flp:LogFile={};Verbosity=detailed",
                log_path.to_string_lossy()
            ));
            build_log_path = Some(log_path);
        }
    } else if env::var_os("CODEQL_TRACER_LOG").is_some() {
        let log_dir = project_dir.join("obj");
        let _ = fs::create_dir_all(&log_dir);
        let log_path = log_dir.join("xtask-dotnet-build.log");
        let _ = fs::remove_file(&log_path);
        build.arg(format!(
            "/flp:LogFile={};Verbosity=detailed",
            log_path.to_string_lossy()
        ));
        build_log_path = Some(log_path);
    }
    build.stdout(Stdio::piped());
    build.stderr(Stdio::piped());

    let build_display = format_command(&build);
    println!("$ {}", build_display);
    let build_output = build
        .output()
        .with_context(|| "failed to spawn dotnet build")?;
    if !build_output.status.success() {
        if let Some(log_path) = build_log_path.as_ref() {
            if log_path.exists() {
                print_msbuild_log_tail(log_path);
            } else {
                println!(
                    "Expected dotnet build log at {} but it was not produced; showing captured output instead.",
                    log_path.display()
                );
            }
        }
        if let Some(tracer) = env::var_os("CODEQL_TRACER_LOG") {
            let tracer_path = PathBuf::from(tracer);
            print_tracer_log_tail(&tracer_path);
        }
        print_command_output("dotnet build", &build_output);
        bail!("dotnet build failed with status {}", build_output.status);
    }
    if let Some(log_path) = build_log_path {
        let _ = fs::remove_file(log_path);
    }

    let mut pack = Command::new("dotnet");
    pack.current_dir(&project_dir);
    pack.arg("pack");
    pack.arg("--no-build");
    pack.arg("-c");
    pack.arg(configuration);
    pack.arg(&dir_arg);
    pack.arg(&profile_arg);
    if ignore_missing {
        pack.arg("/p:IgnoreMissingArtifacts=true");
    }
    run_command(pack, "dotnet pack")?;

    Ok(project_dir.join("bin").join(configuration))
}

fn print_msbuild_log_tail(path: &Path) {
    const MAX_LINES: usize = 200;

    match File::open(path) {
        Ok(file) => {
            let reader = BufReader::new(file);
            let mut tail = VecDeque::with_capacity(MAX_LINES);
            for line in reader.lines().flatten() {
                if tail.len() == MAX_LINES {
                    tail.pop_front();
                }
                tail.push_back(line);
            }

            if tail.is_empty() {
                println!(
                    "MSBuild log {} was empty or not written before failure.",
                    path.display()
                );
                return;
            }

            println!("--- dotnet build log tail ({}):", path.display());
            for entry in tail {
                println!("{entry}");
            }
            println!("--- end dotnet build log tail ---");
        }
        Err(error) => {
            println!(
                "Failed to read dotnet build log at {}: {}",
                path.display(),
                error
            );
        }
    }
}

fn print_tracer_log_tail(path: &Path) {
    const MAX_LINES: usize = 200;

    match File::open(path) {
        Ok(file) => {
            let reader = BufReader::new(file);
            let mut tail = VecDeque::with_capacity(MAX_LINES);
            for line in reader.lines().flatten() {
                if tail.len() == MAX_LINES {
                    tail.pop_front();
                }
                tail.push_back(line);
            }

            if tail.is_empty() {
                println!(
                    "CodeQL tracer log {} was empty or not written before failure.",
                    path.display()
                );
                return;
            }

            println!("--- CodeQL tracer log tail ({}):", path.display());
            for entry in tail {
                println!("{entry}");
            }
            println!("--- end CodeQL tracer log tail ---");
        }
        Err(error) => {
            println!(
                "Failed to read CodeQL tracer log at {}: {}",
                path.display(),
                error
            );
        }
    }
}

fn print_command_output(label: &str, output: &Output) {
    const MAX_LINES: usize = 200;

    fn print_stream(label: &str, stream: &str, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }

        let text = String::from_utf8_lossy(bytes);
        let lines: Vec<_> = text.lines().collect();
        let total = lines.len();
        let start = total.saturating_sub(MAX_LINES);
        println!(
            "--- {} {} (showing last {} of {} line(s)) ---",
            label,
            stream,
            total - start,
            total
        );
        for line in &lines[start..] {
            println!("{line}");
        }
        println!("--- end {} {} ---", label, stream);
        true
    }

    let stdout_emitted = print_stream(label, "stdout", &output.stdout);
    let stderr_emitted = print_stream(label, "stderr", &output.stderr);
    if !stdout_emitted && !stderr_emitted {
        println!("{} produced no stdout or stderr output.", label);
    }
}

impl BuildNugetCommand {
    /// Entry point executed by the xtask harness.
    pub fn run(&self) -> Result<()> {
        let config = self.to_config();
        let result = build_nuget_package(&config)?;

        println!(
            "NuGet package(s) available under {}",
            result.package_dir.display()
        );

        if result.packages.is_empty() {
            println!("No NuGet packages were produced; check earlier log output.");
        } else {
            print_package_listing(&result.packages)?;
        }

        Ok(())
    }

    pub fn to_config(&self) -> BuildNugetConfig {
        BuildNugetConfig {
            targets: self.targets.clone(),
            release: self.release,
            artifacts_dir: self.artifacts_dir.clone(),
            enforce_artifacts: self.enforce_artifacts,
        }
    }
}

fn print_package_listing(packages: &[PathBuf]) -> Result<()> {
    for package in packages {
        println!("Contents of {}:", package.display());
        let file =
            File::open(package).with_context(|| format!("failed to open {}", package.display()))?;
        let mut archive = ZipArchive::new(file)
            .with_context(|| format!("failed to read zip archive from {}", package.display()))?;

        let mut entries = Vec::new();
        for index in 0..archive.len() {
            let file = archive.by_index(index).with_context(|| {
                format!("failed to access entry {index} in {}", package.display())
            })?;
            entries.push(file.name().to_string());
        }

        entries.sort();
        for entry in entries {
            println!("  {}", entry);
        }
    }

    Ok(())
}

/// Builds (if required) and tests the C# bindings against the packaged NuGet.
#[derive(Args, Clone)]
pub struct TestCsharpCommand {
    /// Build the Rust FFI artefacts for the provided target triple (defaults to the host).
    #[arg(long = "target", value_name = "TRIPLE")]
    pub targets: Vec<String>,

    /// Build and pack using the Release configuration (defaults to Debug).
    #[arg(long)]
    pub release: bool,

    /// Override the directory that contains compiled regorus FFI artefacts.
    #[arg(long, value_name = "PATH")]
    pub artifacts_dir: Option<PathBuf>,

    /// Require all platform artefacts to exist before packing.
    #[arg(long)]
    pub enforce_artifacts: bool,

    /// Always rebuild the NuGet package instead of reusing an existing archive.
    #[arg(long)]
    pub force_nuget: bool,
}

impl TestCsharpCommand {
    pub fn run(&self) -> Result<()> {
        let workspace = workspace_root();
        let configuration = if self.release { "Release" } else { "Debug" };
        let mut package_dir = workspace
            .join("bindings/csharp/Regorus/bin")
            .join(configuration);

        let build_config = BuildNugetConfig {
            targets: self.targets.clone(),
            release: self.release,
            artifacts_dir: self.artifacts_dir.clone(),
            enforce_artifacts: self.enforce_artifacts,
        };

        let mut packages = find_packages(&package_dir)?;
        if self.force_nuget || packages.is_empty() {
            println!(
                "{} NuGet package(s); invoking build...",
                if self.force_nuget {
                    "Forcing rebuild of"
                } else {
                    "Missing"
                }
            );
            let build = build_nuget_package(&build_config)?;
            package_dir = build.package_dir;
            packages = build.packages;
        } else {
            println!(
                "Reusing existing NuGet package(s) under {}.",
                package_dir.display()
            );
        }

        if packages.is_empty() {
            return Err(anyhow!(
                "No NuGet packages are available under {} after build",
                package_dir.display()
            ));
        }

        println!("Using NuGet package(s):");
        for package in &packages {
            println!("  {}", package.display());
        }

        run_regorus_tests(&workspace, configuration, &package_dir)?;

        Ok(())
    }
}

fn run_regorus_tests(workspace: &Path, configuration: &str, package_dir: &Path) -> Result<()> {
    let nuget_source = package_dir
        .to_str()
        .ok_or_else(|| anyhow!("NuGet directory path contains invalid UTF-8"))?;
    let source_property = format!("/p:RestoreAdditionalProjectSources={}", nuget_source);

    let regorus_tests = workspace.join("bindings/csharp/Regorus.Tests");
    restore_with_source(&regorus_tests, &source_property, "Regorus.Tests")?;

    let mut test = Command::new("dotnet");
    test.current_dir(&regorus_tests);
    test.arg("test");
    test.arg("--no-restore");
    test.arg("-c");
    test.arg(configuration);
    test.arg("--arch");
    test.arg(dotnet_host_arch());
    run_command(test, "dotnet test (Regorus.Tests)")?;

    let test_app = workspace.join("bindings/csharp/TestApp");
    restore_with_source(&test_app, &source_property, "TestApp")?;
    let mut build = Command::new("dotnet");
    build.current_dir(&test_app);
    build.arg("build");
    build.arg("--no-restore");
    build.arg("-c");
    build.arg(configuration);
    build.arg("--arch");
    build.arg(dotnet_host_arch());
    run_command(build, "dotnet build (TestApp)")?;

    let mut run = Command::new("dotnet");
    run.current_dir(&test_app);
    run.arg("run");
    run.arg("--no-build");
    run.arg("--framework");
    run.arg("net8.0");
    run.arg("-c");
    run.arg(configuration);
    run.arg("--arch");
    run.arg(dotnet_host_arch());
    run_command(run, "dotnet run (TestApp)")?;

    let target_example = workspace.join("bindings/csharp/TargetExampleApp");
    restore_with_source(&target_example, &source_property, "TargetExampleApp")?;
    let mut build_example = Command::new("dotnet");
    build_example.current_dir(&target_example);
    build_example.arg("build");
    build_example.arg("--no-restore");
    build_example.arg("-c");
    build_example.arg(configuration);
    build_example.arg("--arch");
    build_example.arg(dotnet_host_arch());
    run_command(build_example, "dotnet build (TargetExampleApp)")?;

    let mut run_example = Command::new("dotnet");
    run_example.current_dir(&target_example);
    run_example.arg("run");
    run_example.arg("--no-build");
    run_example.arg("--framework");
    run_example.arg("net8.0");
    run_example.arg("-c");
    run_example.arg(configuration);
    run_example.arg("--arch");
    run_example.arg(dotnet_host_arch());
    run_command(run_example, "dotnet run (TargetExampleApp)")?;

    Ok(())
}

fn restore_with_source(project_dir: &Path, source_property: &str, label: &str) -> Result<()> {
    let mut restore = Command::new("dotnet");
    restore.current_dir(project_dir);
    restore.arg("restore");
    restore.arg("--arch");
    restore.arg(dotnet_host_arch());
    restore.arg(source_property);
    run_command(restore, &format!("dotnet restore ({label})"))
}
