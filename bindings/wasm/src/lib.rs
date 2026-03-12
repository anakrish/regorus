// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(non_snake_case)]

#[cfg(feature = "cedar")]
use regorus::languages::cedar::{compiler as cedar_compiler, parser::Parser as CedarParser};
use regorus::languages::rego::compiler::Compiler;
use regorus::rvm::program::{
    generate_assembly_listing, generate_tabular_assembly_listing, AssemblyListingConfig,
    DeserializationResult, Program as RvmProgram,
};
use regorus::rvm::vm::{ExecutionMode, RegoVM};
#[cfg(feature = "cedar")]
use regorus::Source;
use regorus::{compile_policy_with_entrypoint, PolicyModule, Rc, Value};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[cfg(feature = "azure_policy")]
use regorus::languages::azure_policy::{compiler as ap_compiler, parser as ap_parser};

#[wasm_bindgen]
/// WASM wrapper for [`regorus::Engine`]
pub struct Engine {
    engine: regorus::Engine,
}

#[derive(Deserialize)]
struct ModuleSpec {
    id: String,
    content: String,
}

#[cfg(feature = "cedar")]
#[derive(Deserialize)]
struct CedarPolicySpec {
    id: String,
    content: String,
}

#[wasm_bindgen]
pub struct Program {
    program: Arc<RvmProgram>,
}

#[wasm_bindgen]
pub struct ProgramDeserializationResult {
    program: Arc<RvmProgram>,
    is_partial: bool,
}

#[wasm_bindgen]
impl ProgramDeserializationResult {
    /// Whether the program was partially deserialized.
    #[wasm_bindgen(getter)]
    pub fn isPartial(&self) -> bool {
        self.is_partial
    }

    /// Get the deserialized program.
    pub fn program(&self) -> Program {
        Program {
            program: self.program.clone(),
        }
    }
}

#[wasm_bindgen]
pub struct Rvm {
    vm: RegoVM,
}

fn error_to_jsvalue<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&format!("{e}"))
}

#[cfg(feature = "azure_policy")]
fn parse_alias_map_json(
    alias_map_json: Option<String>,
) -> Result<BTreeMap<String, String>, JsValue> {
    use regorus::languages::azure_policy::aliases::AliasRegistry;
    match alias_map_json {
        Some(json) => {
            // Try parsing as a flat BTreeMap<String, String> first (pre-processed).
            if let Ok(map) = serde_json::from_str::<BTreeMap<String, String>>(&json) {
                return Ok(map);
            }
            // Otherwise, parse as the raw provider-alias catalog array and convert.
            let mut registry = AliasRegistry::new();
            registry
                .load_from_json(&json)
                .map_err(error_to_jsvalue)?;
            Ok(registry.alias_map())
        }
        None => Ok(BTreeMap::new()),
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Engine {
    /// Clone a [`Engine`]
    ///
    /// To avoid having to parse same policy again, the engine can be cloned
    /// after policies and data have been added.
    fn clone(&self) -> Self {
        Self {
            engine: self.engine.clone(),
        }
    }
}

#[wasm_bindgen]
impl Engine {
    #[wasm_bindgen(constructor)]
    /// Construct a new Engine
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html
    pub fn new() -> Self {
        Self {
            engine: regorus::Engine::new(),
        }
    }

    /// Turn on rego v0.
    ///
    /// Regorus defaults to rego v1.
    ///
    /// * `enable`: Whether to enable or disable rego v0.
    pub fn setRegoV0(&mut self, enable: bool) {
        self.engine.set_rego_v0(enable)
    }

    /// Add a policy
    ///
    /// The policy is parsed into AST.
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.add_policy
    ///
    /// * `path`: A filename to be associated with the policy.
    /// * `rego`: Rego policy.
    pub fn addPolicy(&mut self, path: String, rego: String) -> Result<String, JsValue> {
        self.engine.add_policy(path, rego).map_err(error_to_jsvalue)
    }

    /// Add policy data.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.add_data
    /// * `data`: JSON encoded value to be used as policy data.
    pub fn addDataJson(&mut self, data: String) -> Result<(), JsValue> {
        let data = regorus::Value::from_json_str(&data).map_err(error_to_jsvalue)?;
        self.engine.add_data(data).map_err(error_to_jsvalue)
    }

    /// Get the list of packages defined by loaded policies.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.get_packages
    pub fn getPackages(&self) -> Result<Vec<String>, JsValue> {
        self.engine.get_packages().map_err(error_to_jsvalue)
    }

    /// Get the list of policies.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.get_policies
    pub fn getPolicies(&self) -> Result<String, JsValue> {
        self.engine.get_policies_as_json().map_err(error_to_jsvalue)
    }

    /// Clear policy data.
    ///
    /// See https://docs.rs/regorus/0.1.0-alpha.2/regorus/struct.Engine.html#method.clear_data
    pub fn clearData(&mut self) -> Result<(), JsValue> {
        self.engine.clear_data();
        Ok(())
    }

    /// Set input.
    ///
    /// See https://docs.rs/regorus/0.1.0-alpha.2/regorus/struct.Engine.html#method.set_input
    /// * `input`: JSON encoded value to be used as input to query.
    pub fn setInputJson(&mut self, input: String) -> Result<(), JsValue> {
        let input = regorus::Value::from_json_str(&input).map_err(error_to_jsvalue)?;
        self.engine.set_input(input);
        Ok(())
    }

    /// Evaluate query.
    ///
    /// See https://docs.rs/regorus/0.1.0-alpha.2/regorus/struct.Engine.html#method.eval_query
    /// * `query`: Rego expression to be evaluate.
    pub fn evalQuery(&mut self, query: String) -> Result<String, JsValue> {
        let results = self
            .engine
            .eval_query(query, false)
            .map_err(error_to_jsvalue)?;
        serde_json::to_string_pretty(&results).map_err(error_to_jsvalue)
    }

    /// Evaluate rule(s) at given path.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.eval_rule
    ///
    /// * `path`: The full path to the rule(s).
    pub fn evalRule(&mut self, path: String) -> Result<String, JsValue> {
        let v = self.engine.eval_rule(path).map_err(error_to_jsvalue)?;
        v.to_json_str().map_err(error_to_jsvalue)
    }

    /// Gather output from print statements instead of emiting to stderr.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.set_gather_prints
    /// * `b`: Whether to enable gathering prints or not.
    pub fn setGatherPrints(&mut self, b: bool) {
        self.engine.set_gather_prints(b)
    }

    /// Take the gathered output of print statements.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.take_prints
    pub fn takePrints(&mut self) -> Result<Vec<String>, JsValue> {
        self.engine.take_prints().map_err(error_to_jsvalue)
    }

    /// Enable/disable policy coverage.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.set_enable_coverage
    /// * `b`: Whether to enable gathering coverage or not.
    #[cfg(feature = "coverage")]
    pub fn setEnableCoverage(&mut self, enable: bool) {
        self.engine.set_enable_coverage(enable)
    }

    /// Get the coverage report as json.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.get_coverage_report
    #[cfg(feature = "coverage")]
    pub fn getCoverageReport(&self) -> Result<String, JsValue> {
        let report = self
            .engine
            .get_coverage_report()
            .map_err(error_to_jsvalue)?;
        serde_json::to_string_pretty(&report).map_err(error_to_jsvalue)
    }

    /// Clear gathered coverage data.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.clear_coverage_data
    #[cfg(feature = "coverage")]
    pub fn clearCoverageData(&mut self) {
        self.engine.clear_coverage_data()
    }

    /// Get ANSI color coded coverage report.
    ///
    /// See https://docs.rs/regorus/latest/regorus/coverage/struct.Report.html#method.to_string_pretty
    #[cfg(feature = "coverage")]
    pub fn getCoverageReportPretty(&self) -> Result<String, JsValue> {
        let report = self
            .engine
            .get_coverage_report()
            .map_err(error_to_jsvalue)?;
        report.to_string_pretty().map_err(error_to_jsvalue)
    }

    /// Get AST of policies.
    ///
    /// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.get_ast_as_json
    #[cfg(feature = "ast")]
    pub fn getAstAsJson(&self) -> Result<String, JsValue> {
        self.engine.get_ast_as_json().map_err(error_to_jsvalue)
    }
}

#[wasm_bindgen]
impl Program {
    /// Compile an RVM program from modules and entry points.
    pub fn compileFromModules(
        data_json: String,
        modules_json: String,
        entry_points_json: String,
    ) -> Result<Program, JsValue> {
        let data = Value::from_json_str(&data_json).map_err(error_to_jsvalue)?;
        let modules: Vec<ModuleSpec> =
            serde_json::from_str(&modules_json).map_err(error_to_jsvalue)?;
        let entry_points: Vec<String> =
            serde_json::from_str(&entry_points_json).map_err(error_to_jsvalue)?;
        if entry_points.is_empty() {
            return Err(error_to_jsvalue(
                "entry_points must contain at least one entry",
            ));
        }

        let policy_modules: Vec<PolicyModule> = modules
            .into_iter()
            .map(|module| PolicyModule {
                id: Rc::from(module.id.as_str()),
                content: Rc::from(module.content.as_str()),
            })
            .collect();

        let entry_points_ref: Vec<&str> = entry_points.iter().map(|s| s.as_str()).collect();
        let compiled =
            compile_policy_with_entrypoint(data, &policy_modules, Rc::from(entry_points_ref[0]))
                .map_err(error_to_jsvalue)?;
        let program = Compiler::compile_from_policy(&compiled, &entry_points_ref)
            .map_err(error_to_jsvalue)?;
        Ok(Program { program })
    }

    /// Compile Cedar policies into an RVM program.
    #[cfg(feature = "cedar")]
    pub fn compileCedarPolicies(policies_json: String) -> Result<Program, JsValue> {
        let specs: Vec<CedarPolicySpec> =
            serde_json::from_str(&policies_json).map_err(error_to_jsvalue)?;
        if specs.is_empty() {
            return Err(error_to_jsvalue(
                "policies_json must contain at least one policy",
            ));
        }

        let mut policies = Vec::new();
        for spec in specs {
            let source = Source::from_contents(spec.id, spec.content).map_err(error_to_jsvalue)?;
            let mut parser = CedarParser::new(&source).map_err(error_to_jsvalue)?;
            let mut parsed = parser.parse().map_err(error_to_jsvalue)?;
            policies.append(&mut parsed);
        }

        let program = cedar_compiler::compile_to_program(&policies).map_err(error_to_jsvalue)?;
        Ok(Program {
            program: Arc::new(program),
        })
    }

    /// Compile a Cedar expression into an RVM program.
    #[cfg(feature = "cedar")]
    pub fn compileCedarExpression(expr: String) -> Result<Program, JsValue> {
        let source =
            Source::from_contents("<cedar-expr>".to_string(), expr).map_err(error_to_jsvalue)?;
        let mut parser = CedarParser::new(&source).map_err(error_to_jsvalue)?;
        let parsed = parser.parse_expression().map_err(error_to_jsvalue)?;
        let program = cedar_compiler::compile_expr_to_program(&parsed).map_err(error_to_jsvalue)?;
        Ok(Program {
            program: Arc::new(program),
        })
    }

    /// Compile an Azure Policy rule JSON object into an RVM program.
    ///
    /// `policy_rule_json` must be the JSON for a `policyRule` object.
    /// `alias_map_json` is an optional JSON object mapping lowercase FQ aliases
    /// to short names, typically produced from `AliasRegistry::alias_map()`.
    #[cfg(feature = "azure_policy")]
    pub fn compileAzurePolicyRule(
        policy_rule_json: String,
        alias_map_json: Option<String>,
    ) -> Result<Program, JsValue> {
        let source = regorus::Source::from_contents("policyRule.json".into(), policy_rule_json)
            .map_err(error_to_jsvalue)?;
        let rule = ap_parser::parse_policy_rule(&source).map_err(error_to_jsvalue)?;
        let alias_map = parse_alias_map_json(alias_map_json)?;
        let program = ap_compiler::compile_policy_rule_with_aliases(&rule, alias_map)
            .map_err(error_to_jsvalue)?;

        Ok(Program { program })
    }

    /// Compile a full Azure Policy definition JSON object into an RVM program.
    ///
    /// `policy_definition_json` can be wrapped (`{ "properties": ... }`) or
    /// unwrapped; parameter defaults are included in the compiled program.
    /// `alias_map_json` is an optional JSON object mapping lowercase FQ aliases
    /// to short names, typically produced from `AliasRegistry::alias_map()`.
    #[cfg(feature = "azure_policy")]
    pub fn compileAzurePolicyDefinition(
        policy_definition_json: String,
        alias_map_json: Option<String>,
    ) -> Result<Program, JsValue> {
        let source =
            regorus::Source::from_contents("policyDefinition.json".into(), policy_definition_json)
                .map_err(error_to_jsvalue)?;
        let definition = ap_parser::parse_policy_definition(&source).map_err(error_to_jsvalue)?;
        let alias_map = parse_alias_map_json(alias_map_json)?;
        let program = ap_compiler::compile_policy_definition_with_aliases(&definition, alias_map)
            .map_err(error_to_jsvalue)?;

        Ok(Program { program })
    }

    /// Whether this compiled program contains any HostAwait instruction.
    ///
    /// Clients can use this to decide whether to run the VM in suspendable mode.
    #[wasm_bindgen(getter)]
    pub fn hasHostAwait(&self) -> bool {
        self.program.has_host_await()
    }

    /// Serialize a program to binary format.
    pub fn serializeBinary(&self) -> Result<Vec<u8>, JsValue> {
        self.program
            .serialize_binary()
            .map_err(|e| error_to_jsvalue(e.to_string()))
    }

    /// Deserialize an RVM program from binary format.
    pub fn deserializeBinary(data: Vec<u8>) -> Result<ProgramDeserializationResult, JsValue> {
        let (program, is_partial) =
            match RvmProgram::deserialize_binary(&data).map_err(error_to_jsvalue)? {
                DeserializationResult::Complete(program) => (program, false),
                DeserializationResult::Partial(program) => (program, true),
            };
        Ok(ProgramDeserializationResult {
            program: Arc::new(program),
            is_partial,
        })
    }

    /// Generate a readable assembly listing.
    pub fn generateListing(&self) -> Result<String, JsValue> {
        Ok(generate_assembly_listing(
            self.program.as_ref(),
            &AssemblyListingConfig::default(),
        ))
    }

    /// Generate a tabular assembly listing.
    pub fn generateTabularListing(&self) -> Result<String, JsValue> {
        Ok(generate_tabular_assembly_listing(
            self.program.as_ref(),
            &AssemblyListingConfig::default(),
        ))
    }
}

#[wasm_bindgen]
impl Rvm {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self { vm: RegoVM::new() }
    }

    /// Load a program into the VM.
    pub fn loadProgram(&mut self, program: &Program) {
        self.vm.load_program(program.program.clone());
    }

    /// Set VM data from JSON.
    pub fn setDataJson(&mut self, data_json: String) -> Result<(), JsValue> {
        let data = Value::from_json_str(&data_json).map_err(error_to_jsvalue)?;
        self.vm.set_data(data).map_err(error_to_jsvalue)
    }

    /// Set VM input from JSON.
    pub fn setInputJson(&mut self, input_json: String) -> Result<(), JsValue> {
        let input = Value::from_json_str(&input_json).map_err(error_to_jsvalue)?;
        self.vm.set_input(input);
        Ok(())
    }

    /// Set execution mode (0 = run-to-completion, 1 = suspendable).
    pub fn setExecutionMode(&mut self, mode: u8) -> Result<(), JsValue> {
        let mode = match mode {
            0 => ExecutionMode::RunToCompletion,
            1 => ExecutionMode::Suspendable,
            _ => return Err(error_to_jsvalue("invalid execution mode")),
        };
        self.vm.set_execution_mode(mode);
        Ok(())
    }

    /// Execute the program and return the JSON result.
    pub fn execute(&mut self) -> Result<String, JsValue> {
        let value = self.vm.execute().map_err(error_to_jsvalue)?;
        value.to_json_str().map_err(error_to_jsvalue)
    }

    /// Execute an entry point by name and return the JSON result.
    pub fn executeEntryPoint(&mut self, entry_point: String) -> Result<String, JsValue> {
        let value = self
            .vm
            .execute_entry_point_by_name(&entry_point)
            .map_err(error_to_jsvalue)?;
        value.to_json_str().map_err(error_to_jsvalue)
    }

    /// Resume execution with an optional JSON value.
    pub fn resume(&mut self, resume_json: Option<String>) -> Result<String, JsValue> {
        let value = if let Some(json) = resume_json {
            Some(Value::from_json_str(&json).map_err(error_to_jsvalue)?)
        } else {
            None
        };
        let result = self.vm.resume(value).map_err(error_to_jsvalue)?;
        result.to_json_str().map_err(error_to_jsvalue)
    }

    /// Get the execution state as a string.
    pub fn getExecutionState(&self) -> String {
        format!("{:?}", self.vm.execution_state())
    }
}

impl Default for Rvm {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Policy Analysis (requires `policy-analysis` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "policy-analysis")]
mod analysis_wasm {
    use super::*;
    use regorus::rvm::analysis::{
        self, AnalysisConfig, PreparedProblem,
    };

    /// Deserialize an `AnalysisConfig` from JSON, applying defaults for
    /// omitted fields.
    fn parse_config(config_json: Option<String>) -> Result<AnalysisConfig, JsValue> {
        match config_json {
            Some(json) => serde_json::from_str(&json).map_err(error_to_jsvalue),
            None => Ok(AnalysisConfig::default()),
        }
    }

    /// Parse `"file:line"` strings into `(file, line)` tuples.
    fn parse_line_specs_vec(specs: &[String]) -> Result<Vec<(String, usize)>, JsValue> {
        let mut out = Vec::with_capacity(specs.len());
        for spec in specs {
            let parts: Vec<&str> = spec.rsplitn(2, ':').collect();
            if parts.len() != 2 {
                return Err(JsValue::from_str(&format!("Invalid line spec: '{spec}'. Expected FILE:LINE")));
            }
            let line: usize = parts[0]
                .parse()
                .map_err(|_| JsValue::from_str(&format!("Invalid line number in '{spec}'")))?;
            out.push((parts[1].to_string(), line));
        }
        Ok(out)
    }

    /// WASM wrapper for a prepared analysis problem.
    ///
    /// Holds the translated SMT constraints and extraction plan in memory.
    /// Call `smtLib2()` to get SMT-LIB2 text for an external solver,
    /// or `problemJson()` to get the full problem as JSON.
    /// After solving, call `interpretSolution()` with the solver result.
    #[wasm_bindgen]
    pub struct AnalysisProblem {
        prepared: PreparedProblem,
    }

    #[wasm_bindgen]
    impl AnalysisProblem {
        /// Get the SMT-LIB2 text representation of this problem.
        ///
        /// Send this to an external SMT solver (e.g., Z3 WASM).
        pub fn smtLib2(&self) -> String {
            self.prepared.render_smt_lib2()
        }

        /// Get the full problem as a JSON string.
        ///
        /// The JSON conforms to the `SmtProblem` schema from `regorus-smt`.
        /// Use this for fine-grained control over solver interaction.
        pub fn problemJson(&self) -> Result<String, JsValue> {
            self.prepared.problem_json().map_err(error_to_jsvalue)
        }

        /// Get any warnings produced during translation.
        pub fn warnings(&self) -> Vec<String> {
            self.prepared.warnings.clone()
        }

        /// Interpret a solver result and produce an analysis result.
        ///
        /// `solution_json` must be a JSON-serialized `SmtCheckResult` from
        /// `regorus-smt`.  Returns a JSON object with `satisfiable`,
        /// `input`, `warnings`, etc.
        pub fn interpretSolution(&self, solution_json: String) -> Result<String, JsValue> {
            let check: regorus::regorus_smt::SmtCheckResult =
                serde_json::from_str(&solution_json).map_err(error_to_jsvalue)?;
            let result = self.prepared.interpret(&check);
            // Serialize the AnalysisResult to JSON.
            let output = serde_json::json!({
                "satisfiable": result.satisfiable,
                "input": result.input.map(|v| v.to_json_str().ok()).flatten(),
                "warnings": result.warnings,
                "solver_smt": result.solver_smt,
                "model_string": result.model_string,
            });
            serde_json::to_string_pretty(&output).map_err(error_to_jsvalue)
        }
    }

    // -----------------------------------------------------------------------
    // TestSuitePlan — iterative test-generation via external solver
    // -----------------------------------------------------------------------

    /// WASM wrapper for iterative test-suite generation.
    ///
    /// Usage from JS:
    /// ```js
    /// const suite = wasm.prepareTestSuite(program, data, output, ep, config, 10);
    /// while (true) {
    ///     const problem = suite.nextProblem();
    ///     if (!problem) break;
    ///     const solution = await solveWithZ3(problem.smtLib2());
    ///     suite.recordSolution(solution);
    /// }
    /// const result = suite.getResult();
    /// ```
    #[wasm_bindgen]
    pub struct TestSuitePlan {
        suite: analysis::PreparedTestSuite,
    }

    #[wasm_bindgen]
    impl TestSuitePlan {
        /// Get the next SMT problem to solve, or `undefined` if all lines
        /// have been covered (or `max_tests` reached).
        #[wasm_bindgen(js_name = "nextProblem")]
        pub fn next_problem(&mut self) -> Option<AnalysisProblem> {
            self.suite.next_problem().map(|p| AnalysisProblem { prepared: p })
        }

        /// Record a solver result for the current target line.
        ///
        /// `solution_json` is a JSON `SmtCheckResult`.
        /// Returns JSON: `{ "satisfiable": bool, "input": string|null,
        ///   "covered_lines": [[file, line], ...],
        ///   "condition_coverage": [["file:line", bool], ...] }` on SAT, or
        /// `{ "satisfiable": false }` on UNSAT/Unknown.
        #[wasm_bindgen(js_name = "recordSolution")]
        pub fn record_solution(&mut self, solution_json: String) -> Result<String, JsValue> {
            let check: regorus::regorus_smt::SmtCheckResult =
                serde_json::from_str(&solution_json).map_err(error_to_jsvalue)?;
            let tc = self.suite.record_solution(&check);
            match tc {
                Some(tc) => {
                    let input_json = tc.input.to_json_str().map_err(error_to_jsvalue)?;
                    let lines: Vec<serde_json::Value> = tc.covered_lines.iter().map(|(f, l)| {
                        serde_json::json!([f, l])
                    }).collect();
                    let cond_cov: Vec<serde_json::Value> = tc.condition_coverage.iter().map(|(loc, val, expr)| {
                        serde_json::json!([loc, val, expr])
                    }).collect();
                    let output = serde_json::json!({
                        "satisfiable": true,
                        "input": input_json,
                        "covered_lines": lines,
                        "condition_coverage": cond_cov,
                    });
                    serde_json::to_string_pretty(&output).map_err(error_to_jsvalue)
                }
                None => {
                    let output = serde_json::json!({ "satisfiable": false });
                    serde_json::to_string_pretty(&output).map_err(error_to_jsvalue)
                }
            }
        }

        /// Get the final test-suite result as JSON.
        ///
        /// Returns `{ test_cases, coverable_lines, covered_lines,
        ///   condition_goals, condition_goals_covered, warnings }`.
        #[wasm_bindgen(js_name = "getResult")]
        pub fn get_result(&self) -> Result<String, JsValue> {
            let cases: Vec<serde_json::Value> = self.suite.test_cases().iter().map(|tc| {
                let input_json = tc.input.to_json_str().unwrap_or_default();
                let lines: Vec<serde_json::Value> = tc.covered_lines.iter().map(|(f, l)| {
                    serde_json::json!([f, l])
                }).collect();
                let cond_cov: Vec<serde_json::Value> = tc.condition_coverage.iter().map(|(loc, val, expr)| {
                    serde_json::json!([loc, val, expr])
                }).collect();
                serde_json::json!({
                    "input": input_json,
                    "covered_lines": lines,
                    "condition_coverage": cond_cov,
                })
            }).collect();
            let output = serde_json::json!({
                "test_cases": cases,
                "coverable_lines": self.suite.coverable_lines(),
                "covered_lines": self.suite.covered_count(),
                "condition_goals": self.suite.condition_goals(),
                "condition_goals_covered": self.suite.condition_goals_covered(),
                "warnings": self.suite.current_warnings(),
            });
            serde_json::to_string_pretty(&output).map_err(error_to_jsvalue)
        }
    }

    /// Prepare an iterative test-suite generator.
    ///
    /// * `program` — Compiled RVM program.
    /// * `data_json` — JSON-encoded policy data.
    /// * `desired_output_json` — Optional output constraint (e.g., `"false"`).
    /// * `entry_point` — Entry point name.
    /// * `config_json` — Optional JSON `AnalysisConfig`.
    /// * `max_tests` — Maximum number of test cases to generate.
    /// * `condition_coverage` — Whether to include condition-coverage (Phase 2).
    #[wasm_bindgen(js_name = "prepareTestSuite")]
    pub fn prepare_test_suite(
        program: &Program,
        data_json: String,
        desired_output_json: Option<String>,
        entry_point: String,
        config_json: Option<String>,
        max_tests: u32,
        condition_coverage: bool,
    ) -> Result<TestSuitePlan, JsValue> {
        let data = Value::from_json_str(&data_json).map_err(error_to_jsvalue)?;
        let desired = match desired_output_json {
            Some(json) => Some(Value::from_json_str(&json).map_err(error_to_jsvalue)?),
            None => None,
        };
        let config = parse_config(config_json)?;

        let suite = analysis::prepare_test_suite(
            &program.program,
            &data,
            &entry_point,
            desired.as_ref(),
            &config,
            max_tests as usize,
            condition_coverage,
        )
        .map_err(error_to_jsvalue)?;

        Ok(TestSuitePlan { suite })
    }

    /// Prepare a generate-input analysis problem.
    ///
    /// Translates the policy to SMT constraints targeting the given output.
    /// Returns an `AnalysisProblem` that can be sent to an external solver.
    ///
    /// * `program` — Compiled RVM program.
    /// * `data_json` — JSON-encoded policy data (or `"{}"`).
    /// * `desired_output_json` — The value the entry point should produce (e.g., `"true"`).
    /// * `entry_point` — Entry point name (e.g., `"data.test.allow"`).
    /// * `config_json` — Optional JSON `AnalysisConfig` (uses defaults if omitted).
    #[wasm_bindgen(js_name = "prepareGenerateInput")]
    pub fn prepare_generate_input(
        program: &Program,
        data_json: String,
        desired_output_json: String,
        entry_point: String,
        config_json: Option<String>,
    ) -> Result<AnalysisProblem, JsValue> {
        let data = Value::from_json_str(&data_json).map_err(error_to_jsvalue)?;
        let desired = Value::from_json_str(&desired_output_json).map_err(error_to_jsvalue)?;
        let config = parse_config(config_json)?;

        let prepared = analysis::prepare_generate_input(
            &program.program, &data, &desired, &entry_point, &config,
        )
        .map_err(error_to_jsvalue)?;

        Ok(AnalysisProblem { prepared })
    }

    /// Prepare a satisfiability-check analysis problem.
    ///
    /// Checks whether any input can make the entry point produce a
    /// non-undefined result.
    ///
    /// * `program` — Compiled RVM program.
    /// * `data_json` — JSON-encoded policy data.
    /// * `entry_point` — Entry point name.
    /// * `config_json` — Optional JSON `AnalysisConfig`.
    #[wasm_bindgen(js_name = "prepareIsSatisfiable")]
    pub fn prepare_is_satisfiable(
        program: &Program,
        data_json: String,
        entry_point: String,
        config_json: Option<String>,
    ) -> Result<AnalysisProblem, JsValue> {
        let data = Value::from_json_str(&data_json).map_err(error_to_jsvalue)?;
        let config = parse_config(config_json)?;

        let prepared = analysis::prepare_is_satisfiable(
            &program.program, &data, &entry_point, &config,
        )
        .map_err(error_to_jsvalue)?;

        Ok(AnalysisProblem { prepared })
    }

    /// Prepare an analysis problem for a given goal.
    ///
    /// `goal` is one of:
    ///   - `"expected"` — entry point must produce `desired_output_json` (required).
    ///   - `"non-default"` — entry point must produce any non-default value.
    ///   - `"satisfiable"` — entry point must produce any defined value.
    ///   - `"cover"` — cover specific lines (via `cover_lines`/`avoid_lines` in config).
    ///   - `"output-and-cover"` — both expected output AND line coverage.
    ///
    /// * `program` — Compiled RVM program.
    /// * `data_json` — JSON-encoded policy data.
    /// * `entry_point` — Entry point name.
    /// * `goal` — Goal type string (see above).
    /// * `desired_output_json` — Required for `"expected"` and `"output-and-cover"`.
    /// * `config_json` — Optional JSON `AnalysisConfig`.
    #[wasm_bindgen(js_name = "prepareForGoal")]
    pub fn prepare_for_goal(
        program: &Program,
        data_json: String,
        entry_point: String,
        goal: String,
        desired_output_json: Option<String>,
        config_json: Option<String>,
    ) -> Result<AnalysisProblem, JsValue> {
        let data = Value::from_json_str(&data_json).map_err(error_to_jsvalue)?;
        let config = parse_config(config_json)?;

        let analysis_goal = match goal.as_str() {
            "non-default" => analysis::AnalysisGoal::NonDefault,
            "expected" => {
                let json = desired_output_json
                    .ok_or_else(|| JsValue::from_str("desired_output_json is required for 'expected' goal"))?;
                let desired = Value::from_json_str(&json).map_err(error_to_jsvalue)?;
                analysis::AnalysisGoal::ExpectedOutput(desired)
            }
            "output-and-cover" => {
                let json = desired_output_json
                    .ok_or_else(|| JsValue::from_str("desired_output_json is required for 'output-and-cover' goal"))?;
                let desired = Value::from_json_str(&json).map_err(error_to_jsvalue)?;
                let cover = parse_line_specs_vec(&config.cover_lines)?;
                let avoid = parse_line_specs_vec(&config.avoid_lines)?;
                analysis::AnalysisGoal::OutputAndCoverLines { expected: desired, cover, avoid }
            }
            "cover" => {
                let cover = parse_line_specs_vec(&config.cover_lines)?;
                let avoid = parse_line_specs_vec(&config.avoid_lines)?;
                analysis::AnalysisGoal::CoverLines { cover, avoid }
            }
            _ => {
                // Default to satisfiable check
                return {
                    let prepared = analysis::prepare_is_satisfiable(
                        &program.program, &data, &entry_point, &config,
                    ).map_err(error_to_jsvalue)?;
                    Ok(AnalysisProblem { prepared })
                };
            }
        };

        let prepared = analysis::prepare_for_goal(
            &program.program, &data, &entry_point, &analysis_goal, &config,
        )
        .map_err(error_to_jsvalue)?;

        Ok(AnalysisProblem { prepared })
    }

    /// Prepare a policy-diff analysis problem.
    ///
    /// Finds an input where two policies disagree.
    ///
    /// * `program1`, `program2` — The two compiled RVM programs to compare.
    /// * `data_json` — JSON-encoded policy data (shared).
    /// * `entry_point` — Entry point name (must exist in both programs).
    /// * `desired_output_json` — Optional desired output; defaults to `true`.
    /// * `config_json` — Optional JSON `AnalysisConfig`.
    #[wasm_bindgen(js_name = "preparePolicyDiff")]
    pub fn prepare_policy_diff(
        program1: &Program,
        program2: &Program,
        data_json: String,
        entry_point: String,
        desired_output_json: Option<String>,
        config_json: Option<String>,
    ) -> Result<AnalysisProblem, JsValue> {
        let data = Value::from_json_str(&data_json).map_err(error_to_jsvalue)?;
        let desired = match desired_output_json {
            Some(json) => Some(Value::from_json_str(&json).map_err(error_to_jsvalue)?),
            None => None,
        };
        let config = parse_config(config_json)?;

        let prepared = analysis::prepare_policy_diff(
            &program1.program,
            &program2.program,
            &data,
            &entry_point,
            desired.as_ref(),
            &config,
        )
        .map_err(error_to_jsvalue)?;

        Ok(AnalysisProblem { prepared })
    }

    /// Prepare a policy-subsumption check.
    ///
    /// Checks: for all inputs, if `old_program` produces `desired_output`
    /// then `new_program` also produces `desired_output`.
    ///
    /// When the result is SAT, a counterexample was found and subsumption
    /// does NOT hold.  When UNSAT, subsumption holds.
    ///
    /// * `old_program`, `new_program` — The two compiled RVM programs.
    /// * `data_json` — JSON-encoded policy data (shared).
    /// * `entry_point` — Entry point name (must exist in both programs).
    /// * `desired_output_json` — The desired output value.
    /// * `config_json` — Optional JSON `AnalysisConfig`.
    #[wasm_bindgen(js_name = "preparePolicySubsumes")]
    pub fn prepare_policy_subsumes(
        old_program: &Program,
        new_program: &Program,
        data_json: String,
        entry_point: String,
        desired_output_json: String,
        config_json: Option<String>,
    ) -> Result<AnalysisProblem, JsValue> {
        let data = Value::from_json_str(&data_json).map_err(error_to_jsvalue)?;
        let desired = Value::from_json_str(&desired_output_json).map_err(error_to_jsvalue)?;
        let config = parse_config(config_json)?;

        let prepared = analysis::prepare_policy_subsumes(
            &old_program.program,
            &new_program.program,
            &data,
            &entry_point,
            &desired,
            &config,
        )
        .map_err(error_to_jsvalue)?;

        Ok(AnalysisProblem { prepared })
    }
}

#[cfg(test)]
mod tests {
    use crate::error_to_jsvalue;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    #[allow(dead_code)]
    pub fn basic() -> Result<(), JsValue> {
        let mut engine = crate::Engine::new();
        engine.setEnableCoverage(true);

        // Exercise all APIs.
        engine.addDataJson(
            r#"
        {
           "foo" : "bar"
        }
        "#
            .to_string(),
        )?;

        engine.setInputJson(
            r#"
        {
           "message" : "Hello"
        }
        "#
            .to_string(),
        )?;

        let pkg = engine.addPolicy(
            "hello.rego".to_string(),
            r#"
            package test
            message = input.message"#
                .to_string(),
        )?;
        assert_eq!(pkg, "data.test");

        let results = engine.evalQuery("data".to_string())?;
        let r = regorus::Value::from_json_str(&results).map_err(error_to_jsvalue)?;

        let v = &r["result"][0]["expressions"][0]["value"];

        // Ensure that input and policy were evaluated.
        assert_eq!(v["test"]["message"], regorus::Value::from("Hello"));

        // Test that data was set.
        assert_eq!(v["foo"], regorus::Value::from("bar"));

        // Use eval_rule to perform same query.
        let v = engine.evalRule("data.test.message".to_owned())?;
        let v = regorus::Value::from_json_str(&v).map_err(error_to_jsvalue)?;

        // Ensure that input and policy were evaluated.
        assert_eq!(v, regorus::Value::from("Hello"));

        let pkgs = engine.getPackages()?;
        assert_eq!(pkgs, vec!["data.test"]);

        engine.setGatherPrints(true);
        let _ = engine.evalQuery("print(\"Hello\")".to_owned());
        let prints = engine.takePrints()?;
        assert_eq!(prints, vec!["<query.rego>:1: Hello"]);

        // Test clone.
        let mut engine1 = engine.clone();

        // Test code coverage.
        let report = engine1.getCoverageReport()?;
        let r = regorus::Value::from_json_str(&report).map_err(error_to_jsvalue)?;

        assert_eq!(
            r["files"][0]["covered"]
                .as_array()
                .map_err(crate::error_to_jsvalue)?,
            &vec![regorus::Value::from(3)]
        );

        println!("{}", engine1.getCoverageReportPretty()?);

        engine1.clearCoverageData();

        let policies = engine1.getPolicies()?;
        let v = regorus::Value::from_json_str(&policies).map_err(error_to_jsvalue)?;
        assert_eq!(
            v[0]["path"].as_string().map_err(error_to_jsvalue)?.as_ref(),
            "hello.rego"
        );
        Ok(())
    }
}
