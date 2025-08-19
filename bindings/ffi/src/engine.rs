// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{
    from_c_str, to_ref, to_regorus_result, to_regorus_string_result, RegorusResult, RegorusStatus,
};
use crate::compiled_policy::RegorusCompiledPolicy;
use anyhow::Result;
use std::os::raw::c_char;

/// Wrapper for `regorus::Engine`.
#[derive(Clone)]
pub struct RegorusEngine {
    engine: ::regorus::Engine,
}

#[no_mangle]
/// Construct a new Engine
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html
pub extern "C" fn regorus_engine_new() -> *mut RegorusEngine {
    let mut engine = ::regorus::Engine::new();

    // For more OPA compatibility out of the box, we ask builtins to return undefined
    // instead of raising errors in certain failure scenarios.
    engine.set_strict_builtin_errors(false);

    Box::into_raw(Box::new(RegorusEngine { engine }))
}

/// Clone a [`RegorusEngine`]
///
/// To avoid having to parse same policy again, the engine can be cloned
/// after policies and data have been added.
///
#[no_mangle]
pub extern "C" fn regorus_engine_clone(engine: *mut RegorusEngine) -> *mut RegorusEngine {
    match to_ref(engine) {
        Ok(e) => Box::into_raw(Box::new(e.clone())),
        _ => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn regorus_engine_drop(engine: *mut RegorusEngine) {
    if let Ok(e) = to_ref(engine) {
        unsafe {
            let _ = Box::from_raw(std::ptr::from_mut(e));
        }
    }
}

/// Add a policy
///
/// The policy is parsed into AST.
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.add_policy
///
/// * `path`: A filename to be associated with the policy.
/// * `rego`: Rego policy.
#[no_mangle]
pub extern "C" fn regorus_engine_add_policy(
    engine: *mut RegorusEngine,
    path: *const c_char,
    rego: *const c_char,
) -> RegorusResult {
    to_regorus_string_result(|| -> Result<String> {
        to_ref(engine)?
            .engine
            .add_policy(from_c_str(path)?, from_c_str(rego)?)
    }())
}

#[cfg(feature = "std")]
#[no_mangle]
pub extern "C" fn regorus_engine_add_policy_from_file(
    engine: *mut RegorusEngine,
    path: *const c_char,
) -> RegorusResult {
    to_regorus_string_result(|| -> Result<String> {
        to_ref(engine)?
            .engine
            .add_policy_from_file(from_c_str(path)?)
    }())
}

/// Add policy data.
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.add_data
/// * `data`: JSON encoded value to be used as policy data.
#[no_mangle]
pub extern "C" fn regorus_engine_add_data_json(
    engine: *mut RegorusEngine,
    data: *const c_char,
) -> RegorusResult {
    to_regorus_result(|| -> Result<()> {
        to_ref(engine)?
            .engine
            .add_data(regorus::Value::from_json_str(&from_c_str(data)?)?)
    }())
}

/// Get list of loaded Rego packages as JSON.
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.get_packages
#[no_mangle]
pub extern "C" fn regorus_engine_get_packages(engine: *mut RegorusEngine) -> RegorusResult {
    to_regorus_string_result(|| -> Result<String> {
        serde_json::to_string_pretty(&to_ref(engine)?.engine.get_packages()?)
            .map_err(anyhow::Error::msg)
    }())
}

/// Get list of policies as JSON.
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.get_policies
#[no_mangle]
pub extern "C" fn regorus_engine_get_policies(engine: *mut RegorusEngine) -> RegorusResult {
    to_regorus_string_result(|| -> Result<String> {
        to_ref(engine)?.engine.get_policies_as_json()
    }())
}

#[cfg(feature = "std")]
#[no_mangle]
pub extern "C" fn regorus_engine_add_data_from_json_file(
    engine: *mut RegorusEngine,
    path: *const c_char,
) -> RegorusResult {
    to_regorus_result(|| -> Result<()> {
        to_ref(engine)?
            .engine
            .add_data(regorus::Value::from_json_file(from_c_str(path)?)?)
    }())
}

/// Clear policy data.
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.clear_data
#[no_mangle]
pub extern "C" fn regorus_engine_clear_data(engine: *mut RegorusEngine) -> RegorusResult {
    to_regorus_result(|| -> Result<()> {
        to_ref(engine)?.engine.clear_data();
        Ok(())
    }())
}

/// Set input.
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.set_input
/// * `input`: JSON encoded value to be used as input to query.
#[no_mangle]
pub extern "C" fn regorus_engine_set_input_json(
    engine: *mut RegorusEngine,
    input: *const c_char,
) -> RegorusResult {
    to_regorus_result(|| -> Result<()> {
        to_ref(engine)?
            .engine
            .set_input(regorus::Value::from_json_str(&from_c_str(input)?)?);
        Ok(())
    }())
}

#[cfg(feature = "std")]
#[no_mangle]
pub extern "C" fn regorus_engine_set_input_from_json_file(
    engine: *mut RegorusEngine,
    path: *const c_char,
) -> RegorusResult {
    to_regorus_result(|| -> Result<()> {
        to_ref(engine)?
            .engine
            .set_input(regorus::Value::from_json_file(from_c_str(path)?)?);
        Ok(())
    }())
}

/// Evaluate query.
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.eval_query
/// * `query`: Rego expression to be evaluate.
#[no_mangle]
pub extern "C" fn regorus_engine_eval_query(
    engine: *mut RegorusEngine,
    query: *const c_char,
) -> RegorusResult {
    let output = || -> Result<String> {
        let results = to_ref(engine)?
            .engine
            .eval_query(from_c_str(query)?, false)?;
        Ok(serde_json::to_string_pretty(&results)?)
    }();
    match output {
        Ok(out) => RegorusResult::ok_string(out),
        Err(e) => to_regorus_result(Err(e)),
    }
}

/// Evaluate specified rule.
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.eval_rule
/// * `rule`: Path to the rule.
#[no_mangle]
pub extern "C" fn regorus_engine_eval_rule(
    engine: *mut RegorusEngine,
    rule: *const c_char,
) -> RegorusResult {
    let output = || -> Result<String> {
        to_ref(engine)?
            .engine
            .eval_rule(from_c_str(rule)?)?
            .to_json_str()
    }();
    match output {
        Ok(out) => RegorusResult::ok_string(out),
        Err(e) => to_regorus_result(Err(e)),
    }
}

/// Enable/disable coverage.
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.set_enable_coverage
/// * `enable`: Whether to enable or disable coverage.
#[no_mangle]
#[cfg(feature = "coverage")]
pub extern "C" fn regorus_engine_set_enable_coverage(
    engine: *mut RegorusEngine,
    enable: bool,
) -> RegorusResult {
    to_regorus_result(|| -> Result<()> {
        to_ref(engine)?.engine.set_enable_coverage(enable);
        Ok(())
    }())
}

/// Get coverage report.
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.get_coverage_report
#[no_mangle]
#[cfg(feature = "coverage")]
pub extern "C" fn regorus_engine_get_coverage_report(engine: *mut RegorusEngine) -> RegorusResult {
    let output = || -> Result<String> {
        Ok(serde_json::to_string_pretty(
            &to_ref(engine)?.engine.get_coverage_report()?,
        )?)
    }();
    match output {
        Ok(out) => RegorusResult::ok_string(out),
        Err(e) => to_regorus_result(Err(e)),
    }
}

/// Enable/disable strict builtin errors.
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.set_strict_builtin_errors
/// * `strict`: Whether to raise errors or return undefined on certain scenarios.
#[no_mangle]
pub extern "C" fn regorus_engine_set_strict_builtin_errors(
    engine: *mut RegorusEngine,
    strict: bool,
) -> RegorusResult {
    to_regorus_result(|| -> Result<()> {
        to_ref(engine)?.engine.set_strict_builtin_errors(strict);
        Ok(())
    }())
}

/// Get pretty printed coverage report.
///
/// See https://docs.rs/regorus/latest/regorus/coverage/struct.Report.html#method.to_string_pretty
#[no_mangle]
#[cfg(feature = "coverage")]
pub extern "C" fn regorus_engine_get_coverage_report_pretty(
    engine: *mut RegorusEngine,
) -> RegorusResult {
    let output = || -> Result<String> {
        to_ref(engine)?
            .engine
            .get_coverage_report()?
            .to_string_pretty()
    }();
    match output {
        Ok(out) => RegorusResult::ok_string(out),
        Err(e) => to_regorus_result(Err(e)),
    }
}

/// Clear coverage data.
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.clear_coverage_data
#[no_mangle]
#[cfg(feature = "coverage")]
pub extern "C" fn regorus_engine_clear_coverage_data(engine: *mut RegorusEngine) -> RegorusResult {
    to_regorus_result(|| -> Result<()> {
        to_ref(engine)?.engine.clear_coverage_data();
        Ok(())
    }())
}

/// Whether to gather output of print statements.
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.set_gather_prints
/// * `enable`: Whether to enable or disable gathering print statements.
#[no_mangle]
pub extern "C" fn regorus_engine_set_gather_prints(
    engine: *mut RegorusEngine,
    enable: bool,
) -> RegorusResult {
    to_regorus_result(|| -> Result<()> {
        to_ref(engine)?.engine.set_gather_prints(enable);
        Ok(())
    }())
}

/// Take all the gathered print statements.
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.take_prints
#[no_mangle]
pub extern "C" fn regorus_engine_take_prints(engine: *mut RegorusEngine) -> RegorusResult {
    let output = || -> Result<String> {
        Ok(serde_json::to_string_pretty(
            &to_ref(engine)?.engine.take_prints()?,
        )?)
    }();
    match output {
        Ok(out) => RegorusResult::ok_string(out),
        Err(e) => to_regorus_result(Err(e)),
    }
}

/// Get AST of policies.
///
/// See https://docs.rs/regorus/latest/regorus/coverage/struct.Engine.html#method.get_ast_as_json
#[no_mangle]
#[cfg(feature = "ast")]
pub extern "C" fn regorus_engine_get_ast_as_json(engine: *mut RegorusEngine) -> RegorusResult {
    let output = || -> Result<String> { to_ref(engine)?.engine.get_ast_as_json() }();
    match output {
        Ok(out) => RegorusResult::ok_string(out),
        Err(e) => to_regorus_result(Err(e)),
    }
}

/// Gets the package names defined in each policy added to the engine.
///
/// See https://docs.rs/regorus/latest/regorus/coverage/struct.Engine.html#method.get_policy_package_names
#[no_mangle]
#[cfg(feature = "azure_policy")]
pub extern "C" fn regorus_engine_get_policy_package_names(
    engine: *mut RegorusEngine,
) -> RegorusResult {
    let output = || -> Result<String> {
        serde_json::to_string_pretty(&to_ref(engine)?.engine.get_policy_package_names()?)
            .map_err(anyhow::Error::msg)
    }();
    match output {
        Ok(out) => RegorusResult::ok_string(out),
        Err(e) => to_regorus_result(Err(e)),
    }
}

/// Gets the parameters defined in each policy added to the engine.
///
/// See https://docs.rs/regorus/latest/regorus/coverage/struct.Engine.html#method.get_policy_parameters
#[no_mangle]
#[cfg(feature = "azure_policy")]
pub extern "C" fn regorus_engine_get_policy_parameters(
    engine: *mut RegorusEngine,
) -> RegorusResult {
    let output = || -> Result<String> {
        serde_json::to_string_pretty(&to_ref(engine)?.engine.get_policy_parameters()?)
            .map_err(anyhow::Error::msg)
    }();
    match output {
        Ok(out) => RegorusResult::ok_string(out),
        Err(e) => to_regorus_result(Err(e)),
    }
}

/// Enable/disable rego v1.
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.set_rego_v0
#[no_mangle]
pub extern "C" fn regorus_engine_set_rego_v0(
    engine: *mut RegorusEngine,
    enable: bool,
) -> RegorusResult {
    let output = || -> Result<()> {
        to_ref(engine)?.engine.set_rego_v0(enable);
        Ok(())
    }();
    match output {
        Ok(()) => RegorusResult::ok_void(),
        Err(e) => to_regorus_result(Err(e)),
    }
}

/// Compile a target-aware policy from the current engine state.
///
/// This method creates a compiled policy that can work with Azure Policy targets,
/// enabling resource type inference and target-specific evaluation.
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.compile_for_target
#[no_mangle]
#[cfg(feature = "azure_policy")]
pub extern "C" fn regorus_engine_compile_for_target(engine: *mut RegorusEngine) -> RegorusResult {
    match to_ref(engine) {
        Ok(e) => match e.engine.compile_for_target() {
            Ok(compiled_policy) => {
                let wrapped_policy = RegorusCompiledPolicy { compiled_policy };
                let boxed_policy = Box::new(wrapped_policy);
                RegorusResult::ok_pointer(Box::into_raw(boxed_policy) as *mut std::os::raw::c_void)
            }
            Err(e) => RegorusResult::err_with_message(
                RegorusStatus::CompilationFailed,
                format!("Failed to compile for target: {e}"),
            ),
        },
        Err(e) => RegorusResult::err_with_message(
            RegorusStatus::InvalidArgument,
            format!("Failed to get engine reference: {e}"),
        ),
    }
}

/// Compile a policy with a specific entry point rule.
///
/// This method creates a compiled policy that evaluates a specific rule as the entry point.
///
/// See https://docs.rs/regorus/latest/regorus/struct.Engine.html#method.compile_with_entrypoint
/// * `rule`: The specific rule path to evaluate (e.g., "data.policy.allow")
#[no_mangle]
pub extern "C" fn regorus_engine_compile_with_entrypoint(
    engine: *mut RegorusEngine,
    rule: *const c_char,
) -> RegorusResult {
    let result = || -> Result<RegorusCompiledPolicy> {
        let rule_str = from_c_str(rule)?;
        let rule_rc: regorus::Rc<str> = rule_str.into();
        let compiled_policy = to_ref(engine)?.engine.compile_with_entrypoint(&rule_rc)?;
        Ok(RegorusCompiledPolicy { compiled_policy })
    }();

    match result {
        Ok(wrapped_policy) => {
            let boxed_policy = Box::new(wrapped_policy);
            RegorusResult::ok_pointer(Box::into_raw(boxed_policy) as *mut std::os::raw::c_void)
        }
        Err(e) => RegorusResult::err_with_message(
            RegorusStatus::CompilationFailed,
            format!("Failed to compile with entrypoint: {e}"),
        ),
    }
}
