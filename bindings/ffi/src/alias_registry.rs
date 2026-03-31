// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! FFI bindings for `AliasRegistry` – Azure Policy alias catalog management.

#![cfg(feature = "azure_policy")]

use crate::common::{from_c_str, to_ref, RegorusResult, RegorusStatus};
use crate::panic_guard::with_unwind_guard;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use anyhow::Result;
use core::ffi::{c_char, c_void};
use core::ptr;

use regorus::languages::azure_policy::aliases::AliasRegistry;
use regorus::Source;

/// Opaque wrapper for `AliasRegistry`.
pub struct RegorusAliasRegistry {
    registry: AliasRegistry,
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Create a new, empty `AliasRegistry`.
///
/// The caller must eventually call `regorus_alias_registry_drop` to free the handle.
#[no_mangle]
pub extern "C" fn regorus_alias_registry_new() -> *mut RegorusAliasRegistry {
    let wrapper = RegorusAliasRegistry {
        registry: AliasRegistry::new(),
    };
    Box::into_raw(Box::new(wrapper))
}

/// Drop a `RegorusAliasRegistry`.
#[no_mangle]
pub extern "C" fn regorus_alias_registry_drop(registry: *mut RegorusAliasRegistry) {
    if let Ok(r) = to_ref(registry) {
        unsafe {
            let _ = Box::from_raw(ptr::from_mut(r));
        }
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Load control-plane alias data (array of `ProviderAliases`) into the registry.
///
/// `json` must be a valid null-terminated UTF-8 string containing the JSON
/// array returned by `Get-AzPolicyAlias` or the static
/// `ResourceTypesAndAliases.json` file.
#[no_mangle]
pub extern "C" fn regorus_alias_registry_load_json(
    registry: *mut RegorusAliasRegistry,
    json: *const c_char,
) -> RegorusResult {
    with_unwind_guard(|| {
        let output = || -> Result<()> {
            let json_str = from_c_str(json)?;
            to_ref(registry)?.registry.load_from_json(&json_str)?;
            Ok(())
        }();

        match output {
            Ok(()) => RegorusResult::ok_void(),
            Err(e) => RegorusResult::err_with_message(
                RegorusStatus::InvalidDataFormat,
                format!("Failed to load alias catalog: {e}"),
            ),
        }
    })
}

/// Load a data-plane policy manifest into the registry.
///
/// `json` must be a valid null-terminated UTF-8 string containing a single
/// `DataPolicyManifest` JSON object.
#[no_mangle]
pub extern "C" fn regorus_alias_registry_load_manifest(
    registry: *mut RegorusAliasRegistry,
    json: *const c_char,
) -> RegorusResult {
    with_unwind_guard(|| {
        let output = || -> Result<()> {
            let json_str = from_c_str(json)?;
            to_ref(registry)?
                .registry
                .load_data_policy_manifest_json(&json_str)?;
            Ok(())
        }();

        match output {
            Ok(()) => RegorusResult::ok_void(),
            Err(e) => RegorusResult::err_with_message(
                RegorusStatus::InvalidDataFormat,
                format!("Failed to load data-plane manifest: {e}"),
            ),
        }
    })
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

/// Return the number of resource types loaded in the alias registry.
#[no_mangle]
pub extern "C" fn regorus_alias_registry_len(registry: *mut RegorusAliasRegistry) -> RegorusResult {
    with_unwind_guard(|| {
        let output = || -> Result<i64> {
            let len = to_ref(registry)?.registry.len();
            Ok(len as i64)
        }();

        match output {
            Ok(n) => RegorusResult::ok_int(n),
            Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{e}")),
        }
    })
}

// ---------------------------------------------------------------------------
// Normalize / Denormalize
// ---------------------------------------------------------------------------

/// Normalize an ARM resource JSON and wrap it into the standard input envelope.
///
/// Returns a JSON string: `{ "resource": <normalized>, "parameters": <params> }`.
///
/// * `resource_json` – raw ARM resource JSON
/// * `api_version` – API version string (e.g. `"2023-01-01"`)
/// * `context_json` – JSON object for additional context (pass `"{}"` if none)
/// * `parameters_json` – JSON object of policy parameter values (pass `"{}"` if none)
#[no_mangle]
pub extern "C" fn regorus_alias_registry_normalize_and_wrap(
    registry: *mut RegorusAliasRegistry,
    resource_json: *const c_char,
    api_version: *const c_char,
    context_json: *const c_char,
    parameters_json: *const c_char,
) -> RegorusResult {
    with_unwind_guard(|| {
        let output = || -> Result<String> {
            let resource_str = from_c_str(resource_json)?;
            let api_str = from_c_str(api_version)?;
            let context_str = from_c_str(context_json)?;
            let params_str = from_c_str(parameters_json)?;

            let resource: serde_json::Value = serde_json::from_str(&resource_str)?;
            let context: serde_json::Value = serde_json::from_str(&context_str)?;
            let params: serde_json::Value = serde_json::from_str(&params_str)?;

            let wrapped = to_ref(registry)?.registry.normalize_and_wrap(
                &resource,
                Some(&api_str),
                Some(context),
                Some(params),
            );
            serde_json::to_string(&wrapped)
                .map_err(|e| anyhow::anyhow!("Failed to serialize normalized input: {e}"))
        }();

        match output {
            Ok(s) => RegorusResult::ok_string(s),
            Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{e}")),
        }
    })
}

/// Denormalize a previously-normalized resource JSON back to ARM format.
///
/// * `normalized_json` – the normalized resource JSON
/// * `api_version` – API version string
///
/// Returns the denormalized ARM JSON string.
#[no_mangle]
pub extern "C" fn regorus_alias_registry_denormalize(
    registry: *mut RegorusAliasRegistry,
    normalized_json: *const c_char,
    api_version: *const c_char,
) -> RegorusResult {
    with_unwind_guard(|| {
        let output = || -> Result<String> {
            let normalized_str = from_c_str(normalized_json)?;
            let api_str = from_c_str(api_version)?;

            let normalized: serde_json::Value = serde_json::from_str(&normalized_str)?;

            let result = to_ref(registry)?
                .registry
                .denormalize(&normalized, Some(&api_str));
            serde_json::to_string(&result)
                .map_err(|e| anyhow::anyhow!("Failed to serialize denormalized output: {e}"))
        }();

        match output {
            Ok(s) => RegorusResult::ok_string(s),
            Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{e}")),
        }
    })
}

// ---------------------------------------------------------------------------
// Compilation helpers
// ---------------------------------------------------------------------------

/// Compile an Azure Policy definition JSON into an RVM program.
///
/// This parses the policy JSON, extracts alias maps from the registry,
/// and compiles to an RVM `Program`.
///
/// * `registry` – alias registry handle (may be null for no alias resolution)
/// * `policy_json` – Azure Policy definition JSON string
///
/// Returns a `RegorusProgram` handle on success.
#[no_mangle]
pub extern "C" fn regorus_compile_azure_policy_definition(
    registry: *mut RegorusAliasRegistry,
    policy_json: *const c_char,
) -> RegorusResult {
    with_unwind_guard(|| {
        let output = || -> Result<*mut crate::rvm::RegorusProgram> {
            let policy_str = from_c_str(policy_json)?;
            let source = Source::from_contents("policy.json".into(), policy_str)?;
            let defn = regorus::languages::azure_policy::parser::parse_policy_definition(&source)
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            let program = if registry.is_null() {
                regorus::languages::azure_policy::compiler::compile_policy_definition(&defn)?
            } else {
                let reg = to_ref(registry)?;
                let alias_map = reg.registry.alias_map();
                let alias_modifiable = reg.registry.alias_modifiable_map();
                regorus::languages::azure_policy::compiler::compile_policy_definition_with_aliases(
                    &defn,
                    alias_map,
                    alias_modifiable,
                )?
            };

            Ok(Box::into_raw(Box::new(crate::rvm::RegorusProgram {
                program,
            })))
        }();

        match output {
            Ok(program) => RegorusResult::ok_pointer(program as *mut c_void),
            Err(e) => RegorusResult::err_with_message(
                RegorusStatus::CompilationFailed,
                format!("Azure Policy compilation failed: {e}"),
            ),
        }
    })
}
