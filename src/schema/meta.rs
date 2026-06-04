// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(dead_code)]
use crate::*;
use lazy_static::lazy_static;

const META_SCHEMA: &str = include_str!("meta.schema.json");

lazy_static! {
    /// Lazy static JSON Schema validator for the Regorus meta-schema.
    /// This validator is initialized once and can be used to validate
    /// any schema definition against the Regorus meta-schema format.
    static ref META_SCHEMA_VALIDATOR: Result<jsonschema::Validator, String> = {
        let meta_schema_json: serde_json::Value =
            serde_json::from_str(META_SCHEMA).map_err(|e| e.to_string())?;

        jsonschema::validator_for(&meta_schema_json).map_err(|e| e.to_string())
    };
}

pub(super) fn get_meta_schema() -> &'static str {
    META_SCHEMA
}

/// Validates a schema definition against the Regorus meta-schema.
/// Returns true if the schema is valid, false otherwise.
pub(super) fn validate_schema(schema: &serde_json::Value) -> bool {
    match META_SCHEMA_VALIDATOR.as_ref() {
        Ok(validator) => validator.is_valid(schema),
        Err(_) => false,
    }
}

/// Validates a schema definition against the Regorus meta-schema.
/// Returns Ok(()) if valid, or Err with validation errors if invalid.
pub(super) fn validate_schema_detailed(schema: &serde_json::Value) -> Result<(), Vec<String>> {
    let validator = META_SCHEMA_VALIDATOR
        .as_ref()
        .map_err(|e| vec![format!("meta-schema initialization failed: {e}")])?;

    if let jsonschema::BasicOutput::Invalid(errors) = validator.apply(schema).basic() {
        let msgs: alloc::collections::BTreeSet<String> = errors
            .iter()
            .map(|e| format!("{}: {}", e.instance_location(), e.error_description()))
            .collect();
        let msgs: Vec<String> = msgs.into_iter().collect();
        return Err(msgs);
    }

    Ok(())
}

/// Validates a schema definition from a JSON string.
/// Returns true if the schema is valid, false otherwise.
pub(super) fn validate_schema_str(schema_str: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(schema_str) {
        Ok(schema) => validate_schema(&schema),
        Err(_) => false, // Invalid JSON
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests;
