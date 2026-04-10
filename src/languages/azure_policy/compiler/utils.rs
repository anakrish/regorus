// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#![allow(dead_code)]
#![allow(
    clippy::arithmetic_side_effects,
    clippy::if_then_some_else_none,
    clippy::pattern_type_mismatch,
    clippy::redundant_pub_crate
)]

//! Free helper functions used by the Azure Policy compiler.

use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

use anyhow::{anyhow, bail, Result};

use crate::languages::azure_policy::ast::{Expr, ExprLiteral, JsonValue, ObjectEntry};
use crate::Value;

/// Extract a string literal from an expression, or bail.
pub(super) fn extract_string_literal(expr: &Expr) -> Result<String> {
    match expr {
        Expr::Literal {
            value: ExprLiteral::String(value),
            ..
        } => Ok(value.clone()),
        other => bail!("expected string literal argument, found {:?}", other),
    }
}

/// Split a count field path at the `[*]` wildcard into `(prefix, optional_suffix)`.
pub(super) fn split_count_wildcard_path(path: &str) -> Result<(String, Option<String>)> {
    let wildcard_index = path
        .find("[*]")
        .ok_or_else(|| anyhow!("count.field must contain [*]: {}", path))?;

    let prefix = path[..wildcard_index].to_string();
    let suffix = if wildcard_index + 3 < path.len() {
        let rest = &path[wildcard_index + 3..];
        Some(rest.trim_start_matches('.').to_string())
    } else {
        None
    };

    Ok((prefix, suffix))
}

/// Split a dotted path (without `[*]` wildcards) into its component segments.
///
/// Handles bracket notation:
///   - `tags['key']` → `["tags", "key"]`
///   - `properties['network-acls']` → `["properties", "network-acls"]`
///   - `properties.ipRules[0].value` → `["properties", "ipRules", "0", "value"]`
pub(super) fn split_path_without_wildcards(path: &str) -> Result<Vec<String>> {
    if path.contains("[*]") {
        bail!(
            "wildcard field paths are not supported in this context: {}",
            path
        );
    }

    let mut parts = Vec::new();
    let mut token = String::new();
    let mut bracket = String::new();
    let mut in_bracket = false;

    for ch in path.chars() {
        match ch {
            '.' if !in_bracket => {
                let t = token.trim();
                if !t.is_empty() {
                    parts.push(t.to_string());
                }
                token.clear();
            }
            '[' => {
                in_bracket = true;
                let t = token.trim();
                if !t.is_empty() {
                    parts.push(t.to_string());
                }
                token.clear();
            }
            ']' => {
                in_bracket = false;
                let cleaned = bracket.trim_matches('"').trim_matches('\'').to_string();
                if !cleaned.is_empty() {
                    parts.push(cleaned);
                }
                bracket.clear();
            }
            _ => {
                if in_bracket {
                    bracket.push(ch);
                } else {
                    token.push(ch);
                }
            }
        }
    }

    let t = token.trim();
    if !t.is_empty() {
        parts.push(t.to_string());
    }

    Ok(parts)
}

/// Convert a parsed JSON value from the Azure Policy AST into a runtime [`Value`].
pub(crate) fn json_value_to_runtime(value: &JsonValue) -> Result<Value> {
    match value {
        JsonValue::Null(_) => Ok(Value::Null),
        JsonValue::Bool(_, b) => Ok(Value::Bool(*b)),
        JsonValue::Number(_, raw) => {
            if let Ok(n) = raw.parse::<i64>() {
                return Ok(Value::from(n));
            }
            if let Ok(n) = raw.parse::<f64>() {
                return Ok(Value::from(n));
            }
            bail!("invalid number literal: {}", raw)
        }
        JsonValue::Str(_, s) => Ok(Value::from(s.clone())),
        JsonValue::Array(_, items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(json_value_to_runtime(item)?);
            }
            Ok(Value::from(out))
        }
        JsonValue::Object(_, entries) => {
            let mut obj = Value::new_object();
            let map = obj.as_object_mut()?;
            for ObjectEntry {
                key,
                value: entry_value,
                ..
            } in entries
            {
                map.insert(
                    Value::from(key.clone()),
                    json_value_to_runtime(entry_value)?,
                );
            }
            Ok(obj)
        }
    }
}
