// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
/// Handles `tags['key']` syntax by expanding it to two segments: `tags`, `key`.
pub(super) fn split_path_without_wildcards(path: &str) -> Result<Vec<String>> {
    if path.contains("[*]") {
        bail!(
            "wildcard field paths are not supported in this context: {}",
            path
        );
    }

    let mut parts = Vec::new();
    for segment in path.split('.') {
        let trimmed = segment.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(tag_key) = trimmed
            .strip_prefix("tags['")
            .and_then(|value| value.strip_suffix("']"))
        {
            parts.push("tags".to_string());
            parts.push(tag_key.to_string());
            continue;
        }

        parts.push(trimmed.to_string());
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
