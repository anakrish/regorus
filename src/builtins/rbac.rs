// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RBAC-specific builtin functions
//!
//! This module implements Azure RBAC-specific operators and functions that are not
//! available in the standard Regorus builtin library.

use crate::ast::{Expr, Ref};
use crate::builtins;
use crate::builtins::utils::ensure_args_count;
use crate::lexer::Span;
use crate::value::Value;
use alloc::{format, vec::Vec};
use anyhow::{bail, Result};

pub fn register(m: &mut builtins::BuiltinsMap<&'static str, builtins::BuiltinFcn>) {
    // Action and permission matching
    m.insert("rbac.action_matches", (action_matches, 2));
    m.insert("rbac.suboperation_matches", (suboperation_matches, 2));

    // Numeric operations
    m.insert("rbac.numeric_in_range", (numeric_in_range, 2));

    // List operations
    m.insert("rbac.list_contains", (list_contains, 2));
    m.insert("rbac.list_not_contains", (list_not_contains, 2));

    // Time-of-day operations
    m.insert("rbac.time_of_day_equals", (time_of_day_equals, 2));
    m.insert("rbac.time_of_day_not_equals", (time_of_day_not_equals, 2));
    m.insert(
        "rbac.time_of_day_greater_than",
        (time_of_day_greater_than, 2),
    );
    m.insert(
        "rbac.time_of_day_greater_than_equals",
        (time_of_day_greater_than_equals, 2),
    );
    m.insert("rbac.time_of_day_less_than", (time_of_day_less_than, 2));
    m.insert(
        "rbac.time_of_day_less_than_equals",
        (time_of_day_less_than_equals, 2),
    );
    m.insert("rbac.time_of_day_in_range", (time_of_day_in_range, 2));

    // IP address operations
    m.insert("rbac.ip_match", (ip_match, 2));
    m.insert("rbac.ip_not_match", (ip_not_match, 2));
    m.insert("rbac.ip_in_range", (ip_in_range, 3));

    // Cross-product operations
    m.insert("rbac.for_any_of_any_values", (for_any_of_any_values, 3));
    m.insert("rbac.for_all_of_any_values", (for_all_of_any_values, 3));
    m.insert("rbac.for_any_of_all_values", (for_any_of_all_values, 3));
    m.insert("rbac.for_all_of_all_values", (for_all_of_all_values, 3));

    // Existence checks
    m.insert("rbac.attribute_exists", (attribute_exists, 1));
    m.insert("rbac.attribute_not_exists", (attribute_not_exists, 1));
}

/// Check if action matches pattern with wildcards
///
/// Azure actions follow the pattern: Provider/Resource/Action
/// Example: "Microsoft.Storage/storageAccounts/read"
/// Wildcards (*) match any value at that level
fn action_matches(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let name = "rbac.action_matches";
    ensure_args_count(span, name, params, args, 2)?;

    let action_str = match &args[0] {
        Value::String(s) => s.as_ref(),
        _ => bail!(params[0].span().error("action must be a string")),
    };

    let pattern_str = match &args[1] {
        Value::String(s) => s.as_ref(),
        _ => bail!(params[1].span().error("pattern must be a string")),
    };

    // Split on '/' to get hierarchical parts
    let action_parts: Vec<&str> = action_str.split('/').collect();
    let pattern_parts: Vec<&str> = pattern_str.split('/').collect();

    // Must have same number of parts
    if action_parts.len() != pattern_parts.len() {
        return Ok(Value::Bool(false));
    }

    // Check each part - '*' matches anything
    for (action_part, pattern_part) in action_parts.iter().zip(pattern_parts.iter()) {
        if *pattern_part == "*" {
            continue; // Wildcard matches anything
        }
        if action_part != pattern_part {
            return Ok(Value::Bool(false));
        }
    }

    Ok(Value::Bool(true))
}

/// Check if sub-operation matches pattern
fn suboperation_matches(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let name = "rbac.suboperation_matches";
    ensure_args_count(span, name, params, args, 2)?;

    let subop_str = match &args[0] {
        Value::String(s) => s.as_ref(),
        _ => bail!(params[0].span().error("sub-operation must be a string")),
    };

    let pattern_str = match &args[1] {
        Value::String(s) => s.as_ref(),
        _ => bail!(params[1].span().error("pattern must be a string")),
    };

    // For now, exact match. Can be enhanced for hierarchical matching
    Ok(Value::Bool(subop_str == pattern_str))
}

/// Check if numeric value is in range [start, end] inclusive
fn numeric_in_range(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let name = "rbac.numeric_in_range";
    ensure_args_count(span, name, params, args, 2)?;

    let num = match &args[0] {
        Value::Number(n) => n.as_f64(),
        _ => bail!(params[0].span().error("value must be a number")),
    };

    let array = match &args[1] {
        Value::Array(a) => a.iter().collect::<Vec<_>>(),
        _ => bail!(params[1].span().error("range must be an array")),
    };

    if array.len() != 2 {
        bail!(params[1]
            .span()
            .error("range must have exactly 2 elements [start, end]"));
    }

    let start = match array[0] {
        Value::Number(n) => n.as_f64(),
        _ => bail!(params[1].span().error("range start must be a number")),
    };

    let end = match array[1] {
        Value::Number(n) => n.as_f64(),
        _ => bail!(params[1].span().error("range end must be a number")),
    };

    Ok(Value::Bool(num >= start && num <= end))
}

/// Check if list/array contains value
fn list_contains(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let name = "rbac.list_contains";
    ensure_args_count(span, name, params, args, 2)?;

    let array = match &args[0] {
        Value::Array(a) => a.iter().collect::<Vec<_>>(),
        _ => bail!(params[0].span().error("first argument must be an array")),
    };

    let value = &args[1];

    Ok(Value::Bool(array.iter().any(|item| *item == value)))
}

/// Check if list/array does not contain value
fn list_not_contains(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let result = list_contains(span, params, args, _strict)?;
    match result {
        Value::Bool(b) => Ok(Value::Bool(!b)),
        _ => unreachable!(),
    }
}

/// Parse time string "HH:MM" or "HH:MM:SS" to seconds since midnight
fn parse_time_of_day(time_str: &str, span: &Span) -> Result<u32> {
    let parts: Vec<&str> = time_str.split(':').collect();

    if parts.len() < 2 || parts.len() > 3 {
        bail!(span.error("invalid time format. Expected 'HH:MM' or 'HH:MM:SS'"));
    }

    let hours = parts[0]
        .parse::<u32>()
        .map_err(|_| span.error("invalid hours in time string"))?;
    let minutes = parts[1]
        .parse::<u32>()
        .map_err(|_| span.error("invalid minutes in time string"))?;
    let seconds = if parts.len() == 3 {
        parts[2]
            .parse::<u32>()
            .map_err(|_| span.error("invalid seconds in time string"))?
    } else {
        0
    };

    if hours > 23 || minutes > 59 || seconds > 59 {
        bail!(span.error("time values out of range"));
    }

    Ok(hours * 3600 + minutes * 60 + seconds)
}

/// Time-of-day comparison helper
fn time_of_day_compare_impl(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    op: &str,
) -> Result<Value> {
    ensure_args_count(span, "time_of_day_compare", params, args, 2)?;

    let left_str = match &args[0] {
        Value::String(s) => s.as_ref(),
        _ => bail!(params[0].span().error("time must be a string")),
    };

    let right_str = match &args[1] {
        Value::String(s) => s.as_ref(),
        _ => bail!(params[1].span().error("time must be a string")),
    };

    let left_seconds = parse_time_of_day(left_str, &params[0].span())?;
    let right_seconds = parse_time_of_day(right_str, &params[1].span())?;

    let result = match op {
        "==" => left_seconds == right_seconds,
        "!=" => left_seconds != right_seconds,
        ">" => left_seconds > right_seconds,
        ">=" => left_seconds >= right_seconds,
        "<" => left_seconds < right_seconds,
        "<=" => left_seconds <= right_seconds,
        _ => bail!(span.error(&format!("unknown comparison operator: {}", op))),
    };

    Ok(Value::Bool(result))
}

fn time_of_day_equals(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    time_of_day_compare_impl(span, params, args, "==")
}

fn time_of_day_not_equals(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    time_of_day_compare_impl(span, params, args, "!=")
}

fn time_of_day_greater_than(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    time_of_day_compare_impl(span, params, args, ">")
}

fn time_of_day_greater_than_equals(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    time_of_day_compare_impl(span, params, args, ">=")
}

fn time_of_day_less_than(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    time_of_day_compare_impl(span, params, args, "<")
}

fn time_of_day_less_than_equals(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    time_of_day_compare_impl(span, params, args, "<=")
}

/// Check if time of day is in range [start, end] inclusive
fn time_of_day_in_range(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let name = "rbac.time_of_day_in_range";
    ensure_args_count(span, name, params, args, 2)?;

    let time_str = match &args[0] {
        Value::String(s) => s.as_ref(),
        _ => bail!(params[0].span().error("time must be a string")),
    };

    let array = match &args[1] {
        Value::Array(a) => a.iter().collect::<Vec<_>>(),
        _ => bail!(params[1].span().error("range must be an array")),
    };

    if array.len() != 2 {
        bail!(params[1]
            .span()
            .error("range must have exactly 2 elements [start, end]"));
    }

    let start_str = match array[0] {
        Value::String(s) => s.as_ref(),
        _ => bail!(params[1].span().error("range start must be a string")),
    };

    let end_str = match array[1] {
        Value::String(s) => s.as_ref(),
        _ => bail!(params[1].span().error("range end must be a string")),
    };

    let time_seconds = parse_time_of_day(time_str, &params[0].span())?;
    let start_seconds = parse_time_of_day(start_str, &params[1].span())?;
    let end_seconds = parse_time_of_day(end_str, &params[1].span())?;

    Ok(Value::Bool(
        time_seconds >= start_seconds && time_seconds <= end_seconds,
    ))
}

/// Parse IPv4 address to u32
fn parse_ipv4(ip: &str, span: &Span) -> Result<u32> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        bail!(span.error(&format!("invalid IPv4 address: {}", ip)));
    }

    let mut result: u32 = 0;
    for part in parts {
        let octet = part
            .parse::<u32>()
            .map_err(|_| span.error(&format!("invalid octet in IPv4 address: {}", part)))?;
        if octet > 255 {
            bail!(span.error(&format!("octet out of range: {}", octet)));
        }
        result = (result << 8) | octet;
    }

    Ok(result)
}

/// Parse CIDR notation (e.g., "192.168.1.0/24")
fn parse_cidr(cidr: &str, span: &Span) -> Result<(u32, u32)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        bail!(span.error(&format!("invalid CIDR notation: {}", cidr)));
    }

    let ip = parse_ipv4(parts[0], span)?;
    let prefix_len = parts[1]
        .parse::<u32>()
        .map_err(|_| span.error("invalid prefix length in CIDR"))?;

    if prefix_len > 32 {
        bail!(span.error(&format!("prefix length out of range: {}", prefix_len)));
    }

    let mask = if prefix_len == 0 {
        0
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    };

    Ok((ip & mask, mask))
}

/// Check if IP address matches CIDR pattern
fn ip_match(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "rbac.ip_match";
    ensure_args_count(span, name, params, args, 2)?;

    let ip_str = match &args[0] {
        Value::String(s) => s.as_ref(),
        _ => bail!(params[0].span().error("IP address must be a string")),
    };

    let cidr_str = match &args[1] {
        Value::String(s) => s.as_ref(),
        _ => bail!(params[1].span().error("CIDR pattern must be a string")),
    };

    let ip_addr = parse_ipv4(ip_str, &params[0].span())?;
    let (network, mask) = parse_cidr(cidr_str, &params[1].span())?;

    Ok(Value::Bool((ip_addr & mask) == network))
}

/// Check if IP address does not match CIDR pattern
fn ip_not_match(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let result = ip_match(span, params, args, _strict)?;
    match result {
        Value::Bool(b) => Ok(Value::Bool(!b)),
        _ => unreachable!(),
    }
}

/// Check if IP is in range [start, end] inclusive
fn ip_in_range(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "rbac.ip_in_range";
    ensure_args_count(span, name, params, args, 3)?;

    let ip_str = match &args[0] {
        Value::String(s) => s.as_ref(),
        _ => bail!(params[0].span().error("IP address must be a string")),
    };

    let start_str = match &args[1] {
        Value::String(s) => s.as_ref(),
        _ => bail!(params[1].span().error("start IP must be a string")),
    };

    let end_str = match &args[2] {
        Value::String(s) => s.as_ref(),
        _ => bail!(params[2].span().error("end IP must be a string")),
    };

    let ip_addr = parse_ipv4(ip_str, &params[0].span())?;
    let start_addr = parse_ipv4(start_str, &params[1].span())?;
    let end_addr = parse_ipv4(end_str, &params[2].span())?;

    Ok(Value::Bool(ip_addr >= start_addr && ip_addr <= end_addr))
}

/// Helper function to compare two values with a given operator
fn compare_with_operator(left: &Value, right: &Value, op: &str) -> Result<bool> {
    match op {
        "StringEquals" => match (left, right) {
            (Value::String(l), Value::String(r)) => Ok(l.as_ref() == r.as_ref()),
            _ => bail!("StringEquals requires string values"),
        },
        "StringNotEquals" => match (left, right) {
            (Value::String(l), Value::String(r)) => Ok(l.as_ref() != r.as_ref()),
            _ => bail!("StringNotEquals requires string values"),
        },
        "StringEqualsIgnoreCase" => match (left, right) {
            (Value::String(l), Value::String(r)) => {
                Ok(l.as_ref().to_lowercase() == r.as_ref().to_lowercase())
            }
            _ => bail!("StringEqualsIgnoreCase requires string values"),
        },
        "StringNotEqualsIgnoreCase" => match (left, right) {
            (Value::String(l), Value::String(r)) => {
                Ok(l.as_ref().to_lowercase() != r.as_ref().to_lowercase())
            }
            _ => bail!("StringNotEqualsIgnoreCase requires string values"),
        },
        "NumericEquals" => match (left, right) {
            (Value::Number(l), Value::Number(r)) => Ok(l.as_f64() == r.as_f64()),
            _ => bail!("NumericEquals requires numeric values"),
        },
        "NumericNotEquals" => match (left, right) {
            (Value::Number(l), Value::Number(r)) => Ok(l.as_f64() != r.as_f64()),
            _ => bail!("NumericNotEquals requires numeric values"),
        },
        "NumericLessThan" => match (left, right) {
            (Value::Number(l), Value::Number(r)) => Ok(l.as_f64() < r.as_f64()),
            _ => bail!("NumericLessThan requires numeric values"),
        },
        "NumericLessThanEquals" => match (left, right) {
            (Value::Number(l), Value::Number(r)) => Ok(l.as_f64() <= r.as_f64()),
            _ => bail!("NumericLessThanEquals requires numeric values"),
        },
        "NumericGreaterThan" => match (left, right) {
            (Value::Number(l), Value::Number(r)) => Ok(l.as_f64() > r.as_f64()),
            _ => bail!("NumericGreaterThan requires numeric values"),
        },
        "NumericGreaterThanEquals" => match (left, right) {
            (Value::Number(l), Value::Number(r)) => Ok(l.as_f64() >= r.as_f64()),
            _ => bail!("NumericGreaterThanEquals requires numeric values"),
        },
        _ => bail!("unsupported operator in cross-product comparison: {}", op),
    }
}

/// ForAnyOfAnyValues: Check if ANY element in left matches ANY element in right
fn for_any_of_any_values(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let name = "rbac.for_any_of_any_values";
    ensure_args_count(span, name, params, args, 3)?;

    let left_array = match &args[0] {
        Value::Array(a) => a.iter().collect::<Vec<_>>(),
        _ => bail!(params[0].span().error("first argument must be an array")),
    };

    let right_array = match &args[1] {
        Value::Array(a) => a.iter().collect::<Vec<_>>(),
        _ => bail!(params[1].span().error("second argument must be an array")),
    };

    let op = match &args[2] {
        Value::String(s) => s.as_ref(),
        _ => bail!(params[2].span().error("operator must be a string")),
    };

    for left_item in &left_array {
        for right_item in &right_array {
            if compare_with_operator(left_item, right_item, op)? {
                return Ok(Value::Bool(true));
            }
        }
    }

    Ok(Value::Bool(false))
}

/// ForAllOfAnyValues: Check if ALL elements in left match ANY element in right
fn for_all_of_any_values(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let name = "rbac.for_all_of_any_values";
    ensure_args_count(span, name, params, args, 3)?;

    let left_array = match &args[0] {
        Value::Array(a) => a.iter().collect::<Vec<_>>(),
        _ => bail!(params[0].span().error("first argument must be an array")),
    };

    let right_array = match &args[1] {
        Value::Array(a) => a.iter().collect::<Vec<_>>(),
        _ => bail!(params[1].span().error("second argument must be an array")),
    };

    let op = match &args[2] {
        Value::String(s) => s.as_ref(),
        _ => bail!(params[2].span().error("operator must be a string")),
    };

    if left_array.is_empty() {
        return Ok(Value::Bool(true)); // Empty set trivially satisfies ALL condition
    }

    for left_item in &left_array {
        let mut found = false;
        for right_item in &right_array {
            if compare_with_operator(left_item, right_item, op)? {
                found = true;
                break;
            }
        }
        if !found {
            return Ok(Value::Bool(false));
        }
    }

    Ok(Value::Bool(true))
}

/// ForAnyOfAllValues: Check if ANY element in left matches ALL elements in right
fn for_any_of_all_values(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let name = "rbac.for_any_of_all_values";
    ensure_args_count(span, name, params, args, 3)?;

    let left_array = match &args[0] {
        Value::Array(a) => a.iter().collect::<Vec<_>>(),
        _ => bail!(params[0].span().error("first argument must be an array")),
    };

    let right_array = match &args[1] {
        Value::Array(a) => a.iter().collect::<Vec<_>>(),
        _ => bail!(params[1].span().error("second argument must be an array")),
    };

    let op = match &args[2] {
        Value::String(s) => s.as_ref(),
        _ => bail!(params[2].span().error("operator must be a string")),
    };

    if right_array.is_empty() {
        return Ok(Value::Bool(true)); // Empty set trivially satisfies ALL condition
    }

    for left_item in &left_array {
        let mut matches_all = true;
        for right_item in &right_array {
            if !compare_with_operator(left_item, right_item, op)? {
                matches_all = false;
                break;
            }
        }
        if matches_all {
            return Ok(Value::Bool(true));
        }
    }

    Ok(Value::Bool(false))
}

/// ForAllOfAllValues: Check if ALL elements in left match ALL elements in right
fn for_all_of_all_values(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let name = "rbac.for_all_of_all_values";
    ensure_args_count(span, name, params, args, 3)?;

    let left_array = match &args[0] {
        Value::Array(a) => a.iter().collect::<Vec<_>>(),
        _ => bail!(params[0].span().error("first argument must be an array")),
    };

    let right_array = match &args[1] {
        Value::Array(a) => a.iter().collect::<Vec<_>>(),
        _ => bail!(params[1].span().error("second argument must be an array")),
    };

    let op = match &args[2] {
        Value::String(s) => s.as_ref(),
        _ => bail!(params[2].span().error("operator must be a string")),
    };

    if left_array.is_empty() || right_array.is_empty() {
        return Ok(Value::Bool(true)); // Empty sets trivially satisfy ALL condition
    }

    for left_item in &left_array {
        for right_item in &right_array {
            if !compare_with_operator(left_item, right_item, op)? {
                return Ok(Value::Bool(false));
            }
        }
    }

    Ok(Value::Bool(true))
}

/// Check if attribute exists (is not undefined/null)
fn attribute_exists(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let name = "rbac.attribute_exists";
    ensure_args_count(span, name, params, args, 1)?;

    Ok(Value::Bool(!matches!(
        args[0],
        Value::Undefined | Value::Null
    )))
}

/// Check if attribute does not exist (is undefined/null)
fn attribute_not_exists(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let name = "rbac.attribute_not_exists";
    ensure_args_count(span, name, params, args, 1)?;

    Ok(Value::Bool(matches!(
        args[0],
        Value::Undefined | Value::Null
    )))
}
