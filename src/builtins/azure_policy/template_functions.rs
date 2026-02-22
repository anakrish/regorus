// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ARM template function builtins for Azure Policy expressions.
//!
//! Implements: split, empty, first, last, startsWith,
//! endsWith, int, string, bool, padLeft, ipRangeContains.

use crate::ast::{Expr, Ref};
use crate::builtins;
use crate::lexer::Span;
use crate::value::Value;

use alloc::string::{String, ToString as _};
use anyhow::Result;
use core::net::IpAddr;
use ipnet::IpNet;

use super::helpers::{as_string, try_coerce_to_number};

pub(super) fn register(m: &mut builtins::BuiltinsMap<&'static str, builtins::BuiltinFcn>) {
    m.insert("azure.policy.fn.split", (fn_split, 2));
    m.insert("azure.policy.fn.empty", (fn_empty, 1));
    m.insert("azure.policy.fn.first", (fn_first, 1));
    m.insert("azure.policy.fn.last", (fn_last, 1));
    m.insert("azure.policy.fn.starts_with", (fn_starts_with, 2));
    m.insert("azure.policy.fn.ends_with", (fn_ends_with, 2));
    m.insert("azure.policy.fn.int", (fn_int, 1));
    m.insert("azure.policy.fn.string", (fn_string, 1));
    m.insert("azure.policy.fn.bool", (fn_bool, 1));
    m.insert("azure.policy.fn.pad_left", (fn_pad_left, 3));
    m.insert(
        "azure.policy.fn.ip_range_contains",
        (fn_ip_range_contains, 2),
    );
}

/// `split(inputString, delimiter)` → array of strings.
fn fn_split(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Undefined);
    }

    let (Some(input), Some(delimiter)) = (as_string(&args[0]), as_string(&args[1])) else {
        return Ok(Value::Undefined);
    };

    let parts: alloc::vec::Vec<Value> = input
        .split(&delimiter)
        .map(|s| Value::from(s.to_string()))
        .collect();
    Ok(Value::from(parts))
}

/// `empty(item)` → true if string/array/object is empty or value is null/undefined.
fn fn_empty(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let Some(arg) = args.first() else {
        return Ok(Value::Bool(true));
    };
    let result = match arg {
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        Value::Null | Value::Undefined => true,
        _ => false,
    };
    Ok(Value::Bool(result))
}

/// `first(arg)` → first element of array or first character of string.
fn fn_first(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let Some(arg) = args.first() else {
        return Ok(Value::Undefined);
    };
    match arg {
        Value::Array(a) => Ok(a.first().cloned().unwrap_or(Value::Undefined)),
        Value::String(s) => {
            if let Some(ch) = s.chars().next() {
                Ok(Value::from(ch.to_string()))
            } else {
                Ok(Value::Undefined)
            }
        }
        _ => Ok(Value::Undefined),
    }
}

/// `last(arg)` → last element of array or last character of string.
fn fn_last(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let Some(arg) = args.first() else {
        return Ok(Value::Undefined);
    };
    match arg {
        Value::Array(a) => Ok(a.last().cloned().unwrap_or(Value::Undefined)),
        Value::String(s) => {
            if let Some(ch) = s.chars().last() {
                Ok(Value::from(ch.to_string()))
            } else {
                Ok(Value::Undefined)
            }
        }
        _ => Ok(Value::Undefined),
    }
}

/// `startsWith(stringToSearch, stringToFind)` → bool (case-insensitive).
fn fn_starts_with(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Bool(false));
    }
    let (Some(haystack), Some(needle)) = (as_string(&args[0]), as_string(&args[1])) else {
        return Ok(Value::Bool(false));
    };
    Ok(Value::Bool(
        haystack.to_lowercase().starts_with(&needle.to_lowercase()),
    ))
}

/// `endsWith(stringToSearch, stringToFind)` → bool (case-insensitive).
fn fn_ends_with(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Bool(false));
    }
    let (Some(haystack), Some(needle)) = (as_string(&args[0]), as_string(&args[1])) else {
        return Ok(Value::Bool(false));
    };
    Ok(Value::Bool(
        haystack.to_lowercase().ends_with(&needle.to_lowercase()),
    ))
}

/// `int(valueToConvert)` → integer number.
fn fn_int(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let Some(arg) = args.first() else {
        return Ok(Value::Undefined);
    };
    match arg {
        Value::Number(n) => {
            // Truncate to integer.
            if let Some(i) = n.as_i64() {
                Ok(Value::from(i))
            } else if let Some(f) = n.as_f64() {
                Ok(Value::from(f as i64))
            } else {
                Ok(Value::Undefined)
            }
        }
        Value::String(s) => {
            if let Some(n) = try_coerce_to_number(s) {
                if let Some(i) = n.as_i64() {
                    Ok(Value::from(i))
                } else if let Some(f) = n.as_f64() {
                    Ok(Value::from(f as i64))
                } else {
                    Ok(Value::Undefined)
                }
            } else {
                Ok(Value::Undefined)
            }
        }
        _ => Ok(Value::Undefined),
    }
}

/// `string(valueToConvert)` → string representation.
fn fn_string(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let Some(arg) = args.first() else {
        return Ok(Value::Undefined);
    };
    match arg {
        Value::String(_) => Ok(arg.clone()),
        Value::Bool(b) => Ok(Value::from(b.to_string())),
        Value::Number(n) => Ok(Value::from(n.format_decimal())),
        Value::Null => Ok(Value::from("null")),
        Value::Undefined => Ok(Value::Undefined),
        // For arrays and objects, produce JSON-style representation.
        _ => Ok(Value::from(arg.to_string())),
    }
}

/// `bool(value)` → boolean.
fn fn_bool(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let Some(arg) = args.first() else {
        return Ok(Value::Undefined);
    };
    match arg {
        Value::Bool(_) => Ok(arg.clone()),
        Value::String(s) => match s.to_lowercase().as_str() {
            "true" | "1" => Ok(Value::Bool(true)),
            "false" | "0" => Ok(Value::Bool(false)),
            _ => Ok(Value::Undefined),
        },
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(Value::Bool(i != 0))
            } else if let Some(f) = n.as_f64() {
                Ok(Value::Bool(f != 0.0))
            } else {
                Ok(Value::Undefined)
            }
        }
        _ => Ok(Value::Undefined),
    }
}

/// `padLeft(value, totalWidth, padChar)` → left-padded string.
fn fn_pad_left(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    if args.len() < 2 || args.len() > 3 {
        return Ok(Value::Undefined);
    }

    let Some(value) = as_string(&args[0]) else {
        return Ok(Value::Undefined);
    };

    let width = match &args[1] {
        Value::Number(n) => n
            .as_i64()
            .and_then(|x| usize::try_from(x).ok())
            .or_else(|| n.as_f64().and_then(|x| usize::try_from(x as i64).ok())),
        Value::String(s) => try_coerce_to_number(s).and_then(|n| {
            n.as_i64()
                .and_then(|x| usize::try_from(x).ok())
                .or_else(|| n.as_f64().and_then(|x| usize::try_from(x as i64).ok()))
        }),
        _ => None,
    };

    let Some(total_width) = width else {
        return Ok(Value::Undefined);
    };

    let pad_char = if args.len() == 3 {
        as_string(&args[2])
            .and_then(|s| s.chars().next())
            .unwrap_or(' ')
    } else {
        ' '
    };

    let value_len = value.chars().count();
    if value_len >= total_width {
        return Ok(Value::from(value));
    }

    let pad_count = total_width.saturating_sub(value_len);
    let mut padded = String::with_capacity(total_width);
    for _ in 0..pad_count {
        padded.push(pad_char);
    }
    padded.push_str(&value);

    Ok(Value::from(padded))
}

/// `ipRangeContains(range, targetRange)` → bool.
fn fn_ip_range_contains(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Bool(false));
    }

    let (Some(range), Some(target)) = (as_string(&args[0]), as_string(&args[1])) else {
        return Ok(Value::Bool(false));
    };

    let Ok(net) = range.parse::<IpNet>() else {
        return Ok(Value::Bool(false));
    };

    if target.contains('/') {
        let Ok(target_net) = target.parse::<IpNet>() else {
            return Ok(Value::Bool(false));
        };
        return Ok(Value::Bool(net.contains(&target_net)));
    }

    let Ok(target_ip) = target.parse::<IpAddr>() else {
        return Ok(Value::Bool(false));
    };
    Ok(Value::Bool(net.contains(&target_ip)))
}
