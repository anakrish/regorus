// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ARM template string function builtins for Azure Policy expressions.
//!
//! Implements: indexOf, lastIndexOf, trim, format.

use crate::ast::{Expr, Ref};
use crate::builtins;
use crate::lexer::Span;
use crate::value::Value;

use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use anyhow::Result;

use super::helpers::as_string;

pub(super) fn register(m: &mut builtins::BuiltinsMap<&'static str, builtins::BuiltinFcn>) {
    m.insert("azure.policy.fn.index_of", (fn_index_of, 2));
    m.insert("azure.policy.fn.last_index_of", (fn_last_index_of, 2));
    m.insert("azure.policy.fn.trim", (fn_trim, 1));
    m.insert("azure.policy.fn.format", (fn_format, 0));
}

/// `indexOf(stringToSearch, stringToFind)` → zero-based index, or -1 if not found.
fn fn_index_of(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Undefined);
    }
    let (Some(haystack), Some(needle)) = (as_string(&args[0]), as_string(&args[1])) else {
        return Ok(Value::Undefined);
    };
    match haystack.find(&needle) {
        Some(pos) => Ok(Value::from(pos as i64)),
        None => Ok(Value::from(-1_i64)),
    }
}

/// `lastIndexOf(stringToSearch, stringToFind)` → zero-based index, or -1.
fn fn_last_index_of(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Undefined);
    }
    let (Some(haystack), Some(needle)) = (as_string(&args[0]), as_string(&args[1])) else {
        return Ok(Value::Undefined);
    };
    match haystack.rfind(&needle) {
        Some(pos) => Ok(Value::from(pos as i64)),
        None => Ok(Value::from(-1_i64)),
    }
}

/// `trim(stringToTrim)` → string with leading/trailing whitespace removed.
fn fn_trim(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let Some(arg) = args.first() else {
        return Ok(Value::Undefined);
    };
    let Some(s) = as_string(arg) else {
        return Ok(Value::Undefined);
    };
    Ok(Value::from(s.trim().to_string()))
}

/// `format(formatString, arg0, arg1, ...)` → formatted string.
///
/// ARM template format uses `{0}`, `{1}`, … placeholders.
fn fn_format(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    if args.is_empty() {
        return Ok(Value::Undefined);
    }
    let Some(template) = as_string(&args[0]) else {
        return Ok(Value::Undefined);
    };

    let format_args: Vec<String> = args[1..]
        .iter()
        .map(|v| match v {
            Value::String(s) => s.to_string(),
            Value::Number(n) => n.format_decimal(),
            Value::Bool(b) => b.to_string(),
            Value::Null => "null".to_string(),
            _ => v.to_string(),
        })
        .collect();

    let mut result = template.clone();
    for (i, arg) in format_args.iter().enumerate() {
        let placeholder = alloc::format!("{{{}}}", i);
        result = result.replace(&placeholder, arg);
    }

    Ok(Value::from(result))
}
