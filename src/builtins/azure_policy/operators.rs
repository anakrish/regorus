// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Policy condition operators and logic builtins.

use crate::ast::{Expr, Ref};
use crate::lexer::Span;
use crate::value::Value;

use anyhow::Result;

use super::helpers::{
    as_boolish, as_string, as_string_ci, case_insensitive_equals, compare_values, is_true,
    is_undefined, match_like_pattern_ci, match_pattern, resolve_path,
};

// ── Parameter resolution ──────────────────────────────────────────────

/// `azure.policy.get_parameter(params, defaults, name)`
///
/// Returns `params[name]` if it exists and is not undefined; otherwise
/// falls back to `defaults[name]`.  This lets the compiler bake parameter
/// default values into the program's literal table while still allowing
/// callers to override them via `input.parameters`.
pub(super) fn get_parameter(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    if args.len() != 3 {
        return Ok(Value::Undefined);
    }

    let params_obj = &args[0];
    let defaults_obj = &args[1];
    let name = &args[2];

    // Try caller-supplied parameters first.
    let val = &params_obj[name];
    if !is_undefined(val) {
        return Ok(val.clone());
    }

    // Fall back to compiled-in defaults.
    Ok(defaults_obj[name].clone())
}

// ── Field resolution ──────────────────────────────────────────────────

pub(super) fn resolve_field(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Undefined);
    }

    let Some(path) = as_string(&args[1]) else {
        return Ok(Value::Undefined);
    };

    Ok(resolve_path(&args[0], &path))
}

// ── Logic functions ───────────────────────────────────────────────────

pub(super) fn logic_all(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    Ok(Value::Bool(args.iter().all(is_true)))
}

pub(super) fn logic_any(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    Ok(Value::Bool(args.iter().any(is_true)))
}

pub(super) fn logic_not(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let value = args.first().cloned().unwrap_or(Value::Undefined);
    Ok(Value::Bool(!is_true(&value)))
}

pub(super) fn if_fn(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    if args.len() != 3 {
        return Ok(Value::Undefined);
    }
    if is_true(&args[0]) {
        Ok(args[1].clone())
    } else {
        Ok(args[2].clone())
    }
}

// ── Equality ──────────────────────────────────────────────────────────

pub(super) fn op_equals(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Bool(false));
    }
    Ok(Value::Bool(case_insensitive_equals(&args[0], &args[1])))
}

pub(super) fn op_not_equals(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Bool(false));
    }
    if is_undefined(&args[0]) {
        return Ok(Value::Bool(true));
    }
    Ok(Value::Bool(!case_insensitive_equals(&args[0], &args[1])))
}

// ── Comparison ────────────────────────────────────────────────────────

pub(super) fn op_greater(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    Ok(Value::Bool(compare_values(args).is_some_and(|c| c > 0)))
}

pub(super) fn op_greater_or_equals(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    Ok(Value::Bool(compare_values(args).is_some_and(|c| c >= 0)))
}

pub(super) fn op_less(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    Ok(Value::Bool(compare_values(args).is_some_and(|c| c < 0)))
}

pub(super) fn op_less_or_equals(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    Ok(Value::Bool(compare_values(args).is_some_and(|c| c <= 0)))
}

// ── Set membership ────────────────────────────────────────────────────

pub(super) fn op_in(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    if args.len() != 2 || is_undefined(&args[0]) || is_undefined(&args[1]) {
        return Ok(Value::Bool(false));
    }

    match &args[1] {
        Value::Array(items) => Ok(Value::Bool(
            items
                .iter()
                .any(|item| case_insensitive_equals(item, &args[0])),
        )),
        Value::Set(items) => Ok(Value::Bool(
            items
                .iter()
                .any(|item| case_insensitive_equals(item, &args[0])),
        )),
        _ => Ok(Value::Bool(false)),
    }
}

pub(super) fn op_not_in(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    strict: bool,
) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Bool(false));
    }
    if is_undefined(&args[0]) {
        return Ok(Value::Bool(true));
    }
    let in_result = op_in(span, params, args, strict)?;
    Ok(Value::Bool(!is_true(&in_result)))
}

// ── Contains ──────────────────────────────────────────────────────────

pub(super) fn op_contains(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    if args.len() != 2 || is_undefined(&args[0]) || is_undefined(&args[1]) {
        return Ok(Value::Bool(false));
    }

    match (&args[0], &args[1]) {
        (Value::String(haystack), Value::String(needle)) => Ok(Value::Bool(
            haystack
                .to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase()),
        )),
        (Value::Array(items), value) => Ok(Value::Bool(
            items
                .iter()
                .any(|item| case_insensitive_equals(item, value)),
        )),
        (Value::Set(items), value) => Ok(Value::Bool(
            items
                .iter()
                .any(|item| case_insensitive_equals(item, value)),
        )),
        _ => Ok(Value::Bool(false)),
    }
}

pub(super) fn op_not_contains(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    strict: bool,
) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Bool(false));
    }
    if is_undefined(&args[0]) {
        return Ok(Value::Bool(true));
    }
    let contains_result = op_contains(span, params, args, strict)?;
    Ok(Value::Bool(!is_true(&contains_result)))
}

pub(super) fn op_contains_key(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    if args.len() != 2 || is_undefined(&args[0]) || is_undefined(&args[1]) {
        return Ok(Value::Bool(false));
    }

    match &args[0] {
        Value::Object(map) => Ok(Value::Bool(
            map.keys().any(|key| case_insensitive_equals(key, &args[1])),
        )),
        _ => Ok(Value::Bool(false)),
    }
}

pub(super) fn op_not_contains_key(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    strict: bool,
) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Bool(false));
    }
    if is_undefined(&args[0]) {
        return Ok(Value::Bool(true));
    }
    let result = op_contains_key(span, params, args, strict)?;
    Ok(Value::Bool(!is_true(&result)))
}

// ── Pattern matching ──────────────────────────────────────────────────

pub(super) fn op_like(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Bool(false));
    }
    let (Some(input), Some(pattern)) = (as_string_ci(&args[0]), as_string_ci(&args[1])) else {
        return Ok(Value::Bool(false));
    };

    Ok(Value::Bool(match_like_pattern_ci(&input, &pattern)))
}

pub(super) fn op_not_like(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    strict: bool,
) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Bool(false));
    }
    if is_undefined(&args[0]) {
        return Ok(Value::Bool(true));
    }
    let result = op_like(span, params, args, strict)?;
    Ok(Value::Bool(!is_true(&result)))
}

pub(super) fn op_match(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    Ok(Value::Bool(match_pattern(args, false)))
}

pub(super) fn op_not_match(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Bool(false));
    }
    if is_undefined(&args[0]) {
        return Ok(Value::Bool(true));
    }
    Ok(Value::Bool(!match_pattern(args, false)))
}

pub(super) fn op_match_insensitively(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    Ok(Value::Bool(match_pattern(args, true)))
}

pub(super) fn op_not_match_insensitively(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Bool(false));
    }
    if is_undefined(&args[0]) {
        return Ok(Value::Bool(true));
    }
    Ok(Value::Bool(!match_pattern(args, true)))
}

// ── Exists ────────────────────────────────────────────────────────────

pub(super) fn op_exists(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Bool(false));
    }

    let expected = as_boolish(&args[1]).unwrap_or(false);
    let is_defined = !is_undefined(&args[0]) && !matches!(&args[0], Value::Null);
    Ok(Value::Bool(is_defined == expected))
}
