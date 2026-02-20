// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ARM template numeric function builtins for Azure Policy expressions.
//!
//! Implements: min, max, float.
//!
//! Note: `sub`, `mul`, `div`, `mod` are compiled directly to native RVM
//! instructions (`Sub`, `Mul`, `Div`, `Mod`) and do not need builtins.

use crate::ast::{Expr, Ref};
use crate::builtins;
use crate::lexer::Span;
use crate::value::Value;

use anyhow::Result;

use super::helpers::try_coerce_to_number;

pub(super) fn register(m: &mut builtins::BuiltinsMap<&'static str, builtins::BuiltinFcn>) {
    m.insert("azure.policy.fn.min", (fn_min, 0));
    m.insert("azure.policy.fn.max", (fn_max, 0));
    m.insert("azure.policy.fn.float", (fn_float, 1));
    m.insert("azure.policy.fn.int_div", (fn_int_div, 2));
    m.insert("azure.policy.fn.int_mod", (fn_int_mod, 2));
}

/// `min(arg1, arg2, ...)` or `min(intArray)` → smallest integer/number.
///
/// Accepts either:
/// - Multiple integer arguments: `min(1, 2, 3)` → `1`
/// - A single array argument: `min([1, 2, 3])` → `1`
fn fn_min(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let values = if args.len() == 1 {
        match &args[0] {
            Value::Array(arr) => arr.as_ref().as_slice(),
            _ => args,
        }
    } else {
        args
    };

    if values.is_empty() {
        return Ok(Value::Undefined);
    }

    let mut result: Option<&Value> = None;
    for v in values {
        match v {
            Value::Number(_) => {
                if let Some(current) = result {
                    if v < current {
                        result = Some(v);
                    }
                } else {
                    result = Some(v);
                }
            }
            _ => return Ok(Value::Undefined),
        }
    }

    Ok(result.cloned().unwrap_or(Value::Undefined))
}

/// `max(arg1, arg2, ...)` or `max(intArray)` → largest integer/number.
///
/// Same overloading as `min`.
fn fn_max(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let values = if args.len() == 1 {
        match &args[0] {
            Value::Array(arr) => arr.as_ref().as_slice(),
            _ => args,
        }
    } else {
        args
    };

    if values.is_empty() {
        return Ok(Value::Undefined);
    }

    let mut result: Option<&Value> = None;
    for v in values {
        match v {
            Value::Number(_) => {
                if let Some(current) = result {
                    if v > current {
                        result = Some(v);
                    }
                } else {
                    result = Some(v);
                }
            }
            _ => return Ok(Value::Undefined),
        }
    }

    Ok(result.cloned().unwrap_or(Value::Undefined))
}

/// `float(value)` → floating-point number.
fn fn_float(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let Some(arg) = args.first() else {
        return Ok(Value::Undefined);
    };
    match arg {
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                Ok(Value::from(f))
            } else {
                Ok(arg.clone())
            }
        }
        Value::String(s) => {
            if let Some(n) = try_coerce_to_number(s) {
                if let Some(f) = n.as_f64() {
                    Ok(Value::from(f))
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

/// `div(operand1, operand2)` → integer division (truncating).
///
/// ARM template `div()` performs integer division, unlike the RVM `Div`
/// instruction which may produce floats for non-evenly-divisible operands.
fn fn_int_div(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Undefined);
    }
    let (a, b) = (extract_i64(&args[0]), extract_i64(&args[1]));
    match (a, b) {
        (Some(_), Some(0)) => Ok(Value::Undefined),
        (Some(a), Some(b)) => Ok(Value::from(a / b)),
        _ => Ok(Value::Undefined),
    }
}

/// `mod(operand1, operand2)` → integer modulo.
fn fn_int_mod(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Undefined);
    }
    let (a, b) = (extract_i64(&args[0]), extract_i64(&args[1]));
    match (a, b) {
        (Some(_), Some(0)) => Ok(Value::Undefined),
        (Some(a), Some(b)) => Ok(Value::from(a % b)),
        _ => Ok(Value::Undefined),
    }
}

fn extract_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|x| x as i64)),
        _ => None,
    }
}
