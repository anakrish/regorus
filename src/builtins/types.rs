// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::ast::{Expr, Ref};
use crate::builtins;
use crate::builtins::utils::ensure_n_args;
use crate::lexer::Span;
use crate::value::Value;

use anyhow::Result;

pub(super) fn register(m: &mut builtins::BuiltinsMap<&'static str, builtins::BuiltinFcn>) {
    m.insert("is_array", (is_array, 1));
    m.insert("is_boolean", (is_boolean, 1));
    m.insert("is_null", (is_null, 1));
    m.insert("is_number", (is_number, 1));
    m.insert("is_object", (is_object, 1));
    m.insert("is_set", (is_set, 1));
    m.insert("is_string", (is_string, 1));
    m.insert("type_name", (type_name, 1));
}

fn is_array(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let (args, _params) = ensure_n_args::<1>(span, "is_array", params, args)?;
    Ok(Value::Bool(matches!(&args[0], Value::Array(_))))
}

fn is_boolean(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let (args, _params) = ensure_n_args::<1>(span, "is_boolean", params, args)?;
    Ok(Value::Bool(matches!(&args[0], Value::Bool(_))))
}

fn is_null(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let (args, _params) = ensure_n_args::<1>(span, "is_null", params, args)?;
    Ok(Value::Bool(matches!(&args[0], Value::Null)))
}

fn is_number(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let (args, _params) = ensure_n_args::<1>(span, "is_number", params, args)?;
    Ok(Value::Bool(matches!(&args[0], Value::Number(_))))
}

fn is_object(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let (args, _params) = ensure_n_args::<1>(span, "is_object", params, args)?;
    Ok(Value::Bool(matches!(&args[0], Value::Object(_))))
}

fn is_set(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let (args, _params) = ensure_n_args::<1>(span, "is_set", params, args)?;
    Ok(Value::Bool(matches!(&args[0], Value::Set(_))))
}

fn is_string(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let (args, _params) = ensure_n_args::<1>(span, "is_string", params, args)?;
    Ok(Value::Bool(matches!(&args[0], Value::String(_))))
}

pub(super) fn get_type(value: &Value) -> &str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
        Value::Set(_) => "set",
        Value::Undefined => "undefined",
    }
}

    pub(super) fn type_name(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let (args, _params) = ensure_n_args::<1>(span, "type_name", params, args)?;
    Ok(Value::String(get_type(&args[0]).into()))
}
