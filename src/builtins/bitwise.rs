// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::ast::{Expr, Ref};
use crate::builtins;
use crate::builtins::utils::{ensure_n_args, ensure_numeric, validate_integer_arg};

use crate::lexer::Span;
use crate::value::Value;

use anyhow::Result;

pub(super) fn register(m: &mut builtins::BuiltinsMap<&'static str, builtins::BuiltinFcn>) {
    m.insert("bits.and", (and, 2));
    m.insert("bits.lsh", (lsh, 2));
    m.insert("bits.negate", (negate, 1));
    m.insert("bits.or", (or, 2));
    m.insert("bits.rsh", (rsh, 2));
    m.insert("bits.xor", (xor, 2));
}

fn and(span: &Span, params: &[Ref<Expr>], args: &[Value], strict: bool) -> Result<Value> {
    let name = "bits.and";
    let (args, params) = ensure_n_args::<2>(span, name, params, args)?;

    let v1 = ensure_numeric(name, &params[0], &args[0])?;
    let v2 = ensure_numeric(name, &params[1], &args[1])?;

    if !validate_integer_arg(name, &params[0], &args[0], &v1, strict, true)?
        || !validate_integer_arg(name, &params[1], &args[1], &v2, strict, true)?
    {
        return Ok(Value::Undefined);
    }

    Ok(match v1.and(&v2) {
        Some(v) => Value::from(v),
        _ => Value::Undefined,
    })
}

fn lsh(span: &Span, params: &[Ref<Expr>], args: &[Value], strict: bool) -> Result<Value> {
    let name = "bits.lsh";
    let (args, params) = ensure_n_args::<2>(span, name, params, args)?;

    let v1 = ensure_numeric(name, &params[0], &args[0])?;
    let v2 = ensure_numeric(name, &params[1], &args[1])?;

    if !validate_integer_arg(name, &params[0], &args[0], &v1, strict, true)?
        || !validate_integer_arg(name, &params[1], &args[1], &v2, strict, false)?
    {
        return Ok(Value::Undefined);
    }

    Ok(match v1.lsh(&v2) {
        Some(v) => Value::from(v),
        _ => Value::Undefined,
    })
}

fn negate(span: &Span, params: &[Ref<Expr>], args: &[Value], strict: bool) -> Result<Value> {
    let name = "bits.negate";
    let (args, params) = ensure_n_args::<1>(span, name, params, args)?;

    let v = ensure_numeric(name, &params[0], &args[0])?;

    if !validate_integer_arg(name, &params[0], &args[0], &v, strict, true)? {
        return Ok(Value::Undefined);
    }

    Ok(match v.neg() {
        Some(v) => Value::from(v),
        _ => Value::Undefined,
    })
}

fn or(span: &Span, params: &[Ref<Expr>], args: &[Value], strict: bool) -> Result<Value> {
    let name = "bits.or";
    let (args, params) = ensure_n_args::<2>(span, name, params, args)?;

    let v1 = ensure_numeric(name, &params[0], &args[0])?;
    let v2 = ensure_numeric(name, &params[1], &args[1])?;

    if !validate_integer_arg(name, &params[0], &args[0], &v1, strict, true)?
        || !validate_integer_arg(name, &params[1], &args[1], &v2, strict, true)?
    {
        return Ok(Value::Undefined);
    }

    Ok(match v1.or(&v2) {
        Some(v) => Value::from(v),
        _ => Value::Undefined,
    })
}

fn rsh(span: &Span, params: &[Ref<Expr>], args: &[Value], strict: bool) -> Result<Value> {
    let name = "bits.rsh";
    let (args, params) = ensure_n_args::<2>(span, name, params, args)?;

    let v1 = ensure_numeric(name, &params[0], &args[0])?;
    let v2 = ensure_numeric(name, &params[1], &args[1])?;

    if !validate_integer_arg(name, &params[0], &args[0], &v1, strict, true)?
        || !validate_integer_arg(name, &params[1], &args[1], &v2, strict, false)?
    {
        return Ok(Value::Undefined);
    }

    Ok(match v1.rsh(&v2) {
        Some(v) => Value::from(v),
        _ => Value::Undefined,
    })
}

fn xor(span: &Span, params: &[Ref<Expr>], args: &[Value], strict: bool) -> Result<Value> {
    let name = "bits.xor";
    let (args, params) = ensure_n_args::<2>(span, name, params, args)?;

    let v1 = ensure_numeric(name, &params[0], &args[0])?;
    let v2 = ensure_numeric(name, &params[1], &args[1])?;

    if !validate_integer_arg(name, &params[0], &args[0], &v1, strict, true)?
        || !validate_integer_arg(name, &params[1], &args[1], &v2, strict, true)?
    {
        return Ok(Value::Undefined);
    }

    Ok(match v1.xor(&v2) {
        Some(v) => Value::from(v),
        _ => Value::Undefined,
    })
}
