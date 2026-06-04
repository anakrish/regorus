// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::ast::{Expr, Ref};
use crate::lexer::Span;
use crate::number::Number;
use crate::Rc;
use crate::Value;
use crate::*;

use core::convert::TryInto;

use alloc::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Result};

pub(super) fn ensure_n_args<'a, const N: usize>(
    span: &Span,
    fcn: &'static str,
    params: &'a [Ref<Expr>],
    args: &'a [Value],
) -> Result<(&'a [Value; N], &'a [Ref<Expr>; N])> {
    let args_len = args.len();
    let params_len = params.len();

    if args_len != params_len {
        let err_span = params
            .get(args_len.saturating_sub(1))
            .map(|p| p.span())
            .unwrap_or(span);
        let msg = format!("`{fcn}` received {args_len} arguments for {params_len} parameters");
        bail!(err_span.error(&msg))
    }

    if args_len != N {
        let err_span = if args_len > N {
            params.get(args_len - 1).map(|p| p.span()).unwrap_or(span)
        } else {
            span
        };
        let msg = if N == 1 {
            format!("`{fcn}` expects 1 argument")
        } else {
            format!("`{fcn}` expects {N} arguments")
        };
        bail!(err_span.error(&msg))
    }

    let args_arr: &'a [Value; N] = args.try_into().map_err(|_| {
        let msg = format!("`{fcn}` expects {N} arguments");
        span.error(&msg)
    })?;
    let params_arr: &'a [Ref<Expr>; N] = params.try_into().map_err(|_| {
        let msg = format!("`{fcn}` expects {N} parameters");
        span.error(&msg)
    })?;

    Ok((args_arr, params_arr))
}

pub(super) fn ensure_numeric(fcn: &str, arg: &Expr, v: &Value) -> Result<Number> {
    Ok(match &v {
        Value::Number(n) => n.clone(),
        _ => {
            let span = arg.span();
            bail!(
                span.error(format!("`{fcn}` expects numeric argument. Got `{v}` instead").as_str())
            )
        }
    })
}

pub(super) fn validate_integer_arg(
    fcn: &str,
    param: &Ref<Expr>,
    original_value: &Value,
    numeric_value: &Number,
    strict: bool,
    allow_negative: bool,
) -> Result<bool> {
    if !numeric_value.is_integer() {
        if strict {
            bail!(param.span().error(
                format!("`{fcn}` expects integer arguments. Got `{original_value}`").as_str()
            ));
        }
        return Ok(false);
    }

    if !allow_negative {
        if let Some(int_value) = numeric_value.as_i128() {
            if int_value < 0 {
                if strict {
                    bail!(param.span().error(
                        format!("`{fcn}` expects non-negative integer arguments. Got `{original_value}`")
                            .as_str(),
                    ));
                }
                return Ok(false);
            }
        } else if !numeric_value.is_positive() {
            if strict {
                bail!(param.span().error(
                    format!(
                        "`{fcn}` expects non-negative integer arguments. Got `{original_value}`"
                    )
                    .as_str(),
                ));
            }
            return Ok(false);
        }
    }

    Ok(true)
}

pub(super) fn ensure_string(fcn: &str, arg: &Expr, v: &Value) -> Result<Rc<str>> {
    Ok(match &v {
        Value::String(s) => s.clone(),
        _ => {
            let span = arg.span();
            bail!(span.error(format!("`{fcn}` expects string argument. Got `{v}` instead").as_str()))
        }
    })
}

pub(super) fn ensure_string_element<'a>(
    fcn: &str,
    arg: &Expr,
    v: &'a Value,
    idx: usize,
) -> Result<&'a str> {
    Ok(match &v {
        Value::String(s) => s.as_ref(),
        _ => {
            let span = arg.span();
            bail!(span.error(
                format!("`{fcn}` expects string collection. Element {idx} is not a string.")
                    .as_str()
            ))
        }
    })
}

pub(super) fn ensure_string_collection<'a>(fcn: &str, arg: &Expr, v: &'a Value) -> Result<Vec<&'a str>> {
    let mut collection = vec![];
    match &v {
        Value::Array(a) => {
            for (idx, elem) in a.iter().enumerate() {
                collection.push(ensure_string_element(fcn, arg, elem, idx)?);
            }
        }
        Value::Set(s) => {
            for (idx, elem) in s.iter().enumerate() {
                collection.push(ensure_string_element(fcn, arg, elem, idx)?);
            }
        }
        _ => {
            let span = arg.span();
            bail!(span.error(format!("`{fcn}` expects array/set of strings.").as_str()))
        }
    }
    Ok(collection)
}

pub(super) fn ensure_array(fcn: &str, arg: &Expr, v: Value) -> Result<Rc<Vec<Value>>> {
    Ok(match v {
        Value::Array(a) => a,
        _ => {
            let span = arg.span();
            bail!(span.error(format!("`{fcn}` expects array argument. Got `{v}` instead").as_str()))
        }
    })
}

pub(super) fn ensure_set(fcn: &str, arg: &Expr, v: Value) -> Result<Rc<BTreeSet<Value>>> {
    Ok(match v {
        Value::Set(s) => s,
        _ => {
            let span = arg.span();
            bail!(span.error(format!("`{fcn}` expects set argument. Got `{v}` instead").as_str()))
        }
    })
}

pub(super) fn ensure_object(fcn: &str, arg: &Expr, v: Value) -> Result<Rc<BTreeMap<Value, Value>>> {
    Ok(match v {
        Value::Object(o) => o,
        _ => {
            let span = arg.span();
            bail!(span.error(format!("`{fcn}` expects object argument. Got `{v}` instead").as_str()))
        }
    })
}
