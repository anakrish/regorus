// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::pattern_type_mismatch)]

use crate::ast::{Expr, Ref};
use crate::builtins;
use crate::builtins::utils::{enforce_limit, ensure_args_count, ensure_numeric};
use crate::lexer::Span;
use crate::number::Number;
use crate::value::Value;
use crate::*;

use anyhow::{bail, Result};
use core::cmp::Ordering;

pub fn register(m: &mut builtins::BuiltinsMap<&'static str, builtins::BuiltinFcn>) {
    m.insert("count", (count, 1));
    m.insert("max", (max, 1));
    m.insert("min", (min, 1));
    m.insert("product", (product, 1));
    m.insert("sort", (sort, 1));
    m.insert("sum", (sum, 1));
}

fn insertion_sort_values(items: &mut [Value]) -> Result<()> {
    let len = items.len();
    for i in 1..len {
        let item = items[i].clone();
        let mut j = i;
        while j > 0
            && crate::builtins::comparison::compare_values_with_limit(&item, &items[j - 1])?
                == Ordering::Less
        {
            items[j] = items[j - 1].clone();
            j -= 1;
        }
        items[j] = item;
    }
    Ok(())
}

fn count(span: &Span, params: &[Ref<Expr>], args: &[Value], strict: bool) -> Result<Value> {
    ensure_args_count(span, "count", params, args, 1)?;

    Ok(Value::from(Number::from(match &args[0] {
        Value::Array(a) => a.len(),
        Value::Set(a) => a.len(),
        Value::Object(a) => a.len(),
        Value::String(a) => a.encode_utf16().count(),
        a if strict => {
            let span = params[0].span();
            bail!(span.error(
                format!("`count` requires array/object/set/string argument. Got `{a}`.").as_str()
            ))
        }
        _ => return Ok(Value::Undefined),
    })))
}

fn max(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    ensure_args_count(span, "max", params, args, 1)?;

    Ok(match &args[0] {
        Value::Array(a) if a.is_empty() => Value::Undefined,
        Value::Array(a) => {
            let mut iter = a.iter();
            let mut best = iter.next().cloned().unwrap_or(Value::Undefined);
            for value in iter {
                if crate::builtins::comparison::compare_values_with_limit(value, &best)?
                    == Ordering::Greater
                {
                    best = value.clone();
                }
            }
            best
        }
        Value::Set(a) if a.is_empty() => Value::Undefined,
        Value::Set(a) => {
            let mut iter = a.iter();
            let mut best = iter.next().cloned().unwrap_or(Value::Undefined);
            for value in iter {
                if crate::builtins::comparison::compare_values_with_limit(value, &best)?
                    == Ordering::Greater
                {
                    best = value.clone();
                }
            }
            best
        }
        a => {
            let span = params[0].span();
            bail!(span.error(format!("`max` requires array/set argument. Got `{a}`.").as_str()))
        }
    })
}

fn min(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    ensure_args_count(span, "min", params, args, 1)?;

    Ok(match &args[0] {
        Value::Array(a) if a.is_empty() => Value::Undefined,
        Value::Array(a) => {
            let mut iter = a.iter();
            let mut best = iter.next().cloned().unwrap_or(Value::Undefined);
            for value in iter {
                if crate::builtins::comparison::compare_values_with_limit(value, &best)?
                    == Ordering::Less
                {
                    best = value.clone();
                }
            }
            best
        }
        Value::Set(a) if a.is_empty() => Value::Undefined,
        Value::Set(a) => {
            let mut iter = a.iter();
            let mut best = iter.next().cloned().unwrap_or(Value::Undefined);
            for value in iter {
                if crate::builtins::comparison::compare_values_with_limit(value, &best)?
                    == Ordering::Less
                {
                    best = value.clone();
                }
            }
            best
        }
        a => {
            let span = params[0].span();
            bail!(span.error(format!("`min` requires array/set argument. Got `{a}`.").as_str()))
        }
    })
}

fn product(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    ensure_args_count(span, "product", params, args, 1)?;

    let mut v = Number::from(1_u64);
    Ok(Value::from(match &args[0] {
        Value::Array(a) => {
            for e in a.iter() {
                v.mul_assign(&ensure_numeric("product", &params[0], e)?)?;
            }
            v
        }

        Value::Set(a) => {
            for e in a.iter() {
                v.mul_assign(&ensure_numeric("product", &params[0], e)?)?;
            }
            v
        }
        a => {
            let span = params[0].span();
            bail!(span.error(format!("`product` requires array/set argument. Got `{a}`.").as_str()))
        }
    }))
}

fn sort(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    ensure_args_count(span, "sort", params, args, 1)?;
    Ok(match &args[0] {
        Value::Array(a) => {
            let mut items = Vec::with_capacity(a.len());
            for value in a.iter() {
                items.push(value.clone());
                enforce_limit()?;
            }
            insertion_sort_values(&mut items)?;
            Value::from(items)
        }
        // Sorting a set produces array.
        Value::Set(a) => {
            let mut items = Vec::with_capacity(a.len());
            for value in a.iter() {
                items.push(value.clone());
                // Guard array growth while materializing the sorted set.
                enforce_limit()?;
            }
            insertion_sort_values(&mut items)?;
            Value::from(items)
        }
        a => {
            let span = params[0].span();
            bail!(span.error(format!("`sort` requires array/set argument. Got `{a}`.").as_str()))
        }
    })
}

fn sum(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    ensure_args_count(span, "sum", params, args, 1)?;

    let mut v = Number::from(0_u64);
    Ok(Value::from(match &args[0] {
        Value::Array(a) => {
            for e in a.iter() {
                v.add_assign(&ensure_numeric("sum", &params[0], e)?)?;
            }
            v
        }

        Value::Set(a) => {
            for e in a.iter() {
                v.add_assign(&ensure_numeric("sum", &params[0], e)?)?;
            }
            v
        }
        a => {
            let span = params[0].span();
            bail!(span.error(format!("`sum` requires array/set argument. Got `{a}`.").as_str()))
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString as _;

    fn test_span() -> Span {
        Span {
            source: crate::lexer::Source::from_contents("test.rego".into(), "x".into())
                .expect("source"),
            line: 1,
            col: 1,
            start: 0,
            end: 1,
        }
    }

    fn nested_array(depth: usize) -> Value {
        let mut value = Value::from(0_u64);
        for _ in 0..depth {
            value = Value::from_array(alloc::vec![value]);
        }
        value
    }

    #[test]
    fn sort_rejects_excessive_nesting_depth() {
        let deep = nested_array(crate::builtins::comparison::MAX_COMPARISON_DEPTH + 1);
        let err = sort(
            &test_span(),
            &[],
            &[Value::from_array(alloc::vec![deep.clone(), deep])],
            true,
        )
        .expect_err("deep sort must error");
        assert!(err
            .to_string()
            .contains("value comparison exceeded the maximum supported nesting depth"));
    }
}
