// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ARM template collection function builtins for Azure Policy expressions.
//!
//! Implements: intersection, union, take, skip, range, array, coalesce, createObject.

use crate::ast::{Expr, Ref};
use crate::builtins;
use crate::lexer::Span;
use crate::value::Value;
use crate::Rc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use anyhow::Result;

use super::helpers::is_undefined;

pub(super) fn register(m: &mut builtins::BuiltinsMap<&'static str, builtins::BuiltinFcn>) {
    m.insert("azure.policy.fn.intersection", (fn_intersection, 0));
    m.insert("azure.policy.fn.union", (fn_union, 0));
    m.insert("azure.policy.fn.take", (fn_take, 2));
    m.insert("azure.policy.fn.skip", (fn_skip, 2));
    m.insert("azure.policy.fn.range", (fn_range, 2));
    m.insert("azure.policy.fn.array", (fn_array, 1));
    m.insert("azure.policy.fn.coalesce", (fn_coalesce, 0));
    m.insert("azure.policy.fn.create_object", (fn_create_object, 0));
}

/// `intersection(arg1, arg2, ...)` → elements common to all arrays, or keys common
/// to all objects.
///
/// For arrays: returns elements present in every input array.
/// For objects: returns keys (with values from the first) present in every input.
fn fn_intersection(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    if args.is_empty() {
        return Ok(Value::Undefined);
    }

    match &args[0] {
        Value::Array(first) => {
            // Intersection of arrays: keep elements from first that appear in all others.
            let mut result: Vec<Value> = first.as_ref().clone();
            for arg in &args[1..] {
                let Value::Array(other) = arg else {
                    return Ok(Value::Undefined);
                };
                result.retain(|item| other.contains(item));
            }
            Ok(Value::from(result))
        }
        Value::Object(first) => {
            // Intersection of objects: keys that exist in all objects.
            let mut result: BTreeMap<Value, Value> = first.as_ref().clone();
            for arg in &args[1..] {
                let Value::Object(other) = arg else {
                    return Ok(Value::Undefined);
                };
                result.retain(|k, _| other.contains_key(k));
            }
            Ok(Value::Object(Rc::new(result)))
        }
        _ => Ok(Value::Undefined),
    }
}

/// `union(arg1, arg2, ...)` → all unique elements from arrays, or merged objects.
///
/// For arrays: returns distinct elements across all arrays.
/// For objects: merges all objects (later values overwrite earlier for same key).
fn fn_union(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    if args.is_empty() {
        return Ok(Value::Undefined);
    }

    match &args[0] {
        Value::Array(_) => {
            // Union of arrays: collect unique elements preserving first-seen order.
            let mut seen = alloc::collections::BTreeSet::<Value>::new();
            let mut result = Vec::new();
            for arg in args {
                let Value::Array(arr) = arg else {
                    return Ok(Value::Undefined);
                };
                for item in arr.iter() {
                    if seen.insert(item.clone()) {
                        result.push(item.clone());
                    }
                }
            }
            Ok(Value::from(result))
        }
        Value::Object(_) => {
            // Union of objects: merge, last writer wins.
            let mut result = BTreeMap::<Value, Value>::new();
            for arg in args {
                let Value::Object(obj) = arg else {
                    return Ok(Value::Undefined);
                };
                for (k, v) in obj.iter() {
                    result.insert(k.clone(), v.clone());
                }
            }
            Ok(Value::Object(Rc::new(result)))
        }
        _ => Ok(Value::Undefined),
    }
}

/// `take(originalValue, numberToTake)` → first N elements of array or chars of string.
fn fn_take(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Undefined);
    }

    let count = extract_usize(&args[1]).unwrap_or(0);

    match &args[0] {
        Value::Array(arr) => {
            let n = count.min(arr.len());
            Ok(Value::from(arr[..n].to_vec()))
        }
        Value::String(s) => {
            let taken: alloc::string::String = s.chars().take(count).collect();
            Ok(Value::from(taken))
        }
        _ => Ok(Value::Undefined),
    }
}

/// `skip(originalValue, numberToSkip)` → array/string after skipping N elements.
fn fn_skip(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Undefined);
    }

    let count = extract_usize(&args[1]).unwrap_or(0);

    match &args[0] {
        Value::Array(arr) => {
            let n = count.min(arr.len());
            Ok(Value::from(arr[n..].to_vec()))
        }
        Value::String(s) => {
            let skipped: alloc::string::String = s.chars().skip(count).collect();
            Ok(Value::from(skipped))
        }
        _ => Ok(Value::Undefined),
    }
}

/// `range(startIndex, count)` → array of integers starting at startIndex.
fn fn_range(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Undefined);
    }

    let start = extract_i64(&args[0]);
    let count = extract_i64(&args[1]);

    let (Some(start), Some(count)) = (start, count) else {
        return Ok(Value::Undefined);
    };

    if count < 0 {
        return Ok(Value::Undefined);
    }

    let result: Vec<Value> = (0..count).map(|i| Value::from(start + i)).collect();
    Ok(Value::from(result))
}

/// `array(convertToArray)` → wraps a single value in an array.
///
/// If the input is already an array, returns it as-is.
fn fn_array(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let Some(arg) = args.first() else {
        return Ok(Value::from(Vec::<Value>::new()));
    };
    match arg {
        Value::Array(_) => Ok(arg.clone()),
        _ => Ok(Value::from(alloc::vec![arg.clone()])),
    }
}

/// `coalesce(arg1, arg2, ...)` → first non-null, non-undefined argument.
fn fn_coalesce(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    for arg in args {
        if !is_undefined(arg) && !matches!(arg, Value::Null) {
            return Ok(arg.clone());
        }
    }
    Ok(Value::Null)
}

/// `createObject(key1, value1, key2, value2, ...)` → object from key-value pairs.
fn fn_create_object(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let mut map = BTreeMap::<Value, Value>::new();

    let mut i = 0;
    while i + 1 < args.len() {
        map.insert(args[i].clone(), args[i + 1].clone());
        i += 2;
    }

    Ok(Value::Object(Rc::new(map)))
}

// ── Helpers ───────────────────────────────────────────────────────────

fn extract_usize(v: &Value) -> Option<usize> {
    match v {
        Value::Number(n) => n
            .as_i64()
            .and_then(|x| usize::try_from(x).ok())
            .or_else(|| n.as_f64().and_then(|x| usize::try_from(x as i64).ok())),
        _ => None,
    }
}

fn extract_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|x| x as i64)),
        _ => None,
    }
}
