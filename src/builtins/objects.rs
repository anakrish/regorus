// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::pattern_type_mismatch)]

use crate::ast::{Expr, Ref};
use crate::builtins;
use crate::builtins::utils::{enforce_limit, ensure_args_count, ensure_array, ensure_object};
use crate::lexer::Span;
use crate::Rc;
use crate::Value;
use crate::*;

use alloc::collections::{BTreeMap, BTreeSet};
use core::iter::Iterator;

use anyhow::{bail, Result};

const MAX_OBJECT_RECURSION_DEPTH: usize = 512;

fn ensure_object_recursion_depth(depth: usize, builtin: &str) -> Result<()> {
    if depth > MAX_OBJECT_RECURSION_DEPTH {
        bail!("{builtin} exceeded the maximum supported nesting depth")
    }
    Ok(())
}

pub fn register(m: &mut builtins::BuiltinsMap<&'static str, builtins::BuiltinFcn>) {
    m.insert("json.filter", (json_filter, 2));
    m.insert("json.remove", (json_remove, 2));
    m.insert("object.filter", (filter, 2));
    m.insert("object.get", (get, 3));
    m.insert("object.keys", (keys, 1));
    m.insert("object.remove", (remove, 2));
    m.insert("object.subset", (subset, 2));
    m.insert("object.union", (object_union, 2));
    m.insert("object.union_n", (object_union_n, 1));

    #[cfg(feature = "jsonschema")]
    {
        m.insert("json.match_schema", (json_match_schema, 2));
        m.insert("json.verify_schema", (json_verify_schema, 1));
    }

    #[cfg(feature = "jsonpatch")]
    {
        m.insert("json.patch", (json_patch, 2));
    }
}

fn json_filter_impl(v: &Value, filter: &Value, depth: usize) -> Result<Value> {
    ensure_object_recursion_depth(depth, "json.filter")?;
    let filters = match filter {
        Value::Object(fields) if fields.len() == 1 && filter[&Value::Null] == Value::Null => {
            return Ok(v.clone())
        }
        Value::Object(fields) if !fields.is_empty() => fields,
        _ => return Ok(v.clone()),
    };

    match v {
        Value::Array(_) => {
            let mut items = vec![];
            for (idx, filter) in filters.iter() {
                // The string index must be parseable as a number.
                // TODO: support integer indexes?
                if let Value::String(idx) = idx {
                    if let Ok(idx) = Value::from_json_str(idx) {
                        let item = json_filter_impl(&v[&idx], filter, depth + 1)?;
                        if item != Value::Undefined {
                            items.push(item);
                            // Guard array growth while filtering nested structures.
                            enforce_limit()?;
                        }
                    }
                }
            }
            Ok(Value::from_array(items))
        }

        Value::Set(s) => {
            let mut items = BTreeSet::new();
            for (item, filter) in filters.iter() {
                if s.contains(item) {
                    let item = json_filter_impl(item, filter, depth + 1)?;
                    if item != Value::Undefined {
                        items.insert(item);
                        // Guard set growth when preserving matched entries.
                        enforce_limit()?;
                    }
                }
            }
            Ok(Value::from_set(items))
        }

        Value::Object(_) => {
            let mut items = BTreeMap::new();
            for (key, filter) in filters.iter() {
                let item = json_filter_impl(&v[key], filter, depth + 1)?;
                if item != Value::Undefined {
                    items.insert(key.clone(), item);
                    // Guard map growth as filtered keys accumulate.
                    enforce_limit()?;
                }
            }

            Ok(Value::from_map(items))
        }

        _ => Ok(Value::Undefined),
    }
}

fn json_remove_impl(v: &Value, filter: &Value, depth: usize) -> Result<Value> {
    ensure_object_recursion_depth(depth, "json.remove")?;
    let filters = match filter {
        Value::Object(fields) if !fields.is_empty() => fields,
        _ => return Ok(v.clone()),
    };

    if filter[&Value::Null] == Value::Null {
        return Ok(Value::Undefined);
    }

    match v {
        Value::Array(a) => {
            let mut items = vec![];
            for (idx, item) in a.iter().enumerate() {
                let idx = Value::String(format!("{idx}").into());
                if let Some(f) = filters.get(&idx) {
                    let v = json_remove_impl(item, f, depth + 1)?;
                    if v != Value::Undefined {
                        items.push(v);
                        // Guard array size while removing JSON paths.
                        enforce_limit()?;
                    }
                } else {
                    // Retain the item.
                    items.push(item.clone());
                    // Guard array size while copying retained entries.
                    enforce_limit()?;
                }
            }
            Ok(Value::from_array(items))
        }

        Value::Set(s) => {
            let mut items = BTreeSet::new();
            for item in s.iter() {
                if let Some(f) = filters.get(item) {
                    let v = json_remove_impl(item, f, depth + 1)?;
                    if v != Value::Undefined {
                        items.insert(v);
                        // Guard set size during filtered retention.
                        enforce_limit()?;
                    }
                } else {
                    // Retain the item.
                    items.insert(item.clone());
                    // Guard set size when keeping unmatched entries.
                    enforce_limit()?;
                }
            }
            Ok(Value::from_set(items))
        }

        Value::Object(obj) => {
            let mut items = BTreeMap::new();
            for (key, value) in obj.iter() {
                if let Some(f) = filters.get(key) {
                    let v = json_remove_impl(value, f, depth + 1)?;
                    if v != Value::Undefined {
                        items.insert(key.clone(), v);
                        // Guard map size as filtered properties accumulate.
                        enforce_limit()?;
                    }
                } else {
                    items.insert(key.clone(), value.clone());
                    // Guard map size while copying retained properties.
                    enforce_limit()?;
                }
            }
            Ok(Value::from_map(items))
        }

        _ => Ok(Value::Undefined),
    }
}

fn merge_filters(
    name: &str,
    param: &Expr,
    itr: &mut dyn Iterator<Item = &Value>,
    mut filters: Value,
) -> Result<Value> {
    loop {
        match itr.next() {
            Some(Value::String(s)) => {
                let mut fc = filters;
                let mut f = &mut fc;
                for p in s.split('/') {
                    let vref = f.make_or_get_value_mut(&[p])?;
                    if *vref == Value::Undefined {
                        *vref = Value::new_object();
                    }
                    f = vref;
                    // Guard recursive filter construction as path objects materialize.
                    enforce_limit()?;
                }
                if let Ok(f) = f.as_object_mut() {
                    f.insert(Value::Null, Value::Null);
                    // Guard filter map growth when marking terminal entries.
                    enforce_limit()?;
                };
                filters = fc;
            }
            Some(Value::Array(a)) => {
                let mut fc = filters;
                let mut f = &mut fc;
                for p in a.iter() {
                    let vref = match f {
                        Value::Object(obj) => {
                            let obj = Rc::make_mut(obj);
                            let entry = obj.get_or_insert_with(p.clone(), Value::new_object);
                            // Guard filter map growth when creating nested objects.
                            enforce_limit()?;
                            entry
                        }
                        _ => break,
                    };
                    f = vref;
                    // Guard recursive descent as additional path components attach.
                    enforce_limit()?;
                }
                if let Ok(f) = f.as_object_mut() {
                    f.insert(Value::Null, Value::Null);
                    // Guard filter map growth when sealing terminal markers.
                    enforce_limit()?;
                };
                filters = fc;
            }
            Some(_) => {
                let span = param.span();
                bail!(span.error(
		    format!("`{name}` requires path to be '/' separated string or array of path components.").as_str()));
            }
            None => break,
        }
    }

    Ok(filters)
}

fn json_filter(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "json.filter";
    ensure_args_count(span, name, params, args, 2)?;
    ensure_object(name, &params[0], args[0].clone())?;

    let filters = match &args[1] {
        Value::Array(a) => merge_filters(name, &params[1], &mut a.iter(), Value::new_object())?,
        Value::Set(s) => merge_filters(name, &params[1], &mut s.iter(), Value::new_object())?,
        _ => bail!(span.error(format!("`{name}` requires set/array argument").as_str())),
    };

    if let Ok(v) = filters.as_object() {
        if v.is_empty() {
            return Ok(Value::new_object());
        }
    }

    json_filter_impl(&args[0], &filters, 0)
}

fn json_remove(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "json.remove";
    ensure_args_count(span, name, params, args, 2)?;
    ensure_object(name, &params[0], args[0].clone())?;

    let filters = match &args[1] {
        Value::Array(a) => merge_filters(name, &params[1], &mut a.iter(), Value::new_object())?,
        Value::Set(s) => merge_filters(name, &params[1], &mut s.iter(), Value::new_object())?,
        _ => bail!(span.error(format!("`{name}` requires set/array argument").as_str())),
    };

    json_remove_impl(&args[0], &filters, 0)
}

fn filter(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "object.filter";
    ensure_args_count(span, name, params, args, 2)?;
    let mut obj = ensure_object(name, &params[0], args[0].clone())?;
    let obj_ref = Rc::make_mut(&mut obj);
    match &args[1] {
        Value::Array(a) => {
            let keys: BTreeSet<&Value> = a.iter().collect();
            obj_ref.retain(|k, _| keys.contains(k))
        }
        Value::Set(s) => obj_ref.retain(|k, _| s.contains(k)),
        Value::Object(o) => obj_ref.retain(|k, _| o.contains_key(k)),
        _ => bail!(span.error(format!("`{name}` requires array/object/set argument").as_str())),
    };

    Ok(Value::Object(obj))
}

fn get(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "object.get";
    ensure_args_count(span, name, params, args, 3)?;
    let obj = ensure_object(name, &params[0], args[0].clone())?;
    let default = &args[2];

    Ok(match &args[1] {
        Value::Array(keys) => {
            let mut v = &args[0];
            for a in keys.iter() {
                v = &v[a];
                if v == &Value::Undefined {
                    v = default;
                    break;
                }
            }
            v.clone()
        }
        key => match obj.get(key) {
            Some(v) => v.clone(),
            _ => default.clone(),
        },
    })
}

fn keys(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "object.keys";
    ensure_args_count(span, name, params, args, 1)?;
    let obj = ensure_object(name, &params[0], args[0].clone())?;
    Ok(Value::from_set(obj.keys().cloned().collect()))
}

fn remove(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "object.remove";
    ensure_args_count(span, name, params, args, 2)?;
    let mut obj = ensure_object(name, &params[0], args[0].clone())?;
    let obj_ref = Rc::make_mut(&mut obj);
    match &args[1] {
        Value::Array(a) => {
            let keys: BTreeSet<&Value> = a.iter().collect();
            obj_ref.retain(|k, _| !keys.contains(k))
        }
        Value::Set(s) => obj_ref.retain(|k, _| !s.contains(k)),
        Value::Object(o) => obj_ref.retain(|k, _| !o.contains_key(k)),
        _ => bail!(span.error(format!("`{name}` requires array/object/set argument").as_str())),
    };

    Ok(Value::Object(obj))
}

fn is_subset(sup: &Value, sub: &Value, depth: usize) -> Result<bool> {
    ensure_object_recursion_depth(depth, "object.subset")?;
    Ok(match (sup, sub) {
        (Value::Object(sup), Value::Object(sub)) => {
            for (key, value) in sub.iter() {
                match sup.get(key) {
                    Some(existing) if is_subset(existing, value, depth + 1)? => {}
                    _ => return Ok(false),
                }
            }
            true
        }
        (Value::Set(sup), Value::Set(sub)) => sub.is_subset(sup),
        (Value::Array(sup), Value::Array(sub)) => sup
            .as_slice()
            .windows(sub.len())
            .any(|window| window == sub.as_slice()),
        (Value::Array(sup), Value::Set(_)) => {
            let sup = Value::from_set(sup.iter().cloned().collect());
            is_subset(&sup, sub, depth + 1)?
        }
        (sup, sub) => sup == sub,
    })
}

fn subset(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "object.subset";
    ensure_args_count(span, name, params, args, 2)?;

    Ok(Value::Bool(is_subset(&args[0], &args[1], 0)?))
}

fn union_into(target: &mut Value, source: &Value, depth: usize) -> Result<()> {
    ensure_object_recursion_depth(depth, "object.union")?;
    match (target, source) {
        (Value::Object(target_obj), Value::Object(source_obj)) => {
            let target_obj = Rc::make_mut(target_obj);
            for (key, value) in source_obj.iter() {
                if let Some(existing) = target_obj.get_mut(key) {
                    union_into(existing, value, depth + 1)?;
                } else {
                    target_obj.insert(key.clone(), value.clone());
                    enforce_limit()?;
                }
            }
        }
        (target, source) => *target = source.clone(),
    }
    Ok(())
}

fn union(obj1: &Value, obj2: &Value) -> Result<Value> {
    let mut merged = obj1.clone();
    union_into(&mut merged, obj2, 0)?;
    Ok(merged)
}

fn object_union(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "object.union";
    ensure_args_count(span, name, params, args, 2)?;

    let _ = ensure_object(name, &params[0], args[0].clone())?;
    let _ = ensure_object(name, &params[1], args[1].clone())?;

    let result = union(&args[0], &args[1])?;
    Ok(result)
}

fn object_union_n(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    strict: bool,
) -> Result<Value> {
    let name = "object.union_n";
    ensure_args_count(span, name, params, args, 1)?;

    let arr = ensure_array(name, &params[0], args[0].clone())?;

    let mut u = Value::new_object();
    for (idx, a) in arr.iter().enumerate() {
        if a.as_object().is_err() {
            if strict {
                bail!(params[0]
                    .span()
                    .error(&format!("item at index {idx} is not an object")));
            }
            return Ok(Value::Undefined);
        }
        union_into(&mut u, a, 0)?;
    }

    Ok(u)
}

#[cfg(feature = "jsonschema")]
fn compile_json_schema(param: &Ref<Expr>, arg: &Value) -> Result<jsonschema::Validator> {
    let schema_str = match arg {
        Value::String(schema_str) => schema_str.as_ref().to_string(),
        _ => arg.to_json_str()?,
    };

    if let Ok(schema) = serde_json::from_str(&schema_str) {
        match jsonschema::validator_for(&schema) {
            Ok(schema) => return Ok(schema),
            Err(e) => bail!(e.to_string()),
        }
    }
    bail!(param.span().error("not a valid json schema"))
}

#[cfg(feature = "jsonschema")]
fn json_verify_schema(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    strict: bool,
) -> Result<Value> {
    let name = "json.verify_schema";
    ensure_args_count(span, name, params, args, 1)?;

    Ok(Value::from_array(
        match compile_json_schema(&params[0], &args[0]) {
            Ok(_) => [Value::Bool(true), Value::Null],
            Err(e) if strict => bail!(params[0]
                .span()
                .error(format!("invalid schema: {e}").as_str())),
            Err(e) => [Value::Bool(false), Value::String(e.to_string().into())],
        }
        .to_vec(),
    ))
}

#[cfg(feature = "jsonschema")]
fn json_match_schema(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    strict: bool,
) -> Result<Value> {
    let name = "json.match_schema";
    ensure_args_count(span, name, params, args, 2)?;

    let document: serde_json::Value = serde_json::from_str(&args[0].to_json_str()?)
        .map_err(|err| span.error(&format!("Failed to parse JSON: {err}")))?;

    Ok(Value::from_array(
        match compile_json_schema(&params[1], &args[1]) {
            Ok(schema) => match schema.validate(&document) {
                Ok(_) => [Value::Bool(true), Value::Null],
                Err(e) => [Value::Bool(false), Value::from(e.to_string())],
            },
            Err(e) if strict => bail!(params[1]
                .span()
                .error(format!("invalid schema: {e}").as_str())),
            Err(e) => [Value::Bool(false), Value::String(e.to_string().into())],
        }
        .to_vec(),
    ))
}

// Note: matching OPA's own `builtinJSONPatch`, any failure while applying the
// patch (bad path, missing attribute, failed `test`, ...) yields Undefined
// rather than a hard error -- this builtin never errors on a malformed patch,
// regardless of the `strict-builtin-errors` setting.
#[cfg(feature = "jsonpatch")]
fn json_patch(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "json.patch";
    ensure_args_count(span, name, params, args, 2)?;
    ensure_array(name, &params[1], args[1].clone())?;

    let ops = args[1].as_array()?;

    let patched = super::json_patch::apply(&args[0], ops.as_slice());
    match patched {
        Ok(patched) => Ok(patched),
        // Resource-limit errors must propagate rather than look like an
        // invalid patch, so callers cannot bypass configured limits.
        Err(err)
            if err
                .downcast_ref::<crate::utils::limits::LimitError>()
                .is_some() =>
        {
            Err(err)
        }
        Err(_) => Ok(Value::Undefined),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString as _;

    fn shallow_object() -> Value {
        Value::from_map(BTreeMap::from([(Value::from("k"), Value::from(1_u64))]))
    }

    #[test]
    fn object_union_rejects_excessive_nesting_depth() {
        let mut target = shallow_object();
        let source = shallow_object();
        let err = union_into(&mut target, &source, MAX_OBJECT_RECURSION_DEPTH + 1)
            .expect_err("deep unions must error");
        assert!(err
            .to_string()
            .contains("object.union exceeded the maximum supported nesting depth"));
    }

    #[test]
    fn object_subset_rejects_excessive_nesting_depth() {
        let value = shallow_object();
        let err = is_subset(&value, &value, MAX_OBJECT_RECURSION_DEPTH + 1)
            .expect_err("deep subset checks must error");
        assert!(err
            .to_string()
            .contains("object.subset exceeded the maximum supported nesting depth"));
    }

    #[test]
    fn json_filter_rejects_excessive_nesting_depth() {
        let value = shallow_object();
        let err = json_filter_impl(&value, &value, MAX_OBJECT_RECURSION_DEPTH + 1)
            .expect_err("deep filter must error");
        assert!(err
            .to_string()
            .contains("json.filter exceeded the maximum supported nesting depth"));
    }

    #[test]
    fn json_remove_rejects_excessive_nesting_depth() {
        let value = shallow_object();
        let err = json_remove_impl(&value, &value, MAX_OBJECT_RECURSION_DEPTH + 1)
            .expect_err("deep remove must error");
        assert!(err
            .to_string()
            .contains("json.remove exceeded the maximum supported nesting depth"));
    }
}
