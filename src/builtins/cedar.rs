// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::pattern_type_mismatch)]

use crate::ast::{Expr, Ref};
use crate::builtins;
use crate::builtins::utils::ensure_args_count;
use crate::lexer::Span;
use crate::Rc;
use crate::Value;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::vec::Vec;
use anyhow::{bail, Result};

pub fn register(m: &mut builtins::BuiltinsMap<&'static str, builtins::BuiltinCtxFcn>) {
    m.insert("cedar.in", (cedar_in, 3));
    m.insert("cedar.in_set", (cedar_in_set, 3));
    m.insert("cedar.has", (cedar_has, 3));
    m.insert("cedar.attr", (cedar_attr, 3));
    m.insert("cedar.like", (cedar_like, 2));
    m.insert("cedar.is", (cedar_is, 2));
}

fn cedar_in(
    ctx: &builtins::BuiltinContext,
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    strict: bool,
) -> Result<Value> {
    let name = "cedar.in";
    ensure_args_count(span, name, params, args, 3)?;

    let entity = entity_key_from_value(name, &params[0], &args[0])?;
    let target = entity_key_from_value(name, &params[1], &args[1])?;
    let entities = expect_object(name, &params[2], &args[2])?;

    Ok(Value::Bool(cedar_in_impl(
        ctx, span, &entity, &target, entities, strict,
    )?))
}

fn cedar_in_set(
    ctx: &builtins::BuiltinContext,
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    strict: bool,
) -> Result<Value> {
    let name = "cedar.in_set";
    ensure_args_count(span, name, params, args, 3)?;

    let entity = entity_key_from_value(name, &params[0], &args[0])?;
    let targets = expect_array(name, &params[1], &args[1])?;
    let entities = expect_object(name, &params[2], &args[2])?;

    for target in targets.iter() {
        let target_key = entity_key_from_value(name, &params[1], target)?;
        if cedar_in_impl(ctx, span, &entity, &target_key, entities, strict)? {
            return Ok(Value::Bool(true));
        }
    }

    Ok(Value::Bool(false))
}

fn cedar_has(
    _ctx: &builtins::BuiltinContext,
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let name = "cedar.has";
    ensure_args_count(span, name, params, args, 3)?;

    let entity = &args[0];
    let attr = expect_string_value(name, &params[1], &args[1])?;
    let entities = expect_object(name, &params[2], &args[2])?;

    if let Ok(obj) = entity.as_object() {
        let key = Value::String(attr.clone());
        return Ok(Value::Bool(obj.contains_key(&key)));
    }

    let entity_key = entity_key_from_value(name, &params[0], entity)?;
    let entity_record = match entities.get(&entity_key) {
        Some(Value::Object(map)) => map,
        _ => return Ok(Value::Bool(false)),
    };

    let attrs_key = Value::from("attrs");
    match entity_record.get(&attrs_key) {
        Some(Value::Object(attrs)) => Ok(Value::Bool(attrs.contains_key(&Value::String(attr)))),
        _ => Ok(Value::Bool(false)),
    }
}

fn cedar_attr(
    _ctx: &builtins::BuiltinContext,
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let name = "cedar.attr";
    ensure_args_count(span, name, params, args, 3)?;

    let entity = &args[0];
    let attr = expect_string_value(name, &params[1], &args[1])?;
    let entities = expect_object(name, &params[2], &args[2])?;

    if matches!(entity, Value::Undefined) {
        return Ok(Value::Undefined);
    }

    let attr_key = Value::String(attr.clone());

    if let Ok(obj) = entity.as_object() {
        if let Some(value) = obj.get(&attr_key) {
            return Ok(value.clone());
        }

        let attrs_field_key = Value::from("attrs");
        if let Some(Value::Object(attrs)) = obj.get(&attrs_field_key) {
            return Ok(attrs.get(&attr_key).cloned().unwrap_or(Value::Undefined));
        }

        return Ok(Value::Undefined);
    }

    let entity_key = entity_key_from_value(name, &params[0], entity)?;
    let entity_record = match entities.get(&entity_key) {
        Some(Value::Object(map)) => map,
        _ => return Ok(Value::Undefined),
    };

    let attrs_field_key = Value::from("attrs");
    match entity_record.get(&attrs_field_key) {
        Some(Value::Object(attrs)) => Ok(attrs.get(&attr_key).cloned().unwrap_or(Value::Undefined)),
        _ => Ok(Value::Undefined),
    }
}

fn cedar_like(
    _ctx: &builtins::BuiltinContext,
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let name = "cedar.like";
    ensure_args_count(span, name, params, args, 2)?;

    let input = expect_string_value(name, &params[0], &args[0])?;
    let pattern = expect_string_value(name, &params[1], &args[1])?;

    Ok(Value::Bool(wildcard_match(
        input.as_ref(),
        pattern.as_ref(),
    )))
}

fn cedar_is(
    _ctx: &builtins::BuiltinContext,
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let name = "cedar.is";
    ensure_args_count(span, name, params, args, 2)?;

    let entity = &args[0];
    let type_name = expect_string_value(name, &params[1], &args[1])?;

    if let Ok(obj) = entity.as_object() {
        let type_key = Value::from("type");
        if let Some(Value::String(entity_type)) = obj.get(&type_key) {
            return Ok(Value::Bool(entity_type.as_ref() == type_name.as_ref()));
        }
    }

    let entity_key = entity_key_from_value(name, &params[0], entity)?;
    let Value::String(entity_key) = entity_key else {
        return Ok(Value::Bool(false));
    };

    let mut parts = entity_key.as_ref().split("::");
    let entity_type = parts.next().unwrap_or("");
    Ok(Value::Bool(entity_type == type_name.as_ref()))
}

fn entity_key_from_value(name: &str, param: &Expr, value: &Value) -> Result<Value> {
    match value {
        Value::String(s) => Ok(Value::String(s.clone())),
        Value::Object(obj) => {
            let type_key = Value::from("type");
            let id_key = Value::from("id");
            let Some(Value::String(entity_type)) = obj.get(&type_key) else {
                bail!(param
                    .span()
                    .error(format!("`{name}` expects entity type string").as_str()))
            };
            let Some(Value::String(entity_id)) = obj.get(&id_key) else {
                bail!(param
                    .span()
                    .error(format!("`{name}` expects entity id string").as_str()))
            };
            let combined = format!("{}::{}", entity_type.as_ref(), entity_id.as_ref());
            Ok(Value::String(combined.into()))
        }
        _ => bail!(param
            .span()
            .error(format!("`{name}` expects entity string or object").as_str())),
    }
}

fn expect_object<'a>(
    name: &str,
    param: &Expr,
    value: &'a Value,
) -> Result<&'a BTreeMap<Value, Value>> {
    value.as_object().map_err(|_| {
        param
            .span()
            .error(format!("`{name}` expects object argument").as_str())
    })
}

fn expect_array<'a>(name: &str, param: &Expr, value: &'a Value) -> Result<&'a Vec<Value>> {
    value.as_array().map_err(|_| {
        param
            .span()
            .error(format!("`{name}` expects array argument").as_str())
    })
}

fn expect_string_value(name: &str, param: &Expr, value: &Value) -> Result<Rc<str>> {
    value.as_string().cloned().map_err(|_| {
        param
            .span()
            .error(format!("`{name}` expects string argument").as_str())
    })
}

fn bfs_entity_membership(
    entity: &Value,
    target: &Value,
    entities: &BTreeMap<Value, Value>,
    strict: bool,
    span: &Span,
) -> Result<bool> {
    let mut queue: VecDeque<Value> = VecDeque::new();
    let mut visited: BTreeSet<Value> = BTreeSet::new();

    queue.push_back(entity.clone());
    visited.insert(entity.clone());

    while let Some(current) = queue.pop_front() {
        if &current == target {
            return Ok(true);
        }

        let Some(Value::Object(node)) = entities.get(&current) else {
            continue;
        };

        let parents_key = Value::from("parents");
        let Some(Value::Array(parents)) = node.get(&parents_key) else {
            continue;
        };

        for parent in parents.iter() {
            let Value::String(parent_str) = parent else {
                if strict {
                    bail!(span.error("`cedar.in` expects parent ids to be strings"));
                }
                continue;
            };

            let parent_value = Value::String(parent_str.clone());
            if visited.insert(parent_value.clone()) {
                queue.push_back(parent_value);
            }
        }
    }

    Ok(false)
}

fn cedar_in_impl(
    ctx: &builtins::BuiltinContext,
    span: &Span,
    entity: &Value,
    target: &Value,
    entities: &BTreeMap<Value, Value>,
    strict: bool,
) -> Result<bool> {
    if entity == target {
        return Ok(true);
    }

    if let Some(cache) = ctx.cedar_cache.as_ref() {
        if let Some(hit) = cache.get_membership(entity, target) {
            return Ok(hit);
        }
    }

    let result = bfs_entity_membership(entity, target, entities, strict, span)?;

    if let Some(cache) = ctx.cedar_cache.as_ref() {
        cache.insert_membership(entity.clone(), target.clone(), result);
    }

    Ok(result)
}

fn wildcard_match(input: &str, pattern: &str) -> bool {
    let (mut i, mut p) = (0_usize, 0_usize);
    let mut star_idx: Option<usize> = None;
    let mut match_idx = 0_usize;
    let input_bytes = input.as_bytes();
    let pattern_bytes = pattern.as_bytes();

    while i < input_bytes.len() {
        if p < pattern_bytes.len()
            && (pattern_bytes[p] == b'?' || pattern_bytes[p] == input_bytes[i])
        {
            i += 1;
            p += 1;
        } else if p < pattern_bytes.len() && pattern_bytes[p] == b'*' {
            star_idx = Some(p);
            match_idx = i;
            p += 1;
        } else if let Some(star) = star_idx {
            p = star + 1;
            match_idx += 1;
            i = match_idx;
        } else {
            return false;
        }
    }

    while p < pattern_bytes.len() && pattern_bytes[p] == b'*' {
        p += 1;
    }

    p == pattern_bytes.len()
}
