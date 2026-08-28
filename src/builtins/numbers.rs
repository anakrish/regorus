// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(
    clippy::unseparated_literal_suffix,
    clippy::as_conversions,
    clippy::unused_trait_names,
    clippy::pattern_type_mismatch
)]

use crate::ast::{ArithOp, Expr, Ref};
use crate::builtins;
use crate::builtins::utils::{enforce_limit, ensure_args_count, ensure_numeric};
use crate::lexer::Span;
use crate::number::{BigInt, Number};
use crate::value::Value;
use crate::*;

use anyhow::{anyhow, bail, Result};
use num_traits::ToPrimitive;

#[cfg(feature = "std")]
use rand::RngExt;

const MAX_RANGE_OUTPUT_ELEMENTS: usize = 1_000_000;

fn checked_range_len(start: &Number, end: &Number, step: &BigInt) -> Result<usize> {
    if step <= &BigInt::from(0u8) {
        bail!("step must be positive")
    }

    let start = start.to_big()?;
    let end = end.to_big()?;
    let diff = if end >= start {
        (&*end) - (&*start)
    } else {
        (&*start) - (&*end)
    };
    let len = diff / step + BigInt::from(1u8);
    let max = BigInt::from(MAX_RANGE_OUTPUT_ELEMENTS);
    if len > max {
        bail!("range would produce too many elements")
    }
    len.to_usize()
        .ok_or_else(|| anyhow!("could not determine number of elements"))
}

fn make_step_number(step: &BigInt, ascending: bool) -> Number {
    let signed = if ascending {
        step.clone()
    } else {
        -step.clone()
    };
    Number::BigInt(crate::Rc::new(signed))
}

pub fn register(m: &mut builtins::BuiltinsMap<&'static str, builtins::BuiltinFcn>) {
    m.insert("abs", (abs, 1));
    m.insert("ceil", (ceil, 1));
    m.insert("floor", (floor, 1));
    m.insert("numbers.range", (range, 2));
    m.insert("numbers.range_step", (range_step, 3));
    #[cfg(feature = "std")]
    m.insert("rand.intn", (intn, 2));
    m.insert("round", (round, 1));
}

pub fn arithmetic_operation(
    span: &Span,
    op: &ArithOp,
    expr1: &Expr,
    expr2: &Expr,
    v1: Value,
    v2: Value,
    strict: bool,
) -> Result<Value> {
    let op_name = format!("{op:?}").to_lowercase();
    let v1 = ensure_numeric(op_name.as_str(), expr1, &v1)?;
    let v2 = ensure_numeric(op_name.as_str(), expr2, &v2)?;

    Ok(Value::from(match op {
        ArithOp::Add => v1.add(&v2)?,
        ArithOp::Sub => v1.sub(&v2)?,
        ArithOp::Mul => v1.mul(&v2)?,
        ArithOp::Div if strict && v2 == Number::from(0u64) => bail!(span.error("divide by zero")),
        ArithOp::Div if v2 == Number::from(0u64) => return Ok(Value::Undefined),
        ArithOp::Div => v1.divide(&v2)?,
        ArithOp::Mod if strict && v2 == Number::from(0u64) => bail!(span.error("modulo by zero")),
        ArithOp::Mod if v2 == Number::from(0u64) => return Ok(Value::Undefined),
        ArithOp::Mod if !v1.is_integer() || !v2.is_integer() => {
            bail!(span.error("modulo on floating-point number"))
        }
        ArithOp::Mod => v1.modulo(&v2)?,
    }))
}

fn abs(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    ensure_args_count(span, "abs", params, args, 1)?;
    Ok(Value::from(
        ensure_numeric("abs", &params[0], &args[0])?.abs(),
    ))
}

fn ceil(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    ensure_args_count(span, "ceil", params, args, 1)?;
    Ok(Value::from(
        ensure_numeric("ceil", &params[0], &args[0])?.ceil(),
    ))
}

fn floor(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    ensure_args_count(span, "floor", params, args, 1)?;
    Ok(Value::from(
        ensure_numeric("floor", &params[0], &args[0])?.floor(),
    ))
}

fn range(span: &Span, params: &[Ref<Expr>], args: &[Value], strict: bool) -> Result<Value> {
    let name = "numbers.range";
    ensure_args_count(span, name, params, args, 2)?;
    let v1 = ensure_numeric(name, &params[0], &args[0].clone())?;
    let v2 = ensure_numeric(name, &params[1], &args[1].clone())?;

    match v1.is_integer() {
        false if strict => bail!(params[0].span().error("operand must be integer")),
        false => return Ok(Value::Undefined),
        _ => (),
    }

    match v2.is_integer() {
        false if strict => bail!(params[1].span().error("operand must be integer")),
        false => return Ok(Value::Undefined),
        _ => (),
    }

    let ascending = v2 >= v1;
    let step = BigInt::from(1u8);
    let num_elements = checked_range_len(&v1, &v2, &step)
        .map_err(|_| span.error("could not determine number of elements"))?;

    let mut values = Vec::with_capacity(num_elements);
    let mut value = v1;
    let increment = make_step_number(&step, ascending);
    for idx in 0..num_elements {
        values.push(Value::from(value.clone()));
        enforce_limit()?;
        if idx + 1 < num_elements {
            value.add_assign(&increment)?;
        }
    }
    Ok(Value::from_array(values))
}

fn range_step(span: &Span, params: &[Ref<Expr>], args: &[Value], strict: bool) -> Result<Value> {
    let name = "numbers.range_step";
    ensure_args_count(span, name, params, args, 3)?;
    let v1 = ensure_numeric(name, &params[0], &args[0].clone())?;
    let v2 = ensure_numeric(name, &params[1], &args[1].clone())?;
    let incr = ensure_numeric(name, &params[2], &args[2].clone())?;

    match v1.is_integer() {
        false if strict => bail!(params[0].span().error("operand must be integer")),
        false => return Ok(Value::Undefined),
        _ => (),
    }

    match v2.is_integer() {
        false if strict => bail!(params[1].span().error("operand must be integer")),
        false => return Ok(Value::Undefined),
        _ => (),
    }

    if !incr.is_integer() || incr <= Number::from(0u64) {
        if strict {
            bail!(params[2].span().error("step must be a positive integer"))
        }
        return Ok(Value::Undefined);
    }

    let step = incr.to_big()?;
    let ascending = v2 >= v1;
    let num_elements = checked_range_len(&v1, &v2, &step)
        .map_err(|_| span.error("could not determine number of elements"))?;

    let mut values = Vec::with_capacity(num_elements);
    let increment = make_step_number(&step, ascending);
    let mut value = v1;
    for idx in 0..num_elements {
        values.push(Value::from(value.clone()));
        enforce_limit()?;
        if idx + 1 < num_elements {
            value.add_assign(&increment)?;
        }
    }

    Ok(Value::from_array(values))
}

fn round(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "round";
    ensure_args_count(span, name, params, args, 1)?;
    Ok(Value::from(
        ensure_numeric(name, &params[0], &args[0])?.round(),
    ))
}

#[cfg(feature = "std")]
fn intn(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let fcn = "rand.intn";
    ensure_args_count(span, fcn, params, args, 2)?;
    let _ = crate::builtins::utils::ensure_string(fcn, &params[0], &args[0])?;
    let n = ensure_numeric(fcn, &params[0], &args[1])?;

    Ok(match n.as_u64() {
        Some(0) => Value::from(0u64),
        Some(n) => {
            // TODO: bounds checking; arbitrary precision
            let v = rand::rng().random_range(0..n);
            Value::from(v)
        }
        _ => Value::Undefined,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Engine;
    use alloc::string::ToString;

    fn eval(query: &str) -> Value {
        Engine::new()
            .eval_query(query.to_string(), false)
            .expect("query must succeed")
            .result[0]
            .expressions[0]
            .value
            .clone()
    }

    #[test]
    fn range_handles_i64_min_without_overflow() {
        let value = eval("numbers.range(-9223372036854775808, -9223372036854775808)");
        assert_eq!(value, Value::from_array(alloc::vec![Value::from(i64::MIN)]));
    }

    #[test]
    fn range_step_rejects_zero_step() {
        let err = Engine::new()
            .eval_query("numbers.range_step(1, 3, 0)".to_string(), false)
            .expect_err("zero step must error");
        assert!(err.to_string().contains("step must be a positive integer"));
    }

    #[test]
    fn range_step_rejects_negative_step() {
        let err = Engine::new()
            .eval_query("numbers.range_step(1, 3, -1)".to_string(), false)
            .expect_err("negative step must error");
        assert!(err.to_string().contains("step must be a positive integer"));
    }

    #[test]
    fn range_rejects_unbounded_output_before_allocating() {
        let err = Engine::new()
            .eval_query("numbers.range(0, 1000001)".to_string(), false)
            .expect_err("oversized range must error");
        assert!(err
            .to_string()
            .contains("could not determine number of elements"));
    }
}
