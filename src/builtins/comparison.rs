// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::pattern_type_mismatch)]

use crate::ast::BoolOp;
use crate::value::Value;

use anyhow::{bail, Result};
use core::cmp::Ordering;

pub(crate) const MAX_COMPARISON_DEPTH: usize = 512;

fn value_kind_rank(value: &Value) -> u8 {
    match value {
        Value::Null => 0,
        Value::Bool(_) => 1,
        Value::Number(_) => 2,
        Value::String(_) => 3,
        Value::Array(_) => 4,
        Value::Set(_) => 5,
        Value::Object(_) => 6,
        Value::Undefined => 7,
    }
}

fn compare_values_with_limit_impl(v1: &Value, v2: &Value, depth: usize) -> Result<Ordering> {
    if depth > MAX_COMPARISON_DEPTH {
        bail!("value comparison exceeded the maximum supported nesting depth");
    }

    let rank_cmp = value_kind_rank(v1).cmp(&value_kind_rank(v2));
    if rank_cmp != Ordering::Equal {
        return Ok(rank_cmp);
    }

    match (v1, v2) {
        (Value::Null, Value::Null) | (Value::Undefined, Value::Undefined) => Ok(Ordering::Equal),
        (Value::Bool(lhs), Value::Bool(rhs)) => Ok(lhs.cmp(rhs)),
        (Value::Number(lhs), Value::Number(rhs)) => Ok(lhs.cmp(rhs)),
        (Value::String(lhs), Value::String(rhs)) => Ok(lhs.cmp(rhs)),
        (Value::Array(lhs), Value::Array(rhs)) => {
            for (left, right) in lhs.iter().zip(rhs.iter()) {
                let ordering = compare_values_with_limit_impl(left, right, depth + 1)?;
                if ordering != Ordering::Equal {
                    return Ok(ordering);
                }
            }
            Ok(lhs.len().cmp(&rhs.len()))
        }
        (Value::Set(lhs), Value::Set(rhs)) => {
            for (left, right) in lhs.iter().zip(rhs.iter()) {
                let ordering = compare_values_with_limit_impl(left, right, depth + 1)?;
                if ordering != Ordering::Equal {
                    return Ok(ordering);
                }
            }
            Ok(lhs.len().cmp(&rhs.len()))
        }
        (Value::Object(lhs), Value::Object(rhs)) => {
            let mut lhs_iter = lhs.iter_sorted();
            let mut rhs_iter = rhs.iter_sorted();
            loop {
                match (lhs_iter.next(), rhs_iter.next()) {
                    (Some((lhs_key, lhs_value)), Some((rhs_key, rhs_value))) => {
                        let key_order =
                            compare_values_with_limit_impl(lhs_key, rhs_key, depth + 1)?;
                        if key_order != Ordering::Equal {
                            return Ok(key_order);
                        }
                        let value_order =
                            compare_values_with_limit_impl(lhs_value, rhs_value, depth + 1)?;
                        if value_order != Ordering::Equal {
                            return Ok(value_order);
                        }
                    }
                    (Some(_), None) => return Ok(Ordering::Greater),
                    (None, Some(_)) => return Ok(Ordering::Less),
                    (None, None) => return Ok(Ordering::Equal),
                }
            }
        }
        _ => Ok(Ordering::Equal),
    }
}

pub(crate) fn compare_values_with_limit(v1: &Value, v2: &Value) -> Result<Ordering> {
    compare_values_with_limit_impl(v1, v2, 0)
}

/// compare two values
///
/// When comparing values of different kinds, the following order is honored.
/// That is, null is less than all other kinds of values. bool is greater than
/// null, but less than other kinds of values, and so on.
///
///   1. null
///   2. bool
///   3. number
///   4. string
///   5. Array
///   6. Object
///   7. Set
///
/// Scalar types like null, bool, number, string follow ordering same as what is seen in other languages when compared with values of the same kind.
///
/// When comparing arrays, each item from the first array is compared with the corresponding item from the second array. The ordering is determined by
/// the ordering of the first non-equal items. In case all the compared items
/// are equal, the ordering is determined by comparing the length of the first array
/// with the length of the second array. The smaller array is 'Less' than the larger array.
///
/// Sets compare similar to arrays.
///
/// When comparing objects, each entry (key, value) from the first object is compared with the corresponding
/// entry from the second object. The ordering is determined by the ordering of the first non-equal entries. In case all the compared entries are equal,
/// the ordering is determined by comparing the length of the first object with the length of the second object. The smaller object is 'Less' then the larger object.
///
/// Undefined values are a special case. Comparing an Undefined value with
/// any other value results in Undefined.
///
/// # Arguments
/// * `op` - The comparison operation to perform.
/// * `v1` - The first value.
/// * `v2` - The second value.
pub fn compare(op: &BoolOp, v1: &Value, v2: &Value) -> Result<Value> {
    let ordering = compare_values_with_limit(v1, v2)?;
    Ok(Value::Bool(match op {
        BoolOp::Eq => ordering == Ordering::Equal,
        BoolOp::Ne => ordering != Ordering::Equal,
        BoolOp::Lt => ordering == Ordering::Less,
        BoolOp::Le => ordering != Ordering::Greater,
        BoolOp::Gt => ordering == Ordering::Greater,
        BoolOp::Ge => ordering != Ordering::Less,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString as _;

    fn nested_array(depth: usize) -> Value {
        let mut value = Value::from(0_u64);
        for _ in 0..depth {
            value = Value::from_array(alloc::vec![value]);
        }
        value
    }

    #[test]
    fn compare_rejects_excessive_nesting_depth() {
        let deep = nested_array(MAX_COMPARISON_DEPTH + 1);
        let err = compare(&BoolOp::Eq, &deep, &deep).expect_err("deep compare must error");
        assert!(err
            .to_string()
            .contains("value comparison exceeded the maximum supported nesting depth"));
    }
}
