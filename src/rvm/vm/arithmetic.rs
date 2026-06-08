// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#![allow(clippy::pattern_type_mismatch)]

use crate::value::ValueSet;

use crate::number::Number;
use crate::value::Value;

use super::errors::{Result, VmError};
use super::machine::RegoVM;

impl RegoVM {
    /// Add two values using interpreter's arithmetic logic
    pub(super) fn add_values(&self, a: &Value, b: &Value) -> Result<Value> {
        match (a.to_number(), b.to_number()) {
            (Some(x), Some(y)) => Ok(Value::from_number(x.add(&y)?)),
            _ => Err(VmError::InvalidAddition {
                left: a.clone(),
                right: b.clone(),
                pc: self.pc,
            }),
        }
    }

    /// Subtract two values using interpreter's arithmetic logic
    pub(super) fn sub_values(&self, a: &Value, b: &Value) -> Result<Value> {
        match (a.to_number(), b.to_number()) {
            (Some(x), Some(y)) => Ok(Value::from_number(x.sub(&y)?)),
            _ => match (a, b) {
                (Value::Set(left), Value::Set(right)) => {
                    let diff: ValueSet = left.difference(right).cloned().collect();
                    Ok(Value::from_set(diff))
                }
                _ => Err(VmError::InvalidSubtraction {
                    left: a.clone(),
                    right: b.clone(),
                    pc: self.pc,
                }),
            },
        }
    }

    /// Multiply two values using interpreter's arithmetic logic
    pub(super) fn mul_values(&self, a: &Value, b: &Value) -> Result<Value> {
        match (a.to_number(), b.to_number()) {
            (Some(x), Some(y)) => Ok(Value::from_number(x.mul(&y)?)),
            _ => Err(VmError::InvalidMultiplication {
                left: a.clone(),
                right: b.clone(),
                pc: self.pc,
            }),
        }
    }

    /// Divide two values using interpreter's arithmetic logic
    pub(super) fn div_values(&self, a: &Value, b: &Value) -> Result<Value> {
        match (a.to_number(), b.to_number()) {
            (Some(x), Some(y)) => {
                if y == Number::from(0_u64) {
                    if self.strict_builtin_errors {
                        return Err(VmError::InvalidDivision {
                            left: a.clone(),
                            right: b.clone(),
                            pc: self.pc,
                        });
                    }
                    return Ok(Value::Undefined);
                }

                Ok(Value::from_number(x.divide(&y)?))
            }
            _ => Err(VmError::InvalidDivision {
                left: a.clone(),
                right: b.clone(),
                pc: self.pc,
            }),
        }
    }

    /// Modulo two values using interpreter's arithmetic logic
    pub(super) fn mod_values(&self, a: &Value, b: &Value) -> Result<Value> {
        match (a.to_number(), b.to_number()) {
            (Some(x), Some(y)) => {
                if y == Number::from(0_u64) {
                    if self.strict_builtin_errors {
                        return Err(VmError::InvalidModulo {
                            left: a.clone(),
                            right: b.clone(),
                            pc: self.pc,
                        });
                    }
                    return Ok(Value::Undefined);
                }

                if !x.is_integer() || !y.is_integer() {
                    return Err(VmError::ModuloOnFloat {
                        left: a.clone(),
                        right: b.clone(),
                        pc: self.pc,
                    });
                }

                Ok(Value::from_number(x.modulo(&y)?))
            }
            _ => Err(VmError::InvalidModulo {
                left: a.clone(),
                right: b.clone(),
                pc: self.pc,
            }),
        }
    }

    pub(super) const fn to_bool(&self, value: &Value) -> Option<bool> {
        match value {
            Value::Bool(b) => Some(*b),
            Value::Null if !self.strict_builtin_errors => Some(true),
            _ => None,
        }
    }
}
