// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Aggregated literal information extracted during type analysis.

use alloc::borrow::ToOwned;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use crate::value::Value;

/// Summary of literal values discovered while analysing a policy.
#[derive(Clone, Debug, Default)]
pub struct LiteralTableSketch {
    string_literals: BTreeSet<String>,
    boolean_literals: BTreeSet<bool>,
    numeric_literals: BTreeSet<Value>,
    composite_literals: BTreeSet<Value>,
    null_present: bool,
    undefined_present: bool,
}

impl LiteralTableSketch {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a literal value observed during analysis.
    pub fn record_literal(&mut self, value: &Value) {
        match value {
            Value::String(s) => {
                self.string_literals.insert(s.as_ref().to_owned());
            }
            Value::Bool(flag) => {
                self.boolean_literals.insert(*flag);
            }
            Value::Number(_) => {
                self.numeric_literals.insert(value.clone());
            }
            Value::Array(_) | Value::Object(_) | Value::Set(_) => {
                self.composite_literals.insert(value.clone());
            }
            Value::Null => self.null_present = true,
            Value::Undefined => self.undefined_present = true,
        }
    }

    /// Merge another sketch into this one.
    pub fn merge(&mut self, other: &LiteralTableSketch) {
        self.string_literals
            .extend(other.string_literals.iter().cloned());
        self.boolean_literals
            .extend(other.boolean_literals.iter().copied());
        self.numeric_literals
            .extend(other.numeric_literals.iter().cloned());
        self.composite_literals
            .extend(other.composite_literals.iter().cloned());
        self.null_present |= other.null_present;
        self.undefined_present |= other.undefined_present;
    }

    pub fn string_literals(&self) -> Vec<String> {
        self.string_literals.iter().cloned().collect()
    }

    pub fn boolean_literals(&self) -> Vec<bool> {
        self.boolean_literals.iter().copied().collect()
    }

    pub fn numeric_literals(&self) -> Vec<Value> {
        self.numeric_literals.iter().cloned().collect()
    }

    pub fn composite_literals(&self) -> Vec<Value> {
        self.composite_literals.iter().cloned().collect()
    }

    pub fn null_present(&self) -> bool {
        self.null_present
    }

    pub fn undefined_present(&self) -> bool {
        self.undefined_present
    }
}
