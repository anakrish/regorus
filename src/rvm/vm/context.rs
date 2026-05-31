// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::rvm::instructions::{ComprehensionMode, LoopMode};
use crate::value::Value;
use crate::Rc;
use alloc::vec::Vec;

/// Loop execution context for managing iteration state
#[derive(Debug, Clone)]
pub struct LoopContext {
    pub mode: LoopMode,
    pub iteration_state: IterationState,
    pub key_reg: u8,
    pub value_reg: u8,
    pub result_reg: u8,
    pub body_start: u16,
    pub loop_end: u16,
    pub loop_next_pc: u16, // PC of the LoopNext instruction to avoid searching
    pub body_resume_pc: usize,
    pub success_count: usize,
    pub total_iterations: usize,
    pub current_iteration_failed: bool, // Track if current iteration had condition failures
}

/// Iterator state for different collection types
#[derive(Debug, Clone)]
pub enum IterationState {
    Array {
        items: Rc<Vec<Value>>,
        index: usize,
    },
    Object {
        pairs: Rc<[(Value, Value)]>,
        pos: usize,
    },
    Set {
        values: Rc<[Value]>,
        pos: usize,
    },
    /// Virtual single-element iteration for non-collection values.
    /// Used by Azure Policy's `[*]` on scalar/null fields: presents a single
    /// "virtual" element to iterate over, which is always `Null` regardless
    /// of the underlying source value.
    Single {
        consumed: bool,
    },
}

impl IterationState {
    pub(super) const fn advance(&mut self) {
        match *self {
            Self::Array { ref mut index, .. } => {
                *index = index.saturating_add(1);
            }
            Self::Object { ref mut pos, .. } | Self::Set { ref mut pos, .. } => {
                *pos = pos.saturating_add(1);
            }
            Self::Single {
                ref mut consumed, ..
            } => {
                *consumed = true;
            }
        }
    }
}

#[allow(unused)]
#[derive(Debug, Clone)]
pub struct CallRuleContext {
    pub return_pc: usize,
    pub dest_reg: u8,
    pub result_reg: u8,
    pub rule_index: u16,
    pub rule_type: crate::rvm::program::RuleType,
    pub current_definition_index: usize,
    pub current_body_index: usize,
}

/// Context for tracking active comprehensions
#[derive(Debug, Clone)]
pub(super) struct ComprehensionContext {
    /// Type of comprehension (Array, Set, Object)
    pub(super) mode: ComprehensionMode,
    /// Register storing the comprehension result collection
    pub(super) result_reg: u8,
    /// Register holding the current iteration key
    pub(super) key_reg: u8,
    /// Register holding the current iteration value
    pub(super) value_reg: u8,
    /// Jump target for comprehension body start
    pub(super) body_start: u16,
    /// Jump target for comprehension end
    pub(super) comprehension_end: u16,
    /// Iteration state when comprehension manages iteration itself (None when driven by LoopStart/LoopNext)
    pub(super) iteration_state: Option<IterationState>,
    /// Resume location for the parent frame once this comprehension completes
    pub(super) resume_pc: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collections::Object;

    /// IterationState::Object snapshots (key, value) pairs at construction
    /// time. Mutating the source Value::Object (via Rc::make_mut on a clone)
    /// while the iteration is in flight must not affect the snapshot.
    #[test]
    fn iteration_state_object_is_snapshot_independent_of_source() {
        let mut obj = Object::new();
        obj.insert(Value::from("a"), Value::from(1));
        obj.insert(Value::from("b"), Value::from(2));
        obj.insert(Value::from("c"), Value::from(3));

        let source = Value::Object(Rc::new(obj));

        // Build the snapshot exactly as loops.rs / comprehension.rs do.
        let pairs: Rc<[(Value, Value)]> = match &source {
            Value::Object(o) => o
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>()
                .into(),
            _ => unreachable!(),
        };
        let state = IterationState::Object {
            pairs: Rc::clone(&pairs),
            pos: 0,
        };

        // Mutate a clone of the source mid-iteration.
        let mut alias = source.clone();
        let inner = alias.as_object_mut().expect("object");
        inner.insert(Value::from("a"), Value::from(999));
        inner.insert(Value::from("d"), Value::from(4));
        inner.remove(&Value::from("b"));

        // Snapshot must still report the original 3 entries with original values.
        let collected: Vec<(Value, Value)> = match &state {
            IterationState::Object { pairs, .. } => pairs.to_vec(),
            _ => unreachable!(),
        };
        assert_eq!(collected.len(), 3);
        assert!(collected.contains(&(Value::from("a"), Value::from(1))));
        assert!(collected.contains(&(Value::from("b"), Value::from(2))));
        assert!(collected.contains(&(Value::from("c"), Value::from(3))));
        assert!(!collected
            .iter()
            .any(|(k, _)| k == &Value::from("d")));

        // The original source Value (untouched) is also unchanged.
        let src_obj = source.as_object().expect("object");
        assert_eq!(src_obj.len(), 3);
        assert_eq!(src_obj.get(&Value::from("a")), Some(&Value::from(1)));
    }
}
