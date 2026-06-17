//! The context schema: which `input.*` paths a given enforcement hook can
//! observe, and their types.
//!
//! A policy can only be lifted if every atom's `input_path` binds to a field
//! present here. This encodes the "assumptions = required context schema" gate:
//! an input field the kernel hook cannot observe is not bindable, so the policy
//! stays in user space.

use std::collections::BTreeMap;

/// The scalar type of an observable field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    Str,
    Bool,
    Int,
    Uint,
}

/// A set of observable input fields for a particular enforcement hook.
#[derive(Debug, Clone, Default)]
pub struct ContextSchema {
    fields: BTreeMap<String, FieldType>,
}

impl ContextSchema {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: declare an observable field, e.g.
    /// `with("input.dest_ip", FieldType::Str)`.
    pub fn with(mut self, input_path: impl Into<String>, ty: FieldType) -> Self {
        self.fields.insert(input_path.into(), ty);
        self
    }

    /// The declared type of `input_path`, or `None` if not observable.
    pub fn field_type(&self, input_path: &str) -> Option<FieldType> {
        self.fields.get(input_path).copied()
    }

    pub fn is_observable(&self, input_path: &str) -> bool {
        self.fields.contains_key(input_path)
    }

    pub fn fields(&self) -> &BTreeMap<String, FieldType> {
        &self.fields
    }
}
