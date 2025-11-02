// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Metadata describing virtual data document lookups discovered during analysis.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ast::ExprRef;

/// Component inside a virtual data lookup path.
#[derive(Clone, Debug)]
pub enum VirtualComponent {
    /// Static field access (e.g., `.field`)
    Field(String),
    /// Dynamic segment driven by another expression (e.g., `[expr]`)
    Binding(ExprRef),
}

/// Analyzer-produced description of a virtual data lookup.
#[derive(Clone, Debug)]
pub struct VirtualDataLookup {
    /// Static prefix (root + contiguous literal fields) preceding any dynamic bindings.
    pub static_path: Vec<String>,
    /// Full sequence of path components following the root.
    pub components: Vec<VirtualComponent>,
    /// Normalised pattern string with `*` markers for dynamic segments.
    pub path_pattern: String,
}

impl VirtualDataLookup {
    /// Create a new virtual lookup description.
    pub fn new(
        static_path: Vec<String>,
        components: Vec<VirtualComponent>,
        path_pattern: String,
    ) -> Self {
        Self {
            static_path,
            components,
            path_pattern,
        }
    }

    /// Iterate over dynamic binding expressions in the order they appear in the path.
    pub fn bindings(&self) -> impl Iterator<Item = &ExprRef> {
        self.components
            .iter()
            .filter_map(|component| match component {
                VirtualComponent::Binding(expr) => Some(expr),
                VirtualComponent::Field(_) => None,
            })
    }

    /// Returns the normalised path pattern for this lookup (e.g. `data.pkg.*.item`).
    pub fn pattern(&self) -> &str {
        &self.path_pattern
    }

    /// Returns true if this lookup contains any dynamic bindings within the path.
    pub fn has_dynamic_segments(&self) -> bool {
        self.components
            .iter()
            .any(|component| matches!(component, VirtualComponent::Binding(_)))
    }
}
