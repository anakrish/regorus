// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Path registry — maps access paths (e.g., `input.user.role`) to Z3 variables.
//!
//! The path-based encoding is the central design choice: every access into `input`
//! (or symbolic `data`) discovered during translation gets a flat Z3 variable named
//! by its access path. This makes model-to-JSON extraction trivial.

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use std::collections::HashMap;

use z3::ast::{Bool as Z3Bool, Int as Z3Int, Real as Z3Real, String as Z3String};

use super::types::ValueSort;

/// A single path entry in the registry.
#[derive(Debug, Clone)]
pub struct PathEntry<'ctx> {
    /// The Z3 boolean controlling whether this path is defined (present in input).
    pub defined: Z3Bool<'ctx>,
    /// The inferred sort for this path's value.
    pub sort: ValueSort,
    /// Whether all access components were literal (fully static path).
    pub is_static: bool,
    /// Instruction PCs that access this path (for coverage mapping).
    pub access_pcs: Vec<usize>,

    // The actual Z3 variable. We store one per sort and create on demand.
    pub(crate) bool_var: Option<Z3Bool<'ctx>>,
    pub(crate) int_var: Option<Z3Int<'ctx>>,
    pub(crate) real_var: Option<Z3Real<'ctx>>,
    pub(crate) str_var: Option<Z3String<'ctx>>,
}

/// Registry of all discovered access paths into `input` (and symbolic `data`).
#[allow(missing_debug_implementations)]
pub struct PathRegistry<'ctx> {
    ctx: &'ctx z3::Context,
    paths: HashMap<String, PathEntry<'ctx>>,
    /// Counter for generating unique variable names when paths collide.
    next_id: u32,
}

impl<'ctx> PathRegistry<'ctx> {
    /// Create a new empty registry.
    pub fn new(ctx: &'ctx z3::Context) -> Self {
        Self {
            ctx,
            paths: HashMap::new(),
            next_id: 0,
        }
    }

    /// Get or create a path entry. If the path already exists, its sort may be
    /// refined (Unknown → concrete sort) but never changed between concrete sorts.
    pub fn get_or_create(
        &mut self,
        path: &str,
        sort: ValueSort,
        is_static: bool,
        pc: usize,
    ) -> &mut PathEntry<'ctx> {
        let ctx = self.ctx;
        let next_id = &mut self.next_id;
        self.paths
            .entry(path.to_string())
            .and_modify(|entry| {
                entry.access_pcs.push(pc);
                // Refine sort if currently Unknown
                if entry.sort == ValueSort::Unknown && sort != ValueSort::Unknown {
                    entry.sort = sort;
                }
            })
            .or_insert_with(|| {
                *next_id += 1;
                let defined_name = format!("defined_{}", path);
                let defined = Z3Bool::new_const(ctx, defined_name.as_str());
                PathEntry {
                    defined,
                    sort,
                    is_static,
                    access_pcs: vec![pc],
                    bool_var: None,
                    int_var: None,
                    real_var: None,
                    str_var: None,
                }
            })
    }

    /// Get the Z3 Bool variable for a path, creating it if needed.
    pub fn get_bool(&mut self, path: &str) -> Z3Bool<'ctx> {
        self.get_or_create(path, ValueSort::Bool, true, 0);
        let ctx = self.ctx;
        let entry = self.paths.get_mut(path).unwrap();
        if entry.bool_var.is_none() {
            entry.bool_var = Some(Z3Bool::new_const(ctx, path));
        }
        entry.bool_var.clone().unwrap()
    }

    /// Get the Z3 Int variable for a path, creating it if needed.
    pub fn get_int(&mut self, path: &str) -> Z3Int<'ctx> {
        self.get_or_create(path, ValueSort::Int, true, 0);
        let ctx = self.ctx;
        let entry = self.paths.get_mut(path).unwrap();
        if entry.int_var.is_none() {
            entry.int_var = Some(Z3Int::new_const(ctx, path));
        }
        entry.int_var.clone().unwrap()
    }

    /// Get the Z3 Real variable for a path, creating it if needed.
    pub fn get_real(&mut self, path: &str) -> Z3Real<'ctx> {
        self.get_or_create(path, ValueSort::Real, true, 0);
        let ctx = self.ctx;
        let entry = self.paths.get_mut(path).unwrap();
        if entry.real_var.is_none() {
            entry.real_var = Some(Z3Real::new_const(ctx, path));
        }
        entry.real_var.clone().unwrap()
    }

    /// Get the Z3 String variable for a path, creating it if needed.
    pub fn get_string(&mut self, path: &str) -> Z3String<'ctx> {
        self.get_or_create(path, ValueSort::String, true, 0);
        let ctx = self.ctx;
        let entry = self.paths.get_mut(path).unwrap();
        if entry.str_var.is_none() {
            entry.str_var = Some(Z3String::new_const(ctx, path));
        }
        entry.str_var.clone().unwrap()
    }

    /// Get a path entry by name (immutable).
    pub fn get(&self, path: &str) -> Option<&PathEntry<'ctx>> {
        self.paths.get(path)
    }

    /// Iterate over all registered paths.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &PathEntry<'ctx>)> {
        self.paths.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Number of registered paths.
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Is the registry empty?
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// Update the sort of a path and ensure the corresponding Z3 variable exists.
    pub fn refine_sort(&mut self, path: &str, sort: ValueSort) {
        if let Some(entry) = self.paths.get_mut(path) {
            if entry.sort == ValueSort::Unknown {
                entry.sort = sort;
            }
        }
    }

    /// Pre-seed the registry with sort information derived from an example
    /// input value.  This walks the value recursively, mapping each leaf to
    /// its `ValueSort`.  Array elements are expanded up to `max_elements`
    /// indices so that symbolic witness paths like `input.servers[2].id`
    /// will already have a known sort when the translator encounters them.
    pub fn seed_sorts_from_value(&mut self, prefix: &str, value: &super::super::super::value::Value, max_elements: usize) {
        use super::super::super::value::Value;
        match value {
            Value::Object(obj) => {
                for (k, v) in obj.iter() {
                    let key_str = match k {
                        Value::String(s) => s.to_string(),
                        other => format!("{:?}", other),
                    };
                    let child_path = format!("{}.{}", prefix, key_str);
                    self.seed_sorts_from_value(&child_path, v, max_elements);
                }
            }
            Value::Array(arr) => {
                // Seed sorts for indices 0..max_elements using the types
                // observed in the example array elements.
                for idx in 0..max_elements {
                    // Pick the element from the example (cycle if fewer).
                    if arr.is_empty() {
                        break;
                    }
                    let elem = &arr[idx % arr.len()];
                    let child_path = format!("{}[{}]", prefix, idx);
                    self.seed_sorts_from_value(&child_path, elem, max_elements);
                }
            }
            Value::Bool(_) => {
                // Seed the sort AND create the Z3 variable so it's available
                // for both constraint generation and model extraction.
                self.get_bool(prefix);
            }
            Value::Number(n) => {
                if n.as_f64().is_some() && n.as_i64().is_none() {
                    self.get_real(prefix);
                } else {
                    self.get_int(prefix);
                }
            }
            Value::String(_) => {
                self.get_string(prefix);
            }
            _ => {
                // Null, Undefined, Set — skip.
            }
        }
    }

    /// Get the sort registered for a path, if it exists.
    pub fn get_sort(&self, path: &str) -> Option<ValueSort> {
        self.paths.get(path).map(|e| e.sort)
    }

    /// Get a Z3 variable for a path with the given sort, creating if needed.
    /// Returns `None` if the path doesn't exist.
    pub fn get_var_for_sort(
        &mut self,
        path: &str,
        sort: ValueSort,
    ) -> Option<super::types::SymValue<'ctx>> {
        use super::types::SymValue;

        // Ensure the entry exists
        if !self.paths.contains_key(path) {
            return None;
        }

        match sort {
            ValueSort::Bool => Some(SymValue::Bool(self.get_bool(path))),
            ValueSort::Int => Some(SymValue::Int(self.get_int(path))),
            ValueSort::Real => Some(SymValue::Real(self.get_real(path))),
            ValueSort::String => Some(SymValue::Str(self.get_string(path))),
            ValueSort::Unknown => {
                // Default to String for unknown sorts (most general for Rego).
                Some(SymValue::Str(self.get_string(path)))
            }
        }
    }
}
