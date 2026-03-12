// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Path registry — maps access paths (e.g., `input.user.role`) to SMT variables.
//!
//! The path-based encoding is the central design choice: every access into `input`
//! (or symbolic `data`) discovered during translation gets a flat SMT variable named
//! by its access path. This makes model-to-JSON extraction trivial.

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use std::collections::HashMap;

use regorus_smt::{SmtDecl, SmtExpr, SmtSort};

use super::types::ValueSort;

/// Map a `ValueSort` to the corresponding SMT sort.
#[allow(dead_code)]
fn value_sort_to_smt(sort: ValueSort) -> SmtSort {
    match sort {
        ValueSort::Bool => SmtSort::Bool,
        ValueSort::Int => SmtSort::Int,
        ValueSort::Real => SmtSort::Real,
        ValueSort::String => SmtSort::String,
        ValueSort::Unknown => SmtSort::String, // default
    }
}

/// A single path entry in the registry.
#[derive(Debug, Clone)]
pub struct PathEntry {
    /// The SMT boolean controlling whether this path is defined (present in input).
    pub defined: SmtExpr,
    /// The inferred sort for this path's value.
    pub sort: ValueSort,
    /// Whether all access components were literal (fully static path).
    pub is_static: bool,
    /// Instruction PCs that access this path (for coverage mapping).
    pub access_pcs: Vec<usize>,

    // The actual SMT variable (SmtExpr::Const(id)). One per sort, created on demand.
    pub(crate) bool_var: Option<SmtExpr>,
    pub(crate) int_var: Option<SmtExpr>,
    pub(crate) real_var: Option<SmtExpr>,
    pub(crate) str_var: Option<SmtExpr>,
}

/// Registry of all discovered access paths into `input` (and symbolic `data`).
#[allow(missing_debug_implementations)]
pub struct PathRegistry {
    paths: HashMap<String, PathEntry>,
    /// Counter for generating unique variable IDs.
    next_id: u32,
    /// All SMT constant declarations created by this registry.
    declarations: Vec<SmtDecl>,
}

impl PathRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            paths: HashMap::new(),
            next_id: 0,
            declarations: Vec::new(),
        }
    }

    /// Allocate a fresh SMT constant, returning its `SmtExpr::Const(id)`.
    pub(crate) fn alloc_const(&mut self, name: &str, sort: SmtSort) -> SmtExpr {
        let id = self.next_id;
        self.next_id += 1;
        self.declarations.push(SmtDecl::Const {
            id,
            name: name.into(),
            sort,
        });
        SmtExpr::Const(id)
    }

    /// Get or create a path entry. If the path already exists, its sort may be
    /// refined (Unknown → concrete sort) but never changed between concrete sorts.
    pub fn get_or_create(
        &mut self,
        path: &str,
        sort: ValueSort,
        is_static: bool,
        pc: usize,
    ) -> &mut PathEntry {
        if self.paths.contains_key(path) {
            let entry = self.paths.get_mut(path).unwrap();
            entry.access_pcs.push(pc);
            if entry.sort == ValueSort::Unknown && sort != ValueSort::Unknown {
                entry.sort = sort;
            }
            return entry;
        }

        // Create new entry with a fresh `defined` boolean.
        let defined_name = format!("defined_{}", path);
        let defined = self.alloc_const(&defined_name, SmtSort::Bool);

        self.paths.insert(
            path.to_string(),
            PathEntry {
                defined,
                sort,
                is_static,
                access_pcs: vec![pc],
                bool_var: None,
                int_var: None,
                real_var: None,
                str_var: None,
            },
        );
        self.paths.get_mut(path).unwrap()
    }

    /// Check if any sort-specific variable already exists for this path.
    fn has_any_var(&self, path: &str) -> bool {
        if let Some(entry) = self.paths.get(path) {
            entry.bool_var.is_some()
                || entry.int_var.is_some()
                || entry.real_var.is_some()
                || entry.str_var.is_some()
        } else {
            false
        }
    }

    /// Get the SMT Bool variable for a path, creating it if needed.
    ///
    /// If a variable of a different sort already exists for this path,
    /// the new declaration uses a sort-disambiguated name (`path$Bool`)
    /// to avoid duplicate-name errors in SMT-LIB2 text rendering.
    pub fn get_bool(&mut self, path: &str) -> SmtExpr {
        self.get_or_create(path, ValueSort::Bool, true, 0);
        if let Some(var) = &self.paths.get(path).unwrap().bool_var {
            return var.clone();
        }
        let name = if self.has_any_var(path) {
            format!("{}$Bool", path)
        } else {
            path.to_string()
        };
        let var = self.alloc_const(&name, SmtSort::Bool);
        self.paths.get_mut(path).unwrap().bool_var = Some(var.clone());
        var
    }

    /// Get the SMT Int variable for a path, creating it if needed.
    pub fn get_int(&mut self, path: &str) -> SmtExpr {
        self.get_or_create(path, ValueSort::Int, true, 0);
        if let Some(var) = &self.paths.get(path).unwrap().int_var {
            return var.clone();
        }
        let name = if self.has_any_var(path) {
            format!("{}$Int", path)
        } else {
            path.to_string()
        };
        let var = self.alloc_const(&name, SmtSort::Int);
        self.paths.get_mut(path).unwrap().int_var = Some(var.clone());
        var
    }

    /// Get the SMT Real variable for a path, creating it if needed.
    pub fn get_real(&mut self, path: &str) -> SmtExpr {
        self.get_or_create(path, ValueSort::Real, true, 0);
        if let Some(var) = &self.paths.get(path).unwrap().real_var {
            return var.clone();
        }
        let name = if self.has_any_var(path) {
            format!("{}$Real", path)
        } else {
            path.to_string()
        };
        let var = self.alloc_const(&name, SmtSort::Real);
        self.paths.get_mut(path).unwrap().real_var = Some(var.clone());
        var
    }

    /// Get the SMT String variable for a path, creating it if needed.
    pub fn get_string(&mut self, path: &str) -> SmtExpr {
        self.get_or_create(path, ValueSort::String, true, 0);
        if let Some(var) = &self.paths.get(path).unwrap().str_var {
            return var.clone();
        }
        let name = if self.has_any_var(path) {
            format!("{}$String", path)
        } else {
            path.to_string()
        };
        let var = self.alloc_const(&name, SmtSort::String);
        self.paths.get_mut(path).unwrap().str_var = Some(var.clone());
        var
    }

    /// Get a path entry by name (immutable).
    pub fn get(&self, path: &str) -> Option<&PathEntry> {
        self.paths.get(path)
    }

    /// Iterate over all registered paths.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &PathEntry)> {
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

    /// All SMT declarations created by this registry.
    pub fn declarations(&self) -> &[SmtDecl] {
        &self.declarations
    }

    /// Update the sort of a path and ensure the corresponding SMT variable exists.
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
    pub fn seed_sorts_from_value(
        &mut self,
        prefix: &str,
        value: &super::super::super::value::Value,
        max_elements: usize,
    ) {
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
                    if arr.is_empty() {
                        break;
                    }
                    let elem = &arr[idx % arr.len()];
                    let child_path = format!("{}[{}]", prefix, idx);
                    self.seed_sorts_from_value(&child_path, elem, max_elements);
                }
            }
            Value::Bool(_) => {
                // Seed the sort AND create the SMT variable so it's available
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

    /// Get an SMT variable for a path with the given sort, creating if needed.
    /// Returns `None` if the path doesn't exist.
    pub fn get_var_for_sort(
        &mut self,
        path: &str,
        sort: ValueSort,
    ) -> Option<super::types::SymValue> {
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
