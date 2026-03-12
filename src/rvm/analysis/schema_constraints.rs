// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! JSON Schema → SMT constraint generator.
//!
//! Walks a subset of JSON Schema (draft-07 style) and emits SMT constraints
//! that restrict the symbolic `input` so that only well-typed, non-degenerate
//! values are produced by the solver.
//!
//! ## Supported keywords
//!
//! | Keyword       | Effect                                                    |
//! |---------------|-----------------------------------------------------------|
//! | `type`        | Registers the sort (Bool/Int/Real/String) in the registry |
//! | `properties`  | Recurses into object fields                               |
//! | `items`       | Recurses into array element schema                        |
//! | `required`    | Asserts that each listed field is *defined*                |
//! | `minItems`    | Asserts at least N array elements are defined             |
//! | `maxItems`    | Limits array expansion (caps loop depth)                  |
//! | `minLength`   | Z3 string-length ≥ N constraint                           |
//! | `enum`        | OR of equalities to the listed values                     |
//! | `x-unique`    | Pairwise ≠ across sibling array elements for this field   |
//! | `uniqueItems` | Pairwise ≠ across all elements of a plain-value array     |

use alloc::format;
use alloc::boxed::Box;
use alloc::vec::Vec;

use regorus_smt::SmtExpr;

use super::path_registry::PathRegistry;
use super::types::ValueSort;

/// Apply JSON Schema constraints to the symbolic input.
///
/// `schema` is a JSON-Schema-like object (as a `serde_json::Value`).
/// `prefix` is the access-path prefix (typically `"input"`).
/// `max_elements` caps the array expansion depth (from `AnalysisConfig::max_loop_depth`).
///
/// Returns a vector of SMT constraints that should be asserted into the solver.
pub fn apply_schema_constraints(
    registry: &mut PathRegistry,
    schema: &serde_json::Value,
    prefix: &str,
    max_elements: usize,
) -> Vec<SmtExpr> {
    let mut constraints = Vec::new();
    walk_schema(
        registry,
        schema,
        prefix,
        max_elements,
        &mut constraints,
    );
    constraints
}

/// Recursive schema walker.
fn walk_schema(
    registry: &mut PathRegistry,
    schema: &serde_json::Value,
    path: &str,
    max_elements: usize,
    constraints: &mut Vec<SmtExpr>,
) {
    let obj = match schema.as_object() {
        Some(o) => o,
        None => return,
    };

    // ---- type ----
    let sort = obj
        .get("type")
        .and_then(|t| t.as_str())
        .and_then(|t| match t {
            "boolean" => Some(ValueSort::Bool),
            "integer" => Some(ValueSort::Int),
            "number" => Some(ValueSort::Real),
            "string" => Some(ValueSort::String),
            "object" | "array" => None, // structural — no leaf sort
            _ => None,
        });

    // Register sort and create Z3 variable for leaf types.
    if let Some(s) = sort {
        match s {
            ValueSort::Bool => {
                registry.get_bool(path);
            }
            ValueSort::Int => {
                registry.get_int(path);
            }
            ValueSort::Real => {
                registry.get_real(path);
            }
            ValueSort::String => {
                registry.get_string(path);
            }
            ValueSort::Unknown => {}
        }
    }

    // ---- properties (object) ----
    if let Some(props) = obj.get("properties").and_then(|p| p.as_object()) {
        for (key, sub_schema) in props {
            let child_path = format!("{}.{}", path, key);
            walk_schema(
                registry,
                sub_schema,
                &child_path,
                max_elements,
                constraints,
            );
        }
    }

    // ---- required (object) ----
    if let Some(req) = obj.get("required").and_then(|r| r.as_array()) {
        for field in req {
            if let Some(field_name) = field.as_str() {
                let child_path = format!("{}.{}", path, field_name);
                // Ensure the entry exists (get_or_create with Unknown sort).
                registry.get_or_create(&child_path, ValueSort::Unknown, true, 0);
                let entry = registry.get(&child_path).unwrap();
                let defined = entry.defined.clone();
                constraints.push(defined);
            }
        }
    }

    // ---- items (array) ----
    if let Some(items_schema) = obj.get("items") {
        let min_items = obj.get("minItems").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let max_items = obj
            .get("maxItems")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(max_elements);

        // Expand up to max_items elements.
        let n = max_items.min(max_elements);
        for idx in 0..n {
            let child_path = format!("{}[{}]", path, idx);
            walk_schema(
                registry,
                items_schema,
                &child_path,
                max_elements,
                constraints,
            );
        }

        // minItems: assert that indices 0..min_items are all defined.
        // For objects, this means the object-level path must be defined.
        // For leaf sorts, the leaf entry already exists from the walk above.
        // We assert definedness at the element level — for objects, we need to
        // assert definedness on the element's *required* fields (already handled
        // by the recursive `required` processing). For leaves, we assert the
        // leaf is defined. For now, we assert a synthetic "element defined"
        // constraint: if the items schema is a leaf, assert the leaf; if it's
        // an object, assert all its required fields.
        for idx in 0..min_items.min(n) {
            let child_path = format!("{}[{}]", path, idx);
            apply_min_items_defined(registry, items_schema, &child_path, constraints);
        }

        // ---- x-unique fields across array siblings ----
        if let Some(unique_fields) = obj.get("x-unique").and_then(|u| u.as_array()) {
            apply_x_unique(registry, unique_fields, path, n, constraints);
        }

        // ---- uniqueItems: pairwise ≠ for plain-value arrays ----
        if obj
            .get("uniqueItems")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            apply_unique_items(registry, path, n, constraints);
        }

        // ---- closed-world: elements beyond maxItems are undefined ----
        // Loop witnesses may create paths at indices n..max_elements.
        // Without this constraint, those paths have unconstrained Z3
        // variables that the solver can exploit to satisfy constraints
        // that would be unsatisfiable with valid inputs.
        if n < max_elements {
            for idx in n..max_elements {
                let child_path = format!("{}[{}]", path, idx);
                assert_element_undefined(
                    registry,
                    items_schema,
                    &child_path,
                    max_elements,
                    constraints,
                );
            }
        }
    }

    // ---- minLength (string) ----
    if let Some(min_len) = obj.get("minLength").and_then(|v| v.as_u64()) {
        if min_len > 0 {
            // Ensure the string variable exists.
            let str_var = registry.get_string(path);
            let str_len = SmtExpr::SeqLength(Box::new(str_var));
            let min_val = SmtExpr::IntLit(min_len as i64);
            let ge = SmtExpr::ge(str_len, min_val);
            constraints.push(ge);
        }
    }

    // ---- enum ----
    if let Some(enum_vals) = obj.get("enum").and_then(|e| e.as_array()) {
        let mut disj = Vec::new();
        for val in enum_vals {
            if let Some(eq) = value_equals_json(registry, path, val, sort) {
                disj.push(eq);
            }
        }
        if !disj.is_empty() {
            constraints.push(SmtExpr::Or(disj));
        }
    }
}

/// Assert that an array element is "defined" according to its schema.
///
/// For leaf types, this means the Z3 variable must be defined.
/// For objects with required fields, those fields become defined.
/// For objects without required fields, we assert the first property is defined
/// as a proxy.
fn apply_min_items_defined(
    registry: &mut PathRegistry,
    items_schema: &serde_json::Value,
    element_path: &str,
    constraints: &mut Vec<SmtExpr>,
) {
    let obj = match items_schema.as_object() {
        Some(o) => o,
        None => return,
    };

    let schema_type = obj.get("type").and_then(|t| t.as_str()).unwrap_or("");

    match schema_type {
        "object" => {
            // For an object element, assert that its required fields are defined.
            if let Some(req) = obj.get("required").and_then(|r| r.as_array()) {
                for field in req {
                    if let Some(field_name) = field.as_str() {
                        let field_path = format!("{}.{}", element_path, field_name);
                        registry.get_or_create(&field_path, ValueSort::Unknown, true, 0);
                        let entry = registry.get(&field_path).unwrap();
                        constraints.push(entry.defined.clone());
                    }
                }
            } else if let Some(props) = obj.get("properties").and_then(|p| p.as_object()) {
                // No required list — assert first property as proxy.
                if let Some((first_key, _)) = props.iter().next() {
                    let field_path = format!("{}.{}", element_path, first_key);
                    registry.get_or_create(&field_path, ValueSort::Unknown, true, 0);
                    let entry = registry.get(&field_path).unwrap();
                    constraints.push(entry.defined.clone());
                }
            }
        }
        _ => {
            // Leaf type — assert the element variable itself is defined.
            registry.get_or_create(element_path, ValueSort::Unknown, true, 0);
            let entry = registry.get(element_path).unwrap();
            constraints.push(entry.defined.clone());
        }
    }
}

/// Assert that an array element and all its sub-paths are undefined.
///
/// This implements "closed-world" semantics for arrays: elements beyond
/// `maxItems` must not exist in the input. We walk the item schema
/// recursively and assert `NOT defined` for every path that `walk_schema`
/// would create — leaf variables, object properties, and nested arrays.
fn assert_element_undefined(
    registry: &mut PathRegistry,
    items_schema: &serde_json::Value,
    element_path: &str,
    max_elements: usize,
    constraints: &mut Vec<SmtExpr>,
) {
    let obj = match items_schema.as_object() {
        Some(o) => o,
        None => return,
    };

    let schema_type = obj.get("type").and_then(|t| t.as_str()).unwrap_or("");

    match schema_type {
        "object" => {
            // Recurse into each property and assert all sub-paths are undefined.
            if let Some(props) = obj.get("properties").and_then(|p| p.as_object()) {
                for (key, sub_schema) in props {
                    let child_path = format!("{}.{}", element_path, key);
                    assert_element_undefined(
                        registry,
                        sub_schema,
                        &child_path,
                        max_elements,
                        constraints,
                    );
                }
            }
        }
        "array" => {
            // Nested array — assert all nested elements are undefined.
            if let Some(nested_items) = obj.get("items") {
                let nested_max = obj
                    .get("maxItems")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as usize)
                    .unwrap_or(max_elements)
                    .min(max_elements);
                for idx in 0..nested_max {
                    let child_path = format!("{}[{}]", element_path, idx);
                    assert_element_undefined(
                        registry,
                        nested_items,
                        &child_path,
                        max_elements,
                        constraints,
                    );
                }
            }
        }
        _ => {
            // Leaf type (string, boolean, integer, number) — assert NOT defined.
            let sort = match schema_type {
                "boolean" => ValueSort::Bool,
                "integer" => ValueSort::Int,
                "number" => ValueSort::Real,
                "string" => ValueSort::String,
                _ => ValueSort::Unknown,
            };
            registry.get_or_create(element_path, sort, true, 0);
            let entry = registry.get(element_path).unwrap();
            constraints.push(SmtExpr::not(entry.defined.clone()));
        }
    }
}

/// Apply `uniqueItems` pairwise distinctness for plain-value arrays.
///
/// For arrays whose items are strings, ints, or bools (not objects),
/// this asserts that all defined elements are pairwise distinct.
fn apply_unique_items(
    registry: &mut PathRegistry,
    array_path: &str,
    num_elements: usize,
    constraints: &mut Vec<SmtExpr>,
) {
    for i in 0..num_elements {
        for j in (i + 1)..num_elements {
            let path_i = format!("{}[{}]", array_path, i);
            let path_j = format!("{}[{}]", array_path, j);

            let sort_i = registry.get_sort(&path_i);
            let sort_j = registry.get_sort(&path_j);

            match (sort_i, sort_j) {
                (Some(ValueSort::String), Some(ValueSort::String)) => {
                    let vi = registry.get_string(&path_i);
                    let vj = registry.get_string(&path_j);
                    let di = registry.get(&path_i).unwrap().defined.clone();
                    let dj = registry.get(&path_j).unwrap().defined.clone();
                    let neq = SmtExpr::not(SmtExpr::eq(vi.clone(), vj.clone()));
                    let both_def = SmtExpr::and2(di, dj);
                    constraints.push(SmtExpr::implies(both_def, neq));
                }
                (Some(ValueSort::Int), Some(ValueSort::Int)) => {
                    let vi = registry.get_int(&path_i);
                    let vj = registry.get_int(&path_j);
                    let di = registry.get(&path_i).unwrap().defined.clone();
                    let dj = registry.get(&path_j).unwrap().defined.clone();
                    let neq = SmtExpr::not(SmtExpr::eq(vi.clone(), vj.clone()));
                    let both_def = SmtExpr::and2(di, dj);
                    constraints.push(SmtExpr::implies(both_def, neq));
                }
                (Some(ValueSort::Bool), Some(ValueSort::Bool)) => {
                    let vi = registry.get_bool(&path_i);
                    let vj = registry.get_bool(&path_j);
                    let di = registry.get(&path_i).unwrap().defined.clone();
                    let dj = registry.get(&path_j).unwrap().defined.clone();
                    let neq = SmtExpr::not(SmtExpr::eq(vi.clone(), vj.clone()));
                    let both_def = SmtExpr::and2(di, dj);
                    constraints.push(SmtExpr::implies(both_def, neq));
                }
                _ => {}
            }
        }
    }
}

/// Apply `x-unique` pairwise distinctness constraints.
///
/// `unique_fields` is a JSON array of field names (strings).
/// For each field name, we create pairwise ≠ constraints across all
/// array element indices.
fn apply_x_unique(
    registry: &mut PathRegistry,
    unique_fields: &[serde_json::Value],
    array_path: &str,
    num_elements: usize,
    constraints: &mut Vec<SmtExpr>,
) {
    for field_val in unique_fields {
        let field_name = match field_val.as_str() {
            Some(s) => s,
            None => continue,
        };

        for i in 0..num_elements {
            for j in (i + 1)..num_elements {
                let path_i = format!("{}[{}].{}", array_path, i, field_name);
                let path_j = format!("{}[{}].{}", array_path, j, field_name);

                // Only constrain if both paths have known sorts.
                let sort_i = registry.get_sort(&path_i);
                let sort_j = registry.get_sort(&path_j);

                match (sort_i, sort_j) {
                    (Some(ValueSort::String), Some(ValueSort::String)) => {
                        let vi = registry.get_string(&path_i);
                        let vj = registry.get_string(&path_j);
                        // Both defined → not equal.
                        let di = registry.get(&path_i).unwrap().defined.clone();
                        let dj = registry.get(&path_j).unwrap().defined.clone();
                        let neq = SmtExpr::not(SmtExpr::eq(vi.clone(), vj.clone()));
                        let both_def = SmtExpr::and2(di, dj);
                        constraints.push(SmtExpr::implies(both_def, neq));
                    }
                    (Some(ValueSort::Int), Some(ValueSort::Int)) => {
                        let vi = registry.get_int(&path_i);
                        let vj = registry.get_int(&path_j);
                        let di = registry.get(&path_i).unwrap().defined.clone();
                        let dj = registry.get(&path_j).unwrap().defined.clone();
                        let neq = SmtExpr::not(SmtExpr::eq(vi.clone(), vj.clone()));
                        let both_def = SmtExpr::and2(di, dj);
                        constraints.push(SmtExpr::implies(both_def, neq));
                    }
                    (Some(ValueSort::Bool), Some(ValueSort::Bool)) => {
                        let vi = registry.get_bool(&path_i);
                        let vj = registry.get_bool(&path_j);
                        let di = registry.get(&path_i).unwrap().defined.clone();
                        let dj = registry.get(&path_j).unwrap().defined.clone();
                        let neq = SmtExpr::not(SmtExpr::eq(vi.clone(), vj.clone()));
                        let both_def = SmtExpr::and2(di, dj);
                        constraints.push(SmtExpr::implies(both_def, neq));
                    }
                    (Some(ValueSort::Real), Some(ValueSort::Real)) => {
                        let vi = registry.get_real(&path_i);
                        let vj = registry.get_real(&path_j);
                        let di = registry.get(&path_i).unwrap().defined.clone();
                        let dj = registry.get(&path_j).unwrap().defined.clone();
                        let neq = SmtExpr::not(SmtExpr::eq(vi.clone(), vj.clone()));
                        let both_def = SmtExpr::and2(di, dj);
                        constraints.push(SmtExpr::implies(both_def, neq));
                    }
                    _ => {
                        // Sorts don't match or unknown — skip.
                    }
                }
            }
        }
    }
}

/// Build an SMT equality constraint: `path == json_value`.
fn value_equals_json(
    registry: &mut PathRegistry,
    path: &str,
    val: &serde_json::Value,
    _hint_sort: Option<ValueSort>,
) -> Option<SmtExpr> {
    match val {
        serde_json::Value::String(s) => {
            let var = registry.get_string(path);
            let lit = SmtExpr::StringLit(s.clone());
            Some(SmtExpr::eq(var, lit))
        }
        serde_json::Value::Bool(b) => {
            let var = registry.get_bool(path);
            let lit = SmtExpr::bool_lit(*b);
            Some(SmtExpr::eq(var, lit))
        }
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                let var = registry.get_int(path);
                let lit = SmtExpr::IntLit(i);
                Some(SmtExpr::eq(var, lit))
            } else if let Some(f) = n.as_f64() {
                // Approximate — use string representation for real.
                let var = registry.get_int(path);
                let lit = SmtExpr::IntLit(f as i64);
                Some(SmtExpr::eq(var, lit))
            } else {
                None
            }
        }
        _ => None,
    }
}
