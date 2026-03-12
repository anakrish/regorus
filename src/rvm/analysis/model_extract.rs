// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Model-to-JSON extraction: reads an SMT solution and reconstructs a concrete
//! `input` JSON document from the path variables in the registry.

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use regorus_smt::{SmtCheckResult, SmtValue};

use crate::value::Value;

use super::path_registry::PathRegistry;
use super::types::ValueSort;

/// Extraction plan for one input path.
///
/// Built by [`build_extraction_plan`] before solving; indices refer to
/// entries in [`SmtProblem::extractions`] / [`SmtCheckResult::values`].
#[derive(Debug, Clone)]
pub struct PathExtraction {
    /// The input path suffix (e.g., `"user.role"`).
    pub input_suffix: String,
    /// The value sort for this path.
    pub sort: ValueSort,
    /// Index into `SmtCheckResult::values` for the `defined` boolean.
    pub defined_idx: usize,
    /// Index into `SmtCheckResult::values` for the path's value.
    pub value_idx: usize,
}

/// Build an extraction plan from the path registry.
///
/// Call this *before* solving, in tandem with populating the
/// [`SmtProblem::extractions`] vector.  Each call to
/// [`SmtProblem::add_extraction`] returns an index; those indices
/// are stored in the returned plan so that after solving we can read
/// the matching values from [`SmtCheckResult::values`].
///
/// The caller is responsible for adding the actual extraction entries
/// to the `SmtProblem`; this function only describes *what* to extract.
#[allow(dead_code)]
pub fn build_extraction_plan(registry: &PathRegistry) -> Vec<PathExtraction> {
    let mut plan = Vec::new();
    // The caller must add extractions in the same order.
    // We iterate deterministically (sorted by path) so the plan is stable.
    let mut paths: Vec<(&str, &super::path_registry::PathEntry)> = registry.iter().collect();
    paths.sort_by_key(|(p, _)| *p);

    let mut next_idx: usize = 0;
    for (path, entry) in paths {
        let input_suffix = match path.strip_prefix("input.") {
            Some(s) => s,
            None => continue,
        };

        let defined_idx = next_idx;
        next_idx += 1;
        let value_idx = next_idx;
        next_idx += 1;

        plan.push(PathExtraction {
            input_suffix: input_suffix.to_string(),
            sort: entry.sort,
            defined_idx,
            value_idx,
        });
    }
    plan
}

/// Extract a concrete `input` JSON object from a solved SMT result
/// using a pre-built extraction plan.
///
/// Each path variable like `input.user.role` has two extraction slots:
/// a `defined` boolean and the value.  If defined is false the path is
/// skipped.  Otherwise the concrete value is placed into the result tree.
pub fn extract_input(result: &SmtCheckResult, plan: &[PathExtraction]) -> Value {
    let mut root = Value::new_object();

    for ext in plan {
        // Check if the path is defined.
        match result.values.get(ext.defined_idx) {
            Some(SmtValue::Bool(false)) => continue, // absent
            None => continue,                         // missing extraction
            _ => {}                                   // defined (or unknown → try extracting)
        }

        let concrete_value = extract_value(result, ext);
        if concrete_value != Value::Undefined {
            let segments: Vec<&str> = ext.input_suffix.split('.').collect();
            set_nested(&mut root, &segments, concrete_value);
        }
    }

    // Post-process: clean up arrays by removing trailing null/empty elements
    // that appear when the solver creates witnesses beyond schema bounds.
    clean_up_value(&mut root);

    root
}

/// Extract a concrete value from solver results for a single path.
fn extract_value(result: &SmtCheckResult, ext: &PathExtraction) -> Value {
    match result.values.get(ext.value_idx) {
        Some(SmtValue::Bool(b)) => Value::Bool(*b),
        Some(SmtValue::Int(i)) => Value::from(*i),
        Some(SmtValue::Real(num, den)) => {
            if *den != 0 {
                Value::from(*num as f64 / *den as f64)
            } else {
                Value::Undefined
            }
        }
        Some(SmtValue::String(s)) => {
            // Strip surrounding quotes if present (some solvers include them).
            let unquoted = s.trim_matches('"');
            Value::from(unquoted)
        }
        Some(SmtValue::BitVec(v, _width)) => Value::from(*v),
        Some(SmtValue::Undefined) | None => Value::Undefined,
    }
}

/// Register extraction entries in an [`SmtProblem`] for every input path
/// in the registry.  Returns the extraction plan needed by [`extract_input`].
///
/// For each input path, two extractions are registered:
/// 1. The `defined` boolean (was this path present?).
/// 2. The value variable (the concrete value if present).
///
/// Call this **after** translation & constraint collection but **before**
/// solving.  The returned plan must be passed to [`extract_input`] together
/// with the solver's [`SmtCheckResult`].
pub fn register_extractions(
    problem: &mut regorus_smt::SmtProblem,
    registry: &PathRegistry,
) -> Vec<PathExtraction> {
    use alloc::format;
    use regorus_smt::{SmtExpr, SmtSort};

    let mut plan = Vec::new();
    let mut paths: Vec<(&str, &super::path_registry::PathEntry)> = registry.iter().collect();
    paths.sort_by_key(|(p, _)| *p);

    for (path, entry) in paths {
        let input_suffix = match path.strip_prefix("input.") {
            Some(s) => s,
            None => continue,
        };

        let sort = match entry.sort {
            ValueSort::Bool => SmtSort::Bool,
            ValueSort::Int => SmtSort::Int,
            ValueSort::Real => SmtSort::Real,
            ValueSort::String | ValueSort::Unknown => SmtSort::String,
        };

        // 1. defined boolean
        let defined_idx = problem.extractions.len();
        problem.add_extraction(
            format!("defined_{}", path),
            entry.defined.clone(),
            SmtSort::Bool,
            true,
        );

        // 2. value variable
        let value_idx = problem.extractions.len();
        let value_expr = match entry.sort {
            ValueSort::Bool => entry.bool_var.clone(),
            ValueSort::Int => entry.int_var.clone(),
            ValueSort::Real => entry.real_var.clone(),
            ValueSort::String | ValueSort::Unknown => entry.str_var.clone(),
        };
        if let Some(expr) = value_expr {
            problem.add_extraction(path, expr, sort, true);
        } else {
            // No variable for this sort — add a dummy so indices stay aligned.
            // This is a container path (object/array) created by the `required`
            // keyword; it has no leaf value to extract. Skip adding it to the
            // plan so extract_input won't produce a spurious `false` that
            // overwrites the nested structure built from child paths.
            problem.add_extraction(path, SmtExpr::False, SmtSort::Bool, true);
            continue;
        }

        plan.push(PathExtraction {
            input_suffix: input_suffix.to_string(),
            sort: entry.sort,
            defined_idx,
            value_idx,
        });
    }

    plan
}

/// Parse a segment like `"servers[2]"` into `("servers", Some(2))`,
/// or `"role"` into `("role", None)`.
fn parse_segment(seg: &str) -> (&str, Option<usize>) {
    if let Some(bracket_pos) = seg.find('[') {
        let name = &seg[..bracket_pos];
        let idx_str = &seg[bracket_pos + 1..seg.len() - 1]; // strip [ and ]
        if let Ok(idx) = idx_str.parse::<usize>() {
            return (name, Some(idx));
        }
    }
    (seg, None)
}

/// Set a value at a nested path in a JSON object.
///
/// Handles both object keys and array indices. A segment like `"servers[2]"`
/// creates an array under key `"servers"` and places the value at index 2.
///
/// For path `["servers[1]", "protocols[0]"]` and value `"http"`, produces:
/// `{"servers": [null, {"protocols": ["http"]}]}`
fn set_nested(obj: &mut Value, segments: &[&str], value: Value) {
    if segments.is_empty() {
        return;
    }

    let (name, array_idx) = parse_segment(segments[0]);
    let is_leaf = segments.len() == 1;

    if let Value::Object(ref mut map) = obj {
        let map_mut = crate::Rc::make_mut(map);
        let key = Value::from(name);

        if let Some(idx) = array_idx {
            // This segment has an array index: ensure an array exists under `name`.
            if !map_mut.contains_key(&key) {
                map_mut.insert(key.clone(), Value::from(alloc::vec::Vec::<Value>::new()));
            }
            if let Some(Value::Array(ref mut arr)) = map_mut.get_mut(&key) {
                let arr_mut = crate::Rc::make_mut(arr);
                // Extend with Null up to the required index.
                while arr_mut.len() <= idx {
                    arr_mut.push(Value::Null);
                }
                if is_leaf {
                    arr_mut[idx] = value;
                } else {
                    // Ensure the element at `idx` is an object for further nesting.
                    if arr_mut[idx] == Value::Null {
                        arr_mut[idx] = Value::new_object();
                    }
                    set_nested(&mut arr_mut[idx], &segments[1..], value);
                }
            }
        } else {
            // Plain object key.
            if is_leaf {
                map_mut.insert(key, value);
            } else {
                if !map_mut.contains_key(&key) {
                    map_mut.insert(key.clone(), Value::new_object());
                }
                if let Some(next) = map_mut.get_mut(&key) {
                    set_nested(next, &segments[1..], value);
                }
            }
        }
    }
}

/// Recursively clean up a Value tree:
/// - Remove `null` and junk elements from arrays (solver padding beyond schema bounds)
/// - Remove objects that are empty or have only `null`/undefined fields
/// - Recurse into arrays and objects
fn clean_up_value(val: &mut Value) {
    match val {
        Value::Array(arr) => {
            let arr_mut = crate::Rc::make_mut(arr);
            // Recurse into each element first.
            for elem in arr_mut.iter_mut() {
                clean_up_value(elem);
            }
            // Remove all null/junk elements (interior and trailing).
            // The solver may place unconstrained values at arbitrary indices.
            arr_mut.retain(|v| !is_junk(v));
        }
        Value::Object(map) => {
            let map_mut = crate::Rc::make_mut(map);
            // Recurse into each value.
            for (_, v) in map_mut.iter_mut() {
                clean_up_value(v);
            }
            // Remove fields whose value is junk (null, empty object, empty array).
            let junk_keys: Vec<Value> = map_mut
                .iter()
                .filter(|(_, v)| is_junk(v))
                .map(|(k, _)| k.clone())
                .collect();
            for key in junk_keys {
                map_mut.remove(&key);
            }
        }
        _ => {}
    }
}

/// Returns true if a value is "junk" — produced by the solver for unconstrained paths.
/// Note: empty strings are NOT junk; the solver legitimately picks "" as a satisfying
/// value (e.g. `input.role != "guest"` is satisfied by `role = ""`).
fn is_junk(val: &Value) -> bool {
    match val {
        Value::Null => true,
        Value::Undefined => true,
        Value::Object(map) => map.is_empty() || map.values().all(|v| is_junk(v)),
        Value::Array(arr) => arr.is_empty() || arr.iter().all(|v| is_junk(v)),
        _ => false,
    }
}
