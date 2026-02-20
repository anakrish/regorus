// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Model-to-JSON extraction: reads a Z3 model and reconstructs a concrete
//! `input` JSON document from the path variables in the registry.

use alloc::string::ToString;
use alloc::vec::Vec;

use crate::value::Value;

use super::path_registry::PathRegistry;
use super::types::ValueSort;

/// Extract a concrete `input` JSON object from a Z3 model using the path registry.
///
/// Each path variable like `input.user.role` is evaluated in the model. If defined,
/// its concrete value is placed into the output JSON tree. This is the key payoff
/// of path-based encoding: extraction is a simple iteration over flat variables.
pub fn extract_input<'ctx>(model: &z3::Model<'ctx>, registry: &PathRegistry<'ctx>) -> Value {
    let mut result = Value::new_object();

    for (path, entry) in registry.iter() {
        // Only extract input paths.
        let input_suffix = match path.strip_prefix("input.") {
            Some(s) => s,
            None => continue,
        };

        // Check if the path is defined in the model.
        if let Some(defined_val) = model.eval(&entry.defined, true) {
            if let Some(false) = defined_val.as_bool() {
                continue; // Path is absent from input.
            }
        }

        // Extract the concrete value based on the sort.
        let concrete_value = extract_value_for_entry(model, entry);

        if concrete_value != Value::Undefined {
            // Place the value into the result JSON tree.
            let segments: Vec<&str> = input_suffix.split('.').collect();
            set_nested(&mut result, &segments, concrete_value);
        }
    }

    result
}

/// Extract a concrete value from a Z3 model for a path entry.
fn extract_value_for_entry<'ctx>(
    model: &z3::Model<'ctx>,
    entry: &super::path_registry::PathEntry<'ctx>,
) -> Value {
    match entry.sort {
        ValueSort::Bool => {
            if let Some(ref var) = entry.bool_var {
                if let Some(val) = model.eval(var, true) {
                    if let Some(b) = val.as_bool() {
                        return Value::Bool(b);
                    }
                }
            }
        }
        ValueSort::Int => {
            if let Some(ref var) = entry.int_var {
                if let Some(val) = model.eval(var, true) {
                    if let Some(i) = val.as_i64() {
                        return Value::from(i);
                    }
                }
            }
        }
        ValueSort::Real => {
            if let Some(ref var) = entry.real_var {
                if let Some(val) = model.eval(var, true) {
                    if let Some((num, den)) = val.as_real() {
                        if den != 0 {
                            return Value::from(num as f64 / den as f64);
                        }
                    }
                }
            }
        }
        ValueSort::String | ValueSort::Unknown => {
            if let Some(ref var) = entry.str_var {
                if let Some(val) = model.eval(var, true) {
                    // Z3 string values: try to extract the concrete string.
                    // The `to_string()` method on Z3 ast gives the S-expression
                    // representation. For string constants, this is typically
                    // `"value"` (with quotes). We strip the quotes.
                    let s = val.to_string();
                    let unquoted = s.trim_matches('"');
                    return Value::from(unquoted);
                }
            }
        }
    }

    Value::Undefined
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
