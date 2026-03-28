// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Small helper functions used by the denormalizer.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{Rc, Value};

use super::super::obj_map::{obj_get_mut, obj_remove, ObjMap};

/// Find a key in an ObjMap using case-insensitive comparison.
pub fn find_key_ci(obj: &ObjMap, key: &str) -> Option<Rc<str>> {
    obj.keys().find(|k| k.eq_ignore_ascii_case(key)).cloned()
}

/// Remove a (possibly dot-separated) field from each element of a (possibly
/// nested) array, navigating via the given `array_chain`.
pub fn remove_element_field(obj: &mut ObjMap, array_chain: &[Vec<String>], field: &str) {
    remove_field_at_depth(obj, array_chain, 0, field);
}

fn remove_field_at_depth(obj: &mut ObjMap, array_chain: &[Vec<String>], depth: usize, field: &str) {
    let Some(nav) = array_chain.get(depth) else {
        let segments: Vec<&str> = field.split('.').collect();
        if segments.len() == 1 {
            if let Some(&seg) = segments.first() {
                obj_remove(obj, seg);
            }
        } else if segments.len() > 1 {
            // Navigate to parent, remove leaf.
            remove_at_dotted_path(obj, &segments);
        }
        return;
    };

    let first = match nav.first() {
        Some(f) => f.as_str(),
        None => return,
    };

    let arr_val = if nav.len() == 1 {
        match obj_get_mut(obj, first) {
            Some(v) => v,
            None => return,
        }
    } else {
        let mut cur: &mut Value = match obj_get_mut(obj, first) {
            Some(v) => v,
            None => return,
        };
        for segment in nav.iter().skip(1) {
            cur = match cur.as_object_mut() {
                Ok(inner) => match inner.get_mut(&Value::from(segment.as_str())) {
                    Some(v) => v,
                    None => return,
                },
                Err(_) => return,
            };
        }
        cur
    };

    if let Value::Array(elements) = arr_val {
        let inner = Rc::make_mut(elements);
        for elem in inner.iter_mut() {
            if let Value::Object(obj_rc) = elem {
                let inner_btree = Rc::make_mut(obj_rc);
                remove_field_at_depth_in_btree(
                    inner_btree,
                    array_chain,
                    depth.saturating_add(1),
                    field,
                );
            }
        }
    }
}

/// BTreeMap-native recursion for element-level field removal, avoiding
/// ObjMap round-trips on each array element.
fn remove_field_at_depth_in_btree(
    btree: &mut alloc::collections::BTreeMap<Value, Value>,
    array_chain: &[Vec<String>],
    depth: usize,
    field: &str,
) {
    let Some(nav) = array_chain.get(depth) else {
        let segments: Vec<&str> = field.split('.').collect();
        if segments.len() == 1 {
            if let Some(&seg) = segments.first() {
                btree.remove(&Value::from(seg));
            }
        } else if segments.len() > 1 {
            remove_at_dotted_path_in_btree(btree, &segments);
        }
        return;
    };

    let first = match nav.first() {
        Some(f) => f.as_str(),
        None => return,
    };

    let key_val = Value::from(first);
    let arr_val = if nav.len() == 1 {
        match btree.get_mut(&key_val) {
            Some(v) => v,
            None => return,
        }
    } else {
        let mut cur: &mut Value = match btree.get_mut(&key_val) {
            Some(v) => v,
            None => return,
        };
        for segment in nav.iter().skip(1) {
            cur = match cur.as_object_mut() {
                Ok(inner) => match inner.get_mut(&Value::from(segment.as_str())) {
                    Some(v) => v,
                    None => return,
                },
                Err(_) => return,
            };
        }
        cur
    };

    if let Value::Array(elements) = arr_val {
        let inner = Rc::make_mut(elements);
        for elem in inner.iter_mut() {
            if let Value::Object(obj_rc) = elem {
                let inner_btree = Rc::make_mut(obj_rc);
                remove_field_at_depth_in_btree(
                    inner_btree,
                    array_chain,
                    depth.saturating_add(1),
                    field,
                );
            }
        }
    }
}

/// Remove the leaf segment at a dotted path directly in a BTreeMap.
fn remove_at_dotted_path_in_btree(
    btree: &mut alloc::collections::BTreeMap<Value, Value>,
    segments: &[&str],
) {
    let Some((&leaf, parent_segs)) = segments.split_last() else {
        return;
    };
    if parent_segs.is_empty() {
        btree.remove(&Value::from(leaf));
        return;
    }

    let Some(&first) = parent_segs.first() else {
        return;
    };
    let first_key = Value::from(first);
    let parent_val = match btree.get_mut(&first_key) {
        Some(v) => v,
        None => return,
    };

    if parent_segs.len() == 1 {
        if let Value::Object(inner_rc) = parent_val {
            let inner_btree = Rc::make_mut(inner_rc);
            inner_btree.remove(&Value::from(leaf));
        }
    } else {
        let mut cur = parent_val;
        for &seg in parent_segs.iter().skip(1) {
            cur = match cur.as_object_mut() {
                Ok(inner) => match inner.get_mut(&Value::from(seg)) {
                    Some(v) => v,
                    None => return,
                },
                Err(_) => return,
            };
        }
        if let Value::Object(inner_rc) = cur {
            let inner_btree = Rc::make_mut(inner_rc);
            inner_btree.remove(&Value::from(leaf));
        }
    }
}

/// Remove the leaf segment at a dot-separated path.
fn remove_at_dotted_path(obj: &mut ObjMap, segments: &[&str]) {
    let Some((&leaf, parent_segs)) = segments.split_last() else {
        return;
    };
    if parent_segs.is_empty() {
        obj_remove(obj, leaf);
        return;
    }

    let Some(&first) = parent_segs.first() else {
        return;
    };
    let parent_val = match obj_get_mut(obj, first) {
        Some(v) => v,
        None => return,
    };

    if parent_segs.len() == 1 {
        // parent_val is the parent object; remove leaf from it.
        if let Value::Object(inner_rc) = parent_val {
            let inner_btree = Rc::make_mut(inner_rc);
            inner_btree.remove(&Value::from(leaf));
        }
    } else {
        // Navigate deeper through Value::Object nodes.
        let mut cur = parent_val;
        for &seg in parent_segs.iter().skip(1) {
            cur = match cur.as_object_mut() {
                Ok(inner) => match inner.get_mut(&Value::from(seg)) {
                    Some(v) => v,
                    None => return,
                },
                Err(_) => return,
            };
        }
        if let Value::Object(inner_rc) = cur {
            let inner_btree = Rc::make_mut(inner_rc);
            inner_btree.remove(&Value::from(leaf));
        }
    }
}
