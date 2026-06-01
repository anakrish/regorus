// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(test)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::arithmetic_side_effects,
    clippy::unseparated_literal_suffix,
    clippy::map_unwrap_or,
    clippy::option_if_let_else,
    clippy::pattern_type_mismatch
)]

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::vec::Vec;

use super::Object;
use crate::value::Value;

fn val(i: u64) -> Value {
    Value::from(i)
}

fn make_pairs(n: u64) -> Vec<(Value, Value)> {
    (0..n).map(|i| (val(i), val(i.saturating_mul(2)))).collect()
}

const SIZES: &[u64] = &[0, 1, 2, 4, 8, 64, 256, 1024];

#[test]
fn object_iter_sorted_matches_btreemap_oracle() {
    for &n in SIZES {
        let pairs = make_pairs(n);
        let oracle: BTreeMap<Value, Value> = pairs.iter().cloned().collect();
        let obj: Object = pairs.into_iter().collect();
        let actual: Vec<(&Value, &Value)> = obj.iter_sorted().collect();
        let expected: Vec<(&Value, &Value)> = oracle.iter().collect();
        assert_eq!(actual, expected, "size {n}");
    }
}

#[test]
fn object_iter_multiset_equality_with_oracle() {
    for &n in SIZES {
        let pairs = make_pairs(n);
        let oracle: BTreeMap<Value, Value> = pairs.iter().cloned().collect();
        let obj: Object = pairs.into_iter().collect();
        assert_eq!(obj.len(), oracle.len(), "size {n}");
        let mut a: Vec<(Value, Value)> = obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let mut b: Vec<(Value, Value)> =
            oracle.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        a.sort();
        b.sort();
        assert_eq!(a, b);
    }
}

#[test]
fn object_serde_roundtrip() {
    for &n in &[0_u64, 1, 8, 64] {
        let pairs: Vec<(Value, Value)> = (0..n)
            .map(|i| (Value::String(format!("k{i}").into()), val(i)))
            .collect();
        let obj: Object = pairs.into_iter().collect();
        let json = serde_json::to_string(&obj).expect("ser");
        let back: Object = serde_json::from_str(&json).expect("de");
        assert_eq!(obj, back, "size {n}");
    }
}

#[test]
fn object_eq_invariant_to_insertion_order() {
    let mut a = Object::new();
    let mut b = Object::new();
    for i in 0..32_u64 {
        a.insert(val(i), val(i.saturating_add(1)));
    }
    for i in (0..32_u64).rev() {
        b.insert(val(i), val(i.saturating_add(1)));
    }
    assert_eq!(a, b);
}

#[test]
fn object_remove_and_retain() {
    let mut obj: Object = make_pairs(16).into_iter().collect();
    assert_eq!(obj.remove(&val(0)), Some(val(0)));
    assert!(obj.remove(&val(100)).is_none());
    obj.retain(|_, v| {
        if let Value::Number(ref n) = *v {
            n.as_u64().is_some_and(|x| x % 4 == 0)
        } else {
            false
        }
    });
    for (_, v) in obj.iter_sorted() {
        if let Value::Number(ref n) = *v {
            assert_eq!(n.as_u64().expect("u64") % 4, 0);
        }
    }
}

#[test]
fn object_into_iterator_owned() {
    let obj: Object = make_pairs(8).into_iter().collect();
    let collected: Vec<(Value, Value)> = obj.into_iter().collect();
    assert_eq!(collected.len(), 8);
}

// ---- Duplicate-key semantics --------------------------------------------

#[test]
fn object_from_iter_last_wins_on_duplicate_keys() {
    let obj = Object::from_iter([(val(0), val(1)), (val(0), val(2))]);
    assert_eq!(obj.get(&val(0)), Some(&val(2)));
    assert_eq!(obj.len(), 1);
}

#[test]
fn object_from_btreemap_last_wins_on_duplicate_keys() {
    let mut bm: BTreeMap<Value, Value> = BTreeMap::new();
    bm.insert(val(0), val(1));
    bm.insert(val(0), val(2));
    let obj: Object = bm.into();
    assert_eq!(obj.get(&val(0)), Some(&val(2)));
    assert_eq!(obj.len(), 1);
}

// ---- get_or_insert_with --------------------------------------------------

#[test]
fn object_get_or_insert_with_inserts_when_absent() {
    let mut obj = Object::new();
    let v = obj.get_or_insert_with(val(7), || val(42));
    assert_eq!(*v, val(42));
    *v = val(43);
    assert_eq!(obj.get(&val(7)), Some(&val(43)));
}

#[test]
fn object_get_or_insert_with_returns_existing_when_present() {
    let mut obj = Object::new();
    obj.insert(val(7), val(1));
    let mut closure_called = false;
    let v = obj.get_or_insert_with(val(7), || {
        closure_called = true;
        val(999)
    });
    assert_eq!(*v, val(1));
    assert!(!closure_called, "default closure must not run when present");
}

// ---- Accessor coverage ---------------------------------------------------

#[test]
fn object_accessor_coverage() {
    let mut obj: Object = make_pairs(4).into_iter().collect();

    assert!(obj.contains_key(&val(0)));
    assert!(!obj.contains_key(&val(100)));

    assert_eq!(obj.get(&val(2)), Some(&val(4)));

    if let Some(v) = obj.get_mut(&val(1)) {
        *v = val(999);
    }
    assert_eq!(obj.get(&val(1)), Some(&val(999)));

    let keys: Vec<&Value> = obj.keys().collect();
    assert_eq!(keys.len(), 4);
    let values: Vec<&Value> = obj.values().collect();
    assert_eq!(values.len(), 4);

    for (_, v) in obj.iter_mut() {
        *v = val(0);
    }
    for (_, v) in obj.iter() {
        assert_eq!(*v, val(0));
    }

    let mut other = Object::new();
    other.insert(val(100), val(200));
    obj.append(&mut other);
    assert!(other.is_empty());
    assert!(obj.contains_key(&val(100)));

    obj.clear();
    assert!(obj.is_empty());
}

// ---- IntoIterator for references -----------------------------------------

#[test]
fn object_into_iterator_ref() {
    let obj: Object = make_pairs(4).into_iter().collect();
    let mut count = 0;
    for (_k, _v) in &obj {
        count += 1;
    }
    assert_eq!(count, 4);
}

#[test]
fn object_into_iterator_ref_mut() {
    let mut obj: Object = make_pairs(4).into_iter().collect();
    for (_k, v) in &mut obj {
        *v = val(0);
    }
    for (_, v) in obj.iter() {
        assert_eq!(*v, val(0));
    }
}

// ---- Cursor tests --------------------------------------------------------

#[cfg(feature = "rvm")]
#[test]
fn object_cursor_yields_every_entry_once() {
    for &n in SIZES {
        let pairs = make_pairs(n);
        let obj: Object = pairs.clone().into_iter().collect();
        let mut cursor = obj.cursor();
        let mut collected: Vec<(Value, Value)> = Vec::new();
        while let Some((k, v)) = obj.next(&mut cursor) {
            collected.push((k.clone(), v.clone()));
        }
        let mut a = collected;
        a.sort();
        let mut b = pairs;
        b.sort();
        assert_eq!(a, b, "size {n}");
    }
}

#[cfg(feature = "rvm")]
#[test]
fn object_cursor_resumable_fresh_cursor_restarts() {
    let obj: Object = make_pairs(8).into_iter().collect();
    let mut c1 = obj.cursor();
    let _ = obj.next(&mut c1);
    let _ = obj.next(&mut c1);
    let mut c2 = obj.cursor();
    let first_again = obj.next(&mut c2);
    let first_original = obj.iter().next();
    assert_eq!(
        first_again.map(|(k, v)| (k.clone(), v.clone())),
        first_original.map(|(k, v)| (k.clone(), v.clone()))
    );
}

#[cfg(feature = "rvm")]
#[test]
fn object_cursor_snapshot_independence_via_rc() {
    use crate::Rc;
    let mut obj = Object::new();
    obj.insert(Value::from("a"), Value::from(1));
    obj.insert(Value::from("b"), Value::from(2));
    obj.insert(Value::from("c"), Value::from(3));
    let rc_obj = Rc::new(obj);

    let alias = Rc::clone(&rc_obj);
    let mut cursor = rc_obj.cursor();
    let _ = rc_obj.next(&mut cursor);

    let mut alias_for_mut = alias;
    Rc::make_mut(&mut alias_for_mut).insert(Value::from("d"), Value::from(4));
    Rc::make_mut(&mut alias_for_mut).remove(&Value::from("a"));

    assert_eq!(rc_obj.len(), 3);
    let mut remaining = 0;
    while rc_obj.next(&mut cursor).is_some() {
        remaining += 1;
    }
    assert_eq!(remaining, 2);
}

#[cfg(feature = "rvm")]
#[test]
fn object_cursor_empty_returns_none_immediately() {
    let obj = Object::new();
    let mut cursor = obj.cursor();
    assert!(obj.next(&mut cursor).is_none());
}

// ---- Hand-written Ord consistency ---------------------------------------

#[test]
fn object_ord_invariant_to_insertion_order() {
    let mut a = Object::new();
    let mut b = Object::new();
    for i in 0..16_u64 {
        a.insert(val(i), val(i.saturating_add(1)));
    }
    for i in (0..16_u64).rev() {
        b.insert(val(i), val(i.saturating_add(1)));
    }
    use core::cmp::Ordering;
    assert_eq!(a.cmp(&b), Ordering::Equal);
}

#[test]
fn object_ord_lexicographic_on_sorted_entries() {
    let a: Object = [(val(0), val(0)), (val(1), val(1))].into_iter().collect();
    let b: Object = [(val(0), val(0)), (val(2), val(2))].into_iter().collect();
    assert!(a < b);
}
