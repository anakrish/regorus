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

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::vec::Vec;

use super::{Object, Set};
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
            assert!(n.as_u64().expect("u64") % 4 == 0);
        }
    }
}

#[test]
fn object_get_str() {
    let mut obj = Object::new();
    obj.insert(Value::String("hello".into()), val(1));
    assert_eq!(obj.get_str("hello"), Some(&val(1)));
    assert!(obj.get_str("missing").is_none());
}

#[test]
fn object_into_iterator_owned() {
    let pairs = make_pairs(8);
    let obj: Object = pairs.clone().into_iter().collect();
    let mut out: Vec<(Value, Value)> = obj.into_iter().collect();
    out.sort();
    let mut expected = pairs;
    expected.sort();
    assert_eq!(out, expected);
}

// ---- Set tests ----

#[test]
fn set_iter_sorted_matches_btreeset_oracle() {
    for &n in SIZES {
        let values: Vec<Value> = (0..n).map(val).collect();
        let oracle: BTreeSet<Value> = values.iter().cloned().collect();
        let s: Set = values.into_iter().collect();
        let actual: Vec<&Value> = s.iter_sorted().collect();
        let expected: Vec<&Value> = oracle.iter().collect();
        assert_eq!(actual, expected, "size {n}");
    }
}

#[test]
fn set_iter_multiset_equality_with_oracle() {
    for &n in SIZES {
        let values: Vec<Value> = (0..n).map(val).collect();
        let oracle: BTreeSet<Value> = values.iter().cloned().collect();
        let s: Set = values.into_iter().collect();
        let mut a: Vec<Value> = s.iter().cloned().collect();
        let mut b: Vec<Value> = oracle.iter().cloned().collect();
        a.sort();
        b.sort();
        assert_eq!(a, b);
    }
}

#[test]
fn set_algebra_matches_btreeset() {
    let a_vals: Vec<Value> = (0..32_u64).map(val).collect();
    let b_vals: Vec<Value> = (16..48_u64).map(val).collect();
    let a_btree: BTreeSet<Value> = a_vals.iter().cloned().collect();
    let b_btree: BTreeSet<Value> = b_vals.iter().cloned().collect();
    let a: Set = a_vals.into_iter().collect();
    let b: Set = b_vals.into_iter().collect();

    fn sorted<'a, I: Iterator<Item = &'a Value>>(it: I) -> Vec<&'a Value> {
        let mut v: Vec<&Value> = it.collect();
        v.sort();
        v
    }

    let inter_set = a.intersection(&b);
    assert_eq!(
        sorted(inter_set.iter_sorted()),
        sorted(a_btree.intersection(&b_btree))
    );

    let union_set = a.union(&b);
    assert_eq!(
        sorted(union_set.iter_sorted()),
        sorted(a_btree.union(&b_btree))
    );

    let diff_set = a.difference(&b);
    assert_eq!(
        sorted(diff_set.iter_sorted()),
        sorted(a_btree.difference(&b_btree))
    );

    let sym_set = a.symmetric_difference(&b);
    assert_eq!(
        sorted(sym_set.iter_sorted()),
        sorted(a_btree.symmetric_difference(&b_btree))
    );

    // Subset / superset: trivial + non-trivial cases.
    let proper_subset: Set = (0..16_u64).map(val).collect();
    let non_subset: Set = (30..50_u64).map(val).collect();
    assert!(a.is_subset(&a));
    assert!(proper_subset.is_subset(&a));
    assert!(!non_subset.is_subset(&a));
    assert!(a.is_superset(&proper_subset));
    assert!(!a.is_superset(&non_subset));

    assert!(!a.is_disjoint(&b));
    assert!(Set::from_iter([val(99)]).is_disjoint(&a));
}

#[test]
fn set_first_last() {
    let s: Set = (0..16_u64).map(val).collect();
    assert_eq!(s.first(), Some(&val(0)));
    assert_eq!(s.last(), Some(&val(15)));
    assert!(Set::new().first().is_none());
}

#[test]
fn set_serde_roundtrip() {
    for &n in &[0_u64, 1, 8, 64] {
        let s: Set = (0..n).map(val).collect();
        let json = serde_json::to_string(&s).expect("ser");
        let back: Set = serde_json::from_str(&json).expect("de");
        assert_eq!(s, back, "size {n}");
    }
}

#[test]
fn set_append_drains_other() {
    let mut a: Set = (0..4_u64).map(val).collect();
    let mut b: Set = (4..8_u64).map(val).collect();
    a.append(&mut b);
    assert_eq!(a.len(), 8);
    assert!(b.is_empty());
}

// ---- COW behavior --------------------------------------------------------

#[test]
fn object_value_cow_make_mut_isolates_clones() {
    let a = Value::new_object();
    let b = a.clone();
    let mut b_owned = b;
    b_owned
        .as_object_mut()
        .expect("object")
        .insert(Value::from("x"), Value::from(1));
    // `a` is still empty.
    assert_eq!(a.as_object().expect("object").len(), 0);
    assert_eq!(b_owned.as_object().expect("object").len(), 1);
}

#[test]
fn set_value_cow_make_mut_isolates_clones() {
    let a = Value::new_set();
    let b = a.clone();
    let mut b_owned = b;
    b_owned
        .as_set_mut()
        .expect("set")
        .insert(Value::from("x"));
    assert_eq!(a.as_set().expect("set").len(), 0);
    assert_eq!(b_owned.as_set().expect("set").len(), 1);
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

#[test]
fn set_from_iter_dedups_duplicates() {
    let s: Set = [val(1), val(1), val(2), val(2), val(2)]
        .into_iter()
        .collect();
    assert_eq!(s.len(), 2);
    assert!(s.contains(&val(1)));
    assert!(s.contains(&val(2)));
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
    assert!(obj.get(&val(100)).is_none());

    if let Some(v) = obj.get_mut(&val(2)) {
        *v = val(999);
    }
    assert_eq!(obj.get(&val(2)), Some(&val(999)));
    assert!(obj.get_mut(&val(100)).is_none());

    let mut keys: Vec<&Value> = obj.keys().collect();
    keys.sort();
    assert_eq!(keys.len(), 4);
    assert_eq!(keys[0], &val(0));

    let keys_sorted: Vec<&Value> = obj.keys_sorted().collect();
    assert_eq!(keys_sorted.len(), 4);
    assert_eq!(keys_sorted[0], &val(0));

    let values_sum: u64 = obj
        .values()
        .map(|v| v.as_u64().unwrap_or(0))
        .sum();
    // 0 + 2 + 999 + 6 = 1007
    assert_eq!(values_sum, 1007);

    for (_k, v) in obj.iter_mut() {
        *v = val(0);
    }
    assert!(obj.values().all(|v| v == &val(0)));

    obj.clear();
    assert!(obj.is_empty());
    assert!(!obj.contains_key(&val(0)));
}

#[test]
fn set_accessor_coverage() {
    let mut s: Set = (0..4_u64).map(val).collect();

    assert!(s.contains(&val(2)));
    assert!(!s.contains(&val(100)));

    assert_eq!(s.get(&val(2)), Some(&val(2)));
    assert!(s.get(&val(100)).is_none());

    assert!(s.remove(&val(2)));
    assert!(!s.remove(&val(2)));
    assert_eq!(s.len(), 3);

    s.retain(|v| v != &val(0));
    assert!(!s.contains(&val(0)));
    assert_eq!(s.len(), 2);

    s.clear();
    assert!(s.is_empty());
    assert!(!s.contains(&val(1)));
}

// ---- IntoIterator for references -----------------------------------------

#[test]
fn object_into_iterator_ref() {
    let obj: Object = make_pairs(3).into_iter().collect();
    let mut count = 0;
    let mut sum = 0_u64;
    for (k, v) in &obj {
        sum = sum.saturating_add(k.as_u64().unwrap_or(0));
        sum = sum.saturating_add(v.as_u64().unwrap_or(0));
        count += 1;
    }
    assert_eq!(count, 3);
    // keys 0+1+2 = 3, values 0+2+4 = 6 -> 9
    assert_eq!(sum, 9);
}

#[test]
fn object_into_iterator_ref_mut() {
    let mut obj: Object = make_pairs(3).into_iter().collect();
    for (_k, v) in &mut obj {
        *v = val(0);
    }
    assert!(obj.values().all(|v| v == &val(0)));
}

#[test]
fn set_into_iterator_ref() {
    let s: Set = (0..4_u64).map(val).collect();
    let mut count = 0;
    for _v in &s {
        count += 1;
    }
    assert_eq!(count, 4);
}
