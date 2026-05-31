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

    let inter_set = a.intersection(&b);
    let inter: Vec<&Value> = inter_set.iter_sorted().collect();
    let inter_oracle: Vec<&Value> = a_btree.intersection(&b_btree).collect();
    assert_eq!(inter.len(), inter_oracle.len());
    for (x, y) in inter.iter().zip(inter_oracle.iter()) {
        assert_eq!(x, y);
    }

    let union_self = a.union(&b);
    let union_oracle: BTreeSet<&Value> = a_btree.union(&b_btree).collect();
    assert_eq!(union_self.len(), union_oracle.len());

    let diff = a.difference(&b);
    assert_eq!(diff.len(), a_btree.difference(&b_btree).count());

    assert!(a.is_subset(&a));
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
