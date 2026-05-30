// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::as_conversions,
    clippy::arithmetic_side_effects,
    clippy::unseparated_literal_suffix
)]

use alloc::collections::{BTreeMap, BTreeSet};

use crate::collections::{InsertError, Object, Set};
use crate::number::Number;
use crate::value::Value;

fn sizes() -> &'static [usize] {
    &[0, 1, 2, 4, 8, 64, 256, 1024]
}

fn build_pair(i: usize) -> (Value, Value) {
    (Value::from(i as u64), Value::from((i as u64) * 10))
}

#[test]
fn object_oracle_insert_get_len() {
    for &n in sizes() {
        let mut oracle: BTreeMap<Value, Value> = BTreeMap::new();
        let mut obj = Object::new();
        for i in 0..n {
            let (k, v) = build_pair(i);
            oracle.insert(k.clone(), v.clone());
            obj.try_insert(k, v).expect("finite key");
        }
        assert_eq!(obj.len(), oracle.len());
        assert_eq!(obj.is_empty(), oracle.is_empty());
        for (k, v) in &oracle {
            assert_eq!(obj.as_ref().get(k), Some(v));
            assert!(obj.as_ref().contains_key(k));
        }
    }
}

#[test]
fn object_sorted_iter_matches_oracle() {
    for &n in sizes() {
        let mut oracle: BTreeMap<Value, Value> = BTreeMap::new();
        let mut obj = Object::new();
        for i in (0..n).rev() {
            let (k, v) = build_pair(i);
            oracle.insert(k.clone(), v.clone());
            obj.try_insert(k, v).expect("finite key");
        }
        let mine: alloc::vec::Vec<_> = obj.as_ref().iter().collect();
        let theirs: alloc::vec::Vec<_> = oracle.iter().collect();
        assert_eq!(mine, theirs);
    }
}

#[test]
fn object_remove_matches_oracle() {
    for &n in sizes() {
        let mut oracle: BTreeMap<Value, Value> = BTreeMap::new();
        let mut obj = Object::new();
        for i in 0..n {
            let (k, v) = build_pair(i);
            oracle.insert(k.clone(), v.clone());
            obj.try_insert(k, v).expect("finite key");
        }
        for i in (0..n).step_by(2) {
            let k = Value::from(i as u64);
            assert_eq!(obj.as_mut().remove(&k), oracle.remove(&k));
        }
        let mine: alloc::vec::Vec<_> = obj.as_ref().iter().collect();
        let theirs: alloc::vec::Vec<_> = oracle.iter().collect();
        assert_eq!(mine, theirs);
    }
}

#[test]
fn object_entry_or_insert() {
    let mut obj = Object::new();
    {
        let mut as_mut = obj.as_mut();
        let entry = as_mut.entry(Value::from("k")).expect("finite");
        let v = entry.or_insert(Value::from(1u64));
        *v = Value::from(2u64);
    }
    assert_eq!(
        obj.as_ref().get(&Value::from("k")),
        Some(&Value::from(2u64))
    );
}

#[test]
fn object_non_finite_key_rejected() {
    let mut obj = Object::new();
    let nan = Value::Number(Number::from(f64::NAN));
    match obj.try_insert(nan, Value::from(1u64)) {
        Err(InsertError::NonFiniteKey) => {}
        other => panic!("expected NonFiniteKey, got {other:?}"),
    }
}

#[test]
fn set_oracle_basic() {
    for &n in sizes() {
        let mut oracle: BTreeSet<Value> = BTreeSet::new();
        let mut set = Set::new();
        for i in 0..n {
            let v = Value::from(i as u64);
            oracle.insert(v.clone());
            let _ = set.try_insert(v);
        }
        assert_eq!(set.len(), oracle.len());
        let mine: alloc::vec::Vec<_> = set.as_ref().iter().collect();
        let theirs: alloc::vec::Vec<_> = oracle.iter().collect();
        assert_eq!(mine, theirs);
    }
}

#[test]
fn set_intersection_union_difference() {
    let a = Set::try_from_iter([Value::from(1u64), Value::from(2u64), Value::from(3u64)]).unwrap();
    let b = Set::try_from_iter([Value::from(2u64), Value::from(3u64), Value::from(4u64)]).unwrap();
    let inter = a.as_ref().intersection(&b.as_ref());
    assert_eq!(inter.len(), 2);
    let uni = a.as_ref().union(&b.as_ref());
    assert_eq!(uni.len(), 4);
    let diff = a.as_ref().difference(&b.as_ref());
    assert_eq!(diff.len(), 1);
    assert!(diff.as_ref().contains(&Value::from(1u64)));
}
