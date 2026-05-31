// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use alloc::collections::BTreeSet;
use core::cmp::Ordering;
use core::fmt;

use serde::ser::{SerializeSeq, Serializer};
use serde::{Deserialize, Serialize};

use alloc::string::ToString as _;

use crate::collections::error::InsertError;
use crate::collections::iter::{SetIntoIter, SetIter, SetIterSorted};
use crate::collections::object_storage::check_key;
use crate::collections::set_storage::SetStorage;
use crate::value::Value;
use crate::Rc;

/// Public opaque set. Iteration is sorted by `Value::Ord`.
#[derive(Clone, Default)]
pub struct Set {
    pub(crate) storage: SetStorage,
}

impl Set {
    #[inline]
    pub fn new() -> Self {
        Self {
            storage: SetStorage::new(),
        }
    }

    #[inline]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            storage: SetStorage::with_capacity(cap),
        }
    }

    #[inline]
    pub fn as_ref(&self) -> SetRef<'_> {
        SetRef::new(&self.storage)
    }

    #[inline]
    pub fn as_mut(&mut self) -> SetRefMut<'_> {
        SetRefMut::new(&mut self.storage)
    }

    #[inline]
    pub fn into_value(self) -> Value {
        Value::Set(Rc::new(self))
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.storage.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.storage.is_empty()
    }

    #[inline]
    pub fn insert(&mut self, value: Value) -> Result<bool, InsertError> {
        self.storage.insert(value)
    }

    #[inline]
    pub fn remove(&mut self, value: &Value) -> bool {
        self.storage.as_btreeset_mut().remove(value)
    }

    #[inline]
    pub fn contains(&self, value: &Value) -> bool {
        self.as_ref().contains(value)
    }

    #[inline]
    pub fn get(&self, value: &Value) -> Option<&Value> {
        self.as_ref().get(value)
    }

    #[inline]
    pub fn iter(&self) -> SetIter<'_> {
        self.as_ref().iter()
    }

    #[inline]
    pub fn iter_sorted(&self) -> SetIterSorted<'_> {
        self.as_ref().iter_sorted()
    }

    #[inline]
    pub fn first(&self) -> Option<&Value> {
        self.as_ref().first()
    }

    #[doc(hidden)]
    #[inline]
    pub fn as_btreeset(&self) -> &BTreeSet<Value> {
        self.storage.as_btreeset()
    }

    pub fn retain<F: FnMut(&Value) -> bool>(&mut self, f: F) {
        self.storage.as_btreeset_mut().retain(f);
    }

    #[inline]
    pub fn clear(&mut self) {
        self.storage.clear();
    }

    pub fn extend<I: IntoIterator<Item = Value>>(&mut self, iter: I) -> Result<(), InsertError> {
        for v in iter {
            self.insert(v)?;
        }
        Ok(())
    }

    pub fn append(&mut self, other: &mut Set) {
        self.storage
            .as_btreeset_mut()
            .append(other.storage.as_btreeset_mut());
    }

    #[doc(hidden)]
    #[inline]
    pub fn as_btreeset_mut(&mut self) -> &mut BTreeSet<Value> {
        self.storage.as_btreeset_mut()
    }

    #[inline]
    pub fn intersection(&self, other: &Set) -> Set {
        self.as_ref().intersection(&other.as_ref())
    }

    #[inline]
    pub fn union(&self, other: &Set) -> Set {
        self.as_ref().union(&other.as_ref())
    }

    #[inline]
    pub fn difference(&self, other: &Set) -> Set {
        self.as_ref().difference(&other.as_ref())
    }

    #[inline]
    pub fn is_subset(&self, other: &Set) -> bool {
        self.as_ref().is_subset(&other.as_ref())
    }

    #[inline]
    pub fn is_disjoint(&self, other: &Set) -> bool {
        self.as_ref().is_disjoint(&other.as_ref())
    }

    pub fn try_from_iter<I>(iter: I) -> Result<Self, InsertError>
    where
        I: IntoIterator<Item = Value>,
    {
        let mut s = Self::new();
        for v in iter {
            s.insert(v)?;
        }
        Ok(s)
    }

    #[inline]
    pub(crate) fn from_btreeset(set: BTreeSet<Value>) -> Self {
        Self {
            storage: SetStorage::from_btreeset(set),
        }
    }

    #[inline]
    pub(crate) fn into_btreeset(self) -> BTreeSet<Value> {
        self.storage.into_btreeset()
    }
}

impl FromIterator<Value> for Set {
    fn from_iter<I: IntoIterator<Item = Value>>(it: I) -> Self {
        let mut s = Self::new();
        for v in it {
            let _ = s.insert(v);
        }
        s
    }
}

impl Extend<Value> for Set {
    fn extend<I: IntoIterator<Item = Value>>(&mut self, iter: I) {
        for v in iter {
            let _ = self.insert(v);
        }
    }
}

impl From<Set> for Value {
    fn from(s: Set) -> Self {
        s.into_value()
    }
}

impl From<BTreeSet<Value>> for Set {
    fn from(s: BTreeSet<Value>) -> Self {
        Self::from_btreeset(s)
    }
}

impl fmt::Debug for Set {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set()
            .entries(self.storage.as_btreeset().iter())
            .finish()
    }
}

impl PartialEq for Set {
    fn eq(&self, other: &Self) -> bool {
        self.storage.as_btreeset() == other.storage.as_btreeset()
    }
}

impl Eq for Set {}

impl PartialOrd for Set {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Set {
    fn cmp(&self, other: &Self) -> Ordering {
        self.storage.as_btreeset().cmp(other.storage.as_btreeset())
    }
}

impl Serialize for Set {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let set = self.storage.as_btreeset();
        let mut s = serializer.serialize_seq(Some(set.len()))?;
        for v in set {
            s.serialize_element(v)?;
        }
        s.end()
    }
}

impl<'de> Deserialize<'de> for Set {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v: alloc::vec::Vec<Value> = alloc::vec::Vec::deserialize(deserializer)?;
        let mut s = Self::new();
        for item in v {
            s.insert(item)
                .map_err(|e| serde::de::Error::custom(e.to_string()))?;
        }
        Ok(s)
    }
}

// ----- borrow views -----

#[derive(Copy, Clone, Debug)]
pub struct SetRef<'a> {
    inner: &'a SetStorage,
}

impl<'a> SetRef<'a> {
    #[inline]
    pub(crate) const fn new(inner: &'a SetStorage) -> Self {
        Self { inner }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    #[inline]
    pub fn contains(&self, value: &Value) -> bool {
        self.inner.contains(value)
    }
    #[inline]
    pub fn get(&self, value: &Value) -> Option<&'a Value> {
        self.inner.as_btreeset().get(value)
    }
    /// Iteration without an order guarantee. Currently delegates to
    /// `iter_sorted()` because the BTree storage variant naturally
    /// iterates in sorted order; future variants may differ. Callers
    /// MUST NOT depend on the order.
    #[inline]
    pub fn iter(&self) -> SetIter<'a> {
        SetIter::new(self.iter_sorted())
    }
    /// Iteration in sorted order. Use when deterministic order is required.
    #[inline]
    pub fn iter_sorted(&self) -> SetIterSorted<'a> {
        SetIterSorted::new(self.inner.as_btreeset().iter())
    }
    #[inline]
    pub fn first(&self) -> Option<&'a Value> {
        self.iter_sorted().next()
    }

    /// Intersection of two sets.
    pub fn intersection(&self, other: &SetRef<'_>) -> Set {
        let a = self.inner.as_btreeset();
        let b = other.inner.as_btreeset();
        let mut out = Set::new();
        for v in a.intersection(b) {
            // Both sets contain finite keys, so insert is infallible.
            let _ = out.insert(v.clone());
        }
        out
    }

    pub fn union(&self, other: &SetRef<'_>) -> Set {
        let a = self.inner.as_btreeset();
        let b = other.inner.as_btreeset();
        let mut out = Set::new();
        for v in a.union(b) {
            let _ = out.insert(v.clone());
        }
        out
    }

    pub fn difference(&self, other: &SetRef<'_>) -> Set {
        let a = self.inner.as_btreeset();
        let b = other.inner.as_btreeset();
        let mut out = Set::new();
        for v in a.difference(b) {
            let _ = out.insert(v.clone());
        }
        out
    }

    pub fn is_subset(&self, other: &SetRef<'_>) -> bool {
        self.inner
            .as_btreeset()
            .is_subset(other.inner.as_btreeset())
    }

    pub fn is_disjoint(&self, other: &SetRef<'_>) -> bool {
        self.inner
            .as_btreeset()
            .is_disjoint(other.inner.as_btreeset())
    }

    pub fn to_owned_value(&self) -> Value {
        let s: BTreeSet<Value> = self.inner.as_btreeset().clone();
        Value::Set(Rc::new(Set::from_btreeset(s)))
    }

    #[doc(hidden)]
    #[inline]
    pub fn as_btreeset(&self) -> &'a BTreeSet<Value> {
        self.inner.as_btreeset()
    }
}

impl<'a> IntoIterator for SetRef<'a> {
    type Item = &'a Value;
    type IntoIter = SetIter<'a>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[derive(Debug)]
pub struct SetRefMut<'a> {
    inner: &'a mut SetStorage,
}

impl<'a> SetRefMut<'a> {
    #[inline]
    pub(crate) fn new(inner: &'a mut SetStorage) -> Self {
        Self { inner }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    #[inline]
    pub fn contains(&self, value: &Value) -> bool {
        self.inner.contains(value)
    }
    #[inline]
    pub fn iter(&self) -> SetIter<'_> {
        SetIter::new(self.iter_sorted())
    }
    #[inline]
    pub fn iter_sorted(&self) -> SetIterSorted<'_> {
        SetIterSorted::new(self.inner.as_btreeset().iter())
    }
    #[inline]
    pub fn as_ref(&self) -> SetRef<'_> {
        SetRef::new(self.inner)
    }
    #[inline]
    pub fn reborrow(&mut self) -> SetRefMut<'_> {
        SetRefMut::new(self.inner)
    }

    #[inline]
    pub fn insert(&mut self, value: Value) -> Result<bool, InsertError> {
        check_key(&value)?;
        Ok(self.inner.as_btreeset_mut().insert(value))
    }
    #[inline]
    pub fn remove(&mut self, value: &Value) -> bool {
        self.inner.as_btreeset_mut().remove(value)
    }
    pub fn retain<F: FnMut(&Value) -> bool>(&mut self, f: F) {
        self.inner.as_btreeset_mut().retain(f);
    }
    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    pub fn extend<I: IntoIterator<Item = Value>>(&mut self, iter: I) -> Result<(), InsertError> {
        for v in iter {
            self.insert(v)?;
        }
        Ok(())
    }

    /// Append all elements of `other` into `self`, leaving `other` empty.
    pub fn append(&mut self, other: &mut Set) {
        // BTreeSet::append moves elements without allocating.
        self.inner
            .as_btreeset_mut()
            .append(other.storage.as_btreeset_mut());
    }

    #[doc(hidden)]
    #[inline]
    pub fn as_btreeset_mut(&mut self) -> &mut BTreeSet<Value> {
        self.inner.as_btreeset_mut()
    }
}

impl IntoIterator for Set {
    type Item = Value;
    type IntoIter = SetIntoIter;
    fn into_iter(self) -> Self::IntoIter {
        SetIntoIter::new(self.into_btreeset().into_iter())
    }
}

impl<'a> IntoIterator for &'a Set {
    type Item = &'a Value;
    type IntoIter = SetIter<'a>;
    fn into_iter(self) -> SetIter<'a> {
        self.iter()
    }
}
