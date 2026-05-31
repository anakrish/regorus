// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! See [`Set`].

use alloc::collections::BTreeSet;
use alloc::string::ToString as _;
use core::fmt;

use serde::de::{Deserialize, Deserializer, Error as _, SeqAccess, Visitor};
use serde::ser::{Serialize, Serializer};

use crate::value::Value;

/// Opaque, ordered set of [`Value`]s.
///
/// The current storage is `BTreeSet<Value>`. The inner field is private so
/// the backing representation can change without touching call sites.
///
/// See the module-level docs for iteration order semantics.
#[derive(Default, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct Set {
    inner: BTreeSet<Value>,
}

impl Set {
    #[inline]
    pub const fn new() -> Self {
        Self {
            inner: BTreeSet::new(),
        }
    }

    /// Create an empty `Set` with a capacity hint.
    ///
    /// The hint is ignored by the current `BTreeSet`-backed storage. See
    /// [`Object::with_capacity`](super::Object::with_capacity) for rationale.
    #[inline]
    pub const fn with_capacity(_capacity: usize) -> Self {
        Self::new()
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
    pub fn get(&self, value: &Value) -> Option<&Value> {
        self.inner.get(value)
    }

    /// First element in sorted order.
    #[inline]
    pub fn first(&self) -> Option<&Value> {
        self.iter_sorted().next()
    }

    /// Last element in sorted order.
    #[inline]
    pub fn last(&self) -> Option<&Value> {
        self.iter_sorted().next_back()
    }

    /// Iteration in implementation-defined order.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &Value> + '_ {
        self.inner.iter()
    }

    /// Iteration in sorted order (by `Value::Ord`).
    #[inline]
    pub fn iter_sorted(&self) -> impl DoubleEndedIterator<Item = &Value> + '_ {
        self.inner.iter()
    }

    /// Insert `value`. Returns `true` if the value was newly inserted.
    #[inline]
    pub fn insert(&mut self, value: Value) -> bool {
        self.inner.insert(value)
    }

    #[inline]
    pub fn remove(&mut self, value: &Value) -> bool {
        self.inner.remove(value)
    }

    #[inline]
    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&Value) -> bool,
    {
        self.inner.retain(f);
    }

    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    #[inline]
    pub fn append(&mut self, other: &mut Set) {
        self.inner.append(&mut other.inner);
    }

    pub fn intersection(&self, other: &Set) -> Set {
        Set {
            inner: self.inner.intersection(&other.inner).cloned().collect(),
        }
    }

    pub fn union(&self, other: &Set) -> Set {
        Set {
            inner: self.inner.union(&other.inner).cloned().collect(),
        }
    }

    pub fn difference(&self, other: &Set) -> Set {
        Set {
            inner: self.inner.difference(&other.inner).cloned().collect(),
        }
    }

    pub fn symmetric_difference(&self, other: &Set) -> Set {
        Set {
            inner: self
                .inner
                .symmetric_difference(&other.inner)
                .cloned()
                .collect(),
        }
    }

    #[inline]
    pub fn is_subset(&self, other: &Set) -> bool {
        self.inner.is_subset(&other.inner)
    }

    #[inline]
    pub fn is_superset(&self, other: &Set) -> bool {
        self.inner.is_superset(&other.inner)
    }

    #[inline]
    pub fn is_disjoint(&self, other: &Set) -> bool {
        self.inner.is_disjoint(&other.inner)
    }

    #[inline]
    pub fn into_value(self) -> Value {
        Value::Set(crate::Rc::new(self))
    }

    /// Take ownership of the inner set, leaving an empty one behind.
    ///
    /// `pub(crate)` — see `Object::take_inner` for rationale.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn take_inner(&mut self) -> BTreeSet<Value> {
        core::mem::take(&mut self.inner)
    }
}

impl Extend<Value> for Set {
    fn extend<I: IntoIterator<Item = Value>>(&mut self, iter: I) {
        self.inner.extend(iter);
    }
}

impl FromIterator<Value> for Set {
    fn from_iter<I: IntoIterator<Item = Value>>(iter: I) -> Self {
        Self {
            inner: BTreeSet::from_iter(iter),
        }
    }
}

impl IntoIterator for Set {
    type Item = Value;
    type IntoIter = alloc::collections::btree_set::IntoIter<Value>;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a> IntoIterator for &'a Set {
    type Item = &'a Value;
    type IntoIter = alloc::collections::btree_set::Iter<'a, Value>;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

impl From<BTreeSet<Value>> for Set {
    #[inline]
    fn from(set: BTreeSet<Value>) -> Self {
        Self { inner: set }
    }
}

impl From<Set> for Value {
    #[inline]
    fn from(s: Set) -> Self {
        s.into_value()
    }
}

impl fmt::Debug for Set {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter_sorted()).finish()
    }
}

impl Serialize for Set {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Sets serialize as JSON arrays (matches existing Value::Set behavior).
        // Use sorted iteration for canonical output.
        serializer.collect_seq(self.iter_sorted())
    }
}

struct SetVisitor;

impl<'de> Visitor<'de> for SetVisitor {
    type Value = Set;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a sequence of Values")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut set = Set::new();
        while let Some(v) = access.next_element::<Value>()? {
            set.insert(v);
            crate::utils::limits::check_memory_limit_if_needed()
                .map_err(|err| A::Error::custom(err.to_string()))?;
        }
        Ok(set)
    }
}

impl<'de> Deserialize<'de> for Set {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(SetVisitor)
    }
}
