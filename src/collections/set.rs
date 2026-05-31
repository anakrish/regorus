// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! See [`Set`].

use alloc::collections::{btree_set, BTreeSet};
use alloc::string::ToString as _;
use core::cmp::Ordering;
use core::fmt;
use core::iter::FusedIterator;
use core::ops::Bound;

use serde::de::{Deserialize, Deserializer, Error as _, SeqAccess, Visitor};
use serde::ser::{Serialize, Serializer};

use crate::value::Value;

/// Opaque, ordered set of [`Value`]s.
///
/// The current backing storage is `BTreeSet<Value>`. The inner field is
/// private so the representation can change without touching call sites.
///
/// See the module-level docs for iteration order semantics, and
/// [`Set::cursor`] / [`Set::cursor_sorted`] for resumable iteration.
#[derive(Default, Clone, Eq, PartialEq)]
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

    /// Iteration in implementation-defined order. Non-resumable.
    #[inline]
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            inner: self.inner.iter(),
        }
    }

    /// Iteration in sorted order (by `Value::Ord`). Non-resumable.
    #[inline]
    pub fn iter_sorted(&self) -> Iter<'_> {
        Iter {
            inner: self.inner.iter(),
        }
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

    /// Create a resumable cursor over elements in implementation-defined
    /// order. Stable for the lifetime of `&self`. O(1).
    #[inline]
    pub const fn cursor(&self) -> SetCursor {
        SetCursor {
            inner: SetCursorInner::BTree(None),
        }
    }

    /// Advance `cursor` and yield the next element.
    pub fn next<'a>(&'a self, cursor: &mut SetCursor) -> Option<&'a Value> {
        let SetCursorInner::BTree(ref mut last) = cursor.inner;
        let next = last.as_ref().map_or_else(
            || self.inner.iter().next(),
            |prev| {
                self.inner
                    .range((Bound::Excluded(prev.clone()), Bound::Unbounded))
                    .next()
            },
        );
        let v = next?;
        *last = Some(v.clone());
        Some(v)
    }

    /// Create a resumable cursor over elements in sorted order. Stable for
    /// the lifetime of `&self`.
    #[inline]
    pub const fn cursor_sorted(&self) -> SetCursorSorted {
        SetCursorSorted {
            inner: SetCursorSortedInner::BTree(None),
        }
    }

    /// Advance the sorted cursor and yield the next element.
    pub fn next_sorted<'a>(&'a self, cursor: &mut SetCursorSorted) -> Option<&'a Value> {
        let SetCursorSortedInner::BTree(ref mut last) = cursor.inner;
        let next = last.as_ref().map_or_else(
            || self.inner.iter().next(),
            |prev| {
                self.inner
                    .range((Bound::Excluded(prev.clone()), Bound::Unbounded))
                    .next()
            },
        );
        let v = next?;
        *last = Some(v.clone());
        Some(v)
    }
}

/// Opaque resumable cursor over a [`Set`]'s elements in implementation-defined order.
#[derive(Debug, Clone)]
pub struct SetCursor {
    inner: SetCursorInner,
}

#[derive(Debug, Clone)]
enum SetCursorInner {
    BTree(Option<Value>),
}

/// Opaque resumable cursor over a [`Set`]'s elements in sorted order.
#[derive(Debug, Clone)]
pub struct SetCursorSorted {
    inner: SetCursorSortedInner,
}

#[derive(Debug, Clone)]
enum SetCursorSortedInner {
    BTree(Option<Value>),
}

// ---- Hand-written Ord/PartialOrd ----------------------------------------

impl Ord for Set {
    fn cmp(&self, other: &Self) -> Ordering {
        self.iter_sorted().cmp(other.iter_sorted())
    }
}

impl PartialOrd for Set {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
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

// ---- Opaque iterator types ----------------------------------------------

/// Owned iterator over `Value` elements.
#[derive(Debug)]
pub struct IntoIter {
    inner: btree_set::IntoIter<Value>,
}

impl Iterator for IntoIter {
    type Item = Value;
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl DoubleEndedIterator for IntoIter {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back()
    }
}

impl ExactSizeIterator for IntoIter {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl FusedIterator for IntoIter {}

/// Borrowed iterator over `&Value` elements.
#[derive(Debug, Clone)]
pub struct Iter<'a> {
    inner: btree_set::Iter<'a, Value>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a Value;
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<'a> DoubleEndedIterator for Iter<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back()
    }
}

impl<'a> ExactSizeIterator for Iter<'a> {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<'a> FusedIterator for Iter<'a> {}

impl IntoIterator for Set {
    type Item = Value;
    type IntoIter = IntoIter;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        IntoIter {
            inner: self.inner.into_iter(),
        }
    }
}

impl<'a> IntoIterator for &'a Set {
    type Item = &'a Value;
    type IntoIter = Iter<'a>;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        Iter {
            inner: self.inner.iter(),
        }
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
        // Sets serialize as JSON arrays. Use sorted iteration for canonical
        // output.
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
