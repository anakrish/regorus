// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! See [`Object`].

use alloc::collections::{btree_map, BTreeMap};
use alloc::string::ToString as _;
use core::cmp::Ordering;
use core::fmt;
use core::iter::FusedIterator;
use core::ops::Bound;

use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, Visitor};
use serde::ser::{Serialize, SerializeMap as _, Serializer};

use crate::value::Value;

/// Opaque, ordered key-value map keyed by [`Value`].
///
/// The current backing storage is `BTreeMap<Value, Value>`. The inner field
/// is private so the representation can change (two-tier inline+hash, lazy,
/// schema-shared) without touching call sites.
///
/// # Iteration
///
/// - [`Object::iter`] — implementation-defined order; non-resumable.
/// - [`Object::iter_sorted`] — sorted by `Value::Ord`; non-resumable.
/// - [`Object::cursor`] / [`Object::next`] — implementation-defined order,
///   resumable; cheapest per-step cost. Used by interpreter/RVM when iteration
///   must yield mid-flight.
#[derive(Default, Clone, Eq, PartialEq)]
pub struct Object {
    inner: BTreeMap<Value, Value>,
}

impl Object {
    /// Create an empty `Object`.
    #[inline]
    pub const fn new() -> Self {
        Self {
            inner: BTreeMap::new(),
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
    pub fn get(&self, key: &Value) -> Option<&Value> {
        self.inner.get(key)
    }

    #[inline]
    pub fn contains_key(&self, key: &Value) -> bool {
        self.inner.contains_key(key)
    }

    #[inline]
    pub fn get_mut(&mut self, key: &Value) -> Option<&mut Value> {
        self.inner.get_mut(key)
    }

    /// Iteration in implementation-defined order. Non-resumable.
    ///
    /// For the current BTree-backed storage this happens to be sorted, but
    /// callers MUST NOT depend on that. Use [`Object::iter_sorted`] when
    /// deterministic order is required, or [`Object::cursor`] when iteration
    /// must yield and resume.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&Value, &Value)> + '_ {
        self.inner.iter()
    }

    /// Iteration in sorted key order (by `Value::Ord`). Non-resumable.
    ///
    /// Use this for serialization, snapshots, hashing, `Debug`, the
    /// `object.keys` builtin, etc.
    #[inline]
    pub fn iter_sorted(&self) -> Iter<'_> {
        // BTree backend iterates sorted natively.
        Iter {
            inner: self.inner.iter(),
        }
    }

    #[inline]
    pub fn keys(&self) -> impl Iterator<Item = &Value> + '_ {
        self.inner.keys()
    }

    #[inline]
    pub fn values(&self) -> impl Iterator<Item = &Value> + '_ {
        self.inner.values()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_> {
        IterMut {
            inner: self.inner.iter_mut(),
        }
    }

    /// Insert a key-value pair. Returns the previous value if any.
    #[inline]
    pub fn insert(&mut self, key: Value, value: Value) -> Option<Value> {
        self.inner.insert(key, value)
    }

    #[inline]
    pub fn remove(&mut self, key: &Value) -> Option<Value> {
        self.inner.remove(key)
    }

    #[inline]
    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&Value, &mut Value) -> bool,
    {
        self.inner.retain(f);
    }

    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    #[inline]
    pub fn append(&mut self, other: &mut Object) {
        self.inner.append(&mut other.inner);
    }

    /// Gets a mutable reference to the value associated with `key`, inserting
    /// the result of `default()` if absent. Single O(log n) probe.
    pub fn get_or_insert_with<F: FnOnce() -> Value>(
        &mut self,
        key: Value,
        default: F,
    ) -> &mut Value {
        self.inner.entry(key).or_insert_with(default)
    }

    /// Wrap into a `Value::Object`.
    #[inline]
    pub fn into_value(self) -> Value {
        Value::Object(crate::Rc::new(self))
    }

    /// Create a resumable cursor over entries in implementation-defined
    /// order. Stable for the lifetime of `&self`. O(1).
    #[inline]
    pub const fn cursor(&self) -> ObjectCursor {
        ObjectCursor {
            inner: ObjectCursorInner::BTree(None),
        }
    }

    /// Advance `cursor` and yield the next entry. O(log n) for the BTree
    /// backend (range probe); future hash/inline variants may be O(1).
    pub fn next<'a>(&'a self, cursor: &mut ObjectCursor) -> Option<(&'a Value, &'a Value)> {
        let ObjectCursorInner::BTree(ref mut last) = cursor.inner;
        let next = last.as_ref().map_or_else(
            || self.inner.iter().next(),
            |prev| {
                self.inner
                    .range((Bound::Excluded(prev.clone()), Bound::Unbounded))
                    .next()
            },
        );
        let (k, v) = next?;
        *last = Some(k.clone());
        Some((k, v))
    }
}

/// Opaque resumable cursor over an [`Object`]'s entries in
/// implementation-defined order.
#[derive(Debug, Clone)]
pub struct ObjectCursor {
    inner: ObjectCursorInner,
}

#[derive(Debug, Clone)]
enum ObjectCursorInner {
    /// BTree backend cursor: tracks last-seen key. `None` means "before start".
    BTree(Option<Value>),
}

// ---- Hand-written Ord/PartialOrd ----------------------------------------
//
// Implemented in terms of `iter_sorted()` so ordering is consistent with the
// canonical (sorted) view of the entries and is therefore independent of
// the storage variant.

impl Ord for Object {
    fn cmp(&self, other: &Self) -> Ordering {
        self.iter_sorted().cmp(other.iter_sorted())
    }
}

impl PartialOrd for Object {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Use sorted iteration so Debug output is stable across storage
        // variants.
        f.debug_map().entries(self.iter_sorted()).finish()
    }
}

impl Extend<(Value, Value)> for Object {
    fn extend<I: IntoIterator<Item = (Value, Value)>>(&mut self, iter: I) {
        self.inner.extend(iter);
    }
}

impl FromIterator<(Value, Value)> for Object {
    fn from_iter<I: IntoIterator<Item = (Value, Value)>>(iter: I) -> Self {
        Self {
            inner: BTreeMap::from_iter(iter),
        }
    }
}

// ---- Opaque iterator types ----------------------------------------------

/// Owned iterator over `(Value, Value)` entries.
#[derive(Debug)]
pub struct IntoIter {
    inner: btree_map::IntoIter<Value, Value>,
}

impl Iterator for IntoIter {
    type Item = (Value, Value);
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

/// Borrowed iterator over `(&Value, &Value)` entries.
#[derive(Debug, Clone)]
pub struct Iter<'a> {
    inner: btree_map::Iter<'a, Value, Value>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = (&'a Value, &'a Value);
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

/// Borrowed iterator over `(&Value, &mut Value)` entries.
#[derive(Debug)]
pub struct IterMut<'a> {
    inner: btree_map::IterMut<'a, Value, Value>,
}

impl<'a> Iterator for IterMut<'a> {
    type Item = (&'a Value, &'a mut Value);
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<'a> DoubleEndedIterator for IterMut<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back()
    }
}

impl<'a> ExactSizeIterator for IterMut<'a> {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<'a> FusedIterator for IterMut<'a> {}

impl IntoIterator for Object {
    type Item = (Value, Value);
    type IntoIter = IntoIter;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        IntoIter {
            inner: self.inner.into_iter(),
        }
    }
}

impl<'a> IntoIterator for &'a Object {
    type Item = (&'a Value, &'a Value);
    type IntoIter = Iter<'a>;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        Iter {
            inner: self.inner.iter(),
        }
    }
}

impl<'a> IntoIterator for &'a mut Object {
    type Item = (&'a Value, &'a mut Value);
    type IntoIter = IterMut<'a>;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        IterMut {
            inner: self.inner.iter_mut(),
        }
    }
}

impl From<BTreeMap<Value, Value>> for Object {
    #[inline]
    fn from(map: BTreeMap<Value, Value>) -> Self {
        Self { inner: map }
    }
}

impl From<Object> for Value {
    #[inline]
    fn from(o: Object) -> Self {
        o.into_value()
    }
}

impl core::ops::Index<&Value> for Object {
    type Output = Value;
    #[inline]
    #[allow(clippy::indexing_slicing)] // BTreeMap::Index panics on missing — matches std contract
    fn index(&self, key: &Value) -> &Value {
        &self.inner[key]
    }
}

impl Serialize for Object {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let mut map = serializer.serialize_map(Some(self.inner.len()))?;
        // Sorted iteration: canonical JSON.
        for (k, v) in self.iter_sorted() {
            match *k {
                Value::String(_) => map.serialize_entry(k, v)?,
                _ => {
                    // Non-string keys are stringified via serde_json::to_string
                    // so the resulting JSON has valid string keys.
                    let key_str = serde_json::to_string(k).map_err(Error::custom)?;
                    map.serialize_entry(&key_str, v)?;
                }
            }
        }
        map.end()
    }
}

struct ObjectVisitor;

impl<'de> Visitor<'de> for ObjectVisitor {
    type Value = Object;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a map of Value to Value")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut obj = Object::new();
        while let Some((k, v)) = access.next_entry::<Value, Value>()? {
            obj.insert(k, v);
            crate::utils::limits::check_memory_limit_if_needed()
                .map_err(|err| A::Error::custom(err.to_string()))?;
        }
        Ok(obj)
    }
}

impl<'de> Deserialize<'de> for Object {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(ObjectVisitor)
    }
}
