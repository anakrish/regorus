// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! See [`Object`].

use alloc::collections::BTreeMap;
use alloc::string::ToString as _;
use core::fmt;

use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, Visitor};
use serde::ser::{Serialize, SerializeMap as _, Serializer};

use crate::value::Value;

/// Opaque, ordered key-value map keyed by [`Value`].
///
/// The current storage is `BTreeMap<Value, Value>`. The inner field is private
/// so the backing representation can change without touching call sites.
///
/// See the module-level docs for iteration order semantics.
#[derive(Default, Clone, Eq, PartialEq, PartialOrd, Ord)]
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

    /// Create an empty `Object` with a capacity hint.
    ///
    /// The hint is ignored by the current `BTreeMap`-backed storage. It is
    /// retained on the API so future variants (e.g. an inline-cap-N + hash
    /// representation) can use it without another migration.
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
    pub fn get(&self, key: &Value) -> Option<&Value> {
        self.inner.get(key)
    }

    /// Look up by string key.
    ///
    /// Currently equivalent to `self.get(&Value::String(Rc::from(key)))` — the
    /// probe `Value::String` is constructed eagerly, so this allocates an
    /// `Rc<str>` per call. A future storage variant (e.g. hash-backed) may
    /// implement this as an allocation-free lookup; today it is a
    /// convenience wrapper, not a hot-path fast path.
    pub fn get_str(&self, key: &str) -> Option<&Value> {
        let probe = Value::String(key.into());
        self.inner.get(&probe)
    }

    #[inline]
    pub fn contains_key(&self, key: &Value) -> bool {
        self.inner.contains_key(key)
    }

    #[inline]
    pub fn get_mut(&mut self, key: &Value) -> Option<&mut Value> {
        self.inner.get_mut(key)
    }

    /// Iteration in implementation-defined order.
    ///
    /// For the current BTree-backed storage this happens to be sorted, but
    /// callers MUST NOT depend on that. Use [`Object::iter_sorted`] when
    /// deterministic order is required.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&Value, &Value)> + '_ {
        self.inner.iter()
    }

    /// Iteration in sorted key order (by `Value::Ord`).
    ///
    /// Use this for serialization, snapshots, hashing, `Debug`, the
    /// `object.keys` builtin, etc.
    #[inline]
    pub fn iter_sorted(&self) -> impl DoubleEndedIterator<Item = (&Value, &Value)> + '_ {
        self.inner.iter()
    }

    #[inline]
    pub fn keys(&self) -> impl Iterator<Item = &Value> + '_ {
        self.inner.keys()
    }

    #[inline]
    pub fn keys_sorted(&self) -> impl DoubleEndedIterator<Item = &Value> + '_ {
        self.inner.keys()
    }

    #[inline]
    pub fn values(&self) -> impl Iterator<Item = &Value> + '_ {
        self.inner.values()
    }

    #[inline]
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut Value> + '_ {
        self.inner.values_mut()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&Value, &mut Value)> + '_ {
        self.inner.iter_mut()
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

impl IntoIterator for Object {
    type Item = (Value, Value);
    type IntoIter = alloc::collections::btree_map::IntoIter<Value, Value>;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a> IntoIterator for &'a Object {
    type Item = (&'a Value, &'a Value);
    type IntoIter = alloc::collections::btree_map::Iter<'a, Value, Value>;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

impl<'a> IntoIterator for &'a mut Object {
    type Item = (&'a Value, &'a mut Value);
    type IntoIter = alloc::collections::btree_map::IterMut<'a, Value, Value>;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter_mut()
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
                    // Mirror Value::Object's custom serializer: non-string
                    // keys are stringified via serde_json::to_string so the
                    // resulting JSON has valid string keys.
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
