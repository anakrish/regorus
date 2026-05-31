// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use alloc::collections::BTreeMap;
use core::cmp::Ordering;
use core::fmt;

use serde::de::{Deserializer, Error as DeError, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};

use alloc::string::ToString as _;

use crate::collections::entry::{entry_from_storage, MapEntry};
use crate::collections::error::InsertError;
use crate::collections::iter::{IntoIter, Iter, IterMut, IterSorted, Keys, Values, ValuesMut};
use crate::collections::object_storage::{check_key, ObjectStorage};
use crate::value::Value;
use crate::Rc;

/// Public opaque object map. Iteration is sorted by `Value::Ord`.
#[derive(Clone, Default)]
pub struct Object {
    pub(crate) storage: ObjectStorage,
}

impl Object {
    /// Create a new empty `Object`.
    #[inline]
    pub fn new() -> Self {
        Self {
            storage: ObjectStorage::new(),
        }
    }

    /// Create a new empty `Object` (capacity hint currently ignored by the
    /// default BTree-backed storage variant).
    #[inline]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            storage: ObjectStorage::with_capacity(cap),
        }
    }

    /// Borrow a read-only view.
    #[inline]
    pub fn as_ref(&self) -> ObjectRef<'_> {
        ObjectRef::new(&self.storage)
    }

    /// Borrow a mutable view.
    #[inline]
    pub fn as_mut(&mut self) -> ObjectRefMut<'_> {
        ObjectRefMut::new(&mut self.storage)
    }

    /// Wrap into a `Value::Object`.
    #[inline]
    pub fn into_value(self) -> Value {
        Value::Object(Rc::new(self))
    }

    /// Number of entries.
    #[inline]
    pub fn len(&self) -> usize {
        self.storage.len()
    }

    /// Whether the object has no entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.storage.is_empty()
    }

    /// Insert an entry. Returns the previous value if any.
    ///
    /// Returns `Err(InsertError::NonFiniteKey)` when `key` is a non-finite
    /// `Number::Float` (NaN, +∞, -∞).
    #[inline]
    pub fn insert(&mut self, key: Value, value: Value) -> Result<Option<Value>, InsertError> {
        self.storage.insert(key, value)
    }

    #[inline]
    pub fn get_mut(&mut self, key: &Value) -> Option<&mut Value> {
        self.storage.as_btreemap_mut().get_mut(key)
    }

    #[inline]
    pub fn get(&self, key: &Value) -> Option<&Value> {
        self.as_ref().get(key)
    }

    #[inline]
    pub fn get_str(&self, key: &str) -> Option<&Value> {
        self.as_ref().get_str(key)
    }

    #[inline]
    pub fn contains_key(&self, key: &Value) -> bool {
        self.as_ref().contains_key(key)
    }

    #[inline]
    pub fn iter(&self) -> Iter<'_> {
        self.as_ref().iter()
    }

    #[inline]
    pub fn iter_sorted(&self) -> IterSorted<'_> {
        self.as_ref().iter_sorted()
    }

    #[inline]
    pub fn keys(&self) -> Keys<'_> {
        self.as_ref().keys()
    }

    #[inline]
    pub fn values(&self) -> Values<'_> {
        self.as_ref().values()
    }

    #[doc(hidden)]
    #[inline]
    pub fn as_btreemap(&self) -> &BTreeMap<Value, Value> {
        self.storage.as_btreemap()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_> {
        IterMut::new(self.storage.as_btreemap_mut().iter_mut())
    }

    #[inline]
    pub fn values_mut(&mut self) -> ValuesMut<'_> {
        ValuesMut::new(self.storage.as_btreemap_mut().values_mut())
    }

    #[inline]
    pub fn remove(&mut self, key: &Value) -> Option<Value> {
        self.storage.remove(key)
    }

    pub fn retain<F: FnMut(&Value, &mut Value) -> bool>(&mut self, f: F) {
        self.storage.as_btreemap_mut().retain(f);
    }

    #[inline]
    pub fn clear(&mut self) {
        self.storage.clear();
    }

    pub fn extend<I: IntoIterator<Item = (Value, Value)>>(
        &mut self,
        iter: I,
    ) -> Result<(), InsertError> {
        for (k, v) in iter {
            self.insert(k, v)?;
        }
        Ok(())
    }

    pub fn entry(&mut self, key: Value) -> Result<MapEntry<'_>, InsertError> {
        check_key(&key)?;
        Ok(entry_from_storage(&mut self.storage, key))
    }

    #[doc(hidden)]
    #[inline]
    pub fn as_btreemap_mut(&mut self) -> &mut BTreeMap<Value, Value> {
        self.storage.as_btreemap_mut()
    }

    /// Construct an `Object` from an iterator, rejecting non-finite keys.
    pub fn try_from_iter<I>(iter: I) -> Result<Self, InsertError>
    where
        I: IntoIterator<Item = (Value, Value)>,
    {
        let mut obj = Self::new();
        for (k, v) in iter {
            obj.insert(k, v)?;
        }
        Ok(obj)
    }

    /// Construct from a `BTreeMap` (used by the legacy `From<BTreeMap>` impl
    /// on `Value`).
    #[inline]
    pub(crate) fn from_btreemap(map: BTreeMap<Value, Value>) -> Self {
        Self {
            storage: ObjectStorage::from_btreemap(map),
        }
    }

    /// Consume into a `BTreeMap`.
    #[inline]
    pub(crate) fn into_btreemap(self) -> BTreeMap<Value, Value> {
        self.storage.into_btreemap()
    }
}

impl FromIterator<(Value, Value)> for Object {
    fn from_iter<I: IntoIterator<Item = (Value, Value)>>(it: I) -> Self {
        let mut obj = Self::new();
        // Mirror std::collections semantics: silently drop entries with
        // non-finite numeric keys. Callers needing failure semantics use
        // `try_from_iter`.
        for (k, v) in it {
            let _ = obj.insert(k, v);
        }
        obj
    }
}

impl Extend<(Value, Value)> for Object {
    fn extend<I: IntoIterator<Item = (Value, Value)>>(&mut self, iter: I) {
        for (k, v) in iter {
            let _ = self.insert(k, v);
        }
    }
}

impl From<Object> for Value {
    fn from(obj: Object) -> Self {
        obj.into_value()
    }
}

impl From<BTreeMap<Value, Value>> for Object {
    fn from(map: BTreeMap<Value, Value>) -> Self {
        Self::from_btreemap(map)
    }
}

impl fmt::Debug for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.storage.as_btreemap().iter())
            .finish()
    }
}

impl PartialEq for Object {
    fn eq(&self, other: &Self) -> bool {
        self.storage.as_btreemap() == other.storage.as_btreemap()
    }
}

impl Eq for Object {}

impl PartialOrd for Object {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Object {
    fn cmp(&self, other: &Self) -> Ordering {
        self.storage.as_btreemap().cmp(other.storage.as_btreemap())
    }
}

impl Serialize for Object {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let map = self.storage.as_btreemap();
        let mut s = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            s.serialize_entry(k, v)?;
        }
        s.end()
    }
}

struct ObjectVisitor;

impl<'de> Visitor<'de> for ObjectVisitor {
    type Value = Object;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a map")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut obj = Object::new();
        while let Some((k, v)) = access.next_entry::<Value, Value>()? {
            obj.insert(k, v)
                .map_err(|e| M::Error::custom(e.to_string()))?;
        }
        Ok(obj)
    }
}

impl<'de> Deserialize<'de> for Object {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(ObjectVisitor)
    }
}

// --------- Borrow views ---------

/// Read view over an `Object`.
#[derive(Copy, Clone, Debug)]
pub struct ObjectRef<'a> {
    inner: &'a ObjectStorage,
}

impl<'a> ObjectRef<'a> {
    #[inline]
    pub(crate) const fn new(inner: &'a ObjectStorage) -> Self {
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
    pub fn get(&self, key: &Value) -> Option<&'a Value> {
        self.inner.get(key)
    }

    /// String-keyed fast path (avoids constructing a `Value::String`).
    #[inline]
    pub fn get_str(&self, key: &str) -> Option<&'a Value> {
        // Construct a Value::String for lookup. BTreeMap doesn't support
        // borrowed lookup for our enum, so this is the practical fast path.
        let probe = Value::String(Rc::from(key));
        // SAFETY-of-lifetimes: BTreeMap::get returns `&'_ V` tied to the map's
        // lifetime, which is `'a` here.
        self.inner.as_btreemap().get(&probe).map(|v| {
            // re-borrow to outer lifetime `'a`
            let r: &'a Value = v;
            r
        })
    }

    #[inline]
    pub fn contains_key(&self, key: &Value) -> bool {
        self.inner.contains_key(key)
    }

    /// Iteration without an order guarantee. Currently delegates to
    /// `iter_sorted()` because the BTree storage variant naturally iterates
    /// in sorted order; future storage variants may differ. Callers MUST
    /// NOT depend on the order.
    #[inline]
    pub fn iter(&self) -> Iter<'a> {
        Iter::new(self.iter_sorted())
    }

    /// Iteration in sorted key order. Use when deterministic order is
    /// required (serialization, snapshots, `object.keys` builtin, etc.).
    #[inline]
    pub fn iter_sorted(&self) -> IterSorted<'a> {
        IterSorted::new(self.inner.as_btreemap().iter())
    }

    #[inline]
    pub fn keys(&self) -> Keys<'a> {
        Keys::new(self.inner.as_btreemap().keys())
    }

    #[inline]
    pub fn values(&self) -> Values<'a> {
        Values::new(self.inner.as_btreemap().values())
    }

    /// Clone into a freshly-owned `Value::Object`.
    pub fn to_owned_value(&self) -> Value {
        let map: BTreeMap<Value, Value> = self.inner.as_btreemap().clone();
        Value::Object(Rc::new(Object::from_btreemap(map)))
    }

    #[doc(hidden)]
    #[inline]
    pub fn as_btreemap(&self) -> &'a BTreeMap<Value, Value> {
        self.inner.as_btreemap()
    }
}

impl<'a> IntoIterator for ObjectRef<'a> {
    type Item = (&'a Value, &'a Value);
    type IntoIter = Iter<'a>;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Mutable view over an `Object`.
#[derive(Debug)]
pub struct ObjectRefMut<'a> {
    inner: &'a mut ObjectStorage,
}

impl<'a> ObjectRefMut<'a> {
    #[inline]
    pub(crate) fn new(inner: &'a mut ObjectStorage) -> Self {
        Self { inner }
    }

    // Read methods duplicated from ObjectRef.
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
    pub fn get_str(&self, key: &str) -> Option<&Value> {
        let probe = Value::String(Rc::from(key));
        self.inner.as_btreemap().get(&probe)
    }

    #[inline]
    pub fn contains_key(&self, key: &Value) -> bool {
        self.inner.contains_key(key)
    }

    #[inline]
    pub fn iter(&self) -> Iter<'_> {
        Iter::new(self.iter_sorted())
    }

    #[inline]
    pub fn iter_sorted(&self) -> IterSorted<'_> {
        IterSorted::new(self.inner.as_btreemap().iter())
    }

    #[inline]
    pub fn keys(&self) -> Keys<'_> {
        Keys::new(self.inner.as_btreemap().keys())
    }

    #[inline]
    pub fn values(&self) -> Values<'_> {
        Values::new(self.inner.as_btreemap().values())
    }

    #[inline]
    pub fn as_ref(&self) -> ObjectRef<'_> {
        ObjectRef::new(self.inner)
    }

    #[inline]
    pub fn reborrow(&mut self) -> ObjectRefMut<'_> {
        ObjectRefMut::new(self.inner)
    }

    // Mut methods.

    #[inline]
    pub fn get_mut(&mut self, key: &Value) -> Option<&mut Value> {
        self.inner.as_btreemap_mut().get_mut(key)
    }

    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_> {
        IterMut::new(self.inner.as_btreemap_mut().iter_mut())
    }

    #[inline]
    pub fn values_mut(&mut self) -> ValuesMut<'_> {
        ValuesMut::new(self.inner.as_btreemap_mut().values_mut())
    }

    /// Insert an entry. See `Object::insert` for error semantics.
    #[inline]
    pub fn insert(&mut self, key: Value, value: Value) -> Result<Option<Value>, InsertError> {
        self.inner.insert(key, value)
    }

    #[inline]
    pub fn remove(&mut self, key: &Value) -> Option<Value> {
        self.inner.remove(key)
    }

    pub fn retain<F: FnMut(&Value, &mut Value) -> bool>(&mut self, f: F) {
        self.inner.as_btreemap_mut().retain(f);
    }

    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Extend with an iterator. Returns `Err` on the first non-finite key
    /// encountered (the entries before the error have already been inserted).
    pub fn extend<I: IntoIterator<Item = (Value, Value)>>(
        &mut self,
        iter: I,
    ) -> Result<(), InsertError> {
        for (k, v) in iter {
            self.insert(k, v)?;
        }
        Ok(())
    }

    /// Entry API for in-place updates. Validates the key up front so the
    /// subsequent `VacantMapEntry::insert` is infallible.
    pub fn entry(&mut self, key: Value) -> Result<MapEntry<'_>, InsertError> {
        check_key(&key)?;
        Ok(entry_from_storage(self.inner, key))
    }

    #[doc(hidden)]
    #[inline]
    pub fn as_btreemap_mut(&mut self) -> &mut BTreeMap<Value, Value> {
        self.inner.as_btreemap_mut()
    }
}

impl IntoIterator for Object {
    type Item = (Value, Value);
    type IntoIter = IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        IntoIter::new(self.into_btreemap().into_iter())
    }
}

impl<'a> IntoIterator for &'a Object {
    type Item = (&'a Value, &'a Value);
    type IntoIter = Iter<'a>;
    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a mut Object {
    type Item = (&'a Value, &'a mut Value);
    type IntoIter = IterMut<'a>;
    fn into_iter(self) -> IterMut<'a> {
        self.iter_mut()
    }
}

impl core::ops::Index<&Value> for Object {
    type Output = Value;

    fn index(&self, key: &Value) -> &Self::Output {
        self.get(key).unwrap_or(&Value::Undefined)
    }
}
