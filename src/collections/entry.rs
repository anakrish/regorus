// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use alloc::collections::btree_map;

use crate::collections::object_storage::ObjectStorage;
use crate::value::Value;

/// View into a single entry in an `Object`.
#[derive(Debug)]
pub enum MapEntry<'a> {
    /// An entry whose key is currently present.
    Occupied(OccupiedMapEntry<'a>),
    /// An entry whose key is currently absent.
    Vacant(VacantMapEntry<'a>),
}

impl<'a> MapEntry<'a> {
    /// Return a reference to this entry's key.
    pub fn key(&self) -> &Value {
        match self {
            Self::Occupied(o) => o.key(),
            Self::Vacant(v) => v.key(),
        }
    }

    /// Ensure a value is in the entry by inserting `default` if vacant.
    pub fn or_insert(self, default: Value) -> &'a mut Value {
        match self {
            Self::Occupied(o) => o.into_mut(),
            Self::Vacant(v) => v.insert(default),
        }
    }

    /// Ensure a value is in the entry by inserting the result of `f` if vacant.
    pub fn or_insert_with<F: FnOnce() -> Value>(self, f: F) -> &'a mut Value {
        match self {
            Self::Occupied(o) => o.into_mut(),
            Self::Vacant(v) => v.insert(f()),
        }
    }

    /// Apply `f` to the value if occupied.
    #[must_use]
    pub fn and_modify<F: FnOnce(&mut Value)>(mut self, f: F) -> Self {
        if let Self::Occupied(ref mut entry) = self {
            f(entry.get_mut());
        }
        self
    }
}

/// Occupied entry view.
#[derive(Debug)]
pub struct OccupiedMapEntry<'a> {
    inner: btree_map::OccupiedEntry<'a, Value, Value>,
}

impl<'a> OccupiedMapEntry<'a> {
    pub(crate) fn new(inner: btree_map::OccupiedEntry<'a, Value, Value>) -> Self {
        Self { inner }
    }

    pub fn key(&self) -> &Value {
        self.inner.key()
    }

    pub fn get(&self) -> &Value {
        self.inner.get()
    }

    pub fn get_mut(&mut self) -> &mut Value {
        self.inner.get_mut()
    }

    pub fn into_mut(self) -> &'a mut Value {
        self.inner.into_mut()
    }

    pub fn insert(&mut self, value: Value) -> Value {
        self.inner.insert(value)
    }

    pub fn remove(self) -> Value {
        self.inner.remove()
    }
}

/// Vacant entry view.
#[derive(Debug)]
pub struct VacantMapEntry<'a> {
    inner: btree_map::VacantEntry<'a, Value, Value>,
}

impl<'a> VacantMapEntry<'a> {
    pub(crate) fn new(inner: btree_map::VacantEntry<'a, Value, Value>) -> Self {
        Self { inner }
    }

    pub fn key(&self) -> &Value {
        self.inner.key()
    }

    /// Insert the supplied value and return a mutable reference to it.
    ///
    /// Key finiteness has already been validated at `entry` construction.
    pub fn insert(self, value: Value) -> &'a mut Value {
        self.inner.insert(value)
    }
}

/// Construct a `MapEntry` from the storage. The caller has already validated
/// the key's finiteness.
pub(crate) fn entry_from_storage(storage: &mut ObjectStorage, key: Value) -> MapEntry<'_> {
    match storage.as_btreemap_mut().entry(key) {
        btree_map::Entry::Occupied(o) => MapEntry::Occupied(OccupiedMapEntry::new(o)),
        btree_map::Entry::Vacant(v) => MapEntry::Vacant(VacantMapEntry::new(v)),
    }
}
