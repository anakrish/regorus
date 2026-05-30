// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use alloc::collections::BTreeMap;

use crate::collections::error::InsertError;
use crate::number::Number;
use crate::value::Value;

/// Internal storage backing an `Object`.
///
/// The abstraction is designed so additional variants (inline / hash / lazy)
/// can be added in the future without changing the public wrapper API.
///
/// COW for `Value::Object` is provided by the outer `Rc<Object>` at the
/// `Value` level — the inner `BTreeMap` is owned directly here so that
/// an empty `Object` costs a single heap allocation (matching the
/// pre-abstraction layout).
#[derive(Debug, Clone)]
pub(crate) enum ObjectStorage {
    BTree(BTreeMap<Value, Value>),
}

impl Default for ObjectStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectStorage {
    #[inline]
    pub(crate) fn new() -> Self {
        Self::BTree(BTreeMap::new())
    }

    #[inline]
    pub(crate) fn with_capacity(_cap: usize) -> Self {
        // BTreeMap does not support capacity hints.
        Self::new()
    }

    #[inline]
    pub(crate) fn from_btreemap(map: BTreeMap<Value, Value>) -> Self {
        Self::BTree(map)
    }

    #[inline]
    pub(crate) fn as_btreemap(&self) -> &BTreeMap<Value, Value> {
        match self {
            Self::BTree(m) => m,
        }
    }

    #[inline]
    pub(crate) fn as_btreemap_mut(&mut self) -> &mut BTreeMap<Value, Value> {
        match self {
            Self::BTree(m) => m,
        }
    }

    /// Take ownership of the inner BTreeMap.
    #[inline]
    pub(crate) fn into_btreemap(self) -> BTreeMap<Value, Value> {
        match self {
            Self::BTree(m) => m,
        }
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.as_btreemap().len()
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.as_btreemap().is_empty()
    }

    #[inline]
    pub(crate) fn get(&self, key: &Value) -> Option<&Value> {
        self.as_btreemap().get(key)
    }

    #[inline]
    pub(crate) fn contains_key(&self, key: &Value) -> bool {
        self.as_btreemap().contains_key(key)
    }

    #[inline]
    pub(crate) fn insert(
        &mut self,
        key: Value,
        value: Value,
    ) -> Result<Option<Value>, InsertError> {
        check_key(&key)?;
        Ok(self.as_btreemap_mut().insert(key, value))
    }

    #[inline]
    pub(crate) fn remove(&mut self, key: &Value) -> Option<Value> {
        self.as_btreemap_mut().remove(key)
    }

    #[inline]
    pub(crate) fn clear(&mut self) {
        self.as_btreemap_mut().clear();
    }
}

#[inline]
pub(crate) fn check_key(key: &Value) -> Result<(), InsertError> {
    if let Value::Number(Number::Float(f)) = key {
        if !f.is_finite() {
            return Err(InsertError::NonFiniteKey);
        }
    }
    Ok(())
}
