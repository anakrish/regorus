// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use alloc::collections::BTreeSet;

use crate::collections::error::InsertError;
use crate::collections::object_storage::check_key;
use crate::value::Value;

/// Internal storage backing a `Set`.
///
/// COW is provided by the outer `Rc<Set>` at the `Value` level — the inner
/// `BTreeSet` is owned directly here so that an empty `Set` costs a single
/// heap allocation.
#[derive(Debug, Clone)]
pub(crate) enum SetStorage {
    BTree(BTreeSet<Value>),
}

impl Default for SetStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl SetStorage {
    #[inline]
    pub(crate) fn new() -> Self {
        Self::BTree(BTreeSet::new())
    }

    #[inline]
    pub(crate) fn with_capacity(_cap: usize) -> Self {
        Self::new()
    }

    #[inline]
    pub(crate) fn from_btreeset(set: BTreeSet<Value>) -> Self {
        Self::BTree(set)
    }

    #[inline]
    pub(crate) fn as_btreeset(&self) -> &BTreeSet<Value> {
        match self {
            Self::BTree(s) => s,
        }
    }

    #[inline]
    pub(crate) fn as_btreeset_mut(&mut self) -> &mut BTreeSet<Value> {
        match self {
            Self::BTree(s) => s,
        }
    }

    #[inline]
    pub(crate) fn into_btreeset(self) -> BTreeSet<Value> {
        match self {
            Self::BTree(s) => s,
        }
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.as_btreeset().len()
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.as_btreeset().is_empty()
    }

    #[inline]
    pub(crate) fn contains(&self, value: &Value) -> bool {
        self.as_btreeset().contains(value)
    }

    #[inline]
    pub(crate) fn insert(&mut self, value: Value) -> Result<bool, InsertError> {
        check_key(&value)?;
        Ok(self.as_btreeset_mut().insert(value))
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn remove(&mut self, value: &Value) -> bool {
        self.as_btreeset_mut().remove(value)
    }

    #[inline]
    pub(crate) fn clear(&mut self) {
        self.as_btreeset_mut().clear();
    }
}
