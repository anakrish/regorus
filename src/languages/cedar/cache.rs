// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::Value;
use alloc::collections::BTreeMap;

#[cfg(feature = "std")]
use parking_lot::RwLock;
#[cfg(not(feature = "std"))]
use spin::RwLock;

#[derive(Debug, Default)]
pub struct CedarCache {
    inner: RwLock<CedarCacheInner>,
}

#[derive(Debug, Default)]
struct CedarCacheInner {
    membership: BTreeMap<(Value, Value), bool>,
}

impl CedarCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_membership(&self, entity: &Value, target: &Value) -> Option<bool> {
        let inner = self.inner.read();
        inner
            .membership
            .get(&(entity.clone(), target.clone()))
            .copied()
    }

    pub fn insert_membership(&self, entity: Value, target: Value, result: bool) {
        let mut inner = self.inner.write();
        inner.membership.insert((entity, target), result);
    }

    pub fn clear(&self) {
        let mut inner = self.inner.write();
        inner.membership.clear();
    }
}
