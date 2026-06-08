// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Thread-local string interner for `Arc<str>` keys.
//!
//! When deserializing many objects with the same keys (e.g., an array of
//! Kubernetes pods), the interner ensures each unique key string is allocated
//! only once on the heap. Subsequent encounters reuse the existing `Arc<str>`
//! via a cheap refcount bump.

use std::cell::RefCell;
use std::sync::Arc;

use hashbrown::HashSet;

thread_local! {
    static INTERN_TABLE: RefCell<HashSet<Arc<str>>> = RefCell::new(HashSet::new());
}

/// Intern a string, returning a shared `Arc<str>`.
///
/// If the string was previously interned on this thread, returns a clone of the
/// existing `Arc` (refcount bump only — no heap allocation).
pub fn intern(s: &str) -> Arc<str> {
    INTERN_TABLE.with(|table| {
        let mut set = table.borrow_mut();
        if let Some(existing) = set.get(s) {
            Arc::clone(existing)
        } else {
            let arc: Arc<str> = Arc::from(s);
            set.insert(Arc::clone(&arc));
            arc
        }
    })
}

/// Clear the intern table for the current thread.
pub fn clear() {
    INTERN_TABLE.with(|table| {
        table.borrow_mut().clear();
    });
}
