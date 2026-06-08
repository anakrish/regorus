// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Thread-local string interner for `arcstr::ArcStr` keys.

use std::cell::RefCell;

use arcstr::ArcStr;
use hashbrown::HashSet;

thread_local! {
    static INTERN_TABLE: RefCell<HashSet<ArcStr>> = RefCell::new(HashSet::new());
}

/// Intern a string, returning a shared `ArcStr`.
pub fn intern(s: &str) -> ArcStr {
    INTERN_TABLE.with(|table| {
        let mut set = table.borrow_mut();
        if let Some(existing) = set.get(s) {
            existing.clone()
        } else {
            let arc = ArcStr::from(s);
            set.insert(arc.clone());
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
