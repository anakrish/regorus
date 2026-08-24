// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resumable, self-owned cursor over an [`Object`]'s entries.

use core::ops::Bound;

use super::{Object, Repr};
use crate::value::Value;

impl Object {
    /// Create a resumable cursor over entries in implementation-defined
    /// order. Stable for the lifetime of `&self`. O(1).
    #[inline]
    pub const fn cursor(&self) -> ObjectCursor {
        ObjectCursor {
            inner: ObjectCursorInner::Start,
        }
    }

    /// Advance `cursor` and yield the next entry.
    pub fn next<'a>(&'a self, cursor: &mut ObjectCursor) -> Option<(&'a Value, &'a Value)> {
        match (&self.repr, &mut cursor.inner) {
            (Repr::Empty, _) => None,
            (Repr::Frozen(v), ObjectCursorInner::Start) => {
                let (k, val) = v.first()?;
                cursor.inner = ObjectCursorInner::Frozen {
                    index: 0,
                    key: k.clone(),
                };
                Some((k, val))
            }
            (Repr::Frozen(v), ObjectCursorInner::Frozen { index, key }) => {
                let next = frozen_resume(v, *index, key);
                let (k, val) = v.get(next)?;
                cursor.inner = ObjectCursorInner::Frozen {
                    index: next,
                    key: k.clone(),
                };
                Some((k, val))
            }
            (Repr::Frozen(v), ObjectCursorInner::Key(prev)) => {
                let i = frozen_relocate(v, prev);
                let (k, val) = v.get(i)?;
                cursor.inner = ObjectCursorInner::Frozen {
                    index: i,
                    key: k.clone(),
                };
                Some((k, val))
            }
            (Repr::BTree(m), ObjectCursorInner::Start) => {
                let (k, val) = m.iter().next()?;
                cursor.inner = ObjectCursorInner::Key(k.clone());
                Some((k, val))
            }
            (Repr::BTree(m), ObjectCursorInner::Key(prev)) => {
                let (k, val) = m
                    .range((Bound::Excluded(&*prev), Bound::Unbounded))
                    .next()?;
                cursor.inner = ObjectCursorInner::Key(k.clone());
                Some((k, val))
            }
            (Repr::BTree(m), ObjectCursorInner::Frozen { key, .. }) => {
                let (k, val) = m.range((Bound::Excluded(&*key), Bound::Unbounded)).next()?;
                cursor.inner = ObjectCursorInner::Key(k.clone());
                Some((k, val))
            }
        }
    }

    /// Advance `cursor` and yield the next owned entry.
    pub fn next_owned(&self, cursor: &mut ObjectCursor) -> Option<(Value, Value)> {
        self.next(cursor)
            .map(|(key, value)| (key.clone(), value.clone()))
    }
}

/// Resume position in a `Frozen` slice given the last-yielded `index` and its
/// `key`. O(1) when the slice is unchanged since the last step; falls back to an
/// O(log n) binary search only if the object was mutated between calls (so the
/// entry at `index` is no longer `key`).
fn frozen_resume(v: &[(Value, Value)], index: usize, key: &Value) -> usize {
    if v.get(index).map(|(k, _)| k) == Some(key) {
        index.saturating_add(1)
    } else {
        frozen_relocate(v, key)
    }
}

/// Locate the resume index for `key` in a `Frozen` slice by binary search,
/// returning the index of the first entry strictly greater than `key`.
fn frozen_relocate(v: &[(Value, Value)], key: &Value) -> usize {
    match v.binary_search_by(|(k, _)| k.cmp(key)) {
        Ok(i) => i.saturating_add(1),
        Err(i) => i,
    }
}

/// Opaque resumable cursor over an [`Object`]'s entries in
/// implementation-defined order.
///
/// Self-owned: holds no borrow on the `Object`, so it can be stored as a
/// field of a long-lived state struct (e.g. an RVM iteration frame).
#[derive(Debug, Clone)]
pub struct ObjectCursor {
    inner: ObjectCursorInner,
}

#[derive(Debug, Clone)]
enum ObjectCursorInner {
    Start,
    /// Positional resume for a `Frozen` slice: `index` is the last-yielded
    /// entry's position and `key` is its key. The key is retained so resume
    /// stays correct if the object's representation changed (e.g. Frozen →
    /// BTree) or was mutated between calls.
    Frozen {
        index: usize,
        key: Value,
    },
    /// Key-based resume for `BTree` storage (no O(1) positional access).
    Key(Value),
}
