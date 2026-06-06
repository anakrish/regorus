// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! See [`Array`].

mod iter;
mod serde;

use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use core::ops;

use crate::value::Value;
use crate::Rc;

#[cfg(feature = "rvm")]
#[allow(unused_imports)] // surface for downstream PRs
pub use iter::Cursor;
#[allow(unused_imports)] // surface for downstream PRs
pub use iter::{IntoIter, Iter, IterMut};

/// Opaque, ordered sequence of [`Value`]s.
///
/// The current backing storage is `Vec<Value>`. The inner field is private so
/// the representation can change (inline-small, lazy, arena-backed,
/// FFI-backed) without touching call sites.
///
/// # Iteration
///
/// - [`Array::iter`] — sequence order; non-resumable.
/// - [`Array::cursor`] / [`Array::next`] — sequence order, resumable. Used by
///   interpreter/RVM when iteration must yield mid-flight.
#[derive(Default, Clone, Eq, PartialEq)]
pub struct Array {
    inner: Vec<Value>,
}

impl Array {
    /// Create an empty `Array`.
    #[inline]
    pub const fn new() -> Self {
        Self { inner: Vec::new() }
    }

    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
        }
    }

    #[inline]
    pub const fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[inline]
    pub fn get(&self, index: usize) -> Option<&Value> {
        self.inner.get(index)
    }

    #[inline]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Value> {
        self.inner.get_mut(index)
    }

    #[inline]
    pub fn first(&self) -> Option<&Value> {
        self.inner.first()
    }

    #[inline]
    pub fn last(&self) -> Option<&Value> {
        self.inner.last()
    }

    #[inline]
    pub const fn as_slice(&self) -> &[Value] {
        self.inner.as_slice()
    }

    #[inline]
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            inner: self.inner.iter(),
        }
    }

    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_> {
        IterMut {
            inner: self.inner.iter_mut(),
        }
    }

    #[inline]
    pub fn push(&mut self, value: Value) {
        self.inner.push(value);
    }

    #[inline]
    pub fn pop(&mut self) -> Option<Value> {
        self.inner.pop()
    }

    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Inserts `value` at `index`, shifting existing elements right.
    ///
    /// Returns `Some(())` on success, or `None` if `index > self.len()`
    /// (rather than panicking — this is a host-reachable API surface).
    #[inline]
    pub fn insert(&mut self, index: usize, value: Value) -> Option<()> {
        if index > self.inner.len() {
            return None;
        }
        self.inner.insert(index, value);
        Some(())
    }

    /// Removes and returns the element at `index`, shifting subsequent
    /// elements left.
    ///
    /// Returns `None` if `index >= self.len()` (rather than panicking —
    /// this is a host-reachable API surface).
    #[inline]
    pub fn remove(&mut self, index: usize) -> Option<Value> {
        if index >= self.inner.len() {
            return None;
        }
        Some(self.inner.remove(index))
    }

    #[inline]
    pub fn truncate(&mut self, len: usize) {
        self.inner.truncate(len);
    }

    #[inline]
    pub fn sort(&mut self) {
        self.inner.sort();
    }

    #[inline]
    pub fn sort_by<F>(&mut self, compare: F)
    where
        F: FnMut(&Value, &Value) -> Ordering,
    {
        self.inner.sort_by(compare);
    }

    #[inline]
    pub fn dedup(&mut self) {
        self.inner.dedup();
    }

    #[inline]
    pub fn extend_from_slice(&mut self, other: &[Value]) {
        self.inner.extend_from_slice(other);
    }

    #[inline]
    pub fn reverse(&mut self) {
        self.inner.reverse();
    }

    /// Wrap into a `Value::Array`.
    #[inline]
    pub fn into_value(self) -> Value {
        Value::Array(Rc::new(self))
    }

    /// Create a resumable cursor over elements in sequence order. O(1).
    ///
    /// The cursor is fully self-owned (it stores the next index, not a
    /// reference) so it can be stored as a field of a long-lived state struct
    /// — e.g. an RVM iteration frame that persists across instruction
    /// dispatches. Mutating the `Array` between `next()` calls is not rejected
    /// by the borrow checker; the resulting traversal in that case follows the
    /// current contents at each stored index.
    #[cfg(feature = "rvm")]
    #[inline]
    pub const fn cursor(&self) -> Cursor {
        Cursor { next: 0 }
    }

    /// Advance `cursor` and yield the next `(index, value)` pair. O(1).
    #[cfg(feature = "rvm")]
    pub fn next<'a>(&'a self, cursor: &mut Cursor) -> Option<(usize, &'a Value)> {
        let index = cursor.next;
        let value = self.inner.get(index)?;
        cursor.next = index.saturating_add(1);
        Some((index, value))
    }
}

// ---- Hand-written Ord/PartialOrd ----------------------------------------
//
// Implemented in terms of `iter()` so ordering is consistent with the
// canonical sequence view and remains independent of the storage variant.

impl Ord for Array {
    fn cmp(&self, other: &Self) -> Ordering {
        self.iter().cmp(other.iter())
    }
}

impl PartialOrd for Array {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for Array {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl ops::Index<usize> for Array {
    type Output = Value;

    /// Indexes the array. Returns `&Value::Undefined` for out-of-range
    /// indices rather than panicking, matching `Value`'s indexing
    /// semantics. Use [`Array::get`] to distinguish "missing" from
    /// "present-and-Undefined".
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        self.inner.get(index).unwrap_or(&Value::Undefined)
    }
}

impl Extend<Value> for Array {
    fn extend<I: IntoIterator<Item = Value>>(&mut self, iter: I) {
        self.inner.extend(iter);
    }
}

impl FromIterator<Value> for Array {
    fn from_iter<I: IntoIterator<Item = Value>>(iter: I) -> Self {
        Self {
            inner: Vec::from_iter(iter),
        }
    }
}

impl From<Vec<Value>> for Array {
    #[inline]
    fn from(values: Vec<Value>) -> Self {
        Self { inner: values }
    }
}

impl From<Array> for Value {
    #[inline]
    fn from(array: Array) -> Self {
        array.into_value()
    }
}
