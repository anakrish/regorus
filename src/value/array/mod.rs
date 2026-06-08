// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! See [`Array`].

mod iter;
mod serde;

use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use core::ops;

use anyhow::{bail, Result};

use crate::value::Value;

#[cfg(feature = "rvm")]
#[allow(unused_imports)] // surface for downstream PRs
pub use iter::ArrayCursor;
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
///
/// # Memory-limit enforcement
///
/// Growth-path methods that take a fallible `Result` return value
/// ([`Array::push`], [`Array::extend_from_slice`], [`Array::insert`],
/// [`Array::with_capacity`], [`Array::try_from_vec`], [`Array::try_from_iter`])
/// consult the configured cooperative memory limit and report
/// `Err` when it is exceeded; the array is left in a consistent state (any
/// in-progress mutation that would have crossed the limit is rolled back).
///
/// Infallible trait impls ([`Extend`], [`FromIterator`], [`From<Vec<Value>>`])
/// match the [`crate::value::Object`] convention and **do not** consult the
/// cooperative limit — they exist for ergonomic / migration use and rely on the
/// allocator to fail on true OOM. Limit-aware callers must use the explicit
/// fallible methods above.
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

    /// Create an empty `Array` with space for at least `capacity` elements.
    ///
    /// Returns `None` if the requested capacity is too large for the
    /// allocator, or if reserving it would push memory usage past the
    /// configured cooperative limit.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Option<Self> {
        let mut inner = Vec::new();
        inner.try_reserve(capacity).ok()?;
        crate::utils::limits::check_memory_limit_if_needed().ok()?;
        Some(Self { inner })
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

    /// Appends `value` to the end of the array.
    ///
    /// Returns `Err` if the cooperative memory limit would be exceeded by the
    /// appended element; in that case the value is rolled back (popped) before
    /// returning, so the array length is unchanged.
    #[inline]
    pub fn push(&mut self, value: Value) -> Result<()> {
        self.inner.push(value);
        if let Err(err) = crate::utils::limits::check_memory_limit_if_needed() {
            // Roll back the mutation so the caller observes a consistent state.
            self.inner.pop();
            return Err(anyhow::Error::new(err));
        }
        Ok(())
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
    /// Returns `Err` if `index > self.len()` (rather than panicking — this is
    /// a host-reachable API surface) or if the cooperative memory limit would
    /// be exceeded by the appended element; in the limit case the insertion is
    /// rolled back so the array length is unchanged.
    #[inline]
    pub fn insert(&mut self, index: usize, value: Value) -> Result<()> {
        let len = self.inner.len();
        if index > len {
            bail!("Array::insert: index {index} out of bounds (len={len})");
        }
        self.inner.insert(index, value);
        if let Err(err) = crate::utils::limits::check_memory_limit_if_needed() {
            self.inner.remove(index);
            return Err(anyhow::Error::new(err));
        }
        Ok(())
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

    /// Extends the array by cloning values from `other`.
    ///
    /// Checks the cooperative memory limit after each appended element; on
    /// failure, all elements appended by this call (including the offending
    /// one) are rolled back so the array length is unchanged.
    pub fn extend_from_slice(&mut self, other: &[Value]) -> Result<()> {
        let original_len = self.inner.len();
        for value in other {
            self.inner.push(value.clone());
            if let Err(err) = crate::utils::limits::check_memory_limit_if_needed() {
                self.inner.truncate(original_len);
                return Err(anyhow::Error::new(err));
            }
        }
        Ok(())
    }

    #[inline]
    pub fn reverse(&mut self) {
        self.inner.reverse();
    }

    /// Build an `Array` from an existing `Vec<Value>` with memory-limit
    /// enforcement. Returns `Err` if the cooperative limit is exceeded after
    /// taking ownership of `values`.
    #[inline]
    pub fn try_from_vec(values: Vec<Value>) -> Result<Self> {
        let array = Self { inner: values };
        crate::utils::limits::check_memory_limit_if_needed().map_err(anyhow::Error::new)?;
        Ok(array)
    }

    /// Collect an iterator of `Value`s into an `Array` with memory-limit
    /// enforcement per-element. Rolls back any partially-collected state on
    /// limit failure (the returned `Err` leaves nothing behind).
    pub fn try_from_iter<I: IntoIterator<Item = Value>>(iter: I) -> Result<Self> {
        let mut array = Self::new();
        for value in iter {
            array.push(value)?;
        }
        Ok(array)
    }

    /// Wrap into a `Value::Array`.
    #[inline]
    pub fn into_value(self) -> Value {
        Value::Array(crate::Rc::new(self.inner))
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
    pub const fn cursor(&self) -> ArrayCursor {
        ArrayCursor { next: 0 }
    }

    /// Advance `cursor` and yield the next `(index, value)` pair. O(1).
    #[cfg(feature = "rvm")]
    pub fn next<'a>(&'a self, cursor: &mut ArrayCursor) -> Option<(usize, &'a Value)> {
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

// Bulk-insertion trait impls mirror the [`crate::value::Object`] convention:
// they delegate directly to the inner container and **do not** consult the
// cooperative memory limit. Limit-aware callers must use [`Array::push`],
// [`Array::extend_from_slice`], [`Array::try_from_vec`], or
// [`Array::try_from_iter`].

impl Extend<Value> for Array {
    #[inline]
    fn extend<I: IntoIterator<Item = Value>>(&mut self, iter: I) {
        self.inner.extend(iter);
    }
}

impl FromIterator<Value> for Array {
    #[inline]
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
