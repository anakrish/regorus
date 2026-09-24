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

pub use iter::{ArrayIntoIter, ArrayIter, ArrayIterMut, ArrayOwnedIter};

/// Opaque, ordered sequence of [`Value`]s.
///
/// The backing storage is `Vec<Value>` wrapped in a private `Repr` enum. The
/// representation is private so it can change without touching call sites.
#[derive(Default, Clone, Eq, PartialEq)]
pub struct Array {
    repr: Repr,
}

#[derive(Clone, PartialEq, Eq)]
enum Repr {
    Owned(Vec<Value>),
}

impl Default for Repr {
    #[inline]
    fn default() -> Self {
        Repr::Owned(Vec::new())
    }
}

impl Array {
    /// Create an empty `Array`.
    #[inline]
    pub const fn new() -> Self {
        Self {
            repr: Repr::Owned(Vec::new()),
        }
    }

    #[inline]
    pub const fn len(&self) -> usize {
        match &self.repr {
            Repr::Owned(values) => values.len(),
        }
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn get(&self, index: usize) -> Option<&Value> {
        self.as_slice().get(index)
    }

    #[inline]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Value> {
        match &mut self.repr {
            Repr::Owned(values) => values.get_mut(index),
        }
    }

    #[inline]
    pub fn first(&self) -> Option<&Value> {
        self.as_slice().first()
    }

    #[inline]
    pub fn last(&self) -> Option<&Value> {
        self.as_slice().last()
    }

    #[inline]
    pub fn contains(&self, value: &Value) -> bool {
        self.as_slice().contains(value)
    }

    #[inline]
    pub const fn as_slice(&self) -> &[Value] {
        match &self.repr {
            Repr::Owned(values) => values.as_slice(),
        }
    }

    /// Iteration in element order. Non-resumable.
    #[inline]
    pub fn iter(&self) -> ArrayIter<'_> {
        ArrayIter {
            inner: self.as_slice().iter(),
        }
    }

    /// Owned iteration in element order. Non-resumable. Each item is an owned
    /// [`Value`].
    #[inline]
    pub fn iter_owned(&self) -> ArrayOwnedIter<'_> {
        ArrayOwnedIter::new(self)
    }

    #[inline]
    pub fn iter_mut(&mut self) -> ArrayIterMut<'_> {
        ArrayIterMut {
            inner: match &mut self.repr {
                Repr::Owned(values) => values.iter_mut(),
            },
        }
    }

    #[inline]
    pub fn push(&mut self, value: Value) {
        match &mut self.repr {
            Repr::Owned(values) => values.push(value),
        }
    }

    #[inline]
    pub fn append(&mut self, other: &mut Array) {
        match (&mut self.repr, &mut other.repr) {
            (Repr::Owned(values), Repr::Owned(other_values)) => values.append(other_values),
        }
    }

    #[inline]
    pub fn extend<I: IntoIterator<Item = Value>>(&mut self, iter: I) {
        match &mut self.repr {
            Repr::Owned(values) => values.extend(iter),
        }
    }

    /// Append all elements of `other` (by clone) to the end of `self`.
    #[inline]
    pub fn extend_from_slice(&mut self, other: &[Value]) {
        match &mut self.repr {
            Repr::Owned(values) => values.extend_from_slice(other),
        }
    }

    #[inline]
    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&Value) -> bool,
    {
        match &mut self.repr {
            Repr::Owned(values) => values.retain(f),
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        match &mut self.repr {
            Repr::Owned(values) => values.clear(),
        }
    }

    #[inline]
    pub fn reverse(&mut self) {
        match &mut self.repr {
            Repr::Owned(values) => values.reverse(),
        }
    }

    #[inline]
    pub fn sort(&mut self) {
        match &mut self.repr {
            Repr::Owned(values) => values.sort(),
        }
    }

    #[inline]
    pub fn to_vec(&self) -> Vec<Value> {
        self.as_slice().to_vec()
    }

    #[inline]
    pub fn into_vec(self) -> Vec<Value> {
        match self.repr {
            Repr::Owned(values) => values,
        }
    }

    /// Fallible element access that reads through without borrowing.
    ///
    /// `Ok(None)` means the index is out of range. Native storage is infallible
    /// and always returns `Ok`; the `Result` establishes a stable seam so a
    /// later feature can add fallible backends without a second API break.
    #[allow(dead_code)] // wired to interpreter/RVM call sites in later foundation commits
    pub(crate) fn try_element(&self, index: usize) -> anyhow::Result<Option<Value>> {
        match &self.repr {
            Repr::Owned(values) => Ok(values.get(index).cloned()),
        }
    }

    /// Fallible materialization into an owned `Vec<Value>`.
    ///
    /// Native storage clones its backing vector and never errors. The `Result`
    /// mirrors [`Self::try_element`] so a later feature can add a limit-enforcing
    /// materializing backend; native cloning needs no resource-limit check here.
    #[allow(dead_code)] // wired to builtin/eval call sites in later foundation commits
    pub(crate) fn try_to_vec(&self) -> anyhow::Result<Vec<Value>> {
        match &self.repr {
            Repr::Owned(values) => Ok(values.clone()),
        }
    }

    /// Wrap into a `Value::Array`.
    #[inline]
    pub fn into_value(self) -> Value {
        Value::Array(crate::Rc::new(self))
    }

    /// Create a resumable cursor over elements in order. O(1).
    #[inline]
    pub const fn cursor(&self) -> ArrayCursor {
        ArrayCursor { index: 0 }
    }

    /// Advance `cursor` and yield the next element.
    pub fn next<'a>(&'a self, cursor: &mut ArrayCursor) -> Option<&'a Value> {
        let value = self.as_slice().get(cursor.index)?;
        cursor.index = cursor.index.saturating_add(1);
        Some(value)
    }

    /// Advance `cursor` and yield the next owned element.
    pub fn next_owned(&self, cursor: &mut ArrayCursor) -> Option<Value> {
        self.next(cursor).cloned()
    }
}

/// Opaque resumable cursor over an [`Array`]'s elements.
#[derive(Debug, Clone)]
pub struct ArrayCursor {
    index: usize,
}

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

impl Extend<Value> for Array {
    fn extend<I: IntoIterator<Item = Value>>(&mut self, iter: I) {
        match &mut self.repr {
            Repr::Owned(values) => values.extend(iter),
        }
    }
}

impl FromIterator<Value> for Array {
    fn from_iter<I: IntoIterator<Item = Value>>(iter: I) -> Self {
        Self {
            repr: Repr::Owned(Vec::from_iter(iter)),
        }
    }
}

impl From<Vec<Value>> for Array {
    #[inline]
    fn from(values: Vec<Value>) -> Self {
        Self {
            repr: Repr::Owned(values),
        }
    }
}

impl ops::Index<usize> for Array {
    type Output = Value;

    /// Indexes the array. Returns `&Value::Undefined` for out-of-range
    /// indices rather than panicking, matching `Value`'s indexing semantics.
    /// Use [`Array::get`] to distinguish "missing" from "present-and-Undefined".
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        self.as_slice().get(index).unwrap_or(&Value::Undefined)
    }
}

impl From<Array> for Value {
    #[inline]
    fn from(a: Array) -> Self {
        a.into_value()
    }
}
