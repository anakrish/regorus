// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Opaque iterator types for [`Array`].
//!
//! These newtypes wrap the storage backend's iterators so the backend can be
//! swapped without changing any iterator type signatures observed by callers.

use alloc::vec;
use core::iter::FusedIterator;
use core::slice;

use super::Array;
use crate::value::Value;

/// Owned iterator over `Value` elements.
#[derive(Debug)]
pub struct IntoIter {
    pub(super) inner: vec::IntoIter<Value>,
}

impl Iterator for IntoIter {
    type Item = Value;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl DoubleEndedIterator for IntoIter {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back()
    }
}

impl ExactSizeIterator for IntoIter {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl FusedIterator for IntoIter {}

/// Borrowed iterator over `&Value` elements.
#[derive(Debug, Clone)]
pub struct Iter<'a> {
    pub(super) inner: slice::Iter<'a, Value>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a Value;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<'a> DoubleEndedIterator for Iter<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back()
    }
}

impl<'a> ExactSizeIterator for Iter<'a> {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<'a> FusedIterator for Iter<'a> {}

/// Mutable borrowed iterator over `&mut Value` elements.
#[derive(Debug)]
pub struct IterMut<'a> {
    pub(super) inner: slice::IterMut<'a, Value>,
}

impl<'a> Iterator for IterMut<'a> {
    type Item = &'a mut Value;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<'a> DoubleEndedIterator for IterMut<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back()
    }
}

impl<'a> ExactSizeIterator for IterMut<'a> {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl<'a> FusedIterator for IterMut<'a> {}

/// Opaque resumable cursor over an [`Array`]'s elements.
///
/// Self-owned: holds no borrow on the `Array`, so it can be stored as a field
/// of a long-lived state struct (e.g. an RVM iteration frame).
#[cfg(feature = "rvm")]
#[derive(Debug, Clone, Default)]
pub struct Cursor {
    pub(super) next: usize,
}

impl IntoIterator for Array {
    type Item = Value;
    type IntoIter = IntoIter;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        IntoIter {
            inner: self.inner.into_iter(),
        }
    }
}

impl<'a> IntoIterator for &'a Array {
    type Item = &'a Value;
    type IntoIter = Iter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        Iter {
            inner: self.inner.iter(),
        }
    }
}

impl<'a> IntoIterator for &'a mut Array {
    type Item = &'a mut Value;
    type IntoIter = IterMut<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        IterMut {
            inner: self.inner.iter_mut(),
        }
    }
}
