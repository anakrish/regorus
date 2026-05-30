// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use alloc::collections::{btree_map, btree_set};

use crate::value::Value;

/// Iterator over `(key, value)` pairs of an `Object` in sorted key order.
#[derive(Debug, Clone)]
pub struct Iter<'a> {
    inner: btree_map::Iter<'a, Value, Value>,
}

impl<'a> Iter<'a> {
    pub(crate) const fn new(inner: btree_map::Iter<'a, Value, Value>) -> Self {
        Self { inner }
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = (&'a Value, &'a Value);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for Iter<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl core::iter::FusedIterator for Iter<'_> {}

impl<'a> DoubleEndedIterator for Iter<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back()
    }
}

/// Iterator over keys of an `Object` in sorted order.
#[derive(Debug, Clone)]
pub struct Keys<'a> {
    inner: btree_map::Keys<'a, Value, Value>,
}

impl<'a> Keys<'a> {
    pub(crate) const fn new(inner: btree_map::Keys<'a, Value, Value>) -> Self {
        Self { inner }
    }
}

impl<'a> Iterator for Keys<'a> {
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

impl ExactSizeIterator for Keys<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl core::iter::FusedIterator for Keys<'_> {}

/// Iterator over values of an `Object` in sorted key order.
#[derive(Debug, Clone)]
pub struct Values<'a> {
    inner: btree_map::Values<'a, Value, Value>,
}

impl<'a> Values<'a> {
    pub(crate) const fn new(inner: btree_map::Values<'a, Value, Value>) -> Self {
        Self { inner }
    }
}

impl<'a> Iterator for Values<'a> {
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

impl ExactSizeIterator for Values<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl core::iter::FusedIterator for Values<'_> {}

/// Mutable iterator over `(key, value_mut)` pairs of an `Object`.
#[derive(Debug)]
pub struct IterMut<'a> {
    inner: btree_map::IterMut<'a, Value, Value>,
}

impl<'a> IterMut<'a> {
    pub(crate) fn new(inner: btree_map::IterMut<'a, Value, Value>) -> Self {
        Self { inner }
    }
}

impl<'a> Iterator for IterMut<'a> {
    type Item = (&'a Value, &'a mut Value);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for IterMut<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl core::iter::FusedIterator for IterMut<'_> {}

/// Mutable iterator over values of an `Object`.
#[derive(Debug)]
pub struct ValuesMut<'a> {
    inner: btree_map::ValuesMut<'a, Value, Value>,
}

impl<'a> ValuesMut<'a> {
    pub(crate) fn new(inner: btree_map::ValuesMut<'a, Value, Value>) -> Self {
        Self { inner }
    }
}

impl<'a> Iterator for ValuesMut<'a> {
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

impl ExactSizeIterator for ValuesMut<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl core::iter::FusedIterator for ValuesMut<'_> {}

/// Unordered iteration. For the BTree storage variant this delegates to the
/// sorted iterator; future variants may return entries in another order.
#[derive(Debug, Clone)]
pub struct IterUnordered<'a> {
    inner: Iter<'a>,
}

impl<'a> IterUnordered<'a> {
    pub(crate) const fn new(inner: Iter<'a>) -> Self {
        Self { inner }
    }
}

impl<'a> Iterator for IterUnordered<'a> {
    type Item = (&'a Value, &'a Value);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for IterUnordered<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl core::iter::FusedIterator for IterUnordered<'_> {}

/// Owning iterator over an `Object`'s entries.
#[derive(Debug)]
pub struct IntoIter {
    inner: alloc::collections::btree_map::IntoIter<Value, Value>,
}

impl IntoIter {
    pub(crate) fn new(inner: alloc::collections::btree_map::IntoIter<Value, Value>) -> Self {
        Self { inner }
    }
}

impl Iterator for IntoIter {
    type Item = (Value, Value);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for IntoIter {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl core::iter::FusedIterator for IntoIter {}

// ---------- Set iterators ----------

/// Iterator over `Set` elements in sorted order.
#[derive(Debug, Clone)]
pub struct SetIter<'a> {
    inner: btree_set::Iter<'a, Value>,
}

impl<'a> SetIter<'a> {
    pub(crate) const fn new(inner: btree_set::Iter<'a, Value>) -> Self {
        Self { inner }
    }
}

impl<'a> Iterator for SetIter<'a> {
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

impl ExactSizeIterator for SetIter<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl core::iter::FusedIterator for SetIter<'_> {}

impl<'a> DoubleEndedIterator for SetIter<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back()
    }
}

/// Unordered iteration on a `Set`. BTree variant delegates to sorted iter.
#[derive(Debug, Clone)]
pub struct SetIterUnordered<'a> {
    inner: SetIter<'a>,
}

impl<'a> SetIterUnordered<'a> {
    pub(crate) const fn new(inner: SetIter<'a>) -> Self {
        Self { inner }
    }
}

impl<'a> Iterator for SetIterUnordered<'a> {
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

impl ExactSizeIterator for SetIterUnordered<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl core::iter::FusedIterator for SetIterUnordered<'_> {}

/// Owning iterator over `Set` elements.
#[derive(Debug)]
pub struct SetIntoIter {
    inner: alloc::collections::btree_set::IntoIter<Value>,
}

impl SetIntoIter {
    pub(crate) fn new(inner: alloc::collections::btree_set::IntoIter<Value>) -> Self {
        Self { inner }
    }
}

impl Iterator for SetIntoIter {
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

impl ExactSizeIterator for SetIntoIter {
    #[inline]
    fn len(&self) -> usize {
        self.inner.len()
    }
}

impl core::iter::FusedIterator for SetIntoIter {}
