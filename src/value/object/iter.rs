// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Opaque iterator types for [`Object`].

use alloc::collections::btree_map;
use alloc::vec::Vec;
use core::iter::FusedIterator;

use super::{Object, Repr, INLINE_CAP};
use crate::value::Value;

/// Owned iterator over `(Value, Value)` entries.
#[derive(Debug)]
pub struct IntoIter {
    pub(super) inner: IntoIterInner,
}

#[derive(Debug)]
pub(super) enum IntoIterInner {
    Inline(smallvec::IntoIter<[(Value, Value); INLINE_CAP]>),
    Frozen(alloc::vec::IntoIter<(Value, Value)>),
    BTree(btree_map::IntoIter<Value, Value>),
}

impl Iterator for IntoIter {
    type Item = (Value, Value);
    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            IntoIterInner::Inline(it) => it.next(),
            IntoIterInner::Frozen(it) => it.next(),
            IntoIterInner::BTree(it) => it.next(),
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.inner {
            IntoIterInner::Inline(it) => it.size_hint(),
            IntoIterInner::Frozen(it) => it.size_hint(),
            IntoIterInner::BTree(it) => it.size_hint(),
        }
    }
}

impl ExactSizeIterator for IntoIter {
    fn len(&self) -> usize {
        match &self.inner {
            IntoIterInner::Inline(it) => it.len(),
            IntoIterInner::Frozen(it) => it.len(),
            IntoIterInner::BTree(it) => it.len(),
        }
    }
}

impl DoubleEndedIterator for IntoIter {
    fn next_back(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            IntoIterInner::Inline(it) => it.next_back(),
            IntoIterInner::Frozen(it) => it.next_back(),
            IntoIterInner::BTree(it) => it.next_back(),
        }
    }
}

impl FusedIterator for IntoIter {}

/// Borrowed iterator over `(&Value, &Value)` entries.
#[derive(Debug, Clone)]
pub struct Iter<'a> {
    pub(super) inner: IterInner<'a>,
}

#[derive(Debug, Clone)]
pub(super) enum IterInner<'a> {
    Inline(core::slice::Iter<'a, (Value, Value)>),
    Frozen(core::slice::Iter<'a, (Value, Value)>),
    BTree(btree_map::Iter<'a, Value, Value>),
}

impl<'a> Iterator for Iter<'a> {
    type Item = (&'a Value, &'a Value);
    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            IterInner::Inline(it) | IterInner::Frozen(it) => it.next().map(|(k, v)| (k, v)),
            IterInner::BTree(it) => it.next(),
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.inner {
            IterInner::Inline(it) | IterInner::Frozen(it) => it.size_hint(),
            IterInner::BTree(it) => it.size_hint(),
        }
    }
}

impl<'a> ExactSizeIterator for Iter<'a> {
    fn len(&self) -> usize {
        match &self.inner {
            IterInner::Inline(it) | IterInner::Frozen(it) => it.len(),
            IterInner::BTree(it) => it.len(),
        }
    }
}

impl<'a> DoubleEndedIterator for Iter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            IterInner::Inline(it) | IterInner::Frozen(it) => it.next_back().map(|(k, v)| (k, v)),
            IterInner::BTree(it) => it.next_back(),
        }
    }
}

impl<'a> FusedIterator for Iter<'a> {}

/// Borrowed iterator over `(&Value, &mut Value)` entries.
#[derive(Debug)]
pub struct IterMut<'a> {
    pub(super) inner: IterMutInner<'a>,
}

#[derive(Debug)]
pub(super) enum IterMutInner<'a> {
    Inline(core::slice::IterMut<'a, (Value, Value)>),
    Frozen(core::slice::IterMut<'a, (Value, Value)>),
    BTree(btree_map::IterMut<'a, Value, Value>),
}

impl<'a> Iterator for IterMut<'a> {
    type Item = (&'a Value, &'a mut Value);
    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            IterMutInner::Inline(it) | IterMutInner::Frozen(it) => it.next().map(|(k, v)| (&*k, v)),
            IterMutInner::BTree(it) => it.next(),
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.inner {
            IterMutInner::Inline(it) | IterMutInner::Frozen(it) => it.size_hint(),
            IterMutInner::BTree(it) => it.size_hint(),
        }
    }
}

impl<'a> ExactSizeIterator for IterMut<'a> {
    fn len(&self) -> usize {
        match &self.inner {
            IterMutInner::Inline(it) | IterMutInner::Frozen(it) => it.len(),
            IterMutInner::BTree(it) => it.len(),
        }
    }
}

impl<'a> DoubleEndedIterator for IterMut<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            IterMutInner::Inline(it) | IterMutInner::Frozen(it) => {
                it.next_back().map(|(k, v)| (&*k, v))
            }
            IterMutInner::BTree(it) => it.next_back(),
        }
    }
}

impl<'a> FusedIterator for IterMut<'a> {}

impl IntoIterator for Object {
    type Item = (Value, Value);
    type IntoIter = IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        IntoIter {
            inner: match self.repr {
                Repr::Inline(v) => IntoIterInner::Inline((*v).into_iter()),
                Repr::Frozen(v) => IntoIterInner::Frozen(Vec::from(v).into_iter()),
                Repr::BTree(m) => IntoIterInner::BTree(m.into_iter()),
            },
        }
    }
}

impl<'a> IntoIterator for &'a Object {
    type Item = (&'a Value, &'a Value);
    type IntoIter = Iter<'a>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter_sorted()
    }
}

impl<'a> IntoIterator for &'a mut Object {
    type Item = (&'a Value, &'a mut Value);
    type IntoIter = IterMut<'a>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}
