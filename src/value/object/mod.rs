// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! See [`Object`].

mod iter;
mod serde;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use core::ops::Bound;

use smallvec::SmallVec;

use crate::value::Value;

pub use iter::{IntoIter, Iter, IterMut};

/// Inline capacity for the small-object representation. SARIF workload
/// averages 1.65 fields per object, so 4 covers the vast majority of objects
/// without spilling. Above this, we promote to a `BTreeMap`.
pub(super) const INLINE_CAP: usize = 4;

/// Opaque, ordered key-value map keyed by [`Value`].
///
/// Backed by a three-variant representation: mutable small objects build in a
/// boxed inline `SmallVec` (kept sorted by `Value::Ord`), mutable larger ones
/// promote to `BTreeMap`, and read-mostly objects freeze to an exact-size boxed
/// slice. The representation is private so it can change without touching call
/// sites.
///
/// # Iteration
///
/// - [`Object::iter`] — implementation-defined order; non-resumable.
/// - [`Object::iter_sorted`] — sorted by `Value::Ord`; non-resumable.
/// - [`Object::cursor`] / [`Object::next`] — implementation-defined order,
///   resumable; cheapest per-step cost. Used by interpreter/RVM when iteration
///   must yield mid-flight.
#[derive(Default, Clone)]
pub struct Object {
    repr: Repr,
}

#[derive(Clone)]
pub(super) enum Repr {
    /// Sorted-by-key, deduplicated entries. Kept sorted so iteration and
    /// `iter_sorted` are the same and binary search is O(log n).
    Inline(Box<SmallVec<[(Value, Value); INLINE_CAP]>>),
    /// Immutable, sorted, deduplicated entries with no spare capacity.
    Frozen(Box<[(Value, Value)]>),
    BTree(BTreeMap<Value, Value>),
}

impl Default for Repr {
    #[inline]
    fn default() -> Self {
        Repr::Inline(Box::new(SmallVec::new()))
    }
}

impl Object {
    /// Create an empty `Object`.
    #[inline]
    pub fn new() -> Self {
        Self {
            repr: Repr::Inline(Box::new(SmallVec::new())),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        match &self.repr {
            Repr::Inline(v) => v.len(),
            Repr::Frozen(v) => v.len(),
            Repr::BTree(m) => m.len(),
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, key: &Value) -> Option<&Value> {
        match &self.repr {
            Repr::Inline(v) => match v.binary_search_by(|(k, _)| k.cmp(key)) {
                Ok(i) => Some(&v[i].1),
                Err(_) => None,
            },
            Repr::Frozen(v) => match v.binary_search_by(|(k, _)| k.cmp(key)) {
                Ok(i) => Some(&v[i].1),
                Err(_) => None,
            },
            Repr::BTree(m) => m.get(key),
        }
    }

    #[inline]
    pub fn contains_key(&self, key: &Value) -> bool {
        self.get(key).is_some()
    }

    pub fn get_mut(&mut self, key: &Value) -> Option<&mut Value> {
        let thaw = matches!(
            &self.repr,
            Repr::Frozen(v) if v.binary_search_by(|(k, _)| k.cmp(key)).is_ok()
        );
        if thaw {
            self.thaw();
        }
        match &mut self.repr {
            Repr::Inline(v) => match v.binary_search_by(|(k, _)| k.cmp(key)) {
                Ok(i) => Some(&mut v[i].1),
                Err(_) => None,
            },
            Repr::Frozen(_) => None,
            Repr::BTree(m) => m.get_mut(key),
        }
    }

    /// Iteration in implementation-defined order. Non-resumable.
    ///
    /// For both current backends this happens to be sorted by `Value::Ord`,
    /// but callers MUST NOT depend on that. Use [`Object::iter_sorted`] when
    /// deterministic order is required, or [`Object::cursor`] when iteration
    /// must yield and resume.
    pub fn iter(&self) -> impl Iterator<Item = (&Value, &Value)> + '_ {
        self.iter_sorted()
    }

    /// Iteration in sorted key order (by `Value::Ord`). Non-resumable.
    ///
    /// Use this for serialization, snapshots, hashing, `Debug`, the
    /// `object.keys` builtin, etc.
    #[inline]
    pub fn iter_sorted(&self) -> Iter<'_> {
        Iter {
            inner: match &self.repr {
                Repr::Inline(v) => iter::IterInner::Inline(v.iter()),
                Repr::Frozen(v) => iter::IterInner::Frozen(v.iter()),
                Repr::BTree(m) => iter::IterInner::BTree(m.iter()),
            },
        }
    }

    pub fn keys(&self) -> impl Iterator<Item = &Value> + '_ {
        self.iter_sorted().map(|(k, _)| k)
    }

    pub fn keys_sorted(&self) -> impl Iterator<Item = &Value> + '_ {
        self.iter_sorted().map(|(k, _)| k)
    }

    pub fn values(&self) -> impl Iterator<Item = &Value> + '_ {
        self.iter_sorted().map(|(_, v)| v)
    }

    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_> {
        self.thaw();
        IterMut {
            inner: match &mut self.repr {
                Repr::Inline(v) => iter::IterMutInner::Inline(v.iter_mut()),
                Repr::Frozen(v) => iter::IterMutInner::Frozen(v.iter_mut()),
                Repr::BTree(m) => iter::IterMutInner::BTree(m.iter_mut()),
            },
        }
    }

    /// Insert a key-value pair. Returns the previous value if any.
    pub fn insert(&mut self, key: Value, value: Value) -> Option<Value> {
        match core::mem::take(&mut self.repr) {
            Repr::Inline(mut v) => {
                let prev = match v.binary_search_by(|(k, _)| k.cmp(&key)) {
                    Ok(i) => Some(core::mem::replace(&mut v[i].1, value)),
                    Err(i) => {
                        if v.len() < INLINE_CAP {
                            v.insert(i, (key, value));
                            None
                        } else {
                            let mut m = BTreeMap::new();
                            for (k, val) in v.drain(..) {
                                m.insert(k, val);
                            }
                            let prev = m.insert(key, value);
                            self.repr = Repr::BTree(m);
                            return prev;
                        }
                    }
                };
                self.repr = Repr::Inline(v);
                prev
            }
            Repr::Frozen(v) => {
                self.repr = Self::thawed_repr(v);
                self.insert(key, value)
            }
            Repr::BTree(mut m) => {
                let prev = m.insert(key, value);
                self.repr = Repr::BTree(m);
                prev
            }
        }
    }

    pub fn remove(&mut self, key: &Value) -> Option<Value> {
        match core::mem::take(&mut self.repr) {
            Repr::Inline(mut v) => {
                let prev = match v.binary_search_by(|(k, _)| k.cmp(key)) {
                    Ok(i) => Some(v.remove(i).1),
                    Err(_) => None,
                };
                self.repr = Repr::Inline(v);
                prev
            }
            Repr::Frozen(v) => {
                self.repr = Self::thawed_repr(v);
                self.remove(key)
            }
            Repr::BTree(mut m) => {
                let prev = m.remove(key);
                self.repr = Repr::BTree(m);
                prev
            }
        }
    }

    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&Value, &mut Value) -> bool,
    {
        match core::mem::take(&mut self.repr) {
            Repr::Inline(mut v) => {
                v.retain(|(k, val)| f(k, val));
                self.repr = Repr::Inline(v);
            }
            Repr::Frozen(v) => {
                self.repr = Self::thawed_repr(v);
                self.retain(f);
            }
            Repr::BTree(mut m) => {
                m.retain(|k, v| f(k, v));
                self.repr = Repr::BTree(m);
            }
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.repr = Repr::Inline(Box::new(SmallVec::new()));
    }

    pub fn append(&mut self, other: &mut Object) {
        let drained: Vec<(Value, Value)> = match core::mem::take(&mut other.repr) {
            Repr::Inline(v) => (*v).into_iter().collect(),
            Repr::Frozen(v) => Vec::from(v),
            Repr::BTree(m) => m.into_iter().collect(),
        };
        other.repr = Repr::Inline(Box::new(SmallVec::new()));
        for (k, v) in drained {
            self.insert(k, v);
        }
    }

    /// Gets a mutable reference to the value associated with `key`, inserting
    /// the result of `default()` if absent.
    #[expect(
        clippy::unreachable,
        reason = "Frozen is thawed before matching but Rust still requires an exhaustive arm"
    )]
    pub fn get_or_insert_with<F: FnOnce() -> Value>(
        &mut self,
        key: Value,
        default: F,
    ) -> &mut Value {
        self.thaw();
        let need_promote = matches!(
            &self.repr,
            Repr::Inline(v) if v.binary_search_by(|(k, _)| k.cmp(&key)).is_err() && v.len() >= INLINE_CAP
        );
        if need_promote {
            if let Repr::Inline(v) = core::mem::take(&mut self.repr) {
                let mut m = BTreeMap::new();
                for (k, val) in *v {
                    m.insert(k, val);
                }
                self.repr = Repr::BTree(m);
            }
        }
        match &mut self.repr {
            Repr::Inline(v) => match v.binary_search_by(|(k, _)| k.cmp(&key)) {
                Ok(i) => &mut v[i].1,
                Err(i) => {
                    v.insert(i, (key, default()));
                    &mut v[i].1
                }
            },
            Repr::BTree(m) => m.entry(key).or_insert_with(default),
            Repr::Frozen(_) => unreachable!("frozen object was thawed"),
        }
    }

    /// Convert to the immutable boxed-slice representation.
    pub fn freeze(mut self) -> Self {
        self.freeze_in_place();
        self
    }

    /// Wrap into a `Value::Object`.
    #[inline]
    pub fn into_value(self) -> Value {
        Value::Object(crate::Rc::new(self.freeze()))
    }

    #[doc(hidden)]
    pub const fn storage_variant_for_memory_diagnostics(&self) -> &'static str {
        match &self.repr {
            Repr::Inline(_) => "Inline",
            Repr::Frozen(_) => "Frozen",
            Repr::BTree(_) => "BTree",
        }
    }

    fn freeze_in_place(&mut self) {
        match core::mem::take(&mut self.repr) {
            Repr::Inline(v) => {
                self.repr = Repr::Frozen((*v).into_vec().into_boxed_slice());
            }
            Repr::Frozen(v) => {
                self.repr = Repr::Frozen(v);
            }
            Repr::BTree(m) => {
                self.repr = Repr::Frozen(m.into_iter().collect::<Vec<_>>().into_boxed_slice());
            }
        }
    }

    fn thawed_repr(v: Box<[(Value, Value)]>) -> Repr {
        if v.len() <= INLINE_CAP {
            Repr::Inline(Box::new(Vec::from(v).into_iter().collect()))
        } else {
            Repr::BTree(Vec::from(v).into_iter().collect())
        }
    }

    fn thaw(&mut self) {
        let repr = core::mem::take(&mut self.repr);
        self.repr = match repr {
            Repr::Frozen(v) => Self::thawed_repr(v),
            other => other,
        };
    }

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
            (Repr::Frozen(v), ObjectCursorInner::Start) => {
                if let Some((k, val)) = v.first() {
                    cursor.inner = ObjectCursorInner::Index(1);
                    Some((k, val))
                } else {
                    None
                }
            }
            (Repr::Frozen(v), ObjectCursorInner::Index(i)) => {
                if let Some((k, val)) = v.get(*i) {
                    *i = i.saturating_add(1);
                    Some((k, val))
                } else {
                    None
                }
            }
            (Repr::Frozen(v), ObjectCursorInner::Key(prev)) => {
                let i = match v.binary_search_by(|(k, _)| k.cmp(prev)) {
                    Ok(i) => i.saturating_add(1),
                    Err(i) => i,
                };
                if let Some((k, val)) = v.get(i) {
                    cursor.inner = ObjectCursorInner::Index(i.saturating_add(1));
                    Some((k, val))
                } else {
                    None
                }
            }
            (Repr::Inline(v), ObjectCursorInner::Index(i)) => {
                if let Some((k, val)) = v.get(*i) {
                    *i = i.saturating_add(1);
                    Some((k, val))
                } else {
                    None
                }
            }
            (Repr::BTree(m), ObjectCursorInner::Index(i)) => {
                if let Some((k, val)) = m.iter().nth(*i) {
                    *i = i.saturating_add(1);
                    Some((k, val))
                } else {
                    None
                }
            }
            (Repr::Inline(v), ObjectCursorInner::Start) => {
                if let Some((k, val)) = v.first() {
                    cursor.inner = ObjectCursorInner::Key(k.clone());
                    Some((k, val))
                } else {
                    None
                }
            }
            (Repr::Inline(v), ObjectCursorInner::Key(prev)) => {
                let i = match v.binary_search_by(|(k, _)| k.cmp(prev)) {
                    Ok(i) => i.saturating_add(1),
                    Err(i) => i,
                };
                if let Some((k, val)) = v.get(i) {
                    cursor.inner = ObjectCursorInner::Key(k.clone());
                    Some((k, val))
                } else {
                    None
                }
            }
            (Repr::BTree(m), ObjectCursorInner::Start) => {
                let (k, val) = m.iter().next()?;
                cursor.inner = ObjectCursorInner::Key(k.clone());
                Some((k, val))
            }
            (Repr::BTree(m), ObjectCursorInner::Key(prev)) => {
                let (k, val) = m
                    .range((Bound::Excluded(prev.clone()), Bound::Unbounded))
                    .next()?;
                cursor.inner = ObjectCursorInner::Key(k.clone());
                Some((k, val))
            }
        }
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
    Key(Value),
    Index(usize),
}

// ---- Hand-written PartialEq/Eq/Ord -------------------------------------
//
// Defined in terms of `iter_sorted()` so equality and ordering are
// consistent with the canonical (sorted) view of the entries and are
// therefore independent of the storage variant. A derived PartialEq on
// `Repr` would incorrectly distinguish `Inline` from `BTree` even when
// they hold identical entries.

impl PartialEq for Object {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        self.iter_sorted().eq(other.iter_sorted())
    }
}

impl Eq for Object {}

impl Ord for Object {
    fn cmp(&self, other: &Self) -> Ordering {
        self.iter_sorted().cmp(other.iter_sorted())
    }
}

impl PartialOrd for Object {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter_sorted()).finish()
    }
}

impl Extend<(Value, Value)> for Object {
    fn extend<I: IntoIterator<Item = (Value, Value)>>(&mut self, iter: I) {
        for (k, v) in iter {
            self.insert(k, v);
        }
    }
}

impl FromIterator<(Value, Value)> for Object {
    fn from_iter<I: IntoIterator<Item = (Value, Value)>>(iter: I) -> Self {
        let mut o = Object::new();
        for (k, v) in iter {
            o.insert(k, v);
        }
        o
    }
}

impl From<BTreeMap<Value, Value>> for Object {
    fn from(map: BTreeMap<Value, Value>) -> Self {
        if map.len() <= INLINE_CAP {
            let mut v: SmallVec<[(Value, Value); INLINE_CAP]> = SmallVec::new();
            // BTreeMap iterates sorted, so the resulting inline is already sorted.
            for (k, val) in map {
                v.push((k, val));
            }
            Self {
                repr: Repr::Inline(Box::new(v)),
            }
        } else {
            Self {
                repr: Repr::BTree(map),
            }
        }
    }
}

impl From<Object> for Value {
    #[inline]
    fn from(o: Object) -> Self {
        o.into_value()
    }
}
