// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(
    clippy::indexing_slicing,
    clippy::shadow_unrelated,
    clippy::option_if_let_else,
    clippy::semicolon_if_nothing_returned,
    clippy::pattern_type_mismatch,
    clippy::unused_trait_names,
    clippy::as_conversions
)] // value helpers index paths directly for performance

use crate::number::Number;
use num_bigint::BigInt;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
#[cfg(not(feature = "std"))]
use core::cell::OnceCell as ForeignOnce;
use core::cmp::Ordering;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::ops;
use core::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
#[cfg(feature = "std")]
use std::sync::OnceLock as ForeignOnce;

use core::convert::AsRef;
use core::str::FromStr;

use anyhow::{anyhow, bail, Result};
use arcstr::ArcStr;
/// Re-export so out-of-crate FFI can construct interned strings/keys for the
/// foreign value backend without depending on the `arcstr` crate directly.
pub use arcstr::ArcStr as ForeignArcStr;
use serde::de::{self, Deserializer, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};

use crate::*;

/// The concrete set type backing [`Value::Set`].
pub type ValueSet = hashbrown::HashSet<Value>;

/// Entry type for [`ValueMap`].
pub type ValueMapEntry<'a> =
    hashbrown::hash_map::Entry<'a, Value, Value, hashbrown::DefaultHashBuilder>;

/// Sentinel value indicating the cached hash needs recomputation.
const OBJECT_HASH_DIRTY: u64 = u64::MAX;

// ─── Schema ──────────────────────────────────────────────────────────────────

/// A shared key layout for objects with identical string keys.
///
/// Keys are stored sorted so that:
/// - Serialization in sorted order is free (just iterate `sorted_keys`).
/// - Same-schema comparison can iterate values in parallel.
/// - Key storage is shared across all objects with the same key set.
#[derive(Debug, Clone)]
pub struct Schema {
    /// `Value::String(k)` entries in sorted key order.
    sorted_keys: Rc<[Value]>,
    /// key name → index into sorted_keys/values.
    lookup: hashbrown::HashMap<ArcStr, u32>,
}

impl Schema {
    /// Build a schema from a pre-sorted list of key strings.
    fn from_sorted(sorted: &[ArcStr]) -> Rc<Self> {
        let sorted_keys: Rc<[Value]> = sorted
            .iter()
            .map(|k| Value::String(k.clone()))
            .collect::<Vec<_>>()
            .into();
        let lookup: hashbrown::HashMap<ArcStr, u32> = sorted
            .iter()
            .enumerate()
            .map(|(i, k)| (k.clone(), i as u32))
            .collect();
        Rc::new(Schema {
            sorted_keys,
            lookup,
        })
    }
}

// ─── Schema interner ─────────────────────────────────────────────────────────

#[cfg(feature = "std")]
std::thread_local! {
    static SCHEMA_CACHE: core::cell::RefCell<hashbrown::HashMap<Vec<ArcStr>, Rc<Schema>>> =
        core::cell::RefCell::new(hashbrown::HashMap::new());
}

/// Intern a schema for the given key set.  Keys may be in any order.
/// Returns a shared schema, building one if necessary.
#[cfg(feature = "std")]
pub(crate) fn intern_schema(keys: &[ArcStr]) -> Rc<Schema> {
    let mut sorted: Vec<ArcStr> = keys.to_vec();
    sorted.sort();
    SCHEMA_CACHE.with(|cache| {
        let mut map = cache.borrow_mut();
        if let Some(existing) = map.get(&sorted) {
            return existing.clone();
        }
        let schema = Schema::from_sorted(&sorted);
        map.insert(sorted, schema.clone());
        schema
    })
}

/// Build a schema without interning (no_std fallback).
#[cfg(not(feature = "std"))]
pub(crate) fn intern_schema(keys: &[ArcStr]) -> Rc<Schema> {
    let mut sorted: Vec<ArcStr> = keys.to_vec();
    sorted.sort();
    Schema::from_sorted(&sorted)
}

/// Clear the thread-local schema cache.
#[cfg(feature = "std")]
#[allow(dead_code)]
pub fn clear_schema_cache() {
    SCHEMA_CACHE.with(|cache| cache.borrow_mut().clear());
}

/// No-op when there is no thread-local cache.
#[cfg(not(feature = "std"))]
#[allow(dead_code)]
pub fn clear_schema_cache() {}

// ─── Compact object ─────────────────────────────────────────────────────────

/// A compact object: shared schema + flat value array.
#[derive(Debug, Clone)]
struct CompactObject {
    schema: Rc<Schema>,
    values: Box<[Value]>,
    cached_hash: u64,
}

// ─── Map object (fallback) ──────────────────────────────────────────────────

/// Classic HashMap representation for objects with mixed/non-string keys or
/// that have been mutated from compact form.
#[derive(Debug)]
struct MapObject {
    inner: hashbrown::HashMap<Value, Value>,
    cached_hash: AtomicU64,
}

impl Clone for MapObject {
    fn clone(&self) -> Self {
        MapObject {
            inner: self.inner.clone(),
            cached_hash: AtomicU64::new(self.cached_hash.load(AtomicOrdering::Relaxed)),
        }
    }
}

impl MapObject {
    fn new() -> Self {
        MapObject {
            inner: hashbrown::HashMap::new(),
            cached_hash: AtomicU64::new(OBJECT_HASH_DIRTY),
        }
    }

    /// Lazily compute and return the cached hash.
    #[inline]
    fn ensure_hash(&self) -> u64 {
        let h = self.cached_hash.load(AtomicOrdering::Relaxed);
        if h != OBJECT_HASH_DIRTY {
            return h;
        }
        let computed = compute_map_hash(self.inner.iter());
        self.cached_hash.store(computed, AtomicOrdering::Relaxed);
        computed
    }

    #[inline]
    fn invalidate_hash(&mut self) {
        *self.cached_hash.get_mut() = OBJECT_HASH_DIRTY;
    }
}

// ─── Foreign object backend (spike) ──────────────────────────────────────────

/// A read-through backend that materializes object fields on demand.
///
/// This is the object half of the "foreign value backend" spike: a native Rust
/// data structure (e.g. a packed subscription record) is exposed to the RVM as
/// a Rego object without eagerly copying every field into an owned [`Value`].
///
/// Implementors are only asked to *produce* a [`Value`] for a given key. The
/// hot path uses the value-returning accessor [`ValueMap::get_owned`] which
/// calls straight through to [`ObjectBackend::get_value`] and retains nothing;
/// the legacy borrow-returning accessors only work on cold/non-scan fallbacks.
pub trait ObjectBackend: Send + Sync {
    /// Materialize the value for `key`, or `None` if the key is absent.
    fn get_value(&self, key: &str) -> Option<Value>;
    /// The set of keys this object exposes (stable for the object's lifetime).
    fn keys(&self) -> &[ArcStr];
    /// Number of keys.
    fn len(&self) -> usize;
}

/// A foreign-backed object (transient / no-cache spike).
///
/// The hot path (`get_owned`) materializes a fresh [`Value`] on every field
/// access and retains nothing — the returned value is owned by the caller and
/// dropped at last reference. There is deliberately no per-key materialization
/// cache: a full scan keeps only one element materialized at a time, pinning
/// resident memory at the packed-native floor.
///
/// The only retained state is `pairs`, a lazily-built owned snapshot used by the
/// borrow-returning cold fallbacks (iteration, hashing, `get`) that cannot be
/// expressed with a value-returning accessor. `pairs` is NOT populated by the
/// scan hot path, so those retention costs never appear during a scan.
pub struct ForeignObject {
    backend: Rc<dyn ObjectBackend>,
    /// Owned key/value pairs, materialized on first use of a borrow-returning
    /// cold fallback (iteration/hashing/`get`). Never touched on the hot path.
    pairs: ForeignOnce<Vec<(Value, Value)>>,
}

impl ForeignObject {
    fn new(backend: Rc<dyn ObjectBackend>) -> Self {
        ForeignObject {
            backend,
            pairs: ForeignOnce::new(),
        }
    }

    /// Hot path: materialize a fresh owned value for `key` and retain nothing.
    #[inline]
    fn get_owned(&self, key: &str) -> Option<Value> {
        self.backend.get_value(key)
    }

    /// Borrow-returning cold fallback. There is no per-key cache, so we serve
    /// the borrow out of the fully-materialized `pairs` snapshot. This forces
    /// full materialization and is documented as a NON-scan path only (the scan
    /// hot path uses `get_owned`). Retaining `pairs` here is the price of the
    /// legacy `&Value` accessor; it must not be exercised during a scan.
    fn get(&self, key: &str) -> Option<&Value> {
        debug_assert!(
            false,
            "foreign object borrow `get` hit on hot path; use get_owned"
        );
        self.pairs()
            .iter()
            .find(|(k, _)| matches!(k, Value::String(s) if s.as_str() == key))
            .map(|(_, v)| v)
    }

    /// Force full materialization into owned key/value pairs (cold fallback used
    /// by object iteration, hashing, and mutation).
    fn pairs(&self) -> &[(Value, Value)] {
        self.pairs.get_or_init(|| {
            self.backend
                .keys()
                .iter()
                .filter_map(|k| {
                    self.backend
                        .get_value(k.as_str())
                        .map(|v| (Value::String(k.clone()), v))
                })
                .collect()
        })
    }
}

impl Clone for ForeignObject {
    fn clone(&self) -> Self {
        // Cloning shares the backend and starts fresh; there is no cache to copy.
        ForeignObject::new(self.backend.clone())
    }
}

impl fmt::Debug for ForeignObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForeignObject")
            .field("len", &self.backend.len())
            .finish()
    }
}

// ─── ObjectRepr ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum ObjectRepr {
    Compact(CompactObject),
    Map(MapObject),
    /// Read-through foreign backend (materialization-cache spike). Boxed so the
    /// large foreign payload does not bloat the common Compact/Map objects.
    Foreign(Box<ForeignObject>),
}

// ─── ValueMap ────────────────────────────────────────────────────────────────

/// An object map that can be either:
/// - **Compact**: schema-shared, values stored in a flat array indexed by
///   schema position.  Schema keys are sorted so iteration is O(n) in order.
/// - **Map**: classic `HashMap<Value, Value>` for objects with non-string keys
///   or that have been mutated.
pub struct ValueMap {
    repr: ObjectRepr,
}

/// Compute order-independent hash from an iterator of `(&Value, &Value)`.
fn compute_map_hash<'a>(entries: impl Iterator<Item = (&'a Value, &'a Value)>) -> u64 {
    let mut combined: u64 = 0;
    for (k, v) in entries {
        let mut h = FnvHasher::default();
        k.hash(&mut h);
        v.hash(&mut h);
        combined = combined.wrapping_add(h.finish());
    }
    combined
}

impl ValueMap {
    #[inline]
    pub fn new() -> Self {
        ValueMap {
            repr: ObjectRepr::Map(MapObject::new()),
        }
    }

    /// Build a compact object from a schema and values (values must be in
    /// schema's sorted-key order).
    pub(crate) fn from_schema_values(schema: Rc<Schema>, values: Box<[Value]>) -> Self {
        debug_assert_eq!(schema.sorted_keys.len(), values.len());
        let cached_hash = compute_map_hash(schema.sorted_keys.iter().zip(values.iter()));
        ValueMap {
            repr: ObjectRepr::Compact(CompactObject {
                schema,
                values,
                cached_hash,
            }),
        }
    }

    /// Build a foreign (read-through) object from an [`ObjectBackend`].
    pub fn from_object_backend(backend: Rc<dyn ObjectBackend>) -> Self {
        ValueMap {
            repr: ObjectRepr::Foreign(Box::new(ForeignObject::new(backend))),
        }
    }

    /// Returns the schema if this is a compact object.
    #[inline]
    pub fn schema(&self) -> Option<&Rc<Schema>> {
        match &self.repr {
            ObjectRepr::Compact(c) => Some(&c.schema),
            ObjectRepr::Map(_) | ObjectRepr::Foreign(_) => None,
        }
    }

    // --- Read-only operations ---

    #[inline]
    pub fn get(&self, key: &Value) -> Option<&Value> {
        match &self.repr {
            ObjectRepr::Compact(c) => match key {
                Value::String(s) => c
                    .schema
                    .lookup
                    .get(s.as_str())
                    .map(|&idx| &c.values[idx as usize]),
                _ => None, // Compact objects only have string keys
            },
            ObjectRepr::Map(m) => m.inner.get(key),
            ObjectRepr::Foreign(f) => match key {
                Value::String(s) => f.get(s.as_str()),
                _ => None, // Foreign objects only have string keys
            },
        }
    }

    /// Value-returning (non-borrowing) field accessor — the transient hot path.
    ///
    /// For a `Foreign` object this calls straight through to the backend and
    /// retains NOTHING (no cache insert): the returned owned [`Value`] is the
    /// caller's, dropped at last reference. For `Compact`/`Map` it clones the
    /// stored value. Migrating the interpreter's field-access hot path to this
    /// accessor is what lets a foreign scan pin memory at the native floor.
    #[inline]
    pub fn get_owned(&self, key: &Value) -> Option<Value> {
        match &self.repr {
            ObjectRepr::Compact(c) => match key {
                Value::String(s) => c
                    .schema
                    .lookup
                    .get(s.as_str())
                    .map(|&idx| c.values[idx as usize].clone()),
                _ => None,
            },
            ObjectRepr::Map(m) => m.inner.get(key).cloned(),
            ObjectRepr::Foreign(f) => match key {
                Value::String(s) => f.get_owned(s.as_str()),
                _ => None,
            },
        }
    }

    #[inline]
    pub fn contains_key(&self, key: &Value) -> bool {
        match &self.repr {
            ObjectRepr::Compact(c) => match key {
                Value::String(s) => c.schema.lookup.contains_key(s.as_str()),
                _ => false,
            },
            ObjectRepr::Map(m) => m.inner.contains_key(key),
            ObjectRepr::Foreign(f) => match key {
                Value::String(s) => f.backend.keys().iter().any(|k| k.as_str() == s.as_str()),
                _ => false,
            },
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        match &self.repr {
            ObjectRepr::Compact(c) => c.values.len(),
            ObjectRepr::Map(m) => m.inner.len(),
            ObjectRepr::Foreign(f) => f.backend.len(),
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn iter(&self) -> ValueMapIter<'_> {
        match &self.repr {
            ObjectRepr::Compact(c) => ValueMapIter::Compact {
                idx: 0,
                keys: &c.schema.sorted_keys,
                values: &c.values,
            },
            ObjectRepr::Map(m) => ValueMapIter::Map(m.inner.iter()),
            // Cold fallback: force full materialization then iterate owned pairs.
            ObjectRepr::Foreign(f) => ValueMapIter::Pairs(f.pairs().iter()),
        }
    }

    pub fn keys(&self) -> ValueMapKeys<'_> {
        ValueMapKeys(self.iter())
    }

    pub fn values(&self) -> ValueMapValues<'_> {
        ValueMapValues(self.iter())
    }

    /// Iterate in key-sorted order.
    ///
    /// For compact objects this is effectively free (keys are pre-sorted in the
    /// schema).  For map objects, entries are collected and sorted.
    pub fn iter_sorted(&self) -> Vec<(&Value, &Value)> {
        match &self.repr {
            ObjectRepr::Compact(c) => c.schema.sorted_keys.iter().zip(c.values.iter()).collect(),
            ObjectRepr::Map(_) | ObjectRepr::Foreign(_) => {
                let mut entries: Vec<(&Value, &Value)> = self.iter().collect();
                entries.sort_by(|(a, _), (b, _)| a.cmp(b));
                entries
            }
        }
    }

    /// Return the cached order-independent hash, computing it lazily if needed.
    #[inline]
    fn cached_hash(&self) -> u64 {
        match &self.repr {
            ObjectRepr::Compact(c) => c.cached_hash,
            ObjectRepr::Map(m) => m.ensure_hash(),
            ObjectRepr::Foreign(f) => compute_map_hash(f.pairs().iter().map(|(k, v)| (k, v))),
        }
    }

    // --- Mutation operations (ensure map mode) ---

    /// Convert compact/foreign → map for mutation.
    fn ensure_map(&mut self) {
        match &self.repr {
            ObjectRepr::Compact(c) => {
                let mut inner = hashbrown::HashMap::with_capacity(c.values.len());
                for (k, v) in c.schema.sorted_keys.iter().zip(c.values.iter()) {
                    inner.insert(k.clone(), v.clone());
                }
                self.repr = ObjectRepr::Map(MapObject {
                    inner,
                    // Preserve the eagerly-computed hash.
                    cached_hash: AtomicU64::new(c.cached_hash),
                });
            }
            ObjectRepr::Foreign(f) => {
                let inner: hashbrown::HashMap<Value, Value> = f.pairs().iter().cloned().collect();
                self.repr = ObjectRepr::Map(MapObject {
                    inner,
                    cached_hash: AtomicU64::new(OBJECT_HASH_DIRTY),
                });
            }
            ObjectRepr::Map(_) => {}
        }
    }

    #[inline]
    pub fn insert(&mut self, key: Value, value: Value) -> Option<Value> {
        self.ensure_map();
        if let ObjectRepr::Map(m) = &mut self.repr {
            m.invalidate_hash();
            m.inner.insert(key, value)
        } else {
            unreachable!()
        }
    }

    #[inline]
    pub fn get_mut(&mut self, key: &Value) -> Option<&mut Value> {
        self.ensure_map();
        if let ObjectRepr::Map(m) = &mut self.repr {
            m.invalidate_hash();
            m.inner.get_mut(key)
        } else {
            unreachable!()
        }
    }

    #[inline]
    pub fn iter_mut(&mut self) -> hashbrown::hash_map::IterMut<'_, Value, Value> {
        self.ensure_map();
        if let ObjectRepr::Map(m) = &mut self.repr {
            m.invalidate_hash();
            m.inner.iter_mut()
        } else {
            unreachable!()
        }
    }

    #[inline]
    pub fn retain<F: FnMut(&Value, &mut Value) -> bool>(&mut self, f: F) {
        self.ensure_map();
        if let ObjectRepr::Map(m) = &mut self.repr {
            m.invalidate_hash();
            m.inner.retain(f);
        }
    }

    #[inline]
    pub fn entry(&mut self, key: Value) -> ValueMapEntry<'_> {
        self.ensure_map();
        if let ObjectRepr::Map(m) = &mut self.repr {
            m.invalidate_hash();
            m.inner.entry(key)
        } else {
            unreachable!()
        }
    }
}

impl Clone for ValueMap {
    fn clone(&self) -> Self {
        ValueMap {
            repr: self.repr.clone(),
        }
    }
}

impl fmt::Debug for ValueMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl Default for ValueMap {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for ValueMap {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        // Same-schema fast path: if both compact with the same schema,
        // just compare value arrays directly — no key lookup needed.
        if let (ObjectRepr::Compact(a), ObjectRepr::Compact(b)) = (&self.repr, &other.repr) {
            if Rc::ptr_eq(&a.schema, &b.schema) {
                return a.values == b.values;
            }
        }
        // Fallback: point-lookup each entry.
        self.iter().all(|(k, v)| other.get(k) == Some(v))
    }
}

impl Eq for ValueMap {}

impl PartialOrd for ValueMap {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ValueMap {
    fn cmp(&self, other: &Self) -> Ordering {
        let a_sorted = self.iter_sorted();
        let b_sorted = other.iter_sorted();
        a_sorted.cmp(&b_sorted)
    }
}

impl Hash for ValueMap {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.len().hash(state);
        self.cached_hash().hash(state);
    }
}

/// Consuming iterator for `ValueMap`. Always yields `(Value, Value)`.
#[derive(Debug)]
pub enum ValueMapIntoIter {
    Compact {
        idx: usize,
        keys: Rc<[Value]>,
        values: Vec<Value>,
    },
    Map(hashbrown::hash_map::IntoIter<Value, Value>),
}

impl Iterator for ValueMapIntoIter {
    type Item = (Value, Value);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ValueMapIntoIter::Compact { idx, keys, values } => {
                if *idx < values.len() {
                    let k = keys[*idx].clone();
                    let v = core::mem::replace(&mut values[*idx], Value::Null);
                    *idx += 1;
                    Some((k, v))
                } else {
                    None
                }
            }
            ValueMapIntoIter::Map(it) => it.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            ValueMapIntoIter::Compact { idx, values, .. } => {
                let rem = values.len() - *idx;
                (rem, Some(rem))
            }
            ValueMapIntoIter::Map(it) => it.size_hint(),
        }
    }
}

impl IntoIterator for ValueMap {
    type Item = (Value, Value);
    type IntoIter = ValueMapIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        match self.repr {
            ObjectRepr::Compact(c) => ValueMapIntoIter::Compact {
                idx: 0,
                keys: c.schema.sorted_keys.clone(),
                values: c.values.into_vec(),
            },
            ObjectRepr::Map(m) => ValueMapIntoIter::Map(m.inner.into_iter()),
            ObjectRepr::Foreign(f) => {
                // Force materialization then iterate owned pairs.
                let pairs: Vec<(Value, Value)> = f.pairs().to_vec();
                ValueMapIntoIter::Map(
                    pairs
                        .into_iter()
                        .collect::<hashbrown::HashMap<_, _>>()
                        .into_iter(),
                )
            }
        }
    }
}

/// Borrowing iterator for `ValueMap`. Yields `(&Value, &Value)`.
#[derive(Debug)]
pub enum ValueMapIter<'a> {
    Compact {
        idx: usize,
        keys: &'a [Value],
        values: &'a [Value],
    },
    Map(hashbrown::hash_map::Iter<'a, Value, Value>),
    /// Owned key/value pairs (foreign objects, materialized on demand).
    Pairs(core::slice::Iter<'a, (Value, Value)>),
}

impl<'a> Iterator for ValueMapIter<'a> {
    type Item = (&'a Value, &'a Value);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ValueMapIter::Compact { idx, keys, values } => {
                if *idx < values.len() {
                    let k = &keys[*idx];
                    let v = &values[*idx];
                    *idx += 1;
                    Some((k, v))
                } else {
                    None
                }
            }
            ValueMapIter::Map(it) => it.next(),
            ValueMapIter::Pairs(it) => it.next().map(|(k, v)| (k, v)),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            ValueMapIter::Compact { idx, values, .. } => {
                let rem = values.len() - *idx;
                (rem, Some(rem))
            }
            ValueMapIter::Map(it) => it.size_hint(),
            ValueMapIter::Pairs(it) => it.size_hint(),
        }
    }
}

impl<'a> IntoIterator for &'a ValueMap {
    type Item = (&'a Value, &'a Value);
    type IntoIter = ValueMapIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Keys iterator for `ValueMap`.
#[derive(Debug)]
pub struct ValueMapKeys<'a>(ValueMapIter<'a>);

impl<'a> Iterator for ValueMapKeys<'a> {
    type Item = &'a Value;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(k, _)| k)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

/// Values iterator for `ValueMap`.
#[derive(Debug)]
pub struct ValueMapValues<'a>(ValueMapIter<'a>);

impl<'a> Iterator for ValueMapValues<'a> {
    type Item = &'a Value;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|(_, v)| v)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl FromIterator<(Value, Value)> for ValueMap {
    fn from_iter<T: IntoIterator<Item = (Value, Value)>>(iter: T) -> Self {
        ValueMap {
            repr: ObjectRepr::Map(MapObject {
                inner: iter.into_iter().collect(),
                cached_hash: AtomicU64::new(OBJECT_HASH_DIRTY),
            }),
        }
    }
}

// ─── Array (opaque, possibly foreign-backed) ─────────────────────────────────

/// A read-through backend that materializes array elements on demand.
///
/// This is the array half of the foreign value backend spike. A packed native
/// structure (e.g. `NativeSubArray`) implements this trait to expose its
/// elements to the RVM without eagerly building owned [`Value`]s.
pub trait ArrayBackend: Send + Sync {
    /// Materialize the element at `index`, or `None` if out of bounds.
    fn get_value(&self, index: usize) -> Option<Value>;
    /// Number of elements.
    fn len(&self) -> usize;
}

/// A foreign-backed array (transient / no-cache spike).
///
/// `element(idx)` materializes a fresh owned [`Value`] on every call and retains
/// nothing — there is no per-element cache, so a scan that visits each element
/// once keeps only the current element live. The returned value is owned by the
/// caller (the interpreter loop drops it before the next iteration).
pub struct ForeignArray {
    backend: Rc<dyn ArrayBackend>,
    /// Full owned materialization, built lazily by `as_slice`/`as_vec`/`Deref`
    /// (the non-lazy fallback used by `as_array` and by-reference indexing).
    /// This is the ONLY retained state and is never populated by the scan hot
    /// path, which uses `element(idx)`.
    full: ForeignOnce<Vec<Value>>,
}

impl ForeignArray {
    fn new(backend: Rc<dyn ArrayBackend>) -> Self {
        ForeignArray {
            backend,
            full: ForeignOnce::new(),
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.backend.len()
    }

    /// Transient element materialization: fresh value, NO cache insert. The
    /// returned owned value is dropped by the caller at last reference.
    #[inline]
    fn element(&self, index: usize) -> Option<Value> {
        if index >= self.backend.len() {
            return None;
        }
        self.backend.get_value(index)
    }

    /// Force full materialization (non-lazy fallback).
    ///
    /// This is the array analogue of [`ForeignObject::get`]: a `debug_assert`
    /// guards the hot path so any RVM/interpreter site that borrows a foreign
    /// array as a `&[Value]` (via `Deref`/`as_slice`/`as_vec`) instead of using
    /// the lazy [`Array::element`] cursor is caught in release builds (which run
    /// with debug-assertions on). It force-materializes the whole array and
    /// retains it in `full`, breaking the transient floor, so it must only be
    /// reached by documented non-scan fallbacks.
    fn as_slice(&self) -> &[Value] {
        debug_assert!(
            self.full.get().is_some(),
            "foreign array borrow `as_slice`/Deref hit on hot path; use element()"
        );
        self.full
            .get_or_init(|| {
                (0..self.backend.len())
                    .map(|i| self.element(i).unwrap_or(Value::Undefined))
                    .collect()
            })
            .as_slice()
    }
}

impl Clone for ForeignArray {
    fn clone(&self) -> Self {
        // Shares the backend; starts fresh (no cache to copy).
        ForeignArray::new(self.backend.clone())
    }
}

impl fmt::Debug for ForeignArray {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForeignArray")
            .field("len", &self.backend.len())
            .finish()
    }
}

#[derive(Debug, Clone)]
enum ArrayRepr {
    Owned(Vec<Value>),
    /// Boxed so owned arrays are not bloated by the foreign payload.
    Foreign(Box<ForeignArray>),
}

/// An opaque, ordered sequence of [`Value`]s.
///
/// The backing storage is either an owned `Vec<Value>` or a read-through
/// [`ForeignArray`]. Owned arrays behave exactly like a `Vec` (via `Deref` to a
/// slice); foreign arrays materialize elements lazily through
/// [`Array::element`] / [`Array::len`] (the cursor/index API the interpreter's
/// hot loop uses) and only force full materialization when a `&[Value]` /
/// `&Vec<Value>` borrow is unavoidable (`Deref`, `as_slice`, `as_array`).
#[derive(Debug, Clone)]
pub struct Array {
    repr: ArrayRepr,
}

/// The reference-counted array storage behind [`Value::Array`]. Aliased so that
/// feature-agnostic code (e.g. `builtins::utils::ensure_array`) works across the
/// default and optimized value implementations.
pub type ArrayRc = Rc<Array>;

impl Array {
    /// Build a foreign (read-through) array from an [`ArrayBackend`].
    pub fn from_backend(backend: Rc<dyn ArrayBackend>) -> Self {
        Array {
            repr: ArrayRepr::Foreign(Box::new(ForeignArray::new(backend))),
        }
    }

    /// True if this array is foreign-backed.
    #[inline]
    pub fn is_foreign(&self) -> bool {
        matches!(self.repr, ArrayRepr::Foreign(_))
    }

    /// Number of elements (does not force materialization).
    #[inline]
    pub fn len(&self) -> usize {
        match &self.repr {
            ArrayRepr::Owned(v) => v.len(),
            ArrayRepr::Foreign(f) => f.len(),
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Lazily fetch a clone of element `index` (cursor/index API). For owned
    /// arrays this clones from the `Vec`; for foreign arrays it materializes a
    /// FRESH value and retains nothing. Returns `None` if out of bounds.
    #[inline]
    pub fn element(&self, index: usize) -> Option<Value> {
        match &self.repr {
            ArrayRepr::Owned(v) => v.get(index).cloned(),
            ArrayRepr::Foreign(f) => f.element(index),
        }
    }

    /// Return the elements as a `&Vec<Value>`, forcing full materialization for
    /// foreign arrays (the documented non-lazy fallback used by `as_array`).
    #[inline]
    pub fn as_vec(&self) -> &Vec<Value> {
        match &self.repr {
            ArrayRepr::Owned(v) => v,
            ArrayRepr::Foreign(f) => {
                debug_assert!(
                    f.full.get().is_some(),
                    "foreign array borrow `as_vec` hit on hot path; use element()"
                );
                f.full.get_or_init(|| {
                    (0..f.backend.len())
                        .map(|i| f.element(i).unwrap_or(Value::Undefined))
                        .collect()
                })
            }
        }
    }

    /// Return the elements as a slice, forcing full materialization for foreign
    /// arrays (the documented non-lazy fallback).
    #[inline]
    pub fn as_slice(&self) -> &[Value] {
        match &self.repr {
            ArrayRepr::Owned(v) => v.as_slice(),
            ArrayRepr::Foreign(f) => f.as_slice(),
        }
    }

    /// Force materialization to an owned `Vec` and return a mutable borrow.
    pub fn as_owned_mut(&mut self) -> &mut Vec<Value> {
        if let ArrayRepr::Foreign(f) = &self.repr {
            let v: Vec<Value> = f.as_slice().to_vec();
            self.repr = ArrayRepr::Owned(v);
        }
        match &mut self.repr {
            ArrayRepr::Owned(v) => v,
            ArrayRepr::Foreign(_) => unreachable!(),
        }
    }

    // --- Mutation helpers (force owned, delegate to Vec) ---

    #[inline]
    pub fn push(&mut self, v: Value) {
        self.as_owned_mut().push(v);
    }

    #[inline]
    pub fn reverse(&mut self) {
        self.as_owned_mut().reverse();
    }

    #[inline]
    pub fn append(&mut self, other: &mut Array) {
        let tail = core::mem::take(other.as_owned_mut());
        self.as_owned_mut().extend(tail);
    }

    #[inline]
    pub fn sort(&mut self) {
        self.as_owned_mut().sort();
    }
}

impl Default for Array {
    fn default() -> Self {
        Array {
            repr: ArrayRepr::Owned(Vec::new()),
        }
    }
}

impl ops::Deref for Array {
    type Target = [Value];
    #[inline]
    fn deref(&self) -> &[Value] {
        self.as_slice()
    }
}

impl From<Vec<Value>> for Array {
    #[inline]
    fn from(v: Vec<Value>) -> Self {
        Array {
            repr: ArrayRepr::Owned(v),
        }
    }
}

impl From<Array> for Value {
    #[inline]
    fn from(a: Array) -> Value {
        Value::Array(Rc::new(a))
    }
}

impl FromIterator<Value> for Array {
    fn from_iter<T: IntoIterator<Item = Value>>(iter: T) -> Self {
        Array {
            repr: ArrayRepr::Owned(iter.into_iter().collect()),
        }
    }
}

impl PartialEq for Array {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl Eq for Array {}

impl PartialOrd for Array {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Array {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

impl Hash for Array {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}

impl Serialize for Array {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_slice().serialize(serializer)
    }
}

/// A value in a Rego document.
///
/// Value is similar to a [`serde_json::value::Value`], but has the following additional
/// capabilities:
///    - [`Value::Set`] variant to represent sets.
///    - [`Value::Undefined`] variant to represent absence of value.
//     - [`Value::Object`] keys can be other values, not just strings.
///    - Number variants have at least 100 digits of precision for computations.
///
/// Number variants (UInt, Int, Float, BigInt) are flattened into the enum directly,
/// and strings use ArcStr (thin pointer), making Value 16 bytes.
///
/// Value can be efficiently cloned due to the use of reference counting.
#[derive(Debug, Clone)]
pub enum Value {
    /// JSON null.
    Null,

    /// JSON boolean.
    Bool(bool),

    /// Unsigned 64-bit integer.
    UInt(u64),

    /// Signed 64-bit integer.
    Int(i64),

    /// 64-bit floating point.
    Float(f64),

    /// Arbitrary precision integer.
    BigInt(Rc<BigInt>),

    /// JSON string (thin pointer via ArcStr).
    String(ArcStr),

    /// JSON array.
    Array(Rc<Array>),

    /// A set of values.
    /// No JSON equivalent.
    /// Sets are serialized as arrays in JSON.
    Set(Rc<ValueSet>),

    /// An object.
    /// Unlike JSON, keys can be any value, not just string.
    Object(Rc<ValueMap>),

    /// Undefined value.
    /// Used to indicate the absence of a value.
    Undefined,
}

const _: () = assert!(core::mem::size_of::<Value>() == 16);

#[inline]
fn enforce_limit_anyhow() -> Result<()> {
    crate::utils::limits::check_memory_limit_if_needed().map_err(|err| anyhow!(err))
}

#[inline]
fn enforce_limit_for<E: DeError>() -> core::result::Result<(), E> {
    crate::utils::limits::check_memory_limit_if_needed().map_err(|err| E::custom(err.to_string()))
}

/// Simple FNV-1a hasher for order-independent set hashing.
#[derive(Default)]
struct FnvHasher(u64);

impl Hasher for FnvHasher {
    fn write(&mut self, bytes: &[u8]) {
        const PRIME: u64 = 0x00000100000001B3;
        for &b in bytes {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(PRIME);
        }
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

#[doc(hidden)]
impl Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::Error;
        match self {
            Value::Null => serializer.serialize_unit(),
            Value::Bool(b) => serializer.serialize_bool(*b),
            Value::String(s) => serializer.serialize_str(s.as_str()),
            Value::UInt(_) | Value::Int(_) | Value::Float(_) | Value::BigInt(_) => {
                self.to_number().unwrap().serialize(serializer)
            }
            Value::Array(a) => a.serialize(serializer),
            Value::Object(fields) => {
                // iter_sorted is free for compact objects (keys pre-sorted in schema)
                let sorted = fields.iter_sorted();
                let mut map = serializer.serialize_map(Some(sorted.len()))?;
                for (k, v) in sorted {
                    match k {
                        Value::String(_) => map.serialize_entry(k, v)?,
                        _ => {
                            let key_str = serde_json::to_string(k).map_err(Error::custom)?;
                            map.serialize_entry(&key_str, v)?
                        }
                    }
                }
                map.end()
            }

            // display set as a sorted array for deterministic output
            Value::Set(s) => {
                use serde::ser::SerializeSeq;
                let mut sorted: Vec<&Value> = s.iter().collect();
                sorted.sort();
                let mut seq = serializer.serialize_seq(Some(sorted.len()))?;
                for v in sorted {
                    seq.serialize_element(v)?;
                }
                seq.end()
            }

            // display undefined as a special string
            Value::Undefined => serializer.serialize_str("<undefined>"),
        }
    }
}

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a value")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Null)
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Bool(v))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        Value::deserialize(deserializer)
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::from(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::from(v))
    }

    fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::from(v))
    }

    fn visit_i128<E>(self, v: i128) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::from(v))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Float(v))
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(ArcStr::from(s)))
    }

    fn visit_string<E>(self, s: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(ArcStr::from(s.as_str())))
    }

    fn visit_seq<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let mut arr = vec![];
        while let Some(v) = visitor.next_element()? {
            arr.push(v);
            // Enforce allocator limit while expanding a deserialized array.
            enforce_limit_for::<V::Error>()?;
        }
        Ok(Value::from(arr))
    }

    fn visit_map<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
    where
        V: MapAccess<'de>,
    {
        // Collect all entries first, then try to build a compact object.
        let cap = visitor.size_hint().unwrap_or(0);
        let mut raw_keys: Vec<Value> = Vec::with_capacity(cap);
        let mut raw_values: Vec<Value> = Vec::with_capacity(cap);

        while let Some((key, value)) = visitor.next_entry::<Value, Value>()? {
            // Check for serde_json big-number sentinel on the first entry.
            if raw_keys.is_empty() {
                if let (Value::String(k), Value::String(v)) = (&key, &value) {
                    if k.as_str() == "$serde_json::private::Number" {
                        match Number::from_str(v.as_str()) {
                            Ok(n) => return Ok(Value::from_number(n)),
                            _ => return Err(de::Error::custom("failed to read big number")),
                        }
                    }
                }
            }
            raw_keys.push(key);
            raw_values.push(value);
            enforce_limit_for::<V::Error>()?;
        }

        if raw_keys.is_empty() {
            return Ok(Value::new_object());
        }

        // If all keys are strings, build a schema-interned compact object.
        let all_string_keys = raw_keys.iter().all(|k| matches!(k, Value::String(_)));
        if all_string_keys {
            let key_strs: Vec<ArcStr> = raw_keys
                .iter()
                .map(|k| match k {
                    Value::String(s) => s.clone(),
                    _ => unreachable!(),
                })
                .collect();
            let schema = intern_schema(&key_strs);
            let mut sorted_values = vec![Value::Null; key_strs.len()];
            for (i, k) in key_strs.iter().enumerate() {
                if let Some(&idx) = schema.lookup.get(k.as_str()) {
                    sorted_values[idx as usize] =
                        core::mem::replace(&mut raw_values[i], Value::Null);
                }
            }
            Ok(Value::Object(Rc::new(ValueMap::from_schema_values(
                schema,
                sorted_values.into_boxed_slice(),
            ))))
        } else {
            // Fallback: non-string keys present, use Map repr.
            let mut map = ValueMap::new();
            for (k, v) in raw_keys.into_iter().zip(raw_values) {
                map.insert(k, v);
            }
            Ok(Value::from(map))
        }
    }
}

#[doc(hidden)]
impl<'de> Deserialize<'de> for Value {
    fn deserialize<D>(deserializer: D) -> Result<Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ValueVisitor)
    }
}

// ---------------------------------------------------------------------------
//  Eq — pointer-equality fast paths via Rc::ptr_eq
// ---------------------------------------------------------------------------

impl PartialEq for Value {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Null, Value::Null) | (Value::Undefined, Value::Undefined) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::UInt(a), Value::UInt(b)) => a == b,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::Float(a), Value::Float(b)) => a == b,
            (Value::BigInt(a), Value::BigInt(b)) => Rc::ptr_eq(a, b) || a == b,
            // Cross-type numeric: only call to_number() when both sides are numeric.
            (a, b) if a.is_number() && b.is_number() => {
                // SAFETY: is_number() guarantees to_number() returns Some.
                a.to_number().unwrap() == b.to_number().unwrap()
            }
            (Value::String(a), Value::String(b)) => ArcStr::ptr_eq(a, b) || a == b,
            (Value::Array(a), Value::Array(b)) => Rc::ptr_eq(a, b) || a == b,
            (Value::Set(a), Value::Set(b)) => {
                if Rc::ptr_eq(a, b) {
                    return true;
                }
                if a.len() != b.len() {
                    return false;
                }
                a.iter().all(|v| b.contains(v))
            }
            (Value::Object(a), Value::Object(b)) => Rc::ptr_eq(a, b) || a == b,
            _ => false,
        }
    }
}

impl Eq for Value {}

// ---------------------------------------------------------------------------
//  Ord — pointer-equality fast paths, kind-based ordering
// ---------------------------------------------------------------------------

impl Value {
    fn kind_ordinal(&self) -> u8 {
        match self {
            Value::Null => 0,
            Value::Bool(_) => 1,
            Value::UInt(_) | Value::Int(_) | Value::Float(_) | Value::BigInt(_) => 2,
            Value::String(_) => 3,
            Value::Array(_) => 4,
            Value::Set(_) => 5,
            Value::Object(_) => 6,
            Value::Undefined => 7,
        }
    }

    /// Returns `true` if this value is [`Value::Undefined`].
    #[inline(always)]
    pub fn is_undefined(&self) -> bool {
        matches!(self, Value::Undefined)
    }

    /// Returns true if this is a numeric variant.
    #[inline(always)]
    pub fn is_number(&self) -> bool {
        matches!(
            self,
            Value::UInt(_) | Value::Int(_) | Value::Float(_) | Value::BigInt(_)
        )
    }

    /// Extract the number payload as a `Number`, if this is a numeric variant.
    pub fn to_number(&self) -> Option<Number> {
        match self {
            Value::UInt(u) => Some(Number::UInt(*u)),
            Value::Int(i) => Some(Number::Int(*i)),
            Value::Float(f) => Some(Number::Float(*f)),
            Value::BigInt(b) => Some(Number::BigInt(b.clone())),
            _ => None,
        }
    }

    /// Construct a Value from a Number.
    pub fn from_number(n: Number) -> Self {
        match n {
            Number::UInt(u) => Value::UInt(u),
            Number::Int(i) => Value::Int(i),
            Number::Float(f) => Value::Float(f),
            Number::BigInt(b) => Value::BigInt(b),
        }
    }
}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Value {
    fn cmp(&self, other: &Self) -> Ordering {
        let ka = self.kind_ordinal();
        let kb = other.kind_ordinal();
        if ka != kb {
            return ka.cmp(&kb);
        }

        match (self, other) {
            (Value::Null, Value::Null) | (Value::Undefined, Value::Undefined) => Ordering::Equal,
            (Value::Bool(a), Value::Bool(b)) => a.cmp(b),
            (Value::String(a), Value::String(b)) => a.as_str().cmp(b.as_str()),
            (Value::Array(a), Value::Array(b)) => {
                if Rc::ptr_eq(a, b) {
                    Ordering::Equal
                } else {
                    a.cmp(b)
                }
            }
            (Value::Set(a), Value::Set(b)) => {
                if Rc::ptr_eq(a, b) {
                    Ordering::Equal
                } else {
                    let mut a_sorted: Vec<&Value> = a.iter().collect();
                    let mut b_sorted: Vec<&Value> = b.iter().collect();
                    a_sorted.sort();
                    b_sorted.sort();
                    a_sorted.cmp(&b_sorted)
                }
            }
            (Value::Object(a), Value::Object(b)) => {
                if Rc::ptr_eq(a, b) {
                    Ordering::Equal
                } else {
                    a.cmp(b)
                }
            }
            // Same-kind numbers (ka == kb == 2)
            _ => self.to_number().unwrap().cmp(&other.to_number().unwrap()),
        }
    }
}

// ---------------------------------------------------------------------------
//  Hash
// ---------------------------------------------------------------------------

impl Hash for Value {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.kind_ordinal().hash(state);
        match self {
            Value::Null | Value::Undefined => {}
            Value::Bool(b) => b.hash(state),
            Value::String(s) => s.as_str().hash(state),
            Value::Array(a) => {
                a.len().hash(state);
                for v in a.iter() {
                    v.hash(state);
                }
            }
            Value::Set(s) => {
                // Order-independent hash: commutative combination of element hashes.
                s.len().hash(state);
                let mut combined: u64 = 0;
                for v in s.iter() {
                    let mut h = FnvHasher::default();
                    v.hash(&mut h);
                    combined = combined.wrapping_add(h.finish());
                }
                combined.hash(state);
            }
            Value::Object(o) => o.hash(state),
            // Number variants
            _ => self.to_number().unwrap().hash(state),
        }
    }
}

impl fmt::Display for Value {
    /// Display a value.
    ///
    /// A value is displayed by serializing it to JSON using serde_json::to_string.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from("hello");
    /// assert_eq!(format!("{v}"), "\"hello\"");
    /// # Ok(())
    /// # }
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => write!(f, "{s}"),
            Err(_e) => Err(fmt::Error),
        }
    }
}

impl Value {
    /// Create an empty [`Value::Array`]
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let obj = Value::new_array();
    /// assert_eq!(obj.as_array().expect("not an array").len(), 0);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_array() -> Value {
        Value::from(vec![])
    }

    /// Create an empty [`Value::Object`]
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let obj = Value::new_object();
    /// assert_eq!(obj.as_object().expect("not an object").len(), 0);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_object() -> Value {
        Value::from(ValueMap::new())
    }

    /// Create an empty [`Value::Set`]
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let obj = Value::new_set();
    /// assert_eq!(obj.as_set().expect("not a set").len(), 0);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_set() -> Value {
        Value::Set(Rc::new(ValueSet::new()))
    }
}

impl Value {
    /// Deserialize a [`Value`] from JSON.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let json = r#"
    /// [
    ///   null, true, false,
    ///   "hello", 12345,
    ///   { "name" : "regorus" }
    /// ]"#;
    ///
    /// // Deserialize json.
    /// let value = Value::from_json_str(json)?;
    ///
    /// // Assert outer array.
    /// let array = value.as_array().expect("not an array");
    ///
    /// // Assert elements.
    /// assert_eq!(array[0], Value::Null);
    /// assert_eq!(array[1], Value::from(true));
    /// assert_eq!(array[2], Value::from(false));
    /// assert_eq!(array[3], Value::from("hello"));
    /// assert_eq!(array[4], Value::from(12345u64));
    /// let obj = array[5].as_object().expect("not an object");
    /// assert_eq!(obj.len(), 1);
    /// assert_eq!(obj[&Value::from("name")], Value::from("regorus"));
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_json_str(json: &str) -> Result<Value> {
        match serde_json::from_str::<Value>(json) {
            Ok(value) => Ok(value),
            Err(err) => {
                #[cfg(all(feature = "allocator-memory-limits", not(miri)))]
                {
                    // Re-validate allocator limits when serde parsing fails to surface LimitError.
                    match crate::utils::limits::check_global_memory_limit() {
                        Err(limit_err) => Err(anyhow!(limit_err)),
                        Ok(_) => Err(anyhow!(err)),
                    }
                }

                #[cfg(any(miri, not(feature = "allocator-memory-limits")))]
                {
                    Err(anyhow!(err))
                }
            }
        }
    }

    /// Deserialize a [`Value`] from a file containing JSON.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let value = Value::from_json_file("tests/aci/input.json")?;
    ///
    /// // Convert the value back to json.
    /// let json_str = value.to_json_str()?;
    ///
    /// assert_eq!(json_str.trim(),
    ///            std::fs::read_to_string("tests/aci/input.json")?.trim().replace("\r\n", "\n"));
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn from_json_file<P: AsRef<std::path::Path>>(path: P) -> Result<Value> {
        match std::fs::read_to_string(&path) {
            Ok(c) => Self::from_json_str(c.as_str()),
            Err(e) => bail!("Failed to read {}. {e}", path.as_ref().display()),
        }
    }

    /// Serialize a value to JSON.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let value = Value::from_json_file("tests/aci/input.json")?;
    ///
    /// // Convert the value back to json.
    /// let json_str = value.to_json_str()?;
    ///
    /// assert_eq!(json_str.trim(),
    ///            std::fs::read_to_string("tests/aci/input.json")?.trim().replace("\r\n", "\n"));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Sets are serialized as arrays.
    /// ```
    /// # use regorus::*;
    /// # use std::collections::BTreeSet;
    /// # fn main() -> anyhow::Result<()> {
    /// let mut set = BTreeSet::new();
    /// set.insert(Value::from("Hello"));
    /// set.insert(Value::from(1u64));
    ///
    /// let set_value = Value::from(set);
    ///
    /// assert_eq!(
    ///  set_value.to_json_str()?,
    ///  r#"
    ///[
    ///   1,
    ///   "Hello"
    ///]"#.trim());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Non string keys of objects are serialized to json first and the serialized string representation
    /// is emitted as the key.
    /// ```
    /// # use regorus::*;
    /// # use std::collections::BTreeMap;
    /// # fn main() -> anyhow::Result<()> {
    /// let mut obj = BTreeMap::new();
    /// obj.insert(Value::from("Hello"), Value::from("World"));
    /// obj.insert(Value::from([Value::from(1u64)].to_vec()), Value::Null);
    ///
    /// let obj_value = Value::from(obj);
    ///
    /// assert_eq!(
    ///  obj_value.to_json_str()?,
    ///  r#"
    ///{
    ///   "Hello": "World",
    ///   "[1]": null
    ///}"#.trim());
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_json_str(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(anyhow::Error::msg)
    }

    /// Deserialize a value from YAML.
    /// Note: Deserialization from YAML does not support arbitrary precision numbers.
    #[cfg(feature = "yaml")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn from_yaml_str(yaml: &str) -> Result<Value> {
        let value = serde_yaml::from_str(yaml)
            .map_err(|err| anyhow::anyhow!("Failed to parse YAML: {}", err))?;
        Ok(value)
    }

    /// Deserialize a value from a file containing YAML.
    /// Note: Deserialization from YAML does not support arbitrary precision numbers.
    #[cfg(feature = "std")]
    #[cfg(feature = "yaml")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "yaml")))]
    pub fn from_yaml_file(path: &String) -> Result<Value> {
        match std::fs::read_to_string(path) {
            Ok(c) => Self::from_yaml_str(c.as_str()),
            Err(e) => bail!("Failed to read {path}. {e}"),
        }
    }
}

impl From<bool> for Value {
    /// Create a [`Value::Bool`] from `bool`.
    /// ```
    /// # use regorus::*;
    /// # use std::collections::BTreeSet;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(Value::from(true), Value::Bool(true));
    /// # Ok(())
    /// # }
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl From<String> for Value {
    /// Create a [`Value::String`] from `string`.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(Value::from("Hello".to_string()), Value::String(arcstr::ArcStr::from("Hello")));
    /// # Ok(())
    /// # }
    fn from(s: String) -> Self {
        Value::String(ArcStr::from(s.as_str()))
    }
}

impl From<&str> for Value {
    /// Create a [`Value::String`] from `&str`.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(Value::from("Hello"), Value::String(arcstr::ArcStr::from("Hello")));
    /// # Ok(())
    /// # }
    fn from(s: &str) -> Self {
        Value::String(ArcStr::from(s))
    }
}

impl From<u128> for Value {
    /// Create a [`Value::Number`] from `u128`.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(
    ///   Value::from(340_282_366_920_938_463_463_374_607_431_768_211_455u128).as_u128()?,
    ///   340_282_366_920_938_463_463_374_607_431_768_211_455u128);
    /// # Ok(())
    /// # }
    fn from(n: u128) -> Self {
        Value::from_number(Number::from(n))
    }
}

impl From<i128> for Value {
    /// Create a [`Value::Number`] from `i128`.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(
    ///   Value::from(-170141183460469231731687303715884105728i128).as_i128()?,
    ///   -170141183460469231731687303715884105728i128);
    /// # Ok(())
    /// # }
    fn from(n: i128) -> Self {
        Value::from_number(Number::from(n))
    }
}

impl From<u64> for Value {
    /// Create a [`Value::Number`] from `u64`.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(
    ///   Value::from(0u64),
    ///   Value::from_json_str("0")?);
    /// # Ok(())
    /// # }
    fn from(n: u64) -> Self {
        Value::UInt(n)
    }
}

impl From<i64> for Value {
    /// Create a [`Value::Number`] from `i64`.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(
    ///   Value::from(0i64),
    ///   Value::from_json_str("0")?);
    /// # Ok(())
    /// # }
    fn from(n: i64) -> Self {
        Value::Int(n)
    }
}

impl From<u32> for Value {
    /// Create a [`Value::Number`] from `u32`.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(
    ///   Value::from(0u32),
    ///   Value::from_json_str("0")?);
    /// # Ok(())
    /// # }
    fn from(n: u32) -> Self {
        Value::UInt(n as u64)
    }
}

impl From<i32> for Value {
    /// Create a [`Value::Number`] from `i32`.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(
    ///   Value::from(0i32),
    ///   Value::from_json_str("0")?);
    /// # Ok(())
    /// # }
    fn from(n: i32) -> Self {
        Value::Int(n as i64)
    }
}

impl From<f64> for Value {
    /// Create a [`Value::Number`] from `f64`.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(
    ///   Value::from(3.5f64),
    ///   Value::from_numeric_string("3.5")?);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`Value::Number`] stores floating-point values as `f64`, so it inherits the same
    /// ~15-digit precision limit. Adding additional digits to either the literal or a parsed
    /// numeric string causes both to round to the same `f64` value.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let from_float = Value::from(3.141592653589793238462f64);
    /// let from_string = Value::from_numeric_string("3.141592653589793238462")?;
    /// assert_eq!(from_float, from_string);
    ///
    /// // All representations round to approximately 15 digits.
    /// assert_eq!(
    ///   from_float,
    ///   Value::from_numeric_string("3.141592653589793")?);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// If additional precision is required, keep the raw data as strings or use an external
    /// arbitrary-precision numeric type before converting it into [`Value`].
    fn from(n: f64) -> Self {
        Value::Float(n)
    }
}

impl From<serde_json::Value> for Value {
    /// Create a [`Value`] from [`serde_json::Value`].
    ///
    /// Returns [`Value::Undefined`] in case of error.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let json_v = serde_json::json!({ "x":10, "y": 20 });
    /// let v = Value::from(json_v);
    ///
    /// assert_eq!(v["x"].as_u64()?, 10);
    /// assert_eq!(v["y"].as_u64()?, 20);
    /// # Ok(())
    /// # }
    fn from(v: serde_json::Value) -> Self {
        match serde_json::from_value(v) {
            Ok(v) => v,
            _ => Value::Undefined,
        }
    }
}

#[cfg(feature = "yaml")]
#[cfg_attr(docsrs, doc(cfg(feature = "yaml")))]
impl From<serde_yaml::Value> for Value {
    /// Create a [`Value`] from [`serde_yaml::Value`].
    ///
    /// Returns [`Value::Undefined`] in case of error.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let yaml = "
    ///   x: 10
    ///   y: 20
    /// ";
    /// let yaml_v : serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    /// let v = Value::from(yaml_v);
    ///
    /// assert_eq!(v["x"].as_u64()?, 10);
    /// assert_eq!(v["y"].as_u64()?, 20);
    /// # Ok(())
    /// # }
    fn from(v: serde_yaml::Value) -> Self {
        match serde_yaml::from_value(v) {
            Ok(v) => v,
            _ => Value::Undefined,
        }
    }
}

impl Value {
    /// Create a [`Value::Number`] from a string containing numeric representation of a number.
    ///
    /// This is the preferred way for creating arbitrary precision numbers.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from_numeric_string("3.14159265358979323846264338327950288419716939937510")?;
    ///
    /// println!("{}", v.to_json_str()?);
    /// // Prints 3.1415926535897932384626433832795028841971693993751 if serde_json/arbitrary_precision feature is enabled.
    /// // Prints 3.141592653589793 if serde_json/arbitrary_precision is not enabled.
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_numeric_string(s: &str) -> Result<Value> {
        Ok(Value::from_number(
            Number::from_str(s).map_err(|_| anyhow!("not a valid numeric string"))?,
        ))
    }
}

impl From<usize> for Value {
    /// Create a [`Value::Number`] from `usize`.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(
    ///   Value::from(0usize),
    ///   Value::from_json_str("0")?);
    /// # Ok(())
    /// # }
    fn from(n: usize) -> Self {
        Value::UInt(n as u64)
    }
}

#[doc(hidden)]
impl From<Number> for Value {
    fn from(n: Number) -> Self {
        Value::from_number(n)
    }
}

impl From<Vec<Value>> for Value {
    /// Create a [`Value::Array`] from a [`Vec<Value>`].
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let strings = [ "Hello", "World" ];
    ///
    /// let v = Value::from(strings.iter().map(|s| Value::from(*s)).collect::<Vec<Value>>());
    /// assert_eq!(v[0], Value::from(strings[0]));
    /// assert_eq!(v[1], Value::from(strings[1]));
    /// # Ok(())
    /// # }
    fn from(a: Vec<Value>) -> Self {
        Value::Array(Rc::new(Array::from(a)))
    }
}

impl From<BTreeSet<Value>> for Value {
    /// Create a [`Value::Set`] from a [`BTreeSet<Value>`] by converting to [`ValueSet`].
    /// ```
    /// # use regorus::*;
    /// # use std::collections::BTreeSet;
    /// # fn main() -> anyhow::Result<()> {
    /// let strings = [ "Hello", "World" ];
    /// let v = Value::from(strings
    ///            .iter()
    ///            .map(|s| Value::from(*s))
    ///            .collect::<BTreeSet<Value>>());
    ///
    /// let mut items: Vec<&Value> = v.as_set()?.iter().collect();
    /// items.sort();
    /// assert_eq!(items[0], &Value::from(strings[0]));
    /// assert_eq!(items[1], &Value::from(strings[1]));
    /// # Ok(())
    /// # }
    fn from(s: BTreeSet<Value>) -> Self {
        let hs: ValueSet = s.into_iter().collect();
        Value::Set(Rc::new(hs))
    }
}

impl From<ValueSet> for Value {
    fn from(s: ValueSet) -> Self {
        Value::Set(Rc::new(s))
    }
}

impl From<BTreeMap<Value, Value>> for Value {
    /// Create a [`Value::Object`] from a [`BTreeMap<Value>`] by converting to [`ValueMap`].
    /// ```
    /// # use regorus::*;
    /// # use std::collections::BTreeMap;
    /// # fn main() -> anyhow::Result<()> {
    /// let strings = [ ("Hello", "World") ];
    /// let v = Value::from(strings
    ///            .iter()
    ///            .map(|(k,v)| (Value::from(*k), Value::from(*v)))
    ///            .collect::<BTreeMap<Value, Value>>());
    ///
    /// let mut iter = v.as_object()?.iter();
    /// # Ok(())
    /// # }
    fn from(s: BTreeMap<Value, Value>) -> Self {
        let hm: ValueMap = s.into_iter().collect();
        Value::Object(Rc::new(hm))
    }
}

impl From<ValueMap> for Value {
    fn from(s: ValueMap) -> Self {
        Value::Object(Rc::new(s))
    }
}

impl Value {
    pub(crate) fn from_array(a: Vec<Value>) -> Value {
        Value::from(a)
    }

    pub(crate) fn from_set(s: ValueSet) -> Value {
        Value::from(s)
    }

    pub(crate) fn from_map(m: ValueMap) -> Value {
        Value::from(m)
    }

    pub(crate) fn is_empty_object(&self) -> bool {
        self == &Value::new_object()
    }
}

impl Value {
    /// Cast value to [`& bool`] if [`Value::Bool`].
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(true);
    /// assert_eq!(v.as_bool()?, &true);
    /// # Ok(())
    /// # }
    pub fn as_bool(&self) -> Result<&bool> {
        match self {
            Value::Bool(b) => Ok(b),
            _ => Err(anyhow!("not a bool")),
        }
    }

    /// Cast value to [`&mut bool`] if [`Value::Bool`].
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let mut v = Value::from(true);
    /// *v.as_bool_mut()? = false;
    /// # Ok(())
    /// # }
    pub fn as_bool_mut(&mut self) -> Result<&mut bool> {
        match self {
            Value::Bool(b) => Ok(b),
            _ => Err(anyhow!("not a bool")),
        }
    }

    /// Cast value to [`& u128`] if [`Value::Number`].
    ///
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a u128.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(10);
    /// assert_eq!(v.as_u128()?, 10u128);
    ///
    /// let v = Value::from(-10);
    /// assert!(v.as_u128().is_err());
    /// # Ok(())
    /// # }
    pub fn as_u128(&self) -> Result<u128> {
        match self.to_number() {
            Some(b) => {
                if let Some(n) = b.as_u128() {
                    return Ok(n);
                }
                bail!("not a u128");
            }
            _ => Err(anyhow!("not a u128")),
        }
    }

    /// Cast value to [`& i128`] if [`Value::Number`].
    ///
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a i128.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(-10);
    /// assert_eq!(v.as_i128()?, -10i128);
    ///
    /// let v = Value::from_numeric_string("11111111111111111111111111111111111111111111111111")?;
    /// assert!(v.as_i128().is_err());
    /// # Ok(())
    /// # }
    pub fn as_i128(&self) -> Result<i128> {
        match self.to_number() {
            Some(b) => {
                if let Some(n) = b.as_i128() {
                    return Ok(n);
                }
                bail!("not a i128");
            }
            _ => Err(anyhow!("not a i128")),
        }
    }

    /// Cast value to [`& u64`] if [`Value::Number`].
    ///
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a u64.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(10);
    /// assert_eq!(v.as_u64()?, 10u64);
    ///
    /// let v = Value::from(-10);
    /// assert!(v.as_u64().is_err());
    /// # Ok(())
    /// # }
    pub fn as_u64(&self) -> Result<u64> {
        match self.to_number() {
            Some(b) => {
                if let Some(n) = b.as_u64() {
                    return Ok(n);
                }
                bail!("not a u64");
            }
            _ => Err(anyhow!("not a u64")),
        }
    }

    /// Cast value to [`& i64`] if [`Value::Number`].
    ///
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a i64.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(-10);
    /// assert_eq!(v.as_i64()?, -10i64);
    ///
    /// let v = Value::from(340_282_366_920_938_463_463_374_607_431_768_211_455u128);
    /// assert!(v.as_i64().is_err());
    /// # Ok(())
    /// # }
    pub fn as_i64(&self) -> Result<i64> {
        match self.to_number() {
            Some(b) => {
                if let Some(n) = b.as_i64() {
                    return Ok(n);
                }
                bail!("not an i64");
            }
            _ => Err(anyhow!("not an i64")),
        }
    }

    /// Cast value to [`& u32`] if [`Value::Number`].
    ///
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a u32.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(10);
    /// assert_eq!(v.as_u32()?, 10u32);
    ///
    /// let v = Value::from(-10);
    /// assert!(v.as_u32().is_err());
    /// # Ok(())
    /// # }
    pub fn as_u32(&self) -> Result<u32> {
        match self.to_number() {
            Some(b) => {
                if let Some(n) = b.as_u64() {
                    if let Ok(v) = u32::try_from(n) {
                        return Ok(v);
                    }
                }
                bail!("not a u32");
            }
            _ => Err(anyhow!("not a u32")),
        }
    }

    /// Cast value to [`& i32`] if [`Value::Number`].
    ///
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a i32.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(-10);
    /// assert_eq!(v.as_i32()?, -10i32);
    ///
    /// let v = Value::from(2_147_483_648i64);
    /// assert!(v.as_i32().is_err());
    /// # Ok(())
    /// # }
    pub fn as_i32(&self) -> Result<i32> {
        match self.to_number() {
            Some(b) => {
                if let Some(n) = b.as_i64() {
                    if let Ok(v) = i32::try_from(n) {
                        return Ok(v);
                    }
                }
                bail!("not an i32");
            }
            _ => Err(anyhow!("not an i32")),
        }
    }

    /// Cast value to [`& u16`] if [`Value::Number`].
    ///
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a u16.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(10);
    /// assert_eq!(v.as_u16()?, 10u16);
    ///
    /// let v = Value::from(-10);
    /// assert!(v.as_u16().is_err());
    /// # Ok(())
    /// # }
    pub fn as_u16(&self) -> Result<u16> {
        match self.to_number() {
            Some(b) => {
                if let Some(n) = b.as_u64() {
                    if let Ok(v) = u16::try_from(n) {
                        return Ok(v);
                    }
                }
                bail!("not a u16");
            }
            _ => Err(anyhow!("not a u16")),
        }
    }

    /// Cast value to [`& i16`] if [`Value::Number`].
    ///
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a i16.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(-10);
    /// assert_eq!(v.as_i16()?, -10i16);
    ///
    /// let v = Value::from(32768i64);
    /// assert!(v.as_i16().is_err());
    /// # Ok(())
    /// # }
    pub fn as_i16(&self) -> Result<i16> {
        match self.to_number() {
            Some(b) => {
                if let Some(n) = b.as_i64() {
                    if let Ok(v) = i16::try_from(n) {
                        return Ok(v);
                    }
                }
                bail!("not an i16");
            }
            _ => Err(anyhow!("not an i16")),
        }
    }

    /// Cast value to [`& u8`] if [`Value::Number`].
    ///
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a u8.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(10);
    /// assert_eq!(v.as_u8()?, 10u8);
    ///
    /// let v = Value::from(-10);
    /// assert!(v.as_u8().is_err());
    /// # Ok(())
    /// # }
    pub fn as_u8(&self) -> Result<u8> {
        match self.to_number() {
            Some(b) => {
                if let Some(n) = b.as_u64() {
                    if let Ok(v) = u8::try_from(n) {
                        return Ok(v);
                    }
                }
                bail!("not a u8");
            }
            _ => Err(anyhow!("not a u8")),
        }
    }

    /// Cast value to [`& i8`] if [`Value::Number`].
    ///
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a i8.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(-10);
    /// assert_eq!(v.as_i8()?, -10i8);
    ///
    /// let v = Value::from(128);
    /// assert!(v.as_i8().is_err());
    /// # Ok(())
    /// # }
    pub fn as_i8(&self) -> Result<i8> {
        match self.to_number() {
            Some(b) => {
                if let Some(n) = b.as_i64() {
                    if let Ok(v) = i8::try_from(n) {
                        return Ok(v);
                    }
                }
                bail!("not an i8");
            }
            _ => Err(anyhow!("not an i8")),
        }
    }

    /// Cast value to [`& f64`] if [`Value::Number`].
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a i64.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(-10);
    /// assert_eq!(v.as_f64()?, -10f64);
    ///
    /// let v = Value::from(340_282_366_920_938_463_463_374_607_431_768_211_455u128);
    /// assert!(v.as_i64().is_err());
    /// # Ok(())
    /// # }
    pub fn as_f64(&self) -> Result<f64> {
        match self.to_number() {
            Some(b) => {
                if let Some(n) = b.as_f64() {
                    return Ok(n);
                }
                bail!("not a f64");
            }
            _ => Err(anyhow!("not a f64")),
        }
    }

    /// Cast value to [`&ArcStr`] if [`Value::String`].
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from("Hello");
    /// assert_eq!(v.as_string()?.as_ref(), "Hello");
    /// # Ok(())
    /// # }
    pub fn as_string(&self) -> Result<&ArcStr> {
        match self {
            Value::String(s) => Ok(s),
            _ => Err(anyhow!("not a string")),
        }
    }

    /// Cast value to [`&mut ArcStr`] if [`Value::String`].
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let mut v = Value::from("Hello");
    /// *v.as_string_mut()? = arcstr::ArcStr::from("World");
    /// # Ok(())
    /// # }
    pub fn as_string_mut(&mut self) -> Result<&mut ArcStr> {
        match self {
            Value::String(s) => Ok(s),
            _ => Err(anyhow!("not a string")),
        }
    }

    #[doc(hidden)]
    pub fn as_number(&self) -> Result<Number> {
        self.to_number().ok_or_else(|| anyhow!("not a number"))
    }

    /// Cast value to [`& Vec<Value>`] if [`Value::Array`].
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from([Value::from("Hello")].to_vec());
    /// assert_eq!(v.as_array()?[0], Value::from("Hello"));
    /// # Ok(())
    /// # }
    pub fn as_array(&self) -> Result<&Vec<Value>> {
        match self {
            Value::Array(a) => Ok(a.as_vec()),
            _ => Err(anyhow!("not an array")),
        }
    }

    /// Cast value to [`&mut Vec<Value>`] if [`Value::Array`].
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let mut v = Value::from([Value::from("Hello")].to_vec());
    /// v.as_array_mut()?.push(Value::from("World"));
    /// # Ok(())
    /// # }
    pub fn as_array_mut(&mut self) -> Result<&mut Vec<Value>> {
        match self {
            Value::Array(a) => Ok(Rc::make_mut(a).as_owned_mut()),
            _ => Err(anyhow!("not an array")),
        }
    }

    /// Cast value to [`& ValueSet`] if [`Value::Set`].
    /// ```
    /// # use regorus::*;
    /// # use regorus::value::ValueSet;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(
    ///    [Value::from("Hello")]
    ///        .iter()
    ///        .cloned()
    ///        .collect::<ValueSet>(),
    /// );
    /// assert!(v.as_set()?.contains(&Value::from("Hello")));
    /// # Ok(())
    /// # }
    pub fn as_set(&self) -> Result<&ValueSet> {
        match self {
            Value::Set(s) => Ok(s),
            _ => Err(anyhow!("not a set")),
        }
    }

    /// Cast value to [`&mut ValueSet`] if [`Value::Set`].
    /// ```
    /// # use regorus::*;
    /// # use regorus::value::ValueSet;
    /// # fn main() -> anyhow::Result<()> {
    /// let mut v = Value::from(
    ///    [Value::from("Hello")]
    ///        .iter()
    ///        .cloned()
    ///        .collect::<ValueSet>(),
    /// );
    /// v.as_set_mut()?.insert(Value::from("World"));
    /// # Ok(())
    /// # }
    pub fn as_set_mut(&mut self) -> Result<&mut ValueSet> {
        match self {
            Value::Set(s) => Ok(Rc::make_mut(s)),
            _ => Err(anyhow!("not a set")),
        }
    }

    /// Cast value to [`&ValueMap`] if [`Value::Object`].
    /// ```
    /// # use regorus::*;
    /// # use std::collections::BTreeMap;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(
    ///    [(Value::from("Hello"), Value::from("World"))]
    ///        .iter()
    ///        .cloned()
    ///        .collect::<BTreeMap<Value, Value>>(),
    /// );
    /// assert_eq!(v.as_object()?.len(), 1);
    /// # Ok(())
    /// # }
    pub fn as_object(&self) -> Result<&ValueMap> {
        match self {
            Value::Object(m) => Ok(m),
            _ => Err(anyhow!("not an object")),
        }
    }

    /// Value-returning (non-borrowing) index — the transient hot path used by
    /// the interpreter's chained field/element access.
    ///
    /// Semantically equivalent to `self[key].clone()`, but for foreign-backed
    /// objects/arrays it materializes a FRESH owned value and retains nothing
    /// (no cache insert), whereas the `Index` operator must route foreign
    /// objects through the retained `pairs` snapshot. Returns [`Value::Undefined`]
    /// for missing keys / out-of-range indices / non-collections.
    #[inline]
    pub fn index_owned(&self, key: &Value) -> Value {
        match self {
            Value::Object(o) => o.get_owned(key).unwrap_or(Value::Undefined),
            Value::Set(s) => s.get(key).cloned().unwrap_or(Value::Undefined),
            Value::Array(a) => match key.to_number().and_then(|n| n.as_u64()) {
                Some(index) if (index as usize) < a.len() => {
                    a.element(index as usize).unwrap_or(Value::Undefined)
                }
                _ => Value::Undefined,
            },
            _ => Value::Undefined,
        }
    }

    /// Cast value to [`&mut ValueMap`] if [`Value::Object`].
    /// ```
    /// # use regorus::*;
    /// # use std::collections::BTreeMap;
    /// # fn main() -> anyhow::Result<()> {
    /// let mut v = Value::from(
    ///    [(Value::from("Hello"), Value::from("World"))]
    ///        .iter()
    ///        .cloned()
    ///        .collect::<BTreeMap<Value, Value>>(),
    /// );
    /// v.as_object_mut()?.insert(Value::from("Good"), Value::from("Bye"));
    /// # Ok(())
    /// # }
    pub fn as_object_mut(&mut self) -> Result<&mut ValueMap> {
        match self {
            Value::Object(m) => Ok(Rc::make_mut(m)),
            _ => Err(anyhow!("not an object")),
        }
    }
}

impl Value {
    pub(crate) fn make_or_get_value_mut<'a>(&'a mut self, paths: &[&str]) -> Result<&'a mut Value> {
        if paths.is_empty() {
            return Ok(self);
        }

        let key = Value::String(paths[0].into());
        if self == &Value::Undefined {
            *self = Value::new_object();
        }
        if let Value::Object(map) = self {
            if map.get(&key).is_none() {
                Rc::make_mut(map).insert(key.clone(), Value::Undefined);
                // Enforce allocator limit while creating nested object entries.
                enforce_limit_anyhow()?;
            }
        }

        match self {
            Value::Object(map) => match Rc::make_mut(map).get_mut(&key) {
                Some(v) if paths.len() == 1 => Ok(v),
                Some(v) => Self::make_or_get_value_mut(v, &paths[1..]),
                _ => bail!("internal error: unexpected"),
            },
            Value::Undefined if paths.len() > 1 => {
                *self = Value::new_object();
                Self::make_or_get_value_mut(self, paths)
            }
            Value::Undefined => Ok(self),
            _ => bail!("internal error: make: not an selfect {self:?}"),
        }
    }

    pub(crate) fn merge(&mut self, mut new: Value) -> Result<()> {
        if self == &new {
            return Ok(());
        }
        match (self, &mut new) {
            (v @ Value::Undefined, _) => *v = new,
            (Value::Set(ref mut set), Value::Set(new)) => {
                Rc::make_mut(set).extend(Rc::make_mut(new).drain());
                // Enforce allocator limit after merging set entries.
                enforce_limit_anyhow()?;
            }
            (Value::Object(map), Value::Object(new)) => {
                for (k, v) in new.iter() {
                    match map.get(k) {
                        Some(pv) if *pv != *v => {
                            bail!(
                                "value for key `{}` generated multiple times: `{}` and `{}`",
                                serde_json::to_string_pretty(&k).map_err(anyhow::Error::msg)?,
                                serde_json::to_string_pretty(&pv).map_err(anyhow::Error::msg)?,
                                serde_json::to_string_pretty(&v).map_err(anyhow::Error::msg)?,
                            )
                        }
                        _ => {
                            Rc::make_mut(map).insert(k.clone(), v.clone());
                            // Enforce allocator limit after merging object entries.
                            enforce_limit_anyhow()?;
                        }
                    };
                }
            }
            _ => bail!("error: could not merge value"),
        };
        Ok(())
    }
}

impl ops::Index<&Value> for Value {
    type Output = Value;

    /// Index a [`Value`] using a [`Value`].
    ///
    /// [`Value::Undefined`] is returned
    /// - If the index not valid for the collection.
    /// - If the value being indexed is not an array, set or object.
    ///
    /// Sets can be indexed only by elements within the set.
    ///
    /// ```
    /// # use regorus::*;
    /// # use std::collections::BTreeMap;
    /// # fn main() -> anyhow::Result<()> {
    ///
    /// let arr = Value::from([Value::from("Hello")].to_vec());
    /// // Index an array.
    /// assert_eq!(arr[&Value::from(0)].as_string()?.as_ref(), "Hello");
    /// assert_eq!(arr[&Value::from(10)], Value::Undefined);
    ///
    /// let mut set = Value::new_set();
    /// set.as_set_mut()?.insert(Value::from(100));
    /// set.as_set_mut()?.insert(Value::from("Hello"));
    ///
    /// // Index a set.
    /// let item = Value::from("Hello");
    /// assert_eq!(&set[&item], &item);
    /// assert_eq!(&set[&Value::from(10)], &Value::Undefined);
    ///
    /// let mut obj = Value::new_object();
    /// obj.as_object_mut()?.insert(Value::from("Hello"), Value::from("World"));
    /// obj.as_object_mut()?.insert(Value::new_array(), Value::from("bye"));
    ///
    /// // Index an object.
    /// assert_eq!(&obj[Value::from("Hello")].as_string()?.as_ref(), &"World");
    /// assert_eq!(&obj[Value::from("hllo")], &Value::Undefined);
    /// // Index using non-string key.
    /// assert_eq!(&obj[&Value::new_array()].as_string()?.as_ref(), &"bye");
    ///
    /// // Index a non-collection.
    /// assert_eq!(&Value::Null[&Value::from(1)], &Value::Undefined);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// This is the preferred way of indexing a value.
    /// Since constructing a value may be a costly operation (e.g. Value::String),
    /// the caller can construct the index value once and use it many times.
    ///`
    fn index(&self, key: &Value) -> &Self::Output {
        match (self, key) {
            (Value::Object(o), _) => match &o.get(key) {
                Some(v) => v,
                _ => &Value::Undefined,
            },
            (Value::Set(s), _) => match s.get(key) {
                Some(v) => v,
                _ => &Value::Undefined,
            },
            (Value::Array(a), _) => match key.to_number().and_then(|n| n.as_u64()) {
                Some(index) if (index as usize) < a.len() => &a[index as usize],
                _ => &Value::Undefined,
            },
            _ => &Value::Undefined,
        }
    }
}

impl<T> ops::Index<T> for Value
where
    Value: From<T>,
{
    type Output = Value;

    /// Index a [`Value`].
    ///
    ///
    /// A [`Value`] is constructed from the index which is then used for indexing.
    ///
    /// ```
    /// # use regorus::*;
    /// # use std::collections::BTreeMap;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(
    ///    [(Value::from("Hello"), Value::from("World")),
    ///     (Value::from(1), Value::from(2))]
    ///        .iter()
    ///        .cloned()
    ///        .collect::<BTreeMap<Value, Value>>(),
    /// );
    ///
    /// assert_eq!(&v["Hello"].as_string()?.as_ref(), &"World");
    /// # Ok(())
    /// # }
    fn index(&self, key: T) -> &Self::Output {
        &self[&Value::from(key)]
    }
}

#[cfg(test)]
mod size_tests {
    use super::*;
    #[test]
    fn print_value_sizes() {
        std::println!("=== Value type sizes ===");
        std::println!(
            "Value: {} bytes (align {})",
            core::mem::size_of::<Value>(),
            core::mem::align_of::<Value>()
        );
        std::println!(
            "ValueMap (dual repr): {} bytes (align {})",
            core::mem::size_of::<ValueMap>(),
            core::mem::align_of::<ValueMap>()
        );
        std::println!("ObjectRepr: {} bytes", core::mem::size_of::<ObjectRepr>());
        std::println!(
            "CompactObject: {} bytes",
            core::mem::size_of::<CompactObject>()
        );
        std::println!("MapObject: {} bytes", core::mem::size_of::<MapObject>());
        std::println!("Schema: {} bytes", core::mem::size_of::<Schema>());
        std::println!(
            "Rc<ValueMap>: {} bytes",
            core::mem::size_of::<Rc<ValueMap>>()
        );
        std::println!("Number: {} bytes", core::mem::size_of::<Number>());
        std::println!("ArcStr: {} bytes", core::mem::size_of::<ArcStr>());
        std::println!("ValueSet: {} bytes", core::mem::size_of::<ValueSet>());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Foreign value backend spike: mock packed-native subscription store
// ─────────────────────────────────────────────────────────────────────────────
//
// Models a C# `SubscriptionValue[]` kept in a packed Rust structure and exposed
// to the RVM through the foreign array/object backends. Each subscription is a
// 6-field object (short keys i/n/s/p/q/l) reproducing the exact logical data of
// the regmem subscription JSON, so an evaluated policy returns identical results
// whether the input is a fully-parsed Value or a foreign-backed one.
//
// NOTE (spike deviation): the task prose sketched fields as
// `placement: Option<[u8;16]>` / `spending: Option<u8>`. To reproduce the exact
// workload strings (`"p"` is a descriptive placement string, `"l"` is a nested
// `{v,c}` object) we instead pack `zone: u8` and `spending: u16`, and `"s"` is
// materialized as a numeric state code (matching the JSON `"s":2`). The packing
// philosophy (fixed-width fields + interned quota strings) is preserved.

/// One packed subscription record.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct NativeSub {
    /// 16-byte guid, formatted into the "i" field on demand.
    pub id: [u8; 16],
    /// Display name (interned string) -> "n".
    pub name: ArcStr,
    /// State code -> "s" (numeric).
    pub state: u8,
    /// Placement zone -> formatted into "p".
    pub zone: u8,
    /// Index into the shared `quota_table` -> "q".
    pub quota: u16,
    /// Spending value -> "l".v.
    pub spending: u16,
}

/// Packed array of subscriptions plus shared interned tables.
#[doc(hidden)]
#[derive(Debug)]
pub struct NativeSubArray {
    pub subs: Vec<NativeSub>,
    pub quota_table: Vec<ArcStr>,
    keys: Rc<[ArcStr]>,
}

impl NativeSubArray {
    /// Build the mock store for `n` subscriptions, mirroring regmem's generator.
    pub fn generate(n: usize) -> Rc<Self> {
        let quota_table = alloc::vec![ArcStr::from("PayAsYouGo_2014")];
        let keys: Rc<[ArcStr]> = alloc::vec![
            ArcStr::from("i"),
            ArcStr::from("n"),
            ArcStr::from("s"),
            ArcStr::from("p"),
            ArcStr::from("q"),
            ArcStr::from("l"),
        ]
        .into();
        let mut subs = Vec::with_capacity(n);
        for i in 0..n {
            let mut id = [0u8; 16];
            id[0..4].copy_from_slice(&(i as u32).to_be_bytes());
            id[4] = 0x11;
            id[5] = 0x11;
            id[6] = 0x22;
            id[7] = 0x22;
            id[8] = 0x33;
            id[9] = 0x33;
            id[10] = 0x44;
            id[11] = 0x44;
            id[12] = 0x55;
            id[13] = 0x55;
            id[14] = 0x66;
            id[15] = 0x66;
            subs.push(NativeSub {
                id,
                name: ArcStr::from(alloc::format!("Subscription Display {i:06}")),
                state: 2,
                zone: (i % 3) as u8,
                quota: 0,
                spending: 0,
            });
        }
        Rc::new(NativeSubArray {
            subs,
            quota_table,
            keys,
        })
    }
}

fn format_guid(id: &[u8; 16]) -> ArcStr {
    ArcStr::from(alloc::format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7],
        id[8], id[9], id[10], id[11], id[12], id[13], id[14], id[15]
    ))
}

/// Per-element object view over `arr.subs[idx]` (read-through object backend).
struct SubView {
    arr: Rc<NativeSubArray>,
    idx: usize,
}

impl ObjectBackend for SubView {
    fn keys(&self) -> &[ArcStr] {
        &self.arr.keys
    }

    fn len(&self) -> usize {
        6
    }

    fn get_value(&self, key: &str) -> Option<Value> {
        let sub = self.arr.subs.get(self.idx)?;
        match key {
            "i" => Some(Value::String(format_guid(&sub.id))),
            "n" => Some(Value::String(sub.name.clone())),
            "s" => Some(Value::UInt(sub.state as u64)),
            "p" => Some(Value::String(ArcStr::from(alloc::format!(
                "East US 2 (Zone {:02}) Placement",
                sub.zone
            )))),
            "q" => Some(Value::String(
                self.arr.quota_table[sub.quota as usize].clone(),
            )),
            "l" => {
                // Nested object {"v": spending, "c": "None"}.
                let mut m = ValueMap::new();
                m.insert(
                    Value::String(ArcStr::from("v")),
                    Value::UInt(sub.spending as u64),
                );
                m.insert(
                    Value::String(ArcStr::from("c")),
                    Value::String(ArcStr::from("None")),
                );
                Some(Value::Object(Rc::new(m)))
            }
            _ => None,
        }
    }
}

/// Array backend that hands out foreign-object views of each subscription.
struct NativeSubArrayBackend(Rc<NativeSubArray>);

impl ArrayBackend for NativeSubArrayBackend {
    fn len(&self) -> usize {
        self.0.subs.len()
    }

    fn get_value(&self, index: usize) -> Option<Value> {
        if index >= self.0.subs.len() {
            return None;
        }
        let backend: Rc<dyn ObjectBackend> = Rc::new(SubView {
            arr: self.0.clone(),
            idx: index,
        });
        Some(Value::Object(Rc::new(ValueMap::from_object_backend(
            backend,
        ))))
    }
}

impl Value {
    /// Spike: construct a foreign-backed `Value::Array` over a packed
    /// [`NativeSubArray`]. Elements/fields materialize on demand.
    #[doc(hidden)]
    pub fn from_native_sub_array(arr: Rc<NativeSubArray>) -> Value {
        let backend: Rc<dyn ArrayBackend> = Rc::new(NativeSubArrayBackend(arr));
        Value::Array(Rc::new(Array::from_backend(backend)))
    }

    /// Spike: wrap a foreign subscription array as `{"Values":[...],
    /// "ContinuationToken":null}` to mirror the regmem document shape.
    #[doc(hidden)]
    pub fn native_sub_document(arr: Rc<NativeSubArray>) -> Value {
        let mut m = ValueMap::new();
        m.insert(
            Value::String(ArcStr::from("Values")),
            Value::from_native_sub_array(arr),
        );
        m.insert(
            Value::String(ArcStr::from("ContinuationToken")),
            Value::Null,
        );
        Value::Object(Rc::new(m))
    }
}
