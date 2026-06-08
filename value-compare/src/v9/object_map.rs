// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Arena-allocated object map with schema-shared compact representation.
//!
//! Objects deserialized from JSON get a compact representation: one shared
//! `Schema` (sorted keys + lookup) plus a flat arena-allocated value slice.
//! Objects with the same key set share the same `Schema`, enabling O(1)
//! same-schema equality checks and free sorted iteration.
//!
//! Programmatically-built objects use a HashMap fallback.

use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use bumpalo::Bump;
use hashbrown::HashMap;

use super::value::{ArenaValue, Value};
use super::value::ArenaStr;

// ─── Schema ──────────────────────────────────────────────────────────────

/// A shared key layout for objects with identical string keys.
///
/// Keys are stored sorted so that serialization in sorted order is free
/// and same-schema comparison can compare value slices directly.
#[derive(Debug, Clone)]
pub struct Schema {
    /// Sorted key names.
    pub(crate) keys: Arc<[Arc<str>]>,
    /// key → index into keys/values.
    pub(crate) lookup: HashMap<Arc<str>, u32>,
}

impl Schema {
    fn from_sorted_keys(sorted: Vec<Arc<str>>) -> Arc<Self> {
        let lookup: HashMap<Arc<str>, u32> = sorted
            .iter()
            .enumerate()
            .map(|(i, k)| (k.clone(), i as u32))
            .collect();
        Arc::new(Schema {
            keys: sorted.into(),
            lookup,
        })
    }
}

// ─── Schema interner ─────────────────────────────────────────────────────

thread_local! {
    static SCHEMA_CACHE: RefCell<HashMap<Vec<Arc<str>>, Arc<Schema>>> =
        RefCell::new(HashMap::new());
}

/// Intern a schema for the given key set.  Keys need not be sorted.
pub fn intern_schema(keys: &[&str]) -> Arc<Schema> {
    let mut sorted: Vec<Arc<str>> = keys.iter().map(|&s| Arc::from(s)).collect();
    sorted.sort();
    SCHEMA_CACHE.with(|cache| {
        let mut map = cache.borrow_mut();
        if let Some(existing) = map.get(&sorted) {
            return existing.clone();
        }
        let schema = Schema::from_sorted_keys(sorted.clone());
        map.insert(sorted, schema.clone());
        schema
    })
}

/// Clear the schema cache for the current thread.
pub fn clear_schema_cache() {
    SCHEMA_CACHE.with(|cache| {
        cache.borrow_mut().clear();
    });
}

// ─── Entry hash helpers ─────────────────────────────────────────────────

fn entry_hash_str(key: &str, value: &Value<'_>) -> u64 {
    let mut h = DefaultHasher::new();
    3u8.hash(&mut h); // kind_ordinal for String
    key.hash(&mut h);
    value.hash_content(&mut h);
    h.finish()
}

fn entry_hash_val(key: &Value<'_>, value: &Value<'_>) -> u64 {
    let mut h = DefaultHasher::new();
    key.hash_content(&mut h);
    value.hash_content(&mut h);
    h.finish()
}

// ─── CompactObject ──────────────────────────────────────────────────────

/// A compact object: shared schema + arena-allocated flat value array.
///
/// NOTE: The `Arc<Schema>` is leaked when the arena is freed (bumpalo doesn't
/// run destructors).  Schemas are small and interned, so this is acceptable.
struct CompactObject<'a> {
    schema: Arc<Schema>,
    /// Keys in schema sort order, as ArenaStr wrappers for producing Values.
    arena_keys: &'a [&'a ArenaStr<'a>],
    /// Values in schema sort order, arena-allocated.
    values: &'a [Value<'a>],
    cached_hash: u64,
}

// ─── MapObject ──────────────────────────────────────────────────────────

/// Fallback HashMap-based object (used for programmatic construction
/// or objects with non-string keys).
struct MapObject<'a> {
    strings: HashMap<&'a str, Value<'a>, hashbrown::DefaultHashBuilder, &'a Bump>,
    others: Option<HashMap<Value<'a>, Value<'a>, hashbrown::DefaultHashBuilder, &'a Bump>>,
    cached_hash: u64,
}

// ─── ObjectRepr ─────────────────────────────────────────────────────────

enum ObjectRepr<'a> {
    Compact(CompactObject<'a>),
    Map(MapObject<'a>),
}

// ─── ObjectMap ──────────────────────────────────────────────────────────

/// Arena-allocated object map.
///
/// Can be either compact (schema-shared, flat value array) or map-based
/// (HashMap fallback for programmatic construction or mixed key types).
pub struct ObjectMap<'a> {
    repr: ObjectRepr<'a>,
}

impl<'a> ObjectMap<'a> {
    /// Create an empty map-based ObjectMap in the given arena.
    pub fn new_in(arena: &'a Bump) -> Self {
        ObjectMap {
            repr: ObjectRepr::Map(MapObject {
                strings: HashMap::new_in(arena),
                others: None,
                cached_hash: 0,
            }),
        }
    }

    /// Create an empty map-based ObjectMap with pre-allocated capacity.
    pub fn with_capacity_in(arena: &'a Bump, cap: usize) -> Self {
        ObjectMap {
            repr: ObjectRepr::Map(MapObject {
                strings: HashMap::with_capacity_in(cap, arena),
                others: None,
                cached_hash: 0,
            }),
        }
    }

    /// Build a compact object from a schema, arena-allocated keys, and values.
    ///
    /// `arena_keys` and `values` must be in schema sort order.
    pub(crate) fn from_schema_values(
        arena: &'a Bump,
        schema: Arc<Schema>,
        arena_keys: &[&'a str],
        values: &[Value<'a>],
    ) -> Self {
        debug_assert_eq!(schema.keys.len(), arena_keys.len());
        debug_assert_eq!(schema.keys.len(), values.len());
        // Wrap each &str key in an ArenaStr for iterator use.
        let str_wrappers: Vec<&'a ArenaStr<'a>> = arena_keys
            .iter()
            .map(|&k| &*arena.alloc(ArenaStr(k)))
            .collect();
        let keys_slice = arena.alloc_slice_copy(&str_wrappers);
        let vals_slice = arena.alloc_slice_copy(values);
        let mut cached_hash: u64 = 0;
        for (k, v) in arena_keys.iter().zip(vals_slice.iter()) {
            cached_hash = cached_hash.wrapping_add(entry_hash_str(k, v));
        }
        ObjectMap {
            repr: ObjectRepr::Compact(CompactObject {
                schema,
                arena_keys: keys_slice,
                values: vals_slice,
                cached_hash,
            }),
        }
    }

    /// Lookup by `&str` — O(1).
    pub fn get_str(&self, key: &str) -> Option<&Value<'a>> {
        match &self.repr {
            ObjectRepr::Compact(c) => {
                c.schema.lookup.get(key).map(|&idx| &c.values[idx as usize])
            }
            ObjectRepr::Map(m) => m.strings.get(key),
        }
    }

    /// Lookup by arbitrary `Value` key — O(1).
    pub fn get(&self, key: &Value<'a>) -> Option<&Value<'a>> {
        match key {
            Value::Arena(ArenaValue::String(s)) => self.get_str(s.0),
            _ => match &self.repr {
                ObjectRepr::Compact(_) => None,
                ObjectRepr::Map(m) => m.others.as_ref().and_then(|o| o.get(key)),
            },
        }
    }

    /// Insert a string key (overwrites on duplicate), updating cached_hash.
    pub fn insert_str(&mut self, key: &'a str, value: Value<'a>) {
        match &mut self.repr {
            ObjectRepr::Map(m) => {
                if let Some(old_val) = m.strings.get(key) {
                    m.cached_hash = m.cached_hash.wrapping_sub(entry_hash_str(key, old_val));
                }
                m.cached_hash = m.cached_hash.wrapping_add(entry_hash_str(key, &value));
                m.strings.insert(key, value);
            }
            ObjectRepr::Compact(_) => {
                panic!("Cannot insert into a compact ObjectMap");
            }
        }
    }

    /// Insert an arbitrary key (overwrites on duplicate), updating cached_hash.
    pub fn insert(&mut self, key: Value<'a>, value: Value<'a>) {
        match key {
            Value::Arena(ArenaValue::String(s)) => self.insert_str(s.0, value),
            _ => match &mut self.repr {
                ObjectRepr::Map(m) => {
                    if let Some(ref others) = m.others {
                        if let Some(old_val) = others.get(&key) {
                            m.cached_hash =
                                m.cached_hash.wrapping_sub(entry_hash_val(&key, old_val));
                        }
                    }
                    m.cached_hash = m.cached_hash.wrapping_add(entry_hash_val(&key, &value));
                    if let Some(ref mut others) = m.others {
                        others.insert(key, value);
                    } else {
                        let arena = *m.strings.allocator();
                        let mut o = HashMap::new_in(arena);
                        o.insert(key, value);
                        m.others = Some(o);
                    }
                }
                ObjectRepr::Compact(_) => {
                    panic!("Cannot insert into a compact ObjectMap");
                }
            },
        }
    }

    /// Total number of entries.
    pub fn len(&self) -> usize {
        match &self.repr {
            ObjectRepr::Compact(c) => c.values.len(),
            ObjectRepr::Map(m) => {
                m.strings.len() + m.others.as_ref().map_or(0, |o| o.len())
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Precomputed order-independent hash.
    pub fn cached_hash(&self) -> u64 {
        match &self.repr {
            ObjectRepr::Compact(c) => c.cached_hash,
            ObjectRepr::Map(m) => m.cached_hash,
        }
    }

    /// Iterate all entries as `(Value, &Value)`.
    pub fn iter(&self) -> ObjectMapIter<'a, '_> {
        match &self.repr {
            ObjectRepr::Compact(c) => ObjectMapIter::Compact {
                keys: c.arena_keys,
                values: c.values,
                idx: 0,
            },
            ObjectRepr::Map(m) => ObjectMapIter::Map {
                arena: *m.strings.allocator(),
                string_iter: m.strings.iter(),
                other_iter: m.others.as_ref().map(|o| o.iter()),
            },
        }
    }

    /// Iterate all entries sorted by key.
    ///
    /// For compact objects, this is **free** — keys are already sorted.
    pub fn iter_sorted(&self) -> Vec<(Value<'a>, &Value<'a>)> {
        match &self.repr {
            ObjectRepr::Compact(c) => c
                .arena_keys
                .iter()
                .zip(c.values.iter())
                .map(|(&k, v)| (Value::Arena(ArenaValue::String(k)), v))
                .collect(),
            ObjectRepr::Map(_) => {
                let mut entries: Vec<_> = self.iter().collect();
                entries.sort_by(|(a, _), (b, _)| a.cmp(b));
                entries
            }
        }
    }

    /// Returns the schema if this is a compact object.
    pub fn schema(&self) -> Option<&Arc<Schema>> {
        match &self.repr {
            ObjectRepr::Compact(c) => Some(&c.schema),
            ObjectRepr::Map(_) => None,
        }
    }
}

impl Default for ObjectMap<'_> {
    fn default() -> Self {
        panic!("ObjectMap::default() requires an arena; use ObjectMap::new_in(arena)")
    }
}

// ─── ObjectMapIter ──────────────────────────────────────────────────────

pub enum ObjectMapIter<'a, 'b> {
    Compact {
        keys: &'b [&'a ArenaStr<'a>],
        values: &'b [Value<'a>],
        idx: usize,
    },
    Map {
        arena: &'a Bump,
        string_iter: hashbrown::hash_map::Iter<'b, &'a str, Value<'a>>,
        other_iter: Option<hashbrown::hash_map::Iter<'b, Value<'a>, Value<'a>>>,
    },
}

impl<'a, 'b> Iterator for ObjectMapIter<'a, 'b> {
    type Item = (Value<'a>, &'b Value<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ObjectMapIter::Compact { keys, values, idx } => {
                if *idx < keys.len() {
                    let k = Value::Arena(ArenaValue::String(keys[*idx]));
                    let v = &values[*idx];
                    *idx += 1;
                    Some((k, v))
                } else {
                    None
                }
            }
            ObjectMapIter::Map {
                arena,
                string_iter,
                other_iter,
            } => {
                if let Some((&k, v)) = string_iter.next() {
                    let arena_str = &*arena.alloc(ArenaStr(k));
                    return Some((Value::Arena(ArenaValue::String(arena_str)), v));
                }
                if let Some(ref mut it) = other_iter {
                    if let Some((&k, v)) = it.next() {
                        return Some((k, v));
                    }
                }
                None
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            ObjectMapIter::Compact { keys, idx, .. } => {
                let remaining = keys.len() - *idx;
                (remaining, Some(remaining))
            }
            ObjectMapIter::Map {
                string_iter,
                other_iter,
                ..
            } => {
                let (s_lo, s_hi) = string_iter.size_hint();
                let (o_lo, o_hi) = other_iter
                    .as_ref()
                    .map_or((0, Some(0)), |it| it.size_hint());
                (s_lo + o_lo, s_hi.and_then(|a| o_hi.map(|b| a + b)))
            }
        }
    }
}

// ─── ObjectMapBuilder ───────────────────────────────────────────────────

/// Builder for constructing an ObjectMap incrementally (map variant).
pub struct ObjectMapBuilder<'a> {
    map: ObjectMap<'a>,
}

impl<'a> ObjectMapBuilder<'a> {
    pub fn new(arena: &'a Bump) -> Self {
        ObjectMapBuilder {
            map: ObjectMap::new_in(arena),
        }
    }

    pub fn with_capacity(arena: &'a Bump, cap: usize) -> Self {
        ObjectMapBuilder {
            map: ObjectMap::with_capacity_in(arena, cap),
        }
    }

    pub fn insert_str(&mut self, key: &'a str, value: Value<'a>) {
        self.map.insert_str(key, value);
    }

    pub fn insert(&mut self, key: Value<'a>, value: Value<'a>) {
        self.map.insert(key, value);
    }

    /// Freeze into an arena-allocated `&'a ObjectMap`.
    pub fn build(self) -> &'a ObjectMap<'a> {
        let arena = match &self.map.repr {
            ObjectRepr::Map(m) => *m.strings.allocator(),
            _ => unreachable!(),
        };
        arena.alloc(self.map)
    }
}

// ─── PartialEq — same-schema fast path ─────────────────────────────────

impl PartialEq for ObjectMap<'_> {
    fn eq(&self, other: &Self) -> bool {
        if self.cached_hash() != other.cached_hash() {
            return false;
        }
        if self.len() != other.len() {
            return false;
        }

        // Same-schema fast path: if both are compact with the same schema,
        // just compare value slices directly — no key comparison needed.
        if let (ObjectRepr::Compact(a), ObjectRepr::Compact(b)) = (&self.repr, &other.repr) {
            if Arc::ptr_eq(&a.schema.keys, &b.schema.keys) {
                return a.values == b.values;
            }
        }

        // Fallback: point-lookup each entry.
        match (&self.repr, &other.repr) {
            (ObjectRepr::Map(a), ObjectRepr::Map(b)) => {
                for (k, v) in a.strings.iter() {
                    match b.strings.get(k) {
                        Some(ov) if v == ov => {}
                        _ => return false,
                    }
                }
                if let Some(ref ao) = a.others {
                    let bo = match &b.others {
                        Some(bo) => bo,
                        None => return ao.is_empty(),
                    };
                    for (k, v) in ao.iter() {
                        match bo.get(k) {
                            Some(ov) if v == ov => {}
                            _ => return false,
                        }
                    }
                }
                true
            }
            _ => {
                // Cross-repr or both-compact-different-schema: generic path.
                for (k, v) in self.iter() {
                    match other.get(&k) {
                        Some(ov) if v == ov => {}
                        _ => return false,
                    }
                }
                true
            }
        }
    }
}

impl Eq for ObjectMap<'_> {}

// ─── Ord ────────────────────────────────────────────────────────────────

impl PartialOrd for ObjectMap<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ObjectMap<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let a = self.iter_sorted();
        let b = other.iter_sorted();
        a.len().cmp(&b.len()).then_with(|| {
            a.iter()
                .zip(b.iter())
                .map(|((ak, av), (bk, bv))| ak.cmp(bk).then_with(|| av.cmp(bv)))
                .find(|o| *o != std::cmp::Ordering::Equal)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }
}

// ─── Hash ───────────────────────────────────────────────────────────────

impl Hash for ObjectMap<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.len().hash(state);
        self.cached_hash().hash(state);
    }
}

// ─── Debug ──────────────────────────────────────────────────────────────

impl std::fmt::Debug for ObjectMap<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut map = f.debug_map();
        for (k, v) in self.iter() {
            map.entry(&k, v);
        }
        map.finish()
    }
}
