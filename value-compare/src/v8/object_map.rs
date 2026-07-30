// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ObjectMap with schema-shared compact representation.
//!
//! Objects whose keys are all strings and share the same key set use a compact
//! representation: one shared `Schema` (sorted keys + lookup map) plus a flat
//! `Box<[Value]>` of values indexed by schema position.
//!
//! Objects with mixed key types or unique key sets fall back to `HashMap`.
//!
//! Uses `ArcStr` — thin-pointer strings for 16-byte Value.

use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use arcstr::ArcStr;
use hashbrown::HashMap;

use super::value::Value;

// ─── Schema ──────────────────────────────────────────────────────────────────

/// A shared key layout for objects with identical string keys.
///
/// Keys are stored sorted so that:
/// - Serialization in sorted order is free (just iterate `keys`).
/// - Same-schema comparison can iterate values in parallel.
#[derive(Debug, Clone)]
pub struct Schema {
    /// Sorted key names.
    pub(crate) keys: Arc<[ArcStr]>,
    /// key → index into keys/values.
    pub(crate) lookup: HashMap<ArcStr, u32>,
}

impl Schema {
    /// Build a schema from an unsorted set of keys.
    fn from_keys(keys: &[ArcStr]) -> Arc<Self> {
        let mut sorted: Vec<ArcStr> = keys.to_vec();
        sorted.sort();
        let lookup: HashMap<ArcStr, u32> = sorted
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

// ─── Schema interner ─────────────────────────────────────────────────────────

// Thread-local cache of schemas keyed by their sorted key set.
// This ensures objects with the same keys share a single Schema allocation.
thread_local! {
    static SCHEMA_CACHE: RefCell<HashMap<Vec<ArcStr>, Arc<Schema>>> =
        RefCell::new(HashMap::new());
}

pub(crate) fn intern_schema(keys: &[ArcStr]) -> Arc<Schema> {
    let mut sorted: Vec<ArcStr> = keys.to_vec();
    sorted.sort();
    SCHEMA_CACHE.with(|cache| {
        let mut map = cache.borrow_mut();
        if let Some(existing) = map.get(&sorted) {
            return existing.clone();
        }
        let schema = Schema::from_keys(&sorted);
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

// ─── CompactObject ──────────────────────────────────────────────────────────

/// A compact object: shared schema + flat value array.
#[derive(Debug, Clone)]
pub(crate) struct CompactObject {
    schema: Arc<Schema>,
    values: Box<[Value]>,
    cached_hash: u64,
}

// ─── ObjectMap ───────────────────────────────────────────────────────────────

/// An object map that can be either:
/// - **Compact**: schema-shared, values stored in a flat array indexed by schema position.
/// - **Map**: classic HashMap for mixed-key or unique objects.
#[derive(Debug, Clone)]
pub struct ObjectMap {
    repr: ObjectRepr,
}

#[derive(Debug, Clone)]
enum ObjectRepr {
    Compact(CompactObject),
    Map(MapObject),
}

#[derive(Debug, Clone)]
struct MapObject {
    strings: HashMap<ArcStr, Value>,
    other: Option<HashMap<Value, Value>>,
    cached_hash: u64,
}

/// Compute an order-independent hash for a single (key, value) pair.
fn entry_hash(key: &Value, value: &Value) -> u64 {
    let mut h = DefaultHasher::new();
    key.hash_content(&mut h);
    value.hash_content(&mut h);
    h.finish()
}

impl ObjectMap {
    pub fn new() -> Self {
        ObjectMap {
            repr: ObjectRepr::Map(MapObject {
                strings: HashMap::new(),
                other: None,
                cached_hash: 0,
            }),
        }
    }

    pub fn with_capacity(cap: usize) -> Self {
        ObjectMap {
            repr: ObjectRepr::Map(MapObject {
                strings: HashMap::with_capacity(cap),
                other: None,
                cached_hash: 0,
            }),
        }
    }

    /// Build a compact object from a schema and values.
    /// Values must be in the same order as schema.keys.
    pub(crate) fn from_schema_values(schema: Arc<Schema>, values: Box<[Value]>) -> Self {
        debug_assert_eq!(schema.keys.len(), values.len());
        let mut cached_hash: u64 = 0;
        for (k, v) in schema.keys.iter().zip(values.iter()) {
            let kv = Value::String(k.clone());
            cached_hash = cached_hash.wrapping_add(entry_hash(&kv, v));
        }
        ObjectMap {
            repr: ObjectRepr::Compact(CompactObject {
                schema,
                values,
                cached_hash,
            }),
        }
    }

    pub fn from_pairs(pairs: impl IntoIterator<Item = (Value, Value)>) -> Self {
        let mut obj = ObjectMap::new();
        for (k, v) in pairs {
            obj.insert(k, v);
        }
        obj
    }

    pub fn from_regorus_btree(
        m: &std::collections::BTreeMap<regorus::Value, regorus::Value>,
    ) -> Self {
        // Try to build as compact if all keys are strings
        let all_string_keys = m.keys().all(|k| matches!(k, regorus::Value::String(_)));
        if all_string_keys && !m.is_empty() {
            let keys: Vec<ArcStr> = m
                .keys()
                .map(|k| match k {
                    regorus::Value::String(s) => ArcStr::from(s.as_ref()),
                    _ => unreachable!(),
                })
                .collect();
            let schema = intern_schema(&keys);
            let mut sorted_values = vec![Value::Null; keys.len()];
            for (k, v) in m {
                if let regorus::Value::String(s) = k {
                    if let Some(&idx) = schema.lookup.get(s.as_ref()) {
                        sorted_values[idx as usize] = Value::from_regorus(v);
                    }
                }
            }
            return ObjectMap::from_schema_values(schema, sorted_values.into_boxed_slice());
        }

        let mut obj = ObjectMap::with_capacity(m.len());
        for (k, v) in m {
            let key = Value::from_regorus(k);
            let val = Value::from_regorus(v);
            obj.insert(key, val);
        }
        obj
    }

    pub fn get_str(&self, key: &str) -> Option<&Value> {
        match &self.repr {
            ObjectRepr::Compact(c) => c.schema.lookup.get(key).map(|&idx| &c.values[idx as usize]),
            ObjectRepr::Map(m) => m.strings.get(key),
        }
    }

    pub fn get(&self, key: &Value) -> Option<&Value> {
        match key {
            Value::String(s) => self.get_str(s.as_str()),
            _ => match &self.repr {
                ObjectRepr::Compact(_) => None,
                ObjectRepr::Map(m) => m.other.as_ref().and_then(|o| o.get(key)),
            },
        }
    }

    pub fn insert_str(&mut self, key: ArcStr, value: Value) {
        self.ensure_map();
        if let ObjectRepr::Map(m) = &mut self.repr {
            let kv = Value::String(key.clone());
            if let Some(old_val) = m.strings.get(key.as_str()) {
                m.cached_hash = m.cached_hash.wrapping_sub(entry_hash(&kv, old_val));
            }
            m.cached_hash = m.cached_hash.wrapping_add(entry_hash(&kv, &value));
            m.strings.insert(key, value);
        }
    }

    pub fn insert(&mut self, key: Value, value: Value) {
        match key {
            Value::String(s) => self.insert_str(s, value),
            _ => {
                self.ensure_map();
                if let ObjectRepr::Map(m) = &mut self.repr {
                    if let Some(other) = &m.other {
                        if let Some(old_val) = other.get(&key) {
                            m.cached_hash = m.cached_hash.wrapping_sub(entry_hash(&key, old_val));
                        }
                    }
                    m.cached_hash = m.cached_hash.wrapping_add(entry_hash(&key, &value));
                    m.other.get_or_insert_with(HashMap::new).insert(key, value);
                }
            }
        }
    }

    /// Convert compact to map representation for mutation.
    fn ensure_map(&mut self) {
        if let ObjectRepr::Compact(c) = &self.repr {
            let mut strings = HashMap::with_capacity(c.schema.keys.len());
            for (k, v) in c.schema.keys.iter().zip(c.values.iter()) {
                strings.insert(k.clone(), v.clone());
            }
            self.repr = ObjectRepr::Map(MapObject {
                strings,
                other: None,
                cached_hash: c.cached_hash,
            });
        }
    }

    pub fn len(&self) -> usize {
        match &self.repr {
            ObjectRepr::Compact(c) => c.values.len(),
            ObjectRepr::Map(m) => m.strings.len() + m.other.as_ref().map_or(0, |o| o.len()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn cached_hash(&self) -> u64 {
        match &self.repr {
            ObjectRepr::Compact(c) => c.cached_hash,
            ObjectRepr::Map(m) => m.cached_hash,
        }
    }

    pub fn iter(&self) -> ObjectMapIter<'_> {
        match &self.repr {
            ObjectRepr::Compact(c) => ObjectMapIter::Compact { idx: 0, obj: c },
            ObjectRepr::Map(m) => ObjectMapIter::Map {
                string_iter: m.strings.iter(),
                other_iter: m.other.as_ref().map(|o| o.iter()),
            },
        }
    }

    /// Iterate in key-sorted order.
    ///
    /// For compact objects, this is **free** — keys are already sorted in the schema.
    pub fn iter_sorted(&self) -> Vec<(Value, &Value)> {
        match &self.repr {
            ObjectRepr::Compact(c) => c
                .schema
                .keys
                .iter()
                .zip(c.values.iter())
                .map(|(k, v)| (Value::String(k.clone()), v))
                .collect(),
            ObjectRepr::Map(_) => {
                let mut entries: Vec<(Value, &Value)> = self.iter().collect();
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

impl Default for ObjectMap {
    fn default() -> Self {
        ObjectMap::new()
    }
}

// ---------------------------------------------------------------------------
//  Iterator
// ---------------------------------------------------------------------------

#[allow(private_interfaces)]
pub enum ObjectMapIter<'a> {
    Compact {
        idx: usize,
        obj: &'a CompactObject,
    },
    Map {
        string_iter: hashbrown::hash_map::Iter<'a, ArcStr, Value>,
        other_iter: Option<hashbrown::hash_map::Iter<'a, Value, Value>>,
    },
}

impl<'a> Iterator for ObjectMapIter<'a> {
    type Item = (Value, &'a Value);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ObjectMapIter::Compact { idx, obj } => {
                if *idx < obj.values.len() {
                    let k = Value::String(obj.schema.keys[*idx].clone());
                    let v = &obj.values[*idx];
                    *idx += 1;
                    Some((k, v))
                } else {
                    None
                }
            }
            ObjectMapIter::Map {
                string_iter,
                other_iter,
            } => {
                if let Some((k, v)) = string_iter.next() {
                    return Some((Value::String(k.clone()), v));
                }
                if let Some(ref mut it) = other_iter {
                    if let Some((k, v)) = it.next() {
                        return Some((k.clone(), v));
                    }
                }
                None
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            ObjectMapIter::Compact { idx, obj } => {
                let remaining = obj.values.len() - *idx;
                (remaining, Some(remaining))
            }
            ObjectMapIter::Map {
                string_iter,
                other_iter,
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

// ---------------------------------------------------------------------------
//  Eq — same-schema fast path
// ---------------------------------------------------------------------------

impl PartialEq for ObjectMap {
    fn eq(&self, other: &Self) -> bool {
        if self.cached_hash() != other.cached_hash() {
            return false;
        }
        if self.len() != other.len() {
            return false;
        }

        // Same-schema fast path: if both are compact with the same schema,
        // just compare value arrays directly — no key comparison needed.
        if let (ObjectRepr::Compact(a), ObjectRepr::Compact(b)) = (&self.repr, &other.repr) {
            if Arc::ptr_eq(&a.schema.keys, &b.schema.keys) {
                return a.values == b.values;
            }
        }

        // Fallback: point-lookup each entry.
        for (k, v) in self.iter() {
            match other.get(&k) {
                Some(ov) if v == ov => {}
                _ => return false,
            }
        }
        true
    }
}

impl Eq for ObjectMap {}

// ---------------------------------------------------------------------------
//  Ord — kept for Rego comparison operators (not on hot path)
// ---------------------------------------------------------------------------

impl PartialOrd for ObjectMap {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ObjectMap {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.iter_sorted().cmp(&other.iter_sorted())
    }
}

// ---------------------------------------------------------------------------
//  Hash — O(1) via cached_hash
// ---------------------------------------------------------------------------

impl Hash for ObjectMap {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.len().hash(state);
        self.cached_hash().hash(state);
    }
}
