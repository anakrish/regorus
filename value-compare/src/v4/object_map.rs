// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ObjectMap — struct-based object with precomputed order-independent hash.
//!
//! Same design as v3, but uses `arcstr::ArcStr` (8-byte thin pointer) instead
//! of `Arc<str>` (16-byte fat pointer) for string keys.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use arcstr::ArcStr;
use hashbrown::HashMap;

use super::value::Value;

/// Compute an order-independent hash for a single (key, value) pair.
fn entry_hash(key: &Value, value: &Value) -> u64 {
    let mut h = DefaultHasher::new();
    key.hash_content(&mut h);
    value.hash_content(&mut h);
    h.finish()
}

/// An object map that always keeps string keys in a fast HashMap,
/// with an optional overflow map for non-string keys.
#[derive(Debug, Clone)]
pub struct ObjectMap {
    /// String-keyed entries (the common case — nearly all Rego objects).
    strings: HashMap<ArcStr, Value>,

    /// Non-string-keyed entries (rare). `None` if all keys are strings.
    other: Option<HashMap<Value, Value>>,

    /// Precomputed order-independent hash of all entries.
    cached_hash: u64,
}

impl ObjectMap {
    /// Create a new empty object.
    pub fn new() -> Self {
        ObjectMap {
            strings: HashMap::new(),
            other: None,
            cached_hash: 0,
        }
    }

    /// Create a new empty object with pre-allocated capacity for string keys.
    pub fn with_capacity(cap: usize) -> Self {
        ObjectMap {
            strings: HashMap::with_capacity(cap),
            other: None,
            cached_hash: 0,
        }
    }

    /// Build from an iterator of (Value, Value) pairs.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (Value, Value)>) -> Self {
        let mut obj = ObjectMap::new();
        for (k, v) in pairs {
            obj.insert(k, v);
        }
        obj
    }

    /// Build from a regorus BTreeMap.
    pub fn from_regorus_btree(
        m: &std::collections::BTreeMap<regorus::Value, regorus::Value>,
    ) -> Self {
        let mut obj = ObjectMap::with_capacity(m.len());
        for (k, v) in m {
            let key = Value::from_regorus(k);
            let val = Value::from_regorus(v);
            obj.insert(key, val);
        }
        obj
    }

    /// Lookup by `&str` — the fast path. Zero allocation.
    pub fn get_str(&self, key: &str) -> Option<&Value> {
        self.strings.get(key)
    }

    /// Lookup by `Value` key.
    pub fn get(&self, key: &Value) -> Option<&Value> {
        match key {
            Value::String(s) => self.strings.get(s.as_str()),
            _ => self.other.as_ref().and_then(|m| m.get(key)),
        }
    }

    /// Insert a string key.
    pub fn insert_str(&mut self, key: ArcStr, value: Value) {
        let kv = Value::String(key.clone());
        // If replacing, remove old entry's hash contribution.
        if let Some(old_val) = self.strings.get(key.as_str()) {
            self.cached_hash = self.cached_hash.wrapping_sub(entry_hash(&kv, old_val));
        }
        // Add new entry's hash contribution.
        self.cached_hash = self.cached_hash.wrapping_add(entry_hash(&kv, &value));
        self.strings.insert(key, value);
    }

    /// Insert a `Value` key.
    pub fn insert(&mut self, key: Value, value: Value) {
        match key {
            Value::String(s) => self.insert_str(s, value),
            _ => {
                if let Some(other) = &self.other {
                    if let Some(old_val) = other.get(&key) {
                        self.cached_hash = self.cached_hash.wrapping_sub(entry_hash(&key, old_val));
                    }
                }
                self.cached_hash = self.cached_hash.wrapping_add(entry_hash(&key, &value));
                self.other
                    .get_or_insert_with(HashMap::new)
                    .insert(key, value);
            }
        }
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.strings.len() + self.other.as_ref().map_or(0, |m| m.len())
    }

    /// Is the map empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The precomputed hash.
    pub fn cached_hash(&self) -> u64 {
        self.cached_hash
    }

    /// Iterate as (Value, &Value) pairs.
    pub fn iter(&self) -> ObjectMapIter<'_> {
        ObjectMapIter {
            string_iter: self.strings.iter(),
            other_iter: self.other.as_ref().map(|m| m.iter()),
        }
    }

    /// Iterate in sorted order (for Ord comparison and deterministic serialization).
    pub fn iter_sorted(&self) -> Vec<(Value, &Value)> {
        let mut entries: Vec<(Value, &Value)> = self.iter().collect();
        entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        entries
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

pub struct ObjectMapIter<'a> {
    string_iter: hashbrown::hash_map::Iter<'a, ArcStr, Value>,
    other_iter: Option<hashbrown::hash_map::Iter<'a, Value, Value>>,
}

impl<'a> Iterator for ObjectMapIter<'a> {
    type Item = (Value, &'a Value);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some((k, v)) = self.string_iter.next() {
            return Some((Value::String(k.clone()), v));
        }
        if let Some(ref mut it) = self.other_iter {
            if let Some((k, v)) = it.next() {
                return Some((k.clone(), v));
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let (s_lo, s_hi) = self.string_iter.size_hint();
        let (o_lo, o_hi) = self
            .other_iter
            .as_ref()
            .map_or((0, Some(0)), |it| it.size_hint());
        (s_lo + o_lo, s_hi.and_then(|a| o_hi.map(|b| a + b)))
    }
}

// ---------------------------------------------------------------------------
//  Eq — fast rejection via cached hash
// ---------------------------------------------------------------------------

impl PartialEq for ObjectMap {
    fn eq(&self, other: &Self) -> bool {
        if self.cached_hash != other.cached_hash {
            return false;
        }
        if self.len() != other.len() {
            return false;
        }
        for (k, v) in self.strings.iter() {
            match other.strings.get(k.as_str()) {
                Some(ov) if v == ov => {}
                _ => return false,
            }
        }
        if let Some(ref s_other) = self.other {
            let o_other = match &other.other {
                Some(m) => m,
                None => return false,
            };
            for (k, v) in s_other.iter() {
                match o_other.get(k) {
                    Some(ov) if v == ov => {}
                    _ => return false,
                }
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
        let a = self.iter_sorted();
        let b = other.iter_sorted();
        a.iter()
            .zip(b.iter())
            .map(|((ka, va), (kb, vb))| ka.cmp(kb).then_with(|| va.cmp(vb)))
            .find(|o| *o != std::cmp::Ordering::Equal)
            .unwrap_or_else(|| a.len().cmp(&b.len()))
    }
}

// ---------------------------------------------------------------------------
//  Hash — O(1), returns precomputed hash
// ---------------------------------------------------------------------------

impl Hash for ObjectMap {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.len().hash(state);
        self.cached_hash.hash(state);
    }
}
