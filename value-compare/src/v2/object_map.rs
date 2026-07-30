// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ObjectMap — string-key-specialized object for Value.
//!
//! Same as v1 but uses `Arc<str>` instead of `SmolStr` for HashMap keys.
//! This avoids the SmolStr dependency and allows sharing Arc<str> between
//! HashMap keys and Value::String variants without conversion.

use std::sync::Arc;

use hashbrown::HashMap;

use super::value::Value;

/// An object map that specializes for the common case of string-only keys.
#[derive(Debug, Clone)]
pub enum ObjectMap {
    /// All keys are strings. O(1) lookup. Zero allocation for `get_str`.
    StringKeyed(HashMap<Arc<str>, Value>),

    /// At least one non-string key. O(1) lookup. Ord computed on the fly.
    Mixed(HashMap<Value, Value>),
}

impl ObjectMap {
    /// Create a new empty string-keyed object.
    pub fn new() -> Self {
        ObjectMap::StringKeyed(HashMap::new())
    }

    /// Create a new empty string-keyed object with pre-allocated capacity.
    pub fn with_capacity(cap: usize) -> Self {
        ObjectMap::StringKeyed(HashMap::with_capacity(cap))
    }

    /// Build from an iterator of (Value, Value) pairs, choosing the best representation.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (Value, Value)>) -> Self {
        let entries: Vec<(Value, Value)> = pairs.into_iter().collect();
        let all_string_keys = entries.iter().all(|(k, _)| matches!(k, Value::String(_)));
        if all_string_keys {
            let map: HashMap<Arc<str>, Value> = entries
                .into_iter()
                .map(|(k, v)| {
                    let key = match k {
                        Value::String(s) => s,
                        _ => unreachable!(),
                    };
                    (key, v)
                })
                .collect();
            ObjectMap::StringKeyed(map)
        } else {
            ObjectMap::Mixed(entries.into_iter().collect())
        }
    }

    /// Build from a regorus BTreeMap, choosing the best representation.
    pub fn from_regorus_btree(
        m: &std::collections::BTreeMap<regorus::Value, regorus::Value>,
    ) -> Self {
        let all_string_keys = m.keys().all(|k| matches!(k, regorus::Value::String(_)));
        if all_string_keys {
            let map: HashMap<Arc<str>, Value> = m
                .iter()
                .map(|(k, v)| {
                    let key = match k {
                        regorus::Value::String(s) => Arc::from(s.as_ref()),
                        _ => unreachable!(),
                    };
                    (key, Value::from_regorus(v))
                })
                .collect();
            ObjectMap::StringKeyed(map)
        } else {
            let map: HashMap<Value, Value> = m
                .iter()
                .map(|(k, v)| (Value::from_regorus(k), Value::from_regorus(v)))
                .collect();
            ObjectMap::Mixed(map)
        }
    }

    /// Lookup by `&str` — the fast path. Zero allocation for StringKeyed.
    pub fn get_str(&self, key: &str) -> Option<&Value> {
        match self {
            ObjectMap::StringKeyed(m) => m.get(key),
            ObjectMap::Mixed(m) => {
                // Must wrap in Value::String to look up in HashMap<Value, Value>.
                let k = Value::String(Arc::from(key));
                m.get(&k)
            }
        }
    }

    /// Lookup by `Value` key.
    pub fn get(&self, key: &Value) -> Option<&Value> {
        match (self, key) {
            (ObjectMap::StringKeyed(m), Value::String(s)) => m.get(s.as_ref()),
            (ObjectMap::StringKeyed(_), _) => None, // non-string key → miss
            (ObjectMap::Mixed(m), _) => m.get(key),
        }
    }

    /// Insert a string key.
    pub fn insert_str(&mut self, key: Arc<str>, value: Value) {
        match self {
            ObjectMap::StringKeyed(m) => {
                m.insert(key, value);
            }
            ObjectMap::Mixed(m) => {
                m.insert(Value::String(key), value);
            }
        }
    }

    /// Insert a `Value` key.
    /// If `self` is `StringKeyed` and the key is not a string, converts to `Mixed`.
    pub fn insert(&mut self, key: Value, value: Value) {
        match key {
            Value::String(s) => {
                self.insert_str(s, value);
            }
            _ => {
                // Must convert to Mixed if currently StringKeyed.
                self.ensure_mixed();
                if let ObjectMap::Mixed(m) = self {
                    m.insert(key, value);
                }
            }
        }
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        match self {
            ObjectMap::StringKeyed(m) => m.len(),
            ObjectMap::Mixed(m) => m.len(),
        }
    }

    /// Is the map empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns true if this map uses string-keyed representation.
    pub fn is_string_keyed(&self) -> bool {
        matches!(self, ObjectMap::StringKeyed(_))
    }

    /// Iterate as (Value, &Value) pairs. Keys are wrapped in Value::String for StringKeyed.
    pub fn iter(&self) -> ObjectMapIter<'_> {
        match self {
            ObjectMap::StringKeyed(m) => ObjectMapIter::String(m.iter()),
            ObjectMap::Mixed(m) => ObjectMapIter::Mixed(m.iter()),
        }
    }

    /// Iterate in sorted order (for Ord comparison and serialization).
    pub fn iter_sorted(&self) -> Vec<(Value, &Value)> {
        let mut entries: Vec<(Value, &Value)> = self.iter().collect();
        entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        entries
    }

    /// Convert to Mixed representation (if not already).
    fn ensure_mixed(&mut self) {
        if let ObjectMap::StringKeyed(m) = self {
            let mixed: HashMap<Value, Value> =
                m.drain().map(|(k, v)| (Value::String(k), v)).collect();
            *self = ObjectMap::Mixed(mixed);
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

pub enum ObjectMapIter<'a> {
    String(hashbrown::hash_map::Iter<'a, Arc<str>, Value>),
    Mixed(hashbrown::hash_map::Iter<'a, Value, Value>),
}

impl<'a> Iterator for ObjectMapIter<'a> {
    type Item = (Value, &'a Value);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ObjectMapIter::String(it) => {
                let (k, v) = it.next()?;
                // Cheap Arc::clone — just bumps the refcount.
                Some((Value::String(Arc::clone(k)), v))
            }
            ObjectMapIter::Mixed(it) => {
                let (k, v) = it.next()?;
                Some((k.clone(), v))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            ObjectMapIter::String(it) => it.size_hint(),
            ObjectMapIter::Mixed(it) => it.size_hint(),
        }
    }
}

// ---------------------------------------------------------------------------
//  Eq / Ord / Hash  — compare as sorted key-value sequences
// ---------------------------------------------------------------------------

impl PartialEq for ObjectMap {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        // Use point lookups instead of sorting — O(n) average case.
        match (self, other) {
            (ObjectMap::StringKeyed(a), ObjectMap::StringKeyed(b)) => a
                .iter()
                .all(|(k, v)| b.get(k.as_ref()).map_or(false, |bv| v == bv)),
            (ObjectMap::Mixed(a), ObjectMap::Mixed(b)) => {
                a.iter().all(|(k, v)| b.get(k).map_or(false, |bv| v == bv))
            }
            // One string-keyed, one mixed: iterate the string-keyed side and look up in the other.
            _ => {
                // Use the generic iter() + get() which works for both.
                for (k, v) in self.iter() {
                    if other.get(&k).map_or(true, |bv| v != bv) {
                        return false;
                    }
                }
                true
            }
        }
    }
}

impl Eq for ObjectMap {}

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

impl std::hash::Hash for ObjectMap {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.len().hash(state);
        // Hash sorted entries for determinism.
        let sorted = self.iter_sorted();
        for (k, v) in &sorted {
            k.hash(state);
            v.hash(state);
        }
    }
}
