// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ObjectMap — same design as v5 but with v6 tagged-pointer `Value`.

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
    strings: HashMap<ArcStr, Value>,
    other: Option<HashMap<Value, Value>>,
    cached_hash: u64,
}

impl ObjectMap {
    pub fn new() -> Self {
        ObjectMap {
            strings: HashMap::new(),
            other: None,
            cached_hash: 0,
        }
    }

    pub fn with_capacity(cap: usize) -> Self {
        ObjectMap {
            strings: HashMap::with_capacity(cap),
            other: None,
            cached_hash: 0,
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
        let mut obj = ObjectMap::with_capacity(m.len());
        for (k, v) in m {
            let key = Value::from_regorus(k);
            let val = Value::from_regorus(v);
            obj.insert(key, val);
        }
        obj
    }

    pub fn get_str(&self, key: &str) -> Option<&Value> {
        self.strings.get(key)
    }

    pub fn get(&self, key: &Value) -> Option<&Value> {
        if let Some(s) = key.as_str_ref() {
            self.strings.get(s)
        } else {
            self.other.as_ref().and_then(|m| m.get(key))
        }
    }

    pub fn insert_str(&mut self, key: ArcStr, value: Value) {
        let kv = Value::from_arcstr(key.clone());
        if let Some(old_val) = self.strings.get(key.as_str()) {
            self.cached_hash = self.cached_hash.wrapping_sub(entry_hash(&kv, old_val));
        }
        self.cached_hash = self.cached_hash.wrapping_add(entry_hash(&kv, &value));
        self.strings.insert(key, value);
    }

    pub fn insert(&mut self, key: Value, value: Value) {
        if let Some(s) = key.as_str_ref() {
            let arc = ArcStr::from(s);
            self.insert_str(arc, value);
        } else {
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

    pub fn len(&self) -> usize {
        self.strings.len() + self.other.as_ref().map_or(0, |m| m.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn cached_hash(&self) -> u64 {
        self.cached_hash
    }

    pub fn iter(&self) -> ObjectMapIter<'_> {
        ObjectMapIter {
            string_iter: self.strings.iter(),
            other_iter: self.other.as_ref().map(|m| m.iter()),
        }
    }

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
            return Some((Value::from_arcstr(k.clone()), v));
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
//  Ord
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
