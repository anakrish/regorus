// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use hashbrown::HashSet;

use super::number::Number;
use super::object_map::ObjectMap;

/// A Rego value with HashSet for sets and precomputed hashes in objects.
///
/// Key differences from v2:
/// - `Set` uses `HashSet<Value>` instead of `BTreeSet<Value>`.
/// - `Hash` for both sets and objects uses order-independent hashing.
/// - Objects carry a precomputed hash for O(1) `Hash` and fast `PartialEq` rejection.
#[derive(Debug, Clone)]
pub enum Value {
    /// JSON null.
    Null,

    /// JSON boolean.
    Bool(bool),

    /// Numeric value.
    Number(Number),

    /// String value. `Arc<str>` for cheap cloning.
    String(Arc<str>),

    /// JSON array.
    Array(Arc<Vec<Value>>),

    /// A set of values (unordered — uses HashSet).
    Set(Arc<HashSet<Value>>),

    /// An object with precomputed hash and optimized key lookup.
    Object(Arc<ObjectMap>),

    /// Undefined value (absence of value).
    Undefined,
}

// ---------------------------------------------------------------------------
//  Construction helpers
// ---------------------------------------------------------------------------

impl Value {
    pub fn new_object() -> Value {
        Value::Object(Arc::new(ObjectMap::new()))
    }

    pub fn new_array() -> Value {
        Value::from(Vec::<Value>::new())
    }

    pub fn new_set() -> Value {
        Value::Set(Arc::new(HashSet::new()))
    }

    /// Index by string key with zero allocation for string-keyed objects.
    pub fn get_str(&self, key: &str) -> &Value {
        match self {
            Value::Object(obj) => obj.get_str(key).unwrap_or(&Value::Undefined),
            _ => &Value::Undefined,
        }
    }

    /// Returns a u8 ordinal for Rego's type ordering:
    ///   null < bool < number < string < array < object < set
    fn kind_ordinal(&self) -> u8 {
        match self {
            Value::Null => 0,
            Value::Bool(_) => 1,
            Value::Number(_) => 2,
            Value::String(_) => 3,
            Value::Array(_) => 4,
            Value::Object(_) => 5,
            Value::Set(_) => 6,
            Value::Undefined => 7,
        }
    }

    /// Hash the *content* of this value using the given hasher.
    /// This is used by ObjectMap's entry_hash to compute per-entry hashes.
    /// It differs from the `Hash` trait impl: for sets and objects it hashes
    /// in a deterministic order (sorted), since entry_hash needs a canonical
    /// per-entry digest.
    pub(crate) fn hash_content<H: Hasher>(&self, state: &mut H) {
        self.kind_ordinal().hash(state);
        match self {
            Value::Null | Value::Undefined => {}
            Value::Bool(b) => b.hash(state),
            Value::Number(n) => n.hash(state),
            Value::String(s) => s.hash(state),
            Value::Array(a) => {
                a.len().hash(state);
                for v in a.iter() {
                    v.hash_content(state);
                }
            }
            Value::Set(s) => {
                s.len().hash(state);
                // For content hashing inside an entry_hash, we need determinism.
                // Use order-independent hashing: sum per-element hashes.
                let mut combined: u64 = 0;
                for v in s.iter() {
                    let mut eh = std::collections::hash_map::DefaultHasher::new();
                    v.hash_content(&mut eh);
                    combined = combined.wrapping_add(eh.finish());
                }
                combined.hash(state);
            }
            Value::Object(o) => {
                o.len().hash(state);
                o.cached_hash().hash(state);
            }
        }
    }

    /// Compute an order-independent hash for a set (sum of per-element hashes).
    fn set_hash(s: &HashSet<Value>) -> u64 {
        let mut combined: u64 = 0;
        for v in s.iter() {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            v.hash_content(&mut h);
            combined = combined.wrapping_add(h.finish());
        }
        combined
    }
}

// ---------------------------------------------------------------------------
//  From impls
// ---------------------------------------------------------------------------

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(Arc::from(s))
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(Arc::from(s.as_str()))
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Value::Number(Number::from(n))
    }
}

impl From<u64> for Value {
    fn from(n: u64) -> Self {
        Value::Number(Number::from(n))
    }
}

impl From<i32> for Value {
    fn from(n: i32) -> Self {
        Value::Number(Number::from(n as i64))
    }
}

impl From<u32> for Value {
    fn from(n: u32) -> Self {
        Value::Number(Number::from(n as u64))
    }
}

impl From<f64> for Value {
    fn from(n: f64) -> Self {
        Value::Number(Number::Float(n))
    }
}

impl From<Vec<Value>> for Value {
    fn from(a: Vec<Value>) -> Self {
        Value::Array(Arc::new(a))
    }
}

impl From<HashSet<Value>> for Value {
    fn from(s: HashSet<Value>) -> Self {
        Value::Set(Arc::new(s))
    }
}

impl From<BTreeSet<Value>> for Value {
    fn from(s: BTreeSet<Value>) -> Self {
        // Convert BTreeSet to HashSet
        let hs: HashSet<Value> = s.into_iter().collect();
        Value::Set(Arc::new(hs))
    }
}

impl From<BTreeMap<Value, Value>> for Value {
    fn from(m: BTreeMap<Value, Value>) -> Self {
        Value::Object(Arc::new(ObjectMap::from_pairs(m)))
    }
}

impl From<ObjectMap> for Value {
    fn from(m: ObjectMap) -> Self {
        Value::Object(Arc::new(m))
    }
}

// ---------------------------------------------------------------------------
//  Eq — fast paths with Arc::ptr_eq and hash-based rejection
// ---------------------------------------------------------------------------

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Undefined, Value::Undefined) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Number(a), Value::Number(b)) => a == b,
            (Value::String(a), Value::String(b)) => Arc::ptr_eq(a, b) || a == b,
            (Value::Array(a), Value::Array(b)) => Arc::ptr_eq(a, b) || a == b,
            (Value::Set(a), Value::Set(b)) => {
                if Arc::ptr_eq(a, b) {
                    return true;
                }
                if a.len() != b.len() {
                    return false;
                }
                // Each element in a must exist in b.
                a.iter().all(|v| b.contains(v))
            }
            (Value::Object(a), Value::Object(b)) => Arc::ptr_eq(a, b) || a == b,
            _ => false,
        }
    }
}

impl Eq for Value {}

// ---------------------------------------------------------------------------
//  Ord — kept for Rego comparison operators
// ---------------------------------------------------------------------------

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Value {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;

        let ka = self.kind_ordinal();
        let kb = other.kind_ordinal();
        if ka != kb {
            return ka.cmp(&kb);
        }

        match (self, other) {
            (Value::Null, Value::Null) => Ordering::Equal,
            (Value::Undefined, Value::Undefined) => Ordering::Equal,
            (Value::Bool(a), Value::Bool(b)) => a.cmp(b),
            (Value::Number(a), Value::Number(b)) => a.cmp(b),
            (Value::String(a), Value::String(b)) => a.as_ref().cmp(b.as_ref()),
            (Value::Array(a), Value::Array(b)) => a.as_ref().cmp(b.as_ref()),
            (Value::Set(a), Value::Set(b)) => {
                // Sort both sets for deterministic comparison.
                let mut a_sorted: Vec<&Value> = a.iter().collect();
                let mut b_sorted: Vec<&Value> = b.iter().collect();
                a_sorted.sort();
                b_sorted.sort();
                a_sorted.cmp(&b_sorted)
            }
            (Value::Object(a), Value::Object(b)) => a.cmp(b),
            _ => Ordering::Equal,
        }
    }
}

// ---------------------------------------------------------------------------
//  Hash — order-independent for sets and objects
// ---------------------------------------------------------------------------

impl Hash for Value {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.kind_ordinal().hash(state);
        match self {
            Value::Null | Value::Undefined => {}
            Value::Bool(b) => b.hash(state),
            Value::Number(n) => n.hash(state),
            Value::String(s) => s.hash(state),
            Value::Array(a) => {
                a.len().hash(state);
                for v in a.iter() {
                    v.hash(state);
                }
            }
            Value::Set(s) => {
                s.len().hash(state);
                // Order-independent: feed the sum into the outer hasher.
                Value::set_hash(s).hash(state);
            }
            Value::Object(o) => o.hash(state),
        }
    }
}

// ---------------------------------------------------------------------------
//  Display
// ---------------------------------------------------------------------------

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => write!(f, "{s}"),
            Err(_) => Err(std::fmt::Error),
        }
    }
}

// ---------------------------------------------------------------------------
//  Index impls
// ---------------------------------------------------------------------------

impl std::ops::Index<&Value> for Value {
    type Output = Value;

    fn index(&self, key: &Value) -> &Self::Output {
        match (self, key) {
            (Value::Object(o), _) => o.get(key).unwrap_or(&Value::Undefined),
            (Value::Set(s), _) => {
                if let Some(v) = s.get(key) {
                    v
                } else {
                    &Value::Undefined
                }
            }
            (Value::Array(a), Value::Number(n)) => match n.as_u64() {
                Some(idx) if (idx as usize) < a.len() => &a[idx as usize],
                _ => &Value::Undefined,
            },
            _ => &Value::Undefined,
        }
    }
}

impl<T> std::ops::Index<T> for Value
where
    Value: From<T>,
{
    type Output = Value;

    fn index(&self, key: T) -> &Self::Output {
        &self[&Value::from(key)]
    }
}

// ---------------------------------------------------------------------------
//  Conversion from regorus::Value (for benchmarks)
// ---------------------------------------------------------------------------

impl Value {
    /// Convert from regorus::Value (baseline) to v3::Value.
    pub fn from_regorus(v: &regorus::Value) -> Self {
        match v {
            regorus::Value::Null => Value::Null,
            regorus::Value::Bool(b) => Value::Bool(*b),
            regorus::Value::String(s) => Value::String(Arc::from(s.as_ref())),
            regorus::Value::Number(_) => {
                let json_str = v.to_json_str().unwrap_or_default();
                let parsed: Value = serde_json::from_str(&json_str).unwrap_or(Value::Null);
                parsed
            }
            regorus::Value::Array(a) => {
                let items: Vec<Value> = a.iter().map(Value::from_regorus).collect();
                Value::from(items)
            }
            regorus::Value::Set(s) => {
                let items: HashSet<Value> = s.iter().map(Value::from_regorus).collect();
                Value::from(items)
            }
            regorus::Value::Object(m) => {
                let obj = ObjectMap::from_regorus_btree(m);
                Value::Object(Arc::new(obj))
            }
            regorus::Value::Undefined => Value::Undefined,
        }
    }
}
