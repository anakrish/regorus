// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use arcstr::ArcStr;
use hashbrown::HashSet;
use num_bigint::BigInt;

use super::number::Number;
use super::object_map::ObjectMap;

/// A Rego value — 16 bytes: ArcStr for strings, Number variants flattened.
///
/// Schema-shared compact objects via `ObjectMap`.
#[derive(Debug, Clone)]
pub enum Value {
    Null,
    Bool(bool),
    UInt(u64),
    Int(i64),
    Float(f64),
    BigInt(Arc<BigInt>),
    String(ArcStr),
    Array(Arc<Vec<Value>>),
    Set(Arc<HashSet<Value>>),
    Object(Arc<ObjectMap>),
    Undefined,
}

const _: () = assert!(std::mem::size_of::<Value>() == 16);

// ---------------------------------------------------------------------------
//  Number helpers
// ---------------------------------------------------------------------------

impl Value {
    /// Extract the number payload as a `Number`, if this is a numeric variant.
    pub fn as_number(&self) -> Option<Number> {
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

    pub fn get_str(&self, key: &str) -> &Value {
        match self {
            Value::Object(obj) => obj.get_str(key).unwrap_or(&Value::Undefined),
            _ => &Value::Undefined,
        }
    }

    pub fn is_number(&self) -> bool {
        matches!(self, Value::UInt(_) | Value::Int(_) | Value::Float(_) | Value::BigInt(_))
    }

    fn kind_ordinal(&self) -> u8 {
        match self {
            Value::Null => 0,
            Value::Bool(_) => 1,
            Value::UInt(_) | Value::Int(_) | Value::Float(_) | Value::BigInt(_) => 2,
            Value::String(_) => 3,
            Value::Array(_) => 4,
            Value::Object(_) => 5,
            Value::Set(_) => 6,
            Value::Undefined => 7,
        }
    }

    pub(crate) fn hash_content<H: Hasher>(&self, state: &mut H) {
        self.kind_ordinal().hash(state);
        match self {
            Value::Null | Value::Undefined => {}
            Value::Bool(b) => b.hash(state),
            Value::String(s) => s.as_str().hash(state),
            Value::Array(a) => {
                a.len().hash(state);
                for v in a.iter() {
                    v.hash_content(state);
                }
            }
            Value::Set(s) => {
                s.len().hash(state);
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
            // Number variants
            _ => self.as_number().unwrap().hash(state),
        }
    }

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
        Value::String(ArcStr::from(s))
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(ArcStr::from(s.as_str()))
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Value::Int(n)
    }
}

impl From<u64> for Value {
    fn from(n: u64) -> Self {
        Value::UInt(n)
    }
}

impl From<i32> for Value {
    fn from(n: i32) -> Self {
        Value::Int(n as i64)
    }
}

impl From<u32> for Value {
    fn from(n: u32) -> Self {
        Value::UInt(n as u64)
    }
}

impl From<f64> for Value {
    fn from(n: f64) -> Self {
        Value::Float(n)
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
            (Value::String(a), Value::String(b)) => ArcStr::ptr_eq(a, b) || a == b,
            (Value::Array(a), Value::Array(b)) => Arc::ptr_eq(a, b) || a == b,
            (Value::Set(a), Value::Set(b)) => {
                if Arc::ptr_eq(a, b) {
                    return true;
                }
                if a.len() != b.len() {
                    return false;
                }
                a.iter().all(|v| b.contains(v))
            }
            (Value::Object(a), Value::Object(b)) => Arc::ptr_eq(a, b) || a == b,
            _ => match (self.as_number(), other.as_number()) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            },
        }
    }
}

impl Eq for Value {}

// ---------------------------------------------------------------------------
//  Ord
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
            (Value::String(a), Value::String(b)) => a.as_str().cmp(b.as_str()),
            (Value::Array(a), Value::Array(b)) => a.as_ref().cmp(b.as_ref()),
            (Value::Set(a), Value::Set(b)) => {
                let mut a_sorted: Vec<&Value> = a.iter().collect();
                let mut b_sorted: Vec<&Value> = b.iter().collect();
                a_sorted.sort();
                b_sorted.sort();
                a_sorted.cmp(&b_sorted)
            }
            (Value::Object(a), Value::Object(b)) => a.cmp(b),
            // Same-kind numbers (ka == kb == 2)
            _ => self.as_number().unwrap().cmp(&other.as_number().unwrap()),
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
                s.len().hash(state);
                Value::set_hash(s).hash(state);
            }
            Value::Object(o) => o.hash(state),
            // Number variants
            _ => self.as_number().unwrap().hash(state),
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
            (Value::Array(a), _) => match key.as_number().and_then(|n| n.as_u64()) {
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
//  Conversion from regorus::Value
// ---------------------------------------------------------------------------

impl Value {
    pub fn from_regorus(v: &regorus::Value) -> Self {
        match v {
            regorus::Value::Null => Value::Null,
            regorus::Value::Bool(b) => Value::Bool(*b),
            regorus::Value::String(s) => Value::String(ArcStr::from(s.as_ref())),
            regorus::Value::Number(n) => {
                if let Some(u) = n.as_u64() {
                    Value::UInt(u)
                } else if let Some(i) = n.as_i64() {
                    Value::Int(i)
                } else if let Some(f) = n.as_f64() {
                    Value::Float(f)
                } else {
                    // Fallback: parse via JSON
                    let json_str = v.to_json_str().unwrap_or_default();
                    serde_json::from_str(&json_str).unwrap_or(Value::Null)
                }
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

    /// Materialize back to a `regorus::Value`.
    pub fn to_regorus(&self) -> regorus::Value {
        match self {
            Value::Null => regorus::Value::Null,
            Value::Bool(b) => regorus::Value::Bool(*b),
            Value::Undefined => regorus::Value::Undefined,
            Value::String(s) => regorus::Value::String(regorus::Rc::from(s.as_str())),
            Value::UInt(u) => regorus::Value::Number((*u).into()),
            Value::Int(i) => regorus::Value::Number((*i).into()),
            Value::Float(f) => regorus::Value::Number((*f).into()),
            Value::BigInt(b) => regorus::Value::Number((**b).clone().into()),
            Value::Array(a) => {
                let items: Vec<regorus::Value> = a.iter().map(|v| v.to_regorus()).collect();
                regorus::Value::Array(regorus::Rc::new(items))
            }
            Value::Set(s) => {
                let items: std::collections::BTreeSet<regorus::Value> =
                    s.iter().map(|v| v.to_regorus()).collect();
                regorus::Value::Set(regorus::Rc::new(items))
            }
            Value::Object(o) => {
                let items: std::collections::BTreeMap<regorus::Value, regorus::Value> =
                    o.iter().map(|(k, v)| (k.to_regorus(), v.to_regorus())).collect();
                regorus::Value::Object(regorus::Rc::new(items))
            }
        }
    }
}
