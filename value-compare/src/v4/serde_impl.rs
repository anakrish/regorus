// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Serialize / Deserialize for v4::Value.
//!
//! Same as v3 but uses `arcstr::ArcStr` instead of `Arc<str>`.

use std::fmt;
use std::sync::Arc;

use arcstr::ArcStr;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq, Serializer};
use serde::{Deserialize, Serialize};

use super::number::Number;
use super::object_map::ObjectMap;
use super::value::Value;

// ---------------------------------------------------------------------------
//  SortedValue wrapper — deterministic serialization
// ---------------------------------------------------------------------------

/// Wrapper that serializes a `Value` with sorted keys and sorted set elements.
pub struct SortedValue<'a>(pub &'a Value);

impl Serialize for SortedValue<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            Value::Object(o) => {
                let sorted = o.iter_sorted();
                let mut map = serializer.serialize_map(Some(sorted.len()))?;
                for (k, v) in &sorted {
                    let key_str = match k {
                        Value::String(s) => s.to_string(),
                        other => serde_json::to_string(other).map_err(serde::ser::Error::custom)?,
                    };
                    map.serialize_entry(&key_str, &SortedValue(v))?;
                }
                map.end()
            }
            Value::Array(a) => {
                let mut seq = serializer.serialize_seq(Some(a.len()))?;
                for v in a.iter() {
                    seq.serialize_element(&SortedValue(v))?;
                }
                seq.end()
            }
            Value::Set(s) => {
                let mut items: Vec<&Value> = s.iter().collect();
                items.sort();
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for v in &items {
                    seq.serialize_element(&SortedValue(v))?;
                }
                seq.end()
            }
            other => other.serialize(serializer),
        }
    }
}

// ---------------------------------------------------------------------------
//  Serialize
// ---------------------------------------------------------------------------

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Value::Null => serializer.serialize_unit(),
            Value::Undefined => serializer.serialize_unit(),
            Value::Bool(b) => serializer.serialize_bool(*b),
            Value::Number(n) => n.serialize(serializer),
            Value::String(s) => serializer.serialize_str(s),
            Value::Array(a) => {
                let mut seq = serializer.serialize_seq(Some(a.len()))?;
                for v in a.iter() {
                    seq.serialize_element(v)?;
                }
                seq.end()
            }
            Value::Set(s) => {
                let mut seq = serializer.serialize_seq(Some(s.len()))?;
                for v in s.iter() {
                    seq.serialize_element(v)?;
                }
                seq.end()
            }
            Value::Object(o) => {
                let mut map = serializer.serialize_map(Some(o.len()))?;
                for (k, v) in o.iter() {
                    let key_str = match &k {
                        Value::String(s) => s.to_string(),
                        other => serde_json::to_string(other).map_err(serde::ser::Error::custom)?,
                    };
                    map.serialize_entry(&key_str, v)?;
                }
                map.end()
            }
        }
    }
}

// ---------------------------------------------------------------------------
//  Deserialize
// ---------------------------------------------------------------------------

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ValueVisitor)
    }
}

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(Number::UInt(v)))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(Number::Int(v)))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Ok(Value::Number(Number::Float(v)))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(ArcStr::from(v)))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(ArcStr::from(v.as_str())))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(Arc::new(items)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut obj = ObjectMap::with_capacity(map.size_hint().unwrap_or(0));
        while let Some((key, value)) = map.next_entry::<String, Value>()? {
            obj.insert_str(ArcStr::from(key.as_str()), value);
        }
        Ok(Value::Object(Arc::new(obj)))
    }
}

// ---------------------------------------------------------------------------
//  Interned deserialization — reuses ArcStr for repeated keys
// ---------------------------------------------------------------------------

pub struct Interned(pub Value);

impl<'de> Deserialize<'de> for Interned {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_any(InternedValueVisitor)
            .map(Interned)
    }
}

struct InternedValueVisitor;

impl<'de> Visitor<'de> for InternedValueVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(Number::UInt(v)))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(Number::Int(v)))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Ok(Value::Number(Number::Float(v)))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(ArcStr::from(v)))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(ArcStr::from(v.as_str())))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(item) = seq.next_element::<Interned>()? {
            items.push(item.0);
        }
        Ok(Value::Array(Arc::new(items)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        use super::interner::intern;
        let mut obj = ObjectMap::with_capacity(map.size_hint().unwrap_or(0));
        while let Some((key, value)) = map.next_entry::<String, Interned>()? {
            obj.insert_str(intern(&key), value.0);
        }
        Ok(Value::Object(Arc::new(obj)))
    }
}
