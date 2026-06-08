// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Serialize / Deserialize for v5 NaN-boxed Value.

use std::fmt;

use arcstr::ArcStr;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq, Serializer};
use serde::{Deserialize, Serialize};

use super::object_map::ObjectMap;
use super::value::Value;

// ---------------------------------------------------------------------------
//  SortedValue wrapper — deterministic serialization
// ---------------------------------------------------------------------------

/// Wrapper that serializes a `Value` with sorted keys and sorted set elements.
pub struct SortedValue<'a>(pub &'a Value);

impl Serialize for SortedValue<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.0.is_object() {
            let o = self.0.as_object().unwrap();
            let sorted = o.iter_sorted();
            let mut map = serializer.serialize_map(Some(sorted.len()))?;
            for (k, v) in &sorted {
                let key_str = match k.as_str_ref() {
                    Some(s) => s.to_string(),
                    None => {
                        serde_json::to_string(k).map_err(serde::ser::Error::custom)?
                    }
                };
                map.serialize_entry(&key_str, &SortedValue(v))?;
            }
            map.end()
        } else if self.0.is_array() {
            let a = self.0.as_array().unwrap();
            let mut seq = serializer.serialize_seq(Some(a.len()))?;
            for v in a.iter() {
                seq.serialize_element(&SortedValue(v))?;
            }
            seq.end()
        } else if self.0.is_set() {
            let s = self.0.as_set().unwrap();
            let mut items: Vec<&Value> = s.iter().collect();
            items.sort();
            let mut seq = serializer.serialize_seq(Some(items.len()))?;
            for v in &items {
                seq.serialize_element(&SortedValue(v))?;
            }
            seq.end()
        } else {
            self.0.serialize(serializer)
        }
    }
}

// ---------------------------------------------------------------------------
//  Serialize
// ---------------------------------------------------------------------------

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.is_null() || self.is_undefined() {
            return serializer.serialize_unit();
        }
        if let Some(b) = self.as_bool() {
            return serializer.serialize_bool(b);
        }
        if self.is_number() {
            return serialize_number(self, serializer);
        }
        if let Some(s) = self.as_str_ref() {
            return serializer.serialize_str(s);
        }
        if let Some(a) = self.as_array() {
            let mut seq = serializer.serialize_seq(Some(a.len()))?;
            for v in a.iter() {
                seq.serialize_element(v)?;
            }
            return seq.end();
        }
        if let Some(s) = self.as_set() {
            let mut seq = serializer.serialize_seq(Some(s.len()))?;
            for v in s.iter() {
                seq.serialize_element(v)?;
            }
            return seq.end();
        }
        if let Some(o) = self.as_object() {
            let mut map = serializer.serialize_map(Some(o.len()))?;
            for (k, v) in o.iter() {
                let key_str = match k.as_str_ref() {
                    Some(s) => s.to_string(),
                    None => {
                        serde_json::to_string(&k).map_err(serde::ser::Error::custom)?
                    }
                };
                map.serialize_entry(&key_str, v)?;
            }
            return map.end();
        }
        serializer.serialize_unit()
    }
}

fn serialize_number<S: Serializer>(v: &Value, serializer: S) -> Result<S::Ok, S::Error> {
    // Try integer serialization first (most JSON numbers are integers).
    if let Some(u) = v.as_u64() {
        return serializer.serialize_u64(u);
    }
    if let Some(i) = v.as_i64() {
        return serializer.serialize_i64(i);
    }
    if let Some(f) = v.as_f64() {
        return serializer.serialize_f64(f);
    }
    // Fallback: format as string and parse as serde_json::Number.
    let s = v.format_number();
    let n = std::str::FromStr::from_str(&s)
        .map(|n: serde_json::Number| n)
        .map_err(|_| serde::ser::Error::custom("could not serialize number"))?;
    n.serialize(serializer)
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
        Ok(Value::null())
    }

    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::null())
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::bool_val(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Ok(Value::from_f64(v))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::from_arcstr(ArcStr::from(v)))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::from_arcstr(ArcStr::from(v.as_str())))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Value::from_array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut obj = ObjectMap::with_capacity(map.size_hint().unwrap_or(0));
        while let Some((key, value)) = map.next_entry::<String, Value>()? {
            obj.insert_str(ArcStr::from(key.as_str()), value);
        }
        Ok(Value::from_object(obj))
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
        Ok(Value::null())
    }

    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::null())
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::bool_val(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Ok(Value::from_f64(v))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::from_arcstr(ArcStr::from(v)))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::from_arcstr(ArcStr::from(v.as_str())))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(item) = seq.next_element::<Interned>()? {
            items.push(item.0);
        }
        Ok(Value::from_array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        use super::interner::intern;
        let mut obj = ObjectMap::with_capacity(map.size_hint().unwrap_or(0));
        while let Some((key, value)) = map.next_entry::<String, Interned>()? {
            obj.insert_str(intern(&key), value.0);
        }
        Ok(Value::from_object(obj))
    }
}
