// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Serialization and deserialization for v9 arena-allocated values.
//!
//! - `from_json` — parse JSON directly into an arena using `DeserializeSeed`.
//! - `from_json_interned` — same, with string deduplication.
//! - `Serialize` — standard serde serialization (reads arena data).
//! - `SortedValue` — deterministic serialization with sorted keys/sets.

use std::fmt;

use bumpalo::Bump;
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq, Serializer};
use serde::Serialize;

use super::object_map::{intern_schema, ObjectMap};
use super::value::{ArenaArray, ArenaStr, ArenaValue, Value};

// ═══════════════════════════════════════════════════════════════════════════
//  Public entry points
// ═══════════════════════════════════════════════════════════════════════════

/// Parse a JSON string directly into arena-allocated `Value`s.
pub fn from_json<'a>(arena: &'a Bump, json: &str) -> Result<Value<'a>, serde_json::Error> {
    let mut de = serde_json::Deserializer::from_str(json);
    let seed = ArenaSeed { arena };
    DeserializeSeed::deserialize(seed, &mut de)
}

/// Parse a JSON string into arena-allocated `Value`s with string interning.
///
/// Repeated string values (e.g. object keys) are deduplicated — only one copy
/// is allocated in the arena.
pub fn from_json_interned<'a>(
    arena: &'a Bump,
    interner: &mut StringInterner<'a>,
    json: &str,
) -> Result<Value<'a>, serde_json::Error> {
    let mut de = serde_json::Deserializer::from_str(json);
    let seed = InternedArenaSeed { arena, interner };
    DeserializeSeed::deserialize(seed, &mut de)
}

// ═══════════════════════════════════════════════════════════════════════════
//  StringInterner
// ═══════════════════════════════════════════════════════════════════════════

/// Deduplicates strings within an arena.
pub struct StringInterner<'a> {
    set: hashbrown::HashSet<&'a str>,
    arena: &'a Bump,
}

impl<'a> StringInterner<'a> {
    pub fn new(arena: &'a Bump) -> Self {
        StringInterner {
            set: hashbrown::HashSet::new(),
            arena,
        }
    }

    pub fn intern(&mut self, s: &str) -> &'a str {
        if let Some(&existing) = self.set.get(s) {
            existing
        } else {
            let interned = self.arena.alloc_str(s);
            self.set.insert(interned);
            interned
        }
    }

    /// Clear the interner cache (arena allocations remain).
    pub fn clear(&mut self) {
        self.set.clear();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Non-interned deserialization via DeserializeSeed
// ═══════════════════════════════════════════════════════════════════════════

struct ArenaSeed<'a> {
    arena: &'a Bump,
}

impl<'a, 'de> DeserializeSeed<'de> for ArenaSeed<'a> {
    type Value = Value<'a>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value<'a>, D::Error> {
        deserializer.deserialize_any(ArenaVisitor { arena: self.arena })
    }
}

struct ArenaVisitor<'a> {
    arena: &'a Bump,
}

impl<'a, 'de> Visitor<'de> for ArenaVisitor<'a> {
    type Value = Value<'a>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value<'a>, E> {
        Ok(Value::Arena(ArenaValue::Null))
    }

    fn visit_none<E: de::Error>(self) -> Result<Value<'a>, E> {
        Ok(Value::Arena(ArenaValue::Null))
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value<'a>, E> {
        Ok(Value::Arena(ArenaValue::Bool(v)))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value<'a>, E> {
        Ok(Value::Arena(ArenaValue::UInt(v)))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value<'a>, E> {
        Ok(Value::Arena(ArenaValue::Int(v)))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value<'a>, E> {
        Ok(Value::Arena(ArenaValue::Float(v)))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value<'a>, E> {
        Ok(Value::Arena(ArenaValue::String(self.arena.alloc(ArenaStr(self.arena.alloc_str(v))))))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Value<'a>, E> {
        Ok(Value::Arena(ArenaValue::String(self.arena.alloc(ArenaStr(self.arena.alloc_str(&v))))))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value<'a>, A::Error> {
        let mut items = bumpalo::collections::Vec::new_in(self.arena);
        while let Some(item) = seq.next_element_seed(ArenaSeed { arena: self.arena })? {
            items.push(item);
        }
        Ok(Value::Arena(ArenaValue::Array(self.arena.alloc(ArenaArray(items.into_bump_slice())))))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value<'a>, A::Error> {
        let arena = self.arena;
        let cap = map.size_hint().unwrap_or(0);
        let mut keys: Vec<&'a str> = Vec::with_capacity(cap);
        let mut values: Vec<Value<'a>> = Vec::with_capacity(cap);

        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value_seed(ArenaSeed { arena })?;
            let key_str = arena.alloc_str(&key);
            keys.push(key_str);
            values.push(value);
        }

        if keys.is_empty() {
            return Ok(Value::Arena(ArenaValue::Object(arena.alloc(ObjectMap::new_in(arena)))));
        }

        // Intern schema for same-schema equality fast path.
        let schema = intern_schema(&keys);

        // Reorder keys and values to schema sort order.
        let n = keys.len();
        let mut sorted_keys: Vec<&'a str> = vec![""; n];
        let mut sorted_values: Vec<Value<'a>> = vec![Value::Arena(ArenaValue::Null); n];
        for (k, v) in keys.iter().zip(values.iter()) {
            let &idx = schema.lookup.get(*k).unwrap();
            sorted_keys[idx as usize] = *k;
            sorted_values[idx as usize] = *v;
        }

        Ok(Value::Arena(ArenaValue::Object(arena.alloc(
            ObjectMap::from_schema_values(arena, schema, &sorted_keys, &sorted_values),
        ))))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Interned deserialization via DeserializeSeed
// ═══════════════════════════════════════════════════════════════════════════

struct InternedArenaSeed<'a, 'i> {
    arena: &'a Bump,
    interner: &'i mut StringInterner<'a>,
}

impl<'a, 'i, 'de> DeserializeSeed<'de> for InternedArenaSeed<'a, 'i> {
    type Value = Value<'a>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value<'a>, D::Error> {
        deserializer.deserialize_any(InternedArenaVisitor {
            arena: self.arena,
            interner: self.interner,
        })
    }
}

struct InternedArenaVisitor<'a, 'i> {
    arena: &'a Bump,
    interner: &'i mut StringInterner<'a>,
}

impl<'a, 'i, 'de> Visitor<'de> for InternedArenaVisitor<'a, 'i> {
    type Value = Value<'a>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value<'a>, E> {
        Ok(Value::Arena(ArenaValue::Null))
    }

    fn visit_none<E: de::Error>(self) -> Result<Value<'a>, E> {
        Ok(Value::Arena(ArenaValue::Null))
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value<'a>, E> {
        Ok(Value::Arena(ArenaValue::Bool(v)))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value<'a>, E> {
        Ok(Value::Arena(ArenaValue::UInt(v)))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value<'a>, E> {
        Ok(Value::Arena(ArenaValue::Int(v)))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value<'a>, E> {
        Ok(Value::Arena(ArenaValue::Float(v)))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value<'a>, E> {
        let s = self.interner.intern(v);
        Ok(Value::Arena(ArenaValue::String(self.arena.alloc(ArenaStr(s)))))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Value<'a>, E> {
        let s = self.interner.intern(&v);
        Ok(Value::Arena(ArenaValue::String(self.arena.alloc(ArenaStr(s)))))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value<'a>, A::Error> {
        let arena = self.arena;
        let interner = self.interner;
        let mut items = bumpalo::collections::Vec::new_in(arena);
        while let Some(item) = seq.next_element_seed(InternedArenaSeed {
            arena,
            interner: &mut *interner,
        })? {
            items.push(item);
        }
        Ok(Value::Arena(ArenaValue::Array(arena.alloc(ArenaArray(items.into_bump_slice())))))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value<'a>, A::Error> {
        let arena = self.arena;
        let interner = self.interner;
        let cap = map.size_hint().unwrap_or(0);
        let mut keys: Vec<&'a str> = Vec::with_capacity(cap);
        let mut values: Vec<Value<'a>> = Vec::with_capacity(cap);

        while let Some(key) = map.next_key::<String>()? {
            let key_str = interner.intern(&key);
            let value = map.next_value_seed(InternedArenaSeed {
                arena,
                interner: &mut *interner,
            })?;
            keys.push(key_str);
            values.push(value);
        }

        if keys.is_empty() {
            return Ok(Value::Arena(ArenaValue::Object(arena.alloc(ObjectMap::new_in(arena)))));
        }

        // Intern schema for same-schema equality fast path.
        let schema = intern_schema(&keys);

        // Reorder keys and values to schema sort order.
        let n = keys.len();
        let mut sorted_keys: Vec<&'a str> = vec![""; n];
        let mut sorted_values: Vec<Value<'a>> = vec![Value::Arena(ArenaValue::Null); n];
        for (k, v) in keys.iter().zip(values.iter()) {
            let &idx = schema.lookup.get(*k).unwrap();
            sorted_keys[idx as usize] = *k;
            sorted_values[idx as usize] = *v;
        }

        Ok(Value::Arena(ArenaValue::Object(arena.alloc(
            ObjectMap::from_schema_values(arena, schema, &sorted_keys, &sorted_values),
        ))))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Serialize
// ═══════════════════════════════════════════════════════════════════════════

impl Serialize for Value<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Value::Arena(inner) => inner.serialize(serializer),
            Value::Ext(ext) => ext.serialize(serializer),
        }
    }
}

impl Serialize for ArenaValue<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            ArenaValue::Null | ArenaValue::Undefined => serializer.serialize_unit(),
            ArenaValue::Bool(b) => serializer.serialize_bool(*b),
            ArenaValue::String(s) => serializer.serialize_str(s.0),
            ArenaValue::Array(a) => {
                let mut seq = serializer.serialize_seq(Some(a.0.len()))?;
                for v in a.0.iter() {
                    seq.serialize_element(v)?;
                }
                seq.end()
            }
            ArenaValue::Set(s) => {
                let mut seq = serializer.serialize_seq(Some(s.len()))?;
                for v in s.iter() {
                    seq.serialize_element(v)?;
                }
                seq.end()
            }
            ArenaValue::Object(o) => {
                let mut map = serializer.serialize_map(Some(o.len()))?;
                for (k, v) in o.iter() {
                    let key_str = match k.as_str_ref() {
                        Some(s) => s.to_string(),
                        None => serde_json::to_string(&k)
                            .map_err(serde::ser::Error::custom)?,
                    };
                    map.serialize_entry(&key_str, v)?;
                }
                map.end()
            }
            _ => self.as_number().unwrap().serialize(serializer),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  SortedValue — deterministic serialization
// ═══════════════════════════════════════════════════════════════════════════

/// Wrapper for deterministic serialization (sorted keys, sorted sets).
pub struct SortedValue<'a>(pub &'a Value<'a>);

impl Serialize for SortedValue<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Value::Arena(ArenaValue::Object(o)) => {
                let sorted = o.iter_sorted();
                let mut map = serializer.serialize_map(Some(sorted.len()))?;
                for (k, v) in &sorted {
                    let key_str = match k.as_str_ref() {
                        Some(s) => s.to_string(),
                        None => serde_json::to_string(k)
                            .map_err(serde::ser::Error::custom)?,
                    };
                    map.serialize_entry(&key_str, &SortedValue(v))?;
                }
                map.end()
            }
            Value::Arena(ArenaValue::Array(a)) => {
                let mut seq = serializer.serialize_seq(Some(a.0.len()))?;
                for v in a.0.iter() {
                    seq.serialize_element(&SortedValue(v))?;
                }
                seq.end()
            }
            Value::Arena(ArenaValue::Set(s)) => {
                // Sort elements for deterministic output.
                let mut elems: Vec<_> = s.iter().copied().collect();
                elems.sort_unstable();
                let mut seq = serializer.serialize_seq(Some(elems.len()))?;
                for v in &elems {
                    seq.serialize_element(&SortedValue(v))?;
                }
                seq.end()
            }
            // Ref and other leaf variants delegate to Value::serialize
            other => other.serialize(serializer),
        }
    }
}
