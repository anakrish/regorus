// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(
    clippy::indexing_slicing,
    clippy::shadow_unrelated,
    clippy::option_if_let_else,
    clippy::semicolon_if_nothing_returned,
    clippy::pattern_type_mismatch,
    clippy::unused_trait_names,
    clippy::as_conversions
)] // value helpers index paths directly for performance

use crate::collections::{Map, Set, SMALL_OBJECT_INLINE, SMALL_SET_INLINE};
use crate::number::Number;
use crate::CIString;

use alloc::vec::Vec;
use core::fmt;
use core::ops;

use core::convert::AsRef;
use core::str::FromStr;

use anyhow::{anyhow, bail, Result};
use serde::de::{self, Deserializer, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};

use crate::*;
use smallvec::SmallVec;

/// A value in a Rego document.
///
/// Value is similar to a [`serde_json::value::Value`], but has the following additional
/// capabilities:
///    - [`Value::Set`] variant to represent sets.
///    - [`Value::Undefined`] variant to represent absence of value.
//     - [`Value::Object`] keys can be other values, not just strings.
///    - [`Value::Number`] has at least 100 digits of precision for computations.
///
/// Value can be efficiently cloned due to the use of reference counting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// JSON null.
    Null,

    /// JSON boolean.
    Bool(bool),

    /// JSON number.
    /// At least 100 digits of precision.
    Number(Number),

    /// JSON string.
    String(Rc<str>),

    /// JSON array.
    Array(Rc<Vec<Value>>),

    /// A set of values.
    /// No JSON equivalent.
    /// Sets are serialized as arrays in JSON.
    Set(Rc<SetStorage<Value>>),

    /// An object.
    /// Unlike JSON, keys can be any value, not just string (in general mode).
    Object(Rc<ObjectStorage>),

    /// Undefined value.
    /// Used to indicate the absence of a value.
    Undefined,
}

#[inline]
fn enforce_limit_anyhow() -> Result<()> {
    crate::utils::limits::check_memory_limit_if_needed().map_err(|err| anyhow!(err))
}

#[inline]
fn enforce_limit_for<E: DeError>() -> core::result::Result<(), E> {
    crate::utils::limits::check_memory_limit_if_needed().map_err(|err| E::custom(err.to_string()))
}

#[doc(hidden)]
impl Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::Error;
        match self {
            Value::Null => serializer.serialize_unit(),
            Value::Bool(b) => serializer.serialize_bool(*b),
            Value::String(s) => serializer.serialize_str(s.as_ref()),
            Value::Number(n) => n.serialize(serializer),
            Value::Array(a) => a.serialize(serializer),
            Value::Object(fields) => {
                let mut map = serializer.serialize_map(Some(fields.len()))?;
                for (k, v) in fields.iter() {
                    match &k {
                        Value::String(_) => map.serialize_entry(&k, v)?,
                        _ => {
                            let key_str = serde_json::to_string(&k).map_err(Error::custom)?;
                            map.serialize_entry(&key_str, v)?
                        }
                    }
                }
                map.end()
            }

            // display set as an array
            Value::Set(s) => s.serialize(serializer),

            // display undefined as a special string
            Value::Undefined => serializer.serialize_str("<undefined>"),
        }
    }
}

struct ValueVisitor;

impl<T: Serialize + Eq + core::hash::Hash> Serialize for SetStorage<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        for v in self.iter() {
            seq.serialize_element(v)?;
        }
        seq.end()
    }
}

#[doc(hidden)]
impl<'de> Deserialize<'de> for Value {
    fn deserialize<D>(deserializer: D) -> Result<Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ValueVisitor)
    }
}

impl fmt::Display for Value {
    /// Display a value.
    ///
    /// A value is displayed by serializing it to JSON using serde_json::to_string.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from("hello");
    /// assert_eq!(format!("{v}"), "\"hello\"");
    /// # Ok(())
    /// # }
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => write!(f, "{s}"),
            Err(_e) => Err(fmt::Error),
        }
    }
}

// Storage for objects: small inline map promoted to hash map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectStorage {
    General(ObjectStore<Value>),
    CaseInsensitive(ObjectStore<CIString>),
}

#[derive(Clone, Debug)]
pub enum SetStorage<T> {
    Small(SmallVec<[T; SMALL_SET_INLINE]>),
    Hash(Set<T>),
}

impl<T: PartialEq + Eq + core::hash::Hash> PartialEq for SetStorage<T> {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        match (self, other) {
            (SetStorage::Small(a), SetStorage::Small(b)) => a == b,
            (SetStorage::Hash(a), SetStorage::Hash(b)) => a == b,
            // Different variants but same elements
            _ => {
                // Compare element by element
                self.iter().all(|v| other.contains(v))
            }
        }
    }
}

impl<T: Eq + core::hash::Hash> Eq for SetStorage<T> {}

#[derive(Clone, Debug)]
pub enum ObjectStore<K> {
    Small(SmallVec<[(K, Value); SMALL_OBJECT_INLINE]>),
    Hash(Map<K, Value>),
}

impl<K: PartialEq + Eq + core::hash::Hash> PartialEq for ObjectStore<K> {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        match (self, other) {
            (ObjectStore::Small(a), ObjectStore::Small(b)) => a == b,
            (ObjectStore::Hash(a), ObjectStore::Hash(b)) => a == b,
            // Different variants: compare key-value pairs
            _ => {
                match self {
                    ObjectStore::Small(sv) => sv.iter().all(|(k, v)| other.get(k) == Some(v)),
                    ObjectStore::Hash(map) => map.iter().all(|(k, v)| other.get(k) == Some(v)),
                }
            }
        }
    }
}

impl<K: Eq + core::hash::Hash> Eq for ObjectStore<K> {}

impl<K> ObjectStore<K> {
    pub fn len(&self) -> usize {
        match self {
            ObjectStore::Small(sv) => sv.len(),
            ObjectStore::Hash(map) => map.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<K: Eq + core::hash::Hash> ObjectStore<K> {
    pub fn get(&self, key: &K) -> Option<&Value> {
        match self {
            ObjectStore::Small(sv) => sv.iter().find_map(|(k, v)| if k == key { Some(v) } else { None }),
            ObjectStore::Hash(map) => map.get(key),
        }
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut Value> {
        match self {
            ObjectStore::Small(sv) => sv.iter_mut().find_map(|(k, v)| if k == key { Some(v) } else { None }),
            ObjectStore::Hash(map) => map.get_mut(key),
        }
    }

    pub fn insert(&mut self, key: K, value: Value) -> Option<Value> {
        match self {
            ObjectStore::Small(sv) => {
                if let Some((_, v)) = sv.iter_mut().find(|(k, _)| k == &key) {
                    return Some(core::mem::replace(v, value));
                }
                if sv.len() < SMALL_OBJECT_INLINE {
                    sv.push((key, value));
                    None
                } else {
                    let mut map: Map<K, Value> = Map::with_capacity_and_hasher(sv.len(), crate::collections::DefaultBuildHasher::default());
                    for (k, v) in sv.drain(..) {
                        map.insert(k, v);
                    }
                    let old = map.insert(key, value);
                    *self = ObjectStore::Hash(map);
                    old
                }
            }
            ObjectStore::Hash(map) => map.insert(key, value),
        }
    }

    pub fn iter(&self) -> ObjectStoreIter<'_, K> {
        match self {
            ObjectStore::Small(sv) => ObjectStoreIter::Small(sv.iter()),
            ObjectStore::Hash(map) => ObjectStoreIter::Hash(map.iter()),
        }
    }

    pub fn iter_mut(&mut self) -> ObjectStoreIterMut<'_, K> {
        match self {
            ObjectStore::Small(sv) => ObjectStoreIterMut::Small(sv.iter_mut()),
            ObjectStore::Hash(map) => ObjectStoreIterMut::Hash(map.iter_mut()),
        }
    }
}

pub enum ObjectStoreIter<'a, K> {
    Small(core::slice::Iter<'a, (K, Value)>),
    Hash(hashbrown::hash_map::Iter<'a, K, Value>),
}

impl<'a, K> fmt::Debug for ObjectStoreIter<'a, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectStoreIter").finish()
    }
}

impl<'a, K> Iterator for ObjectStoreIter<'a, K>
where
    K: Clone,
{
    type Item = (K, &'a Value);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ObjectStoreIter::Small(iter) => iter.next().map(|(k, v)| (k.clone(), v)),
            ObjectStoreIter::Hash(iter) => iter.next().map(|(k, v)| (k.clone(), v)),
        }
    }
}

pub enum ObjectStoreIterMut<'a, K> {
    Small(core::slice::IterMut<'a, (K, Value)>),
    Hash(hashbrown::hash_map::IterMut<'a, K, Value>),
}

impl<'a, K> fmt::Debug for ObjectStoreIterMut<'a, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectStoreIterMut").finish()
    }
}

impl<'a, K> Iterator for ObjectStoreIterMut<'a, K>
where
    K: Clone,
{
    type Item = (K, &'a mut Value);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ObjectStoreIterMut::Small(iter) => iter.next().map(|(k, v)| (k.clone(), v)),
            ObjectStoreIterMut::Hash(iter) => iter.next().map(|(k, v)| (k.clone(), v)),
        }
    }
}

impl<T> SetStorage<T> {
    pub fn len(&self) -> usize {
        match self {
            SetStorage::Small(sv) => sv.len(),
            SetStorage::Hash(set) => set.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T: Eq + core::hash::Hash> SetStorage<T> {
    pub fn contains(&self, value: &T) -> bool {
        match self {
            SetStorage::Small(sv) => sv.contains(value),
            SetStorage::Hash(set) => set.contains(value),
        }
    }

    pub fn insert(&mut self, value: T) -> bool {
        match self {
            SetStorage::Small(sv) => {
                if sv.contains(&value) {
                    return false;
                }
                if sv.len() < SMALL_SET_INLINE {
                    sv.push(value);
                    true
                } else {
                    let mut set: Set<T> = Set::with_capacity_and_hasher(sv.len(), crate::collections::DefaultBuildHasher::default());
                    for v in sv.drain(..) {
                        set.insert(v);
                    }
                    let inserted = set.insert(value);
                    *self = SetStorage::Hash(set);
                    inserted
                }
            }
            SetStorage::Hash(set) => set.insert(value),
        }
    }

    pub fn iter(&self) -> SetIter<'_, T> {
        match self {
            SetStorage::Small(sv) => SetIter::Small(sv.iter()),
            SetStorage::Hash(set) => SetIter::Hash(set.iter()),
        }
    }

    pub fn get(&self, value: &T) -> Option<&T> {
        match self {
            SetStorage::Small(sv) => sv.iter().find(|v| *v == value),
            SetStorage::Hash(set) => set.get(value),
        }
    }

    pub fn append(&mut self, other: &mut SetStorage<T>) {
        match other {
            SetStorage::Small(sv) => {
                for v in sv.drain(..) {
                    self.insert(v);
                }
            }
            SetStorage::Hash(set) => {
                for v in set.drain() {
                    self.insert(v);
                }
            }
        }
    }
}

pub enum SetIter<'a, T> {
    Small(core::slice::Iter<'a, T>),
    Hash(hashbrown::hash_set::Iter<'a, T>),
}

impl<'a, T> fmt::Debug for SetIter<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetIter").finish()
    }
}

impl<'a, T> Iterator for SetIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            SetIter::Small(iter) => iter.next(),
            SetIter::Hash(iter) => iter.next(),
        }
    }
}

#[derive(Debug)]
pub struct ObjectEntries<'a> {
    inner: ObjectEntriesInner<'a>,
}

#[derive(Debug)]
enum ObjectEntriesInner<'a> {
    General(ObjectStoreIter<'a, Value>),
    CaseInsensitive(ObjectStoreIter<'a, CIString>),
}

impl<'a> Iterator for ObjectEntries<'a> {
    type Item = (Value, &'a Value);

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            ObjectEntriesInner::General(iter) => iter.next().map(|(k, v)| (k, v)),
            ObjectEntriesInner::CaseInsensitive(iter) => iter
                .next()
                .map(|(k, v)| (Value::String(k.as_ref().into()), v)),
        }
    }
}

#[derive(Debug)]
pub struct ObjectEntriesMut<'a> {
    inner: ObjectEntriesMutInner<'a>,
}

#[derive(Debug)]
enum ObjectEntriesMutInner<'a> {
    General(ObjectStoreIterMut<'a, Value>),
    CaseInsensitive(ObjectStoreIterMut<'a, CIString>),
}

impl<'a> Iterator for ObjectEntriesMut<'a> {
    type Item = (Value, &'a mut Value);

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            ObjectEntriesMutInner::General(iter) => iter.next().map(|(k, v)| (k, v)),
            ObjectEntriesMutInner::CaseInsensitive(iter) => iter
                .next()
                .map(|(k, v)| (Value::String(k.as_ref().into()), v)),
        }
    }
}

impl ObjectStorage {
    pub fn len(&self) -> usize {
        match self {
            ObjectStorage::General(store) => store.len(),
            ObjectStorage::CaseInsensitive(store) => store.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains_key(&self, key: &Value) -> bool {
        self.get(key).is_some()
    }

    pub fn get(&self, key: &Value) -> Option<&Value> {
        match self {
            ObjectStorage::General(store) => store.get(key),
            ObjectStorage::CaseInsensitive(store) => match key {
                Value::String(s) => {
                    let ci = CIString::from(s.as_ref());
                    store.get(&ci)
                }
                _ => None,
            },
        }
    }

    pub fn get_mut(&mut self, key: &Value) -> Option<&mut Value> {
        match self {
            ObjectStorage::General(store) => store.get_mut(key),
            ObjectStorage::CaseInsensitive(store) => match key {
                Value::String(s) => {
                    let ci = CIString::from(s.as_ref());
                    store.get_mut(&ci)
                }
                _ => None,
            },
        }
    }

    pub fn insert(&mut self, key: Value, value: Value) -> Option<Value> {
        match self {
            ObjectStorage::General(store) => store.insert(key, value),
            ObjectStorage::CaseInsensitive(store) => match key {
                Value::String(s) => {
                    let ci = CIString::from(s.as_ref());
                    store.insert(ci, value)
                }
                _ => None,
            },
        }
    }

    pub fn iter(&self) -> ObjectEntries<'_> {
        match self {
            ObjectStorage::General(store) => ObjectEntries {
                inner: ObjectEntriesInner::General(store.iter()),
            },
            ObjectStorage::CaseInsensitive(store) => ObjectEntries {
                inner: ObjectEntriesInner::CaseInsensitive(store.iter()),
            },
        }
    }

    pub fn iter_mut(&mut self) -> ObjectEntriesMut<'_> {
        match self {
            ObjectStorage::General(store) => ObjectEntriesMut {
                inner: ObjectEntriesMutInner::General(store.iter_mut()),
            },
            ObjectStorage::CaseInsensitive(store) => ObjectEntriesMut {
                inner: ObjectEntriesMutInner::CaseInsensitive(store.iter_mut()),
            },
        }
    }

    pub fn values(&self) -> ObjectValues<'_> {
        ObjectValues { inner: self.iter() }
    }

    pub fn keys(&self) -> ObjectKeys<'_> {
        ObjectKeys { inner: self.iter() }
    }

    pub fn retain<F: FnMut(&Value, &Value) -> bool>(&mut self, mut f: F) {
        match self {
            ObjectStorage::General(store) => match store {
                ObjectStore::Small(sv) => sv.retain(|(k, v)| f(k, v)),
                ObjectStore::Hash(map) => map.retain(|k, v| f(k, v)),
            },
            ObjectStorage::CaseInsensitive(store) => match store {
                ObjectStore::Small(sv) => sv.retain(|(k, v)| {
                    let key = Value::String(k.as_ref().into());
                    f(&key, v)
                }),
                ObjectStore::Hash(map) => {
                    map.retain(|k, v| {
                        let key = Value::String(k.as_ref().into());
                        f(&key, v)
                    });
                }
            },
        }
    }

    pub fn entry(&mut self, key: Value) -> ObjectEntry<'_> {
        match self {
            ObjectStorage::General(store) => {
                match store {
                    ObjectStore::Small(sv) => {
                        if let Some(idx) = sv.iter().position(|(k, _)| k == &key) {
                            ObjectEntry::Occupied(OccupiedObjectEntry { storage: store, key, index: Some(idx) })
                        } else {
                            ObjectEntry::Vacant(VacantObjectEntry { storage: store, key })
                        }
                    }
                    ObjectStore::Hash(_) => {
                        // Check occupancy first then return the right entry
                        if store.get(&key).is_some() {
                            ObjectEntry::Occupied(OccupiedObjectEntry { storage: store, key, index: None })
                        } else {
                            ObjectEntry::Vacant(VacantObjectEntry { storage: store, key })
                        }
                    }
                }
            }
            ObjectStorage::CaseInsensitive(store) => {
                let ci = match &key {
                    Value::String(s) => CIString::from(s.as_ref()),
                    _ => CIString::from(""),
                };
                match store {
                    ObjectStore::Small(sv) => {
                        if let Some(idx) = sv.iter().position(|(k, _)| k == &ci) {
                            ObjectEntry::OccupiedCI(OccupiedCIObjectEntry { storage: store, _ci: ci, key, index: Some(idx) })
                        } else {
                            ObjectEntry::VacantCI(VacantCIObjectEntry { storage: store, ci, key })
                        }
                    }
                    ObjectStore::Hash(_) => {
                        if store.get(&ci).is_some() {
                            ObjectEntry::OccupiedCI(OccupiedCIObjectEntry { storage: store, _ci: ci, key, index: None })
                        } else {
                            ObjectEntry::VacantCI(VacantCIObjectEntry { storage: store, ci, key })
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct ObjectValues<'a> {
    inner: ObjectEntries<'a>,
}

impl<'a> Iterator for ObjectValues<'a> {
    type Item = &'a Value;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(_, v)| v)
    }
}

#[derive(Debug)]
pub struct ObjectKeys<'a> {
    inner: ObjectEntries<'a>,
}

impl<'a> Iterator for ObjectKeys<'a> {
    type Item = Value;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, _)| k)
    }
}

// Entry API for ObjectStorage
#[derive(Debug)]
pub enum ObjectEntry<'a> {
    Occupied(OccupiedObjectEntry<'a>),
    Vacant(VacantObjectEntry<'a>),
    OccupiedCI(OccupiedCIObjectEntry<'a>),
    VacantCI(VacantCIObjectEntry<'a>),
}

#[derive(Debug)]
pub struct OccupiedObjectEntry<'a> {
    storage: &'a mut ObjectStore<Value>,
    key: Value,
    index: Option<usize>,
}

impl<'a> OccupiedObjectEntry<'a> {
    pub fn get(&self) -> &Value {
        self.storage.get(&self.key).expect("occupied")
    }
}

#[derive(Debug)]
pub struct VacantObjectEntry<'a> {
    storage: &'a mut ObjectStore<Value>,
    key: Value,
}

#[derive(Debug)]
pub struct OccupiedCIObjectEntry<'a> {
    storage: &'a mut ObjectStore<CIString>,
    _ci: CIString,
    key: Value,
    index: Option<usize>,
}

impl<'a> OccupiedCIObjectEntry<'a> {
    pub fn get(&self) -> &Value {
        self.storage.get(&self._ci).expect("occupied")
    }
}

#[derive(Debug)]
pub struct VacantCIObjectEntry<'a> {
    storage: &'a mut ObjectStore<CIString>,
    ci: CIString,
    #[allow(dead_code)]
    key: Value,
}

impl<'a> ObjectEntry<'a> {
    pub fn or_insert(self, default: Value) -> &'a mut Value {
        self.or_insert_with(|| default)
    }

    pub fn or_insert_with<F: FnOnce() -> Value>(self, default: F) -> &'a mut Value {
        match self {
            ObjectEntry::Occupied(e) => {
                match e.index {
                    Some(idx) => &mut e.storage.as_small_mut().expect("small")[idx].1,
                    None => e.storage.get_mut(&e.key).expect("occupied"),
                }
            }
            ObjectEntry::Vacant(e) => {
                e.storage.insert(e.key.clone(), default());
                e.storage.get_mut(&e.key).expect("just inserted")
            }
            ObjectEntry::OccupiedCI(e) => {
                match e.index {
                    Some(idx) => &mut e.storage.as_small_mut().expect("small")[idx].1,
                    None => {
                        let ci = match &e.key {
                            Value::String(s) => CIString::from(s.as_ref()),
                            _ => CIString::from(""),
                        };
                        e.storage.get_mut(&ci).expect("occupied")
                    }
                }
            }
            ObjectEntry::VacantCI(e) => {
                e.storage.insert(e.ci.clone(), default());
                e.storage.get_mut(&e.ci).expect("just inserted")
            }
        }
    }
}

impl<K> ObjectStore<K> {
    fn as_small_mut(&mut self) -> Option<&mut SmallVec<[(K, Value); SMALL_OBJECT_INLINE]>> {
        match self {
            ObjectStore::Small(sv) => Some(sv),
            _ => None,
        }
    }
}


impl<'de> Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a value")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Null)
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Bool(v))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        Value::deserialize(deserializer)
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::from(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::from(v))
    }

    fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::from(v))
    }

    fn visit_i128<E>(self, v: i128) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::from(v))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::from(Number::from(v)))
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(s.to_string().into()))
    }

    fn visit_string<E>(self, s: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(s.into()))
    }

    fn visit_seq<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let mut arr = vec![];
        while let Some(v) = visitor.next_element()? {
            arr.push(v);
            // Enforce allocator limit while expanding a deserialized array.
            enforce_limit_for::<V::Error>()?;
        }
        Ok(Value::from(arr))
    }

    fn visit_map<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
    where
        V: MapAccess<'de>,
    {
        if let Some((key, value)) = visitor.next_entry()? {
            if let (Value::String(k), Value::String(v)) = (&key, &value) {
                if k.as_ref() == "$serde_json::private::Number" {
                    match Number::from_str(v) {
                        Ok(n) => return Ok(Value::from(n)),
                        _ => return Err(de::Error::custom("failed to read big number")),
                    }
                }
            }
            let mut map = Map::with_capacity(1);
            map.insert(key, value);
            // Enforce allocator limit while expanding a deserialized object.
            enforce_limit_for::<V::Error>()?;
            while let Some((key, value)) = visitor.next_entry()? {
                map.insert(key, value);
                // Enforce allocator limit while expanding a deserialized object.
                enforce_limit_for::<V::Error>()?;
            }
            Ok(Value::from_map_general(map))
        } else {
            Ok(Value::new_object())
        }
    }
}

#[doc(hidden)]
impl From<Set<Value>> for Value {
    fn from(s: Set<Value>) -> Self {
        Value::Set(Rc::new(SetStorage::Hash(s)))
    }
}

impl Value {
    pub(crate) fn from_array(a: Vec<Value>) -> Value {
        Value::from(a)
    }

    pub(crate) fn from_set(s: Set<Value>) -> Value {
        Value::from(s)
    }

    pub(crate) fn from_map_general(m: Map<Value, Value>) -> Value {
        Value::Object(Rc::new(ObjectStorage::General(ObjectStore::Hash(m))))
    }

    pub(crate) fn from_map(m: alloc::collections::BTreeMap<Value, Value>) -> Value {
        let mut map = Map::with_capacity_and_hasher(m.len(), crate::collections::DefaultBuildHasher::default());
        for (k, v) in m {
            map.insert(k, v);
        }
        Value::from_map_general(map)
    }

    #[allow(dead_code)]
    pub(crate) fn from_map_ci(m: Map<CIString, Value>) -> Value {
        Value::Object(Rc::new(ObjectStorage::CaseInsensitive(ObjectStore::Hash(m))))
    }

    pub(crate) fn is_empty_object(&self) -> bool {
        self == &Value::new_object()
    }

    /// Create an empty [`Value::Array`]
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let obj = Value::new_array();
    /// assert_eq!(obj.as_array().expect("not an array").len(), 0);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_array() -> Value {
        Value::from(Vec::new())
    }

    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let obj = Value::new_set();
    /// assert_eq!(obj.as_set().expect("not a set").len(), 0);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_set() -> Value {
        Value::from_set(Set::new())
    }

    /// Create an empty object.
    pub fn new_object() -> Value {
        Value::from_map_general(Map::new())
    }
}

impl Value {
    /// Deserialize a [`Value`] from JSON.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let json = r#"
    /// [
    ///   null, true, false,
    ///   "hello", 12345,
    ///   { "name" : "regorus" }
    /// ]"#;
    ///
    /// // Deserialize json.
    /// let value = Value::from_json_str(json)?;
    ///
    /// // Assert outer array.
    /// let array = value.as_array().expect("not an array");
    ///
    /// // Assert elements.
    /// assert_eq!(array[0], Value::Null);
    /// assert_eq!(array[1], Value::from(true));
    /// assert_eq!(array[2], Value::from(false));
    /// assert_eq!(array[3], Value::from("hello"));
    /// assert_eq!(array[4], Value::from(12345u64));
    /// let obj = array[5].as_object().expect("not an object");
    /// assert_eq!(obj.len(), 1);
    /// assert_eq!(obj[&Value::from("name")], Value::from("regorus"));
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_json_str(json: &str) -> Result<Value> {
        match serde_json::from_str::<Value>(json) {
            Ok(value) => Ok(value),
            Err(err) => {
                #[cfg(feature = "allocator-memory-limits")]
                {
                    // Re-validate allocator limits when serde parsing fails to surface LimitError.
                    match crate::utils::limits::check_global_memory_limit() {
                        Err(limit_err) => Err(anyhow!(limit_err)),
                        Ok(_) => Err(anyhow!(err)),
                    }
                }

                #[cfg(not(feature = "allocator-memory-limits"))]
                {
                    Err(anyhow!(err))
                }
            }
        }
    }

    /// Deserialize a [`Value`] from a file containing JSON.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let value = Value::from_json_file("tests/aci/input.json")?;
    ///
    /// // Convert the value back to json.
    /// let json_str = value.to_json_str()?;
    ///
    /// assert_eq!(json_str.trim(),
    ///            std::fs::read_to_string("tests/aci/input.json")?.trim().replace("\r\n", "\n"));
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn from_json_file<P: AsRef<std::path::Path>>(path: P) -> Result<Value> {
        match std::fs::read_to_string(&path) {
            Ok(c) => Self::from_json_str(c.as_str()),
            Err(e) => bail!("Failed to read {}. {e}", path.as_ref().display()),
        }
    }

    /// Serialize a value to JSON.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let value = Value::from_json_file("tests/aci/input.json")?;
    ///
    /// // Convert the value back to json.
    /// let json_str = value.to_json_str()?;
    ///
    /// assert_eq!(json_str.trim(),
    ///            std::fs::read_to_string("tests/aci/input.json")?.trim().replace("\r\n", "\n"));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Sets are serialized as arrays.
    /// ```
    /// # use regorus::*;
    /// # use std::collections::BTreeSet;
    /// # fn main() -> anyhow::Result<()> {
    /// let mut set = BTreeSet::new();
    /// set.insert(Value::from("Hello"));
    /// set.insert(Value::from(1u64));
    ///
    /// let set_value = Value::from(set);
    ///
    /// assert_eq!(
    ///  set_value.to_json_str()?,
    ///  r#"
    ///[
    ///   1,
    ///   "Hello"
    ///]"#.trim());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Non string keys of objects are serialized to json first and the serialized string representation
    /// is emitted as the key.
    /// ```
    /// # use regorus::*;
    /// # use std::collections::BTreeMap;
    /// # fn main() -> anyhow::Result<()> {
    /// let mut obj = BTreeMap::new();
    /// obj.insert(Value::from("Hello"), Value::from("World"));
    /// obj.insert(Value::from([Value::from(1u64)].to_vec()), Value::Null);
    ///
    /// let obj_value = Value::from(obj);
    ///
    /// assert_eq!(
    ///  obj_value.to_json_str()?,
    ///  r#"
    ///{
    ///   "Hello": "World",
    ///   "[1]": null
    ///}"#.trim());
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_json_str(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(anyhow::Error::msg)
    }

    /// Deserialize a value from YAML.
    /// Note: Deserialization from YAML does not support arbitrary precision numbers.
    #[cfg(feature = "yaml")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn from_yaml_str(yaml: &str) -> Result<Value> {
        let value = serde_yaml::from_str(yaml)
            .map_err(|err| anyhow::anyhow!("Failed to parse YAML: {}", err))?;
        Ok(value)
    }

    /// Deserialize a value from a file containing YAML.
    /// Note: Deserialization from YAML does not support arbitrary precision numbers.
    #[cfg(feature = "std")]
    #[cfg(feature = "yaml")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "yaml")))]
    pub fn from_yaml_file(path: &String) -> Result<Value> {
        match std::fs::read_to_string(path) {
            Ok(c) => Self::from_yaml_str(c.as_str()),
            Err(e) => bail!("Failed to read {path}. {e}"),
        }
    }
}

impl From<bool> for Value {
    /// Create a [`Value::Bool`] from `bool`.
    /// ```
    /// # use regorus::*;
    /// # use std::collections::BTreeSet;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(Value::from(true), Value::Bool(true));
    /// # Ok(())
    /// # }
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl From<String> for Value {
    /// Create a [`Value::String`] from `string`.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(Value::from("Hello".to_string()), Value::String("Hello".into()));
    /// # Ok(())
    /// # }
    fn from(s: String) -> Self {
        Value::String(s.into())
    }
}

impl From<&str> for Value {
    /// Create a [`Value::String`] from `&str`.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(Value::from("Hello"), Value::String("Hello".into()));
    /// # Ok(())
    /// # }
    fn from(s: &str) -> Self {
        Value::String(s.into())
    }
}

impl From<u128> for Value {
    /// Create a [`Value::Number`] from `u128`.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(
    ///   Value::from(340_282_366_920_938_463_463_374_607_431_768_211_455u128).as_u128()?,
    ///   340_282_366_920_938_463_463_374_607_431_768_211_455u128);
    /// # Ok(())
    /// # }
    fn from(n: u128) -> Self {
        Value::Number(Number::from(n))
    }
}

impl From<i128> for Value {
    /// Create a [`Value::Number`] from `i128`.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(
    ///   Value::from(-170141183460469231731687303715884105728i128).as_i128()?,
    ///   -170141183460469231731687303715884105728i128);
    /// # Ok(())
    /// # }
    fn from(n: i128) -> Self {
        Value::Number(Number::from(n))
    }
}

impl From<u64> for Value {
    /// Create a [`Value::Number`] from `u64`.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(
    ///   Value::from(0u64),
    ///   Value::from_json_str("0")?);
    /// # Ok(())
    /// # }
    fn from(n: u64) -> Self {
        Value::Number(Number::from(n))
    }
}

impl From<i64> for Value {
    /// Create a [`Value::Number`] from `i64`.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(
    ///   Value::from(0i64),
    ///   Value::from_json_str("0")?);
    /// # Ok(())
    /// # }
    fn from(n: i64) -> Self {
        Value::Number(Number::from(n))
    }
}

impl From<u32> for Value {
    /// Create a [`Value::Number`] from `u32`.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(
    ///   Value::from(0u32),
    ///   Value::from_json_str("0")?);
    /// # Ok(())
    /// # }
    fn from(n: u32) -> Self {
        Value::Number(Number::from(n as u64))
    }
}

impl From<i32> for Value {
    /// Create a [`Value::Number`] from `i32`.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(
    ///   Value::from(0i32),
    ///   Value::from_json_str("0")?);
    /// # Ok(())
    /// # }
    fn from(n: i32) -> Self {
        Value::Number(Number::from(n as i64))
    }
}

impl From<f64> for Value {
    /// Create a [`Value::Number`] from `f64`.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(
    ///   Value::from(3.5f64),
    ///   Value::from_numeric_string("3.5")?);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`Value::Number`] stores floating-point values as `f64`, so it inherits the same
    /// ~15-digit precision limit. Adding additional digits to either the literal or a parsed
    /// numeric string causes both to round to the same `f64` value.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let from_float = Value::from(3.141592653589793238462f64);
    /// let from_string = Value::from_numeric_string("3.141592653589793238462")?;
    /// assert_eq!(from_float, from_string);
    ///
    /// // All representations round to approximately 15 digits.
    /// assert_eq!(
    ///   from_float,
    ///   Value::from_numeric_string("3.141592653589793")?);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// If additional precision is required, keep the raw data as strings or use an external
    /// arbitrary-precision numeric type before converting it into [`Value`].
    fn from(n: f64) -> Self {
        Value::Number(Number::from(n))
    }
}

impl From<serde_json::Value> for Value {
    /// Create a [`Value`] from [`serde_json::Value`].
    ///
    /// Returns [`Value::Undefined`] in case of error.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let json_v = serde_json::json!({ "x":10, "y": 20 });
    /// let v = Value::from(json_v);
    ///
    /// assert_eq!(v["x"].as_u64()?, 10);
    /// assert_eq!(v["y"].as_u64()?, 20);
    /// # Ok(())
    /// # }
    fn from(v: serde_json::Value) -> Self {
        match serde_json::from_value(v) {
            Ok(v) => v,
            _ => Value::Undefined,
        }
    }
}

#[cfg(feature = "yaml")]
#[cfg_attr(docsrs, doc(cfg(feature = "yaml")))]
impl From<serde_yaml::Value> for Value {
    /// Create a [`Value`] from [`serde_yaml::Value`].
    ///
    /// Returns [`Value::Undefined`] in case of error.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let yaml = "
    ///   x: 10
    ///   y: 20
    /// ";
    /// let yaml_v : serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    /// let v = Value::from(yaml_v);
    ///
    /// assert_eq!(v["x"].as_u64()?, 10);
    /// assert_eq!(v["y"].as_u64()?, 20);
    /// # Ok(())
    /// # }
    fn from(v: serde_yaml::Value) -> Self {
        match serde_yaml::from_value(v) {
            Ok(v) => v,
            _ => Value::Undefined,
        }
    }
}

impl Value {
    /// Create a [`Value::Number`] from a string containing numeric representation of a number.
    ///
    /// This is the preferred way for creating arbitrary precision numbers.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from_numeric_string("3.14159265358979323846264338327950288419716939937510")?;
    ///
    /// println!("{}", v.to_json_str()?);
    /// // Prints 3.1415926535897932384626433832795028841971693993751 if serde_json/arbitrary_precision feature is enabled.
    /// // Prints 3.141592653589793 if serde_json/arbitrary_precision is not enabled.
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_numeric_string(s: &str) -> Result<Value> {
        Ok(Value::Number(
            Number::from_str(s).map_err(|_| anyhow!("not a valid numeric string"))?,
        ))
    }
}

impl From<usize> for Value {
    /// Create a [`Value::Number`] from `usize`.
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// assert_eq!(
    ///   Value::from(0usize),
    ///   Value::from_json_str("0")?);
    /// # Ok(())
    /// # }
    fn from(n: usize) -> Self {
        Value::Number(Number::from(n))
    }
}

#[doc(hidden)]
impl From<Number> for Value {
    fn from(n: Number) -> Self {
        Value::Number(n)
    }
}

impl From<Vec<Value>> for Value {
    /// Create a [`Value::Array`] from a [`Vec<Value>`].
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let strings = [ "Hello", "World" ];
    ///
    /// let v = Value::from(strings.iter().map(|s| Value::from(*s)).collect::<Vec<Value>>());
    /// assert_eq!(v[0], Value::from(strings[0]));
    /// assert_eq!(v[1], Value::from(strings[1]));
    /// # Ok(())
    /// # }
    fn from(a: Vec<Value>) -> Self {
        Value::Array(Rc::new(a))
    }
}

impl From<alloc::collections::BTreeSet<Value>> for Value {
    fn from(s: alloc::collections::BTreeSet<Value>) -> Self {
        let mut set = Set::with_capacity_and_hasher(s.len(), crate::collections::DefaultBuildHasher::default());
        for v in s {
            set.insert(v);
        }
        Value::from_set(set)
    }
}

impl From<alloc::collections::BTreeMap<Value, Value>> for Value {
    fn from(m: alloc::collections::BTreeMap<Value, Value>) -> Self {
        Value::from_map(m)
    }
}

impl Value {
    /// Cast value to [`& bool`] if [`Value::Bool`].
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(true);
    /// assert_eq!(v.as_bool()?, &true);
    /// # Ok(())
    /// # }
    pub fn as_bool(&self) -> Result<&bool> {
        match self {
            Value::Bool(b) => Ok(b),
            _ => Err(anyhow!("not a bool")),
        }
    }

    /// Cast value to [`&mut bool`] if [`Value::Bool`].
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let mut v = Value::from(true);
    /// *v.as_bool_mut()? = false;
    /// # Ok(())
    /// # }
    pub fn as_bool_mut(&mut self) -> Result<&mut bool> {
        match self {
            Value::Bool(b) => Ok(b),
            _ => Err(anyhow!("not a bool")),
        }
    }

    /// Cast value to [`& u128`] if [`Value::Number`].
    ///
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a u128.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(10);
    /// assert_eq!(v.as_u128()?, 10u128);
    ///
    /// let v = Value::from(-10);
    /// assert!(v.as_u128().is_err());
    /// # Ok(())
    /// # }
    pub fn as_u128(&self) -> Result<u128> {
        match self {
            Value::Number(b) => {
                if let Some(n) = b.as_u128() {
                    return Ok(n);
                }
                bail!("not a u128");
            }
            _ => Err(anyhow!("not a u128")),
        }
    }

    /// Cast value to [`& i128`] if [`Value::Number`].
    ///
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a i128.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(-10);
    /// assert_eq!(v.as_i128()?, -10i128);
    ///
    /// let v = Value::from_numeric_string("11111111111111111111111111111111111111111111111111")?;
    /// assert!(v.as_i128().is_err());
    /// # Ok(())
    /// # }
    pub fn as_i128(&self) -> Result<i128> {
        match self {
            Value::Number(b) => {
                if let Some(n) = b.as_i128() {
                    return Ok(n);
                }
                bail!("not a i128");
            }
            _ => Err(anyhow!("not a i128")),
        }
    }

    /// Cast value to [`& u64`] if [`Value::Number`].
    ///
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a u64.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(10);
    /// assert_eq!(v.as_u64()?, 10u64);
    ///
    /// let v = Value::from(-10);
    /// assert!(v.as_u64().is_err());
    /// # Ok(())
    /// # }
    pub fn as_u64(&self) -> Result<u64> {
        match self {
            Value::Number(b) => {
                if let Some(n) = b.as_u64() {
                    return Ok(n);
                }
                bail!("not a u64");
            }
            _ => Err(anyhow!("not a u64")),
        }
    }

    /// Cast value to [`& i64`] if [`Value::Number`].
    ///
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a i64.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(-10);
    /// assert_eq!(v.as_i64()?, -10i64);
    ///
    /// let v = Value::from(340_282_366_920_938_463_463_374_607_431_768_211_455u128);
    /// assert!(v.as_i64().is_err());
    /// # Ok(())
    /// # }
    pub fn as_i64(&self) -> Result<i64> {
        match self {
            Value::Number(b) => {
                if let Some(n) = b.as_i64() {
                    return Ok(n);
                }
                bail!("not an i64");
            }
            _ => Err(anyhow!("not an i64")),
        }
    }

    /// Cast value to [`& u32`] if [`Value::Number`].
    ///
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a u32.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(10);
    /// assert_eq!(v.as_u32()?, 10u32);
    ///
    /// let v = Value::from(-10);
    /// assert!(v.as_u32().is_err());
    /// # Ok(())
    /// # }
    pub fn as_u32(&self) -> Result<u32> {
        match self {
            Value::Number(b) => {
                if let Some(n) = b.as_u64() {
                    if let Ok(v) = u32::try_from(n) {
                        return Ok(v);
                    }
                }
                bail!("not a u32");
            }
            _ => Err(anyhow!("not a u32")),
        }
    }

    /// Cast value to [`& i32`] if [`Value::Number`].
    ///
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a i32.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(-10);
    /// assert_eq!(v.as_i32()?, -10i32);
    ///
    /// let v = Value::from(2_147_483_648i64);
    /// assert!(v.as_i32().is_err());
    /// # Ok(())
    /// # }
    pub fn as_i32(&self) -> Result<i32> {
        match self {
            Value::Number(b) => {
                if let Some(n) = b.as_i64() {
                    if let Ok(v) = i32::try_from(n) {
                        return Ok(v);
                    }
                }
                bail!("not an i32");
            }
            _ => Err(anyhow!("not an i32")),
        }
    }

    /// Cast value to [`& u16`] if [`Value::Number`].
    ///
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a u16.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(10);
    /// assert_eq!(v.as_u16()?, 10u16);
    ///
    /// let v = Value::from(-10);
    /// assert!(v.as_u16().is_err());
    /// # Ok(())
    /// # }
    pub fn as_u16(&self) -> Result<u16> {
        match self {
            Value::Number(b) => {
                if let Some(n) = b.as_u64() {
                    if let Ok(v) = u16::try_from(n) {
                        return Ok(v);
                    }
                }
                bail!("not a u16");
            }
            _ => Err(anyhow!("not a u16")),
        }
    }

    /// Cast value to [`& i16`] if [`Value::Number`].
    ///
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a i16.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(-10);
    /// assert_eq!(v.as_i16()?, -10i16);
    ///
    /// let v = Value::from(32768i64);
    /// assert!(v.as_i16().is_err());
    /// # Ok(())
    /// # }
    pub fn as_i16(&self) -> Result<i16> {
        match self {
            Value::Number(b) => {
                if let Some(n) = b.as_i64() {
                    if let Ok(v) = i16::try_from(n) {
                        return Ok(v);
                    }
                }
                bail!("not an i16");
            }
            _ => Err(anyhow!("not an i16")),
        }
    }

    /// Cast value to [`& u8`] if [`Value::Number`].
    ///
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a u8.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(10);
    /// assert_eq!(v.as_u8()?, 10u8);
    ///
    /// let v = Value::from(-10);
    /// assert!(v.as_u8().is_err());
    /// # Ok(())
    /// # }
    pub fn as_u8(&self) -> Result<u8> {
        match self {
            Value::Number(b) => {
                if let Some(n) = b.as_u64() {
                    if let Ok(v) = u8::try_from(n) {
                        return Ok(v);
                    }
                }
                bail!("not a u8");
            }
            _ => Err(anyhow!("not a u8")),
        }
    }

    /// Cast value to [`& i8`] if [`Value::Number`].
    ///
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a i8.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(-10);
    /// assert_eq!(v.as_i8()?, -10i8);
    ///
    /// let v = Value::from(128);
    /// assert!(v.as_i8().is_err());
    /// # Ok(())
    /// # }
    pub fn as_i8(&self) -> Result<i8> {
        match self {
            Value::Number(b) => {
                if let Some(n) = b.as_i64() {
                    if let Ok(v) = i8::try_from(n) {
                        return Ok(v);
                    }
                }
                bail!("not an i8");
            }
            _ => Err(anyhow!("not an i8")),
        }
    }

    /// Cast value to [`& f64`] if [`Value::Number`].
    /// Error is raised if the value is not a number or if the numeric value
    /// does not fit in a i64.
    ///
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(-10);
    /// assert_eq!(v.as_f64()?, -10f64);
    ///
    /// let v = Value::from(340_282_366_920_938_463_463_374_607_431_768_211_455u128);
    /// assert!(v.as_i64().is_err());
    /// # Ok(())
    /// # }
    pub fn as_f64(&self) -> Result<f64> {
        match self {
            Value::Number(b) => {
                if let Some(n) = b.as_f64() {
                    return Ok(n);
                }
                bail!("not a f64");
            }
            _ => Err(anyhow!("not a f64")),
        }
    }

    /// Cast value to [`& Rc<str>`] if [`Value::String`].
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from("Hello");
    /// assert_eq!(v.as_string()?.as_ref(), "Hello");
    /// # Ok(())
    /// # }
    pub fn as_string(&self) -> Result<&Rc<str>> {
        match self {
            Value::String(s) => Ok(s),
            _ => Err(anyhow!("not a string")),
        }
    }

    /// Cast value to [`&mut Rc<str>`] if [`Value::String`].
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let mut v = Value::from("Hello");
    /// *v.as_string_mut()? = "World".into();
    /// # Ok(())
    /// # }
    pub fn as_string_mut(&mut self) -> Result<&mut Rc<str>> {
        match self {
            Value::String(s) => Ok(s),
            _ => Err(anyhow!("not a string")),
        }
    }

    #[doc(hidden)]
    pub fn as_number(&self) -> Result<&Number> {
        match self {
            Value::Number(n) => Ok(n),
            _ => Err(anyhow!("not a number")),
        }
    }

    #[doc(hidden)]
    pub fn as_number_mut(&mut self) -> Result<&mut Number> {
        match self {
            Value::Number(n) => Ok(n),
            _ => Err(anyhow!("not a number")),
        }
    }

    /// Cast value to [`& Vec<Value>`] if [`Value::Array`].
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from([Value::from("Hello")].to_vec());
    /// assert_eq!(v.as_array()?[0], Value::from("Hello"));
    /// # Ok(())
    /// # }
    pub fn as_array(&self) -> Result<&Vec<Value>> {
        match self {
            Value::Array(a) => Ok(a),
            _ => Err(anyhow!("not an array")),
        }
    }

    /// Cast value to [`&mut Vec<Value>`] if [`Value::Array`].
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let mut v = Value::from([Value::from("Hello")].to_vec());
    /// v.as_array_mut()?.push(Value::from("World"));
    /// # Ok(())
    /// # }
    pub fn as_array_mut(&mut self) -> Result<&mut Vec<Value>> {
        match self {
            Value::Array(a) => Ok(Rc::make_mut(a)),
            _ => Err(anyhow!("not an array")),
        }
    }

    /// Cast value to [`&SetStorage<Value>`] if [`Value::Set`].
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(
    ///    [Value::from("Hello")]
    ///        .iter()
    ///        .cloned()
    ///        .collect::<Set<Value>>(),
    /// );
    /// assert!(matches!(v.as_set()?, SetStorage::Small(_)));
    /// # Ok(())
    /// # }
    pub fn as_set(&self) -> Result<&SetStorage<Value>> {
        match self {
            Value::Set(s) => Ok(s),
            _ => Err(anyhow!("not a set")),
        }
    }

    /// Cast value to [`&mut SetStorage<Value>`] if [`Value::Set`].
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let mut v = Value::from(
    ///    [Value::from("Hello")]
    ///        .iter()
    ///        .cloned()
    ///        .collect::<Set<Value>>(),
    /// );
    /// if let SetStorage::Small(s) = v.as_set_mut()? {
    ///     s.push(Value::from("World"));
    /// }
    /// # Ok(())
    /// # }
    pub fn as_set_mut(&mut self) -> Result<&mut SetStorage<Value>> {
        match self {
            Value::Set(s) => Ok(Rc::make_mut(s)),
            _ => Err(anyhow!("not a set")),
        }
    }

    /// Cast value to [`&ObjectStorage`] if [`Value::Object`].
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(
    ///    [(Value::from("Hello"), Value::from("World"))]
    ///        .iter()
    ///        .cloned()
    ///        .collect::<Map<Value, Value>>(),
    /// );
    /// assert_eq!(
    ///    v.as_object()?.len(),
    ///    1,
    /// );
    /// # Ok(())
    /// # }
    pub fn as_object(&self) -> Result<&ObjectStorage> {
        match self {
            Value::Object(m) => Ok(m),
            _ => Err(anyhow!("not an object")),
        }
    }

    /// Cast value to [`&mut ObjectStorage`] if [`Value::Object`].
    /// ```
    /// # use regorus::*;
    /// # fn main() -> anyhow::Result<()> {
    /// let mut v = Value::from(
    ///    [(Value::from("Hello"), Value::from("World"))]
    ///        .iter()
    ///        .cloned()
    ///        .collect::<Map<Value, Value>>(),
    /// );
    /// v.as_object_mut()?.len();
    /// # Ok(())
    /// # }
    pub fn as_object_mut(&mut self) -> Result<&mut ObjectStorage> {
        match self {
            Value::Object(m) => Ok(Rc::make_mut(m)),
            _ => Err(anyhow!("not an object")),
        }
    }
}

impl Value {
    pub(crate) fn make_or_get_value_mut<'a>(&'a mut self, paths: &[&str]) -> Result<&'a mut Value> {
        if paths.is_empty() {
            return Ok(self);
        }

        let key = Value::String(paths[0].into());
        if self == &Value::Undefined {
            *self = Value::new_object();
        }
        if let Value::Object(map) = self {
            if map.get(&key).is_none() {
                Rc::make_mut(map).insert(key.clone(), Value::Undefined);
                // Enforce allocator limit while creating nested object entries.
                enforce_limit_anyhow()?;
            }
        }

        match self {
            Value::Object(map) => match Rc::make_mut(map).get_mut(&key) {
                Some(v) if paths.len() == 1 => Ok(v),
                Some(v) => Self::make_or_get_value_mut(v, &paths[1..]),
                _ => bail!("internal error: unexpected"),
            },
            Value::Undefined if paths.len() > 1 => {
                *self = Value::new_object();
                Self::make_or_get_value_mut(self, paths)
            }
            Value::Undefined => Ok(self),
            _ => bail!("internal error: make: not an selfect {self:?}"),
        }
    }

    pub(crate) fn merge(&mut self, mut new: Value) -> Result<()> {
        if self == &new {
            return Ok(());
        }
        match (self, &mut new) {
            (v @ Value::Undefined, _) => *v = new,
            (Value::Set(ref mut set), Value::Set(new)) => {
                Rc::make_mut(set).append(Rc::make_mut(new));
                // Enforce allocator limit after merging set entries.
                enforce_limit_anyhow()?;
            }
            (Value::Object(map), Value::Object(new)) => {
                for (k, v) in new.iter() {
                    match map.get(&k) {
                        Some(pv) if *pv != *v => {
                            bail!(
                                "value for key `{}` generated multiple times: `{}` and `{}`",
                                serde_json::to_string_pretty(&k).map_err(anyhow::Error::msg)?,
                                serde_json::to_string_pretty(&pv).map_err(anyhow::Error::msg)?,
                                serde_json::to_string_pretty(&v).map_err(anyhow::Error::msg)?,
                            )
                        }
                        _ => {
                            Rc::make_mut(map).insert(k.clone(), v.clone());
                            // Enforce allocator limit after merging object entries.
                            enforce_limit_anyhow()?;
                        }
                    };
                }
            }
            _ => bail!("error: could not merge value"),
        };
        Ok(())
    }
}

impl ops::Index<&Value> for Value {
    type Output = Value;

    /// Index a [`Value`] using a [`Value`].
    ///
    /// [`Value::Undefined`] is returned
    /// - If the index not valid for the collection.
    /// - If the value being indexed is not an array, set or object.
    ///
    /// Sets can be indexed only by elements within the set.
    ///
    /// ```
    /// # use regorus::*;
    /// # use std::collections::BTreeMap;
    /// # fn main() -> anyhow::Result<()> {
    ///
    /// let arr = Value::from([Value::from("Hello")].to_vec());
    /// // Index an array.
    /// assert_eq!(arr[&Value::from(0)].as_string()?.as_ref(), "Hello");
    /// assert_eq!(arr[&Value::from(10)], Value::Undefined);
    ///
    /// let mut set = Value::new_set();
    /// set.as_set_mut()?.insert(Value::from(100));
    /// set.as_set_mut()?.insert(Value::from("Hello"));
    ///
    /// // Index a set.
    /// let item = Value::from("Hello");
    /// assert_eq!(&set[&item], &item);
    /// assert_eq!(&set[&Value::from(10)], &Value::Undefined);
    ///
    /// let mut obj = Value::new_object();
    /// obj.as_object_mut()?.insert(Value::from("Hello"), Value::from("World"));
    /// obj.as_object_mut()?.insert(Value::new_array(), Value::from("bye"));
    ///
    /// // Index an object.
    /// assert_eq!(&obj[Value::from("Hello")].as_string()?.as_ref(), &"World");
    /// assert_eq!(&obj[Value::from("hllo")], &Value::Undefined);
    /// // Index using non-string key.
    /// assert_eq!(&obj[&Value::new_array()].as_string()?.as_ref(), &"bye");
    ///
    /// // Index a non-collection.
    /// assert_eq!(&Value::Null[&Value::from(1)], &Value::Undefined);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// This is the preferred way of indexing a value.
    /// Since constructing a value may be a costly operation (e.g. Value::String),
    /// the caller can construct the index value once and use it many times.
    ///`
    fn index(&self, key: &Value) -> &Self::Output {
        match (self, key) {
            (Value::Object(o), _) => match &**o {
                ObjectStorage::General(store) => match store {
                    ObjectStore::Small(sv) => sv
                        .iter()
                        .find(|(k, _)| k == key)
                        .map(|(_, v)| v)
                        .unwrap_or(&Value::Undefined),
                    ObjectStore::Hash(map) => map.get(key).unwrap_or(&Value::Undefined),
                },
                ObjectStorage::CaseInsensitive(store) => match store {
                    ObjectStore::Small(sv) => sv
                        .iter()
                        .find(|(k, _)| match key {
                            Value::String(s) => CIString::from(s.clone()) == *k,
                            _ => false,
                        })
                        .map(|(_, v)| v)
                        .unwrap_or(&Value::Undefined),
                    ObjectStore::Hash(map) => match key {
                        Value::String(s) => map
                            .get(&CIString::from(s.clone()))
                            .unwrap_or(&Value::Undefined),
                        _ => &Value::Undefined,
                    },
                },
            },
            (Value::Set(s), _) => match &**s {
                SetStorage::Small(sv) => sv
                    .iter()
                    .find(|v| *v == key)
                    .unwrap_or(&Value::Undefined),
                SetStorage::Hash(set) => set.get(key).unwrap_or(&Value::Undefined),
            },
            (Value::Array(a), Value::Number(n)) => match n.as_u64() {
                Some(index) if (index as usize) < a.len() => &a[index as usize],
                _ => &Value::Undefined,
            },
            _ => &Value::Undefined,
        }
    }
}

impl<T> ops::Index<T> for Value
where
    Value: From<T>,
{
    type Output = Value;

    /// Index a [`Value`].
    ///
    ///
    /// A [`Value`] is constructed from the index which is then used for indexing.
    ///
    /// ```
    /// # use regorus::*;
    /// # use std::collections::BTreeMap;
    /// # fn main() -> anyhow::Result<()> {
    /// let v = Value::from(
    ///    [(Value::from("Hello"), Value::from("World")),
    ///     (Value::from(1), Value::from(2))]
    ///        .iter()
    ///        .cloned()
    ///        .collect::<BTreeMap<Value, Value>>(),
    /// );
    ///
    /// assert_eq!(&v["Hello"].as_string()?.as_ref(), &"World");
    /// assert_eq!(&v[1].as_u64()?, &2u64);
    /// # Ok(())
    /// # }
    fn index(&self, key: T) -> &Self::Output {
        &self[&Value::from(key)]
    }
}

impl core::hash::Hash for Value {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            Value::Null => {}
            Value::Bool(b) => b.hash(state),
            Value::Number(n) => n.hash(state),
            Value::String(s) => s.hash(state),
            Value::Array(a) => a.hash(state),
            Value::Set(s) => s.hash(state),
            Value::Object(o) => match &**o {
                ObjectStorage::General(store) => store.hash(state),
                ObjectStorage::CaseInsensitive(store) => store.hash(state),
            },
            Value::Undefined => {}
        }
    }
}

impl<K: core::hash::Hash + Eq> core::hash::Hash for ObjectStore<K> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        match self {
            ObjectStore::Small(sv) => {
                let mut acc: u64 = 0;
                for (k, v) in sv.iter() {
                    let h1 = crate::collections::hash_with_builder(k);
                    let h2 = crate::collections::hash_with_builder(v);
                    acc ^= h1 ^ (h2.rotate_left(1));
                }
                acc.hash(state);
            }
            ObjectStore::Hash(map) => {
                let mut acc: u64 = 0;
                for (k, v) in map.iter() {
                    let h1 = crate::collections::hash_with_builder(k);
                    let h2 = crate::collections::hash_with_builder(v);
                    acc ^= h1 ^ (h2.rotate_left(1));
                }
                acc.hash(state);
            }
        }
    }
}

impl core::hash::Hash for ObjectStorage {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            ObjectStorage::General(s) => s.hash(state),
            ObjectStorage::CaseInsensitive(s) => s.hash(state),
        }
    }
}

impl<T: core::hash::Hash + Eq> core::hash::Hash for SetStorage<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        match self {
            SetStorage::Small(sv) => {
                let mut acc: u64 = 0;
                for v in sv.iter() {
                    acc ^= crate::collections::hash_with_builder(v);
                }
                acc.hash(state);
            }
            SetStorage::Hash(set) => {
                let mut acc: u64 = 0;
                for v in set.iter() {
                    acc ^= crate::collections::hash_with_builder(v);
                }
                acc.hash(state);
            }
        }
    }
}

// Discriminant order for PartialOrd/Ord: Null < Bool < Number < String < Array < Set < Object < Undefined
fn variant_order(v: &Value) -> u8 {
    match v {
        Value::Null => 0,
        Value::Bool(_) => 1,
        Value::Number(_) => 2,
        Value::String(_) => 3,
        Value::Array(_) => 4,
        Value::Set(_) => 5,
        Value::Object(_) => 6,
        Value::Undefined => 7,
    }
}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Value {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        use core::cmp::Ordering;
        let lhs_ord = variant_order(self);
        let rhs_ord = variant_order(other);
        if lhs_ord != rhs_ord {
            return lhs_ord.cmp(&rhs_ord);
        }
        match (self, other) {
            (Value::Null, Value::Null) => Ordering::Equal,
            (Value::Bool(a), Value::Bool(b)) => a.cmp(b),
            (Value::Number(a), Value::Number(b)) => a.cmp(b),
            (Value::String(a), Value::String(b)) => a.as_ref().cmp(b.as_ref()),
            (Value::Array(a), Value::Array(b)) => a.cmp(b),
            (Value::Set(a), Value::Set(b)) => {
                // Compare as sorted vectors for deterministic ordering.
                let mut va: Vec<&Value> = a.iter().collect();
                let mut vb: Vec<&Value> = b.iter().collect();
                va.sort();
                vb.sort();
                va.cmp(&vb)
            }
            (Value::Object(a), Value::Object(b)) => {
                // Compare as sorted key-value pairs for deterministic ordering.
                let mut pa: Vec<(Value, &Value)> = a.iter().collect();
                let mut pb: Vec<(Value, &Value)> = b.iter().collect();
                pa.sort_by(|x, y| x.0.cmp(&y.0).then_with(|| x.1.cmp(y.1)));
                pb.sort_by(|x, y| x.0.cmp(&y.0).then_with(|| x.1.cmp(y.1)));
                pa.cmp(&pb)
            }
            (Value::Undefined, Value::Undefined) => Ordering::Equal,
            // Unreachable because we handled variant mismatch above.
            _ => Ordering::Equal,
        }
    }
}
