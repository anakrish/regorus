// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Concrete implementation proposal for key sharing optimization

use std::rc::Rc;
use std::collections::{BTreeMap, HashMap};
use std::cell::RefCell;
use serde::de::{self, Deserializer, MapAccess, Visitor};

// Phase 1: Add smol_str dependency and implement hybrid string storage
use smol_str::SmolStr;

/// Optimized string representation that chooses the best storage strategy
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OptimizedString {
    /// For strings <= 22 bytes - stored inline
    Inline(SmolStr),
    /// For longer strings that may benefit from sharing
    Shared(Rc<str>),
}

impl OptimizedString {
    pub fn new(s: &str) -> Self {
        if s.len() <= 22 {
            Self::Inline(SmolStr::new(s))
        } else {
            Self::Shared(s.into())
        }
    }
    
    pub fn from_string(s: String) -> Self {
        if s.len() <= 22 {
            Self::Inline(SmolStr::new(&s))
        } else {
            Self::Shared(s.into())
        }
    }
    
    pub fn as_str(&self) -> &str {
        match self {
            Self::Inline(s) => s.as_str(),
            Self::Shared(s) => s.as_ref(),
        }
    }
}

impl AsRef<str> for OptimizedString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<&str> for OptimizedString {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for OptimizedString {
    fn from(s: String) -> Self {
        Self::from_string(s)
    }
}

// Phase 2: Key interning for frequently used keys
thread_local! {
    static KEY_CACHE: RefCell<HashMap<String, OptimizedString>> = RefCell::new(HashMap::new());
}

/// Statistics for monitoring key sharing effectiveness
#[derive(Debug, Default)]
pub struct KeySharingStats {
    pub total_keys: u64,
    pub cache_hits: u64,
    pub inline_strings: u64,
    pub shared_strings: u64,
}

impl KeySharingStats {
    pub fn hit_ratio(&self) -> f64 {
        if self.total_keys == 0 {
            0.0
        } else {
            self.cache_hits as f64 / self.total_keys as f64
        }
    }
    
    pub fn inline_ratio(&self) -> f64 {
        if self.total_keys == 0 {
            0.0
        } else {
            self.inline_strings as f64 / self.total_keys as f64
        }
    }
}

thread_local! {
    static KEY_STATS: RefCell<KeySharingStats> = RefCell::new(KeySharingStats::default());
}

/// Get an optimized string for object keys with caching
pub fn get_optimized_key(s: &str) -> OptimizedString {
    KEY_STATS.with(|stats| {
        stats.borrow_mut().total_keys += 1;
    });
    
    // For very short strings, skip caching overhead
    if s.len() <= 22 {
        KEY_STATS.with(|stats| {
            stats.borrow_mut().inline_strings += 1;
        });
        return OptimizedString::Inline(SmolStr::new(s));
    }
    
    // For longer strings, use cache
    KEY_CACHE.with(|cache| {
        let mut cache_map = cache.borrow_mut();
        if let Some(cached) = cache_map.get(s) {
            KEY_STATS.with(|stats| {
                stats.borrow_mut().cache_hits += 1;
            });
            cached.clone()
        } else {
            let optimized = OptimizedString::Shared(s.into());
            cache_map.insert(s.to_string(), optimized.clone());
            KEY_STATS.with(|stats| {
                stats.borrow_mut().shared_strings += 1;
            });
            optimized
        }
    })
}

/// Get current key sharing statistics
pub fn get_key_stats() -> KeySharingStats {
    KEY_STATS.with(|stats| stats.borrow().clone())
}

/// Clear key cache and reset statistics (useful for testing)
pub fn clear_key_cache() {
    KEY_CACHE.with(|cache| cache.borrow_mut().clear());
    KEY_STATS.with(|stats| *stats.borrow_mut() = KeySharingStats::default());
}

// Phase 3: Modified Value enum to use optimized strings for object keys
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum OptimizedValue {
    Null,
    Bool(bool),
    Number(crate::Number),
    String(OptimizedString),  // Use optimized string for all string values
    Array(Rc<Vec<OptimizedValue>>),
    Set(Rc<BTreeSet<OptimizedValue>>),
    // Object keys use optimized strings, values can be any OptimizedValue
    Object(Rc<BTreeMap<OptimizedString, OptimizedValue>>),
    Undefined,
}

// Phase 4: Custom deserializer visitor
struct OptimizedValueVisitor;

impl<'de> Visitor<'de> for OptimizedValueVisitor {
    type Value = OptimizedValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("any valid JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(OptimizedValue::Bool(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        // For string values, we could still optimize but less aggressively
        Ok(OptimizedValue::String(OptimizedString::new(value)))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(OptimizedValue::String(OptimizedString::from_string(value)))
    }

    fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
    where
        V: MapAccess<'de>,
    {
        let mut object = BTreeMap::new();
        
        while let Some(key) = map.next_key::<String>()? {
            // Use optimized key with caching for object keys
            let optimized_key = get_optimized_key(&key);
            let value = map.next_value()?;
            object.insert(optimized_key, value);
        }
        
        Ok(OptimizedValue::Object(Rc::new(object)))
    }

    fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
    where
        V: serde::de::SeqAccess<'de>,
    {
        let mut array = Vec::new();
        while let Some(value) = seq.next_element()? {
            array.push(value);
        }
        Ok(OptimizedValue::Array(Rc::new(array)))
    }
}

impl<'de> serde::Deserialize<'de> for OptimizedValue {
    fn deserialize<D>(deserializer: D) -> Result<OptimizedValue, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(OptimizedValueVisitor)
    }
}

// Migration strategy: Gradual adoption
impl From<crate::Value> for OptimizedValue {
    fn from(value: crate::Value) -> Self {
        match value {
            crate::Value::Null => OptimizedValue::Null,
            crate::Value::Bool(b) => OptimizedValue::Bool(b),
            crate::Value::Number(n) => OptimizedValue::Number(n),
            crate::Value::String(s) => OptimizedValue::String(OptimizedString::new(s.as_ref())),
            crate::Value::Array(arr) => {
                let converted: Vec<OptimizedValue> = arr.iter().map(|v| v.clone().into()).collect();
                OptimizedValue::Array(Rc::new(converted))
            },
            crate::Value::Set(set) => {
                let converted: BTreeSet<OptimizedValue> = set.iter().map(|v| v.clone().into()).collect();
                OptimizedValue::Set(Rc::new(converted))
            },
            crate::Value::Object(obj) => {
                let converted: BTreeMap<OptimizedString, OptimizedValue> = obj.iter()
                    .map(|(k, v)| {
                        let key = match k {
                            crate::Value::String(s) => get_optimized_key(s.as_ref()),
                            _ => OptimizedString::new(&serde_json::to_string(k).unwrap_or_default()),
                        };
                        (key, v.clone().into())
                    })
                    .collect();
                OptimizedValue::Object(Rc::new(converted))
            },
            crate::Value::Undefined => OptimizedValue::Undefined,
        }
    }
}

// Benchmarking utilities
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_optimization() {
        clear_key_cache();
        
        // Test common short keys (should use inline storage)
        let key1 = get_optimized_key("id");
        let key2 = get_optimized_key("name");
        let key3 = get_optimized_key("type");
        
        // Test repeated keys (should hit cache for long keys)
        let long_key = "this_is_a_very_long_key_that_exceeds_the_inline_limit";
        let long1 = get_optimized_key(long_key);
        let long2 = get_optimized_key(long_key);
        
        let stats = get_key_stats();
        assert_eq!(stats.total_keys, 5);
        assert_eq!(stats.inline_strings, 3); // id, name, type
        assert_eq!(stats.shared_strings, 1);  // first long key
        assert_eq!(stats.cache_hits, 1);      // second long key
        assert_eq!(stats.hit_ratio(), 0.2);   // 1/5
        assert_eq!(stats.inline_ratio(), 0.6); // 3/5
    }
    
    #[test]
    fn test_memory_efficiency() {
        // Test that inline strings don't allocate
        let inline_str = OptimizedString::new("short");
        match inline_str {
            OptimizedString::Inline(_) => assert!(true),
            OptimizedString::Shared(_) => panic!("Expected inline storage"),
        }
        
        // Test that long strings use shared storage
        let long_str = OptimizedString::new("this is definitely longer than twenty two characters");
        match long_str {
            OptimizedString::Inline(_) => panic!("Expected shared storage"),
            OptimizedString::Shared(_) => assert!(true),
        }
    }
}