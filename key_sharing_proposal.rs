// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Proposal for Key Sharing Optimization in Value Deserialization

use std::rc::Rc;
use std::collections::HashMap;
use std::cell::RefCell;
use serde::de::{self, Deserializer, MapAccess, Visitor};

// Option 1: Thread-local string interning for keys
thread_local! {
    static KEY_INTERNER: RefCell<HashMap<String, Rc<str>>> = RefCell::new(HashMap::new());
}

/// Intern a string key, returning a shared Rc<str>
pub fn intern_key(s: &str) -> Rc<str> {
    KEY_INTERNER.with(|interner| {
        let mut map = interner.borrow_mut();
        if let Some(existing) = map.get(s) {
            existing.clone()
        } else {
            let rc_str: Rc<str> = s.into();
            map.insert(s.to_string(), rc_str.clone());
            rc_str
        }
    })
}

// Option 2: Global string interning with arc for thread safety
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

lazy_static::lazy_static! {
    static ref GLOBAL_KEY_INTERNER: Mutex<HashMap<String, Arc<str>>> = Mutex::new(HashMap::new());
}

pub fn intern_key_global(s: &str) -> Arc<str> {
    let mut interner = GLOBAL_KEY_INTERNER.lock().unwrap();
    if let Some(existing) = interner.get(s) {
        existing.clone()
    } else {
        let arc_str: Arc<str> = s.into();
        interner.insert(s.to_string(), arc_str.clone());
        arc_str
    }
}

// Option 3: Using smol_str for small string optimization
use smol_str::SmolStr;

/// SmolStr provides inline storage for strings up to 22 bytes (on 64-bit systems)
/// This can be very effective for common JSON keys like "name", "id", "type", etc.
pub struct OptimizedValue {
    // Using SmolStr for keys could significantly reduce allocations for common keys
    // SmolStr automatically inlines strings <= 22 bytes, avoiding heap allocation
    pub key_example: SmolStr,
}

// Shared string representation that keeps short keys inline and larger ones shared via Rc
pub enum SharedStr {
    Inline(SmolStr),     // Inline storage for <= 22 bytes when smol_str is available
    Shared(Rc<str>),     // Reference-counted pointer for longer strings or shared keys
}

// Alternate proposal: keep Value::String(Rc<str>) stable and add a per-deserializer arena.
//    - Works in no_std (uses hashbrown + alloc).
//    - All sharing scoped to one payload; no global state or DashMap.
//    - Longer keys reuse Rc<str> slots, short keys still benefit because Rc avoids copies.
use hashbrown::hash_map::Entry;
use hashbrown::HashMap as ArenaMap;

pub struct KeyArena {
    // Box<str> is the owned backing; Rc<str> aliases are handed to Value::String unchanged.
    table: ArenaMap<Box<str>, Rc<str>>,
}

impl KeyArena {
    pub fn new() -> Self {
        Self { table: ArenaMap::new() }
    }

    pub fn intern<'s>(&mut self, key: &'s str) -> Rc<str> {
        match self.table.entry(key.into()) {
            Entry::Occupied(slot) => slot.get().clone(),
            Entry::Vacant(slot) => {
                let shared: Rc<str> = key.into();
                slot.insert(shared.clone());
                shared
            }
        }
    }
}

// During deserialization the visitor receives a mutable KeyArena.
// Every object field fetches keys via arena.intern(key) before inserting into the BTreeMap.
// Values constructed elsewhere keep using Value::String directly, so the public API stays untouched.

// Modified visitor for optimized deserialization
struct OptimizedValueVisitor;

impl<'de> Visitor<'de> for OptimizedValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a value")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        // For string values, we might still want to use regular Rc<str>
        // since they're not typically repeated as much as keys
        Ok(Value::String(s.to_string().into()))
    }

    fn visit_map<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
    where
        V: MapAccess<'de>,
    {
        let mut map = BTreeMap::new();
        
        while let Some(key) = visitor.next_key::<&str>()? {
            // Intern the key to share it across objects
            let interned_key = Value::String(intern_key(key));
            let value = visitor.next_value()?;
            map.insert(interned_key, value);
        }
        
        Ok(Value::from(map))
    }
}

// Statistics tracking for optimization effectiveness
pub struct KeySharingStats {
    pub total_keys_processed: usize,
    pub unique_keys: usize,
    pub memory_saved_bytes: usize,
    pub intern_cache_hits: usize,
}

impl KeySharingStats {
    pub fn efficiency_ratio(&self) -> f64 {
        if self.total_keys_processed == 0 {
            0.0
        } else {
            self.intern_cache_hits as f64 / self.total_keys_processed as f64
        }
    }
}

// Benchmarking structure for testing different approaches
#[cfg(test)]
mod benchmarks {
    use super::*;
    
    // Test data generator for repeated keys scenario
    pub fn generate_test_data_with_repeated_keys(num_objects: usize) -> String {
        let common_keys = ["name", "id", "type", "status", "created_at", "updated_at"];
        let mut json_objects = Vec::new();
        
        for i in 0..num_objects {
            let obj = format!(
                r#"{{"name": "object_{}", "id": {}, "type": "test", "status": "active", "created_at": "2023-01-01", "updated_at": "2023-01-02"}}"#,
                i, i
            );
            json_objects.push(obj);
        }
        
        format!("[{}]", json_objects.join(","))
    }
}