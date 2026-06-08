// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Analysis of smol_str benefits for Regorus Value optimization

/*
SmolStr Benefits Analysis:

1. **Inline Storage**: SmolStr can store strings up to 22 bytes inline (on 64-bit systems)
   - No heap allocation for short strings
   - Perfect for common JSON keys: "id", "name", "type", "status", etc.
   - Zero-copy for string literals

2. **Memory Efficiency**: 
   - Same size as String (24 bytes on 64-bit)
   - But avoids heap allocation for small strings
   - Automatic deduplication of static strings

3. **Performance Benefits**:
   - Faster creation for small strings (no malloc)
   - Better cache locality
   - Reduced memory fragmentation

4. **API Compatibility**:
   - Implements Deref<Target = str>
   - Direct replacement for String in many cases
   - Serialization/deserialization support

Common JSON Key Length Analysis:
- "id": 2 bytes ✓ (inline)
- "name": 4 bytes ✓ (inline) 
- "type": 4 bytes ✓ (inline)
- "status": 6 bytes ✓ (inline)
- "created_at": 10 bytes ✓ (inline)
- "description": 11 bytes ✓ (inline)
- "configuration": 13 bytes ✓ (inline)
- "containerID": 11 bytes ✓ (inline)
- "layerPaths": 10 bytes ✓ (inline)

Most JSON keys in typical payloads are <= 22 bytes!
*/

// Potential integration approaches:

// Option 1: Replace Rc<str> with SmolStr for all strings
pub enum Value {
    Null,
    Bool(bool),
    Number(Number),
    String(SmolStr),  // Instead of Rc<str>
    Array(Rc<Vec<Value>>),
    Set(Rc<BTreeSet<Value>>),
    Object(Rc<BTreeMap<Value, Value>>),
    Undefined,
}

// Option 2: Hybrid approach - SmolStr for keys, Rc<str> for values
pub enum Value {
    Null,
    Bool(bool), 
    Number(Number),
    String(Rc<str>),  // For potentially large string values
    Array(Rc<Vec<Value>>),
    Set(Rc<BTreeSet<Value>>),
    Object(Rc<BTreeMap<SmolStr, Value>>),  // SmolStr keys
    Undefined,
}

// Option 3: Smart string type that chooses best representation
pub enum SmartString {
    Small(SmolStr),      // <= 22 bytes
    Shared(Rc<str>),     // > 22 bytes, potentially shared
}

impl SmartString {
    pub fn new(s: &str) -> Self {
        if s.len() <= 22 {
            Self::Small(SmolStr::new(s))
        } else {
            Self::Shared(s.into())
        }
    }
    
    pub fn as_str(&self) -> &str {
        match self {
            Self::Small(s) => s.as_str(),
            Self::Shared(s) => s.as_ref(),
        }
    }
}

// Memory usage comparison:
/*
Current: Rc<str> for "name" (4 bytes):
- Rc allocation: 24+ bytes (rc count + string data + heap overhead)
- String data: 4 bytes
- Total: ~28+ bytes

With SmolStr for "name":
- SmolStr: 24 bytes (inline storage)
- String data: 4 bytes (inline)
- Total: 24 bytes
- Savings: ~4+ bytes per instance + no heap fragmentation

For 1000 objects with 6 common keys each:
- Current: 6000 * 28+ = 168KB+
- SmolStr: 6000 * 24 = 144KB
- Savings: 24KB+ per 1000 objects (14% reduction)
*/

// Performance considerations:
/*
1. **Creation**: SmolStr::new() is faster for small strings (no malloc)
2. **Cloning**: SmolStr cloning is cheap for small strings (copy 24 bytes)
3. **Comparison**: Same performance as string comparison
4. **Memory locality**: Better cache performance due to inline storage
5. **Thread safety**: SmolStr is Send + Sync, good for multi-threading

Potential downsides:
1. **Larger stack usage**: Each SmolStr is 24 bytes vs 8 bytes for &str
2. **No automatic deduplication**: Unlike Rc<str>, identical SmolStr values aren't shared
3. **Limited inline size**: Strings > 22 bytes still need heap allocation
*/

// Recommendation: Hybrid approach with measurements
pub struct OptimizedValue {
    // Use SmolStr for object keys (typically short and repeated)
    // Keep Rc<str> for string values (can be large, less predictable)
    // Add interning for frequently repeated longer keys
}

// Implementation priority:
/*
1. **Phase 1**: Replace object keys with SmolStr
   - Low risk, high impact for typical JSON
   - Easy to measure improvement

2. **Phase 2**: Add key interning for long keys  
   - For keys > 22 bytes that are repeated
   - Measure effectiveness before/after

3. **Phase 3**: Consider SmolStr for all strings
   - Broader change, need careful performance testing
   - May benefit from profiling real-world usage

4. **Phase 4**: Advanced optimizations
   - Custom allocators for key pools
   - Context-aware string optimization
*/