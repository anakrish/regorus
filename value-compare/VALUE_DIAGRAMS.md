# Value Implementation Diagrams

Architecture diagrams for all Rego Value implementations — baseline through v9.
Designed for PowerPoint presentations.

---

## Overview: Value Size Evolution

```mermaid
graph LR
  subgraph EVOLUTION["<b>Value Size Evolution</b>"]
    direction LR
    BL["<b>Baseline</b><br/>40 bytes<br/>Rc+BTreeMap"]
    V1["<b>v1</b><br/>24 bytes<br/>HashMap+SmolStr"]
    V2["<b>v2</b><br/>24 bytes<br/>HashMap+Arc&lt;str&gt;"]
    V3["<b>v3</b><br/>24 bytes<br/>HashSet+cached_hash"]
    V4["<b>v4</b><br/>16 bytes<br/>ArcStr thin ptr"]
    V5["<b>v5</b><br/>8 bytes<br/>NaN boxing"]
    V6["<b>v6</b><br/>8 bytes<br/>Tagged pointer"]
    V7["<b>v7</b><br/>8 bytes<br/>+Schema sharing"]
    V8["<b>v8</b><br/>16 bytes<br/>Flat enum+Schema"]
    V9["<b>v9</b><br/>16 bytes<br/>Arena Copy+Ext"]
  end

  BL --> V1 --> V2 --> V3 --> V4 --> V5 --> V6 --> V7 --> V8 --> V9

  style BL fill:#d63031,color:#fff
  style V1 fill:#e17055,color:#fff
  style V2 fill:#e17055,color:#fff
  style V3 fill:#e17055,color:#fff
  style V4 fill:#fdcb6e,color:#2d3436
  style V5 fill:#00b894,color:#fff
  style V6 fill:#00b894,color:#fff
  style V7 fill:#00b894,color:#fff
  style V8 fill:#0984e3,color:#fff
  style V9 fill:#6c5ce7,color:#fff
```

---

## Baseline: regorus::Value — 40 bytes

```mermaid
graph LR
  subgraph VALUE["<b>Baseline: regorus::Value</b> — 40 bytes"]
    direction TB
    V{{"Value<br/>(enum, 8 variants)"}}
    V --> N["Null"]
    V --> B["Bool(bool)"]
    V --> NUM["Number(Number)"]
    V --> S["String(Rc&lt;str&gt;)"]
    V --> A["Array(Rc&lt;Vec&lt;Value&gt;&gt;)"]
    V --> ST["Set(Rc&lt;BTreeSet&lt;Value&gt;&gt;)"]
    V --> O["Object(Rc&lt;BTreeMap&lt;Value,Value&gt;&gt;)"]
    V --> U["Undefined"]
  end

  subgraph NUMBER["<b>Number</b> — nested enum"]
    direction TB
    NUM2{{"Number"}}
    NUM2 --> UI["UInt(u64)"]
    NUM2 --> NI["Int(i64)"]
    NUM2 --> FL["Float(f64)"]
    NUM2 --> BI["BigInt(Rc&lt;BigInt&gt;)"]
  end

  NUM --> NUM2

  subgraph NOTES["<b>Key Properties</b>"]
    direction TB
    P1["BTreeMap objects — O(log n) lookup"]
    P2["BTreeSet sets — O(log n) membership"]
    P3["Rc pointers — single-threaded"]
    P4["Nested Number enum adds indirection"]
  end

  style VALUE fill:#e8f4f8,stroke:#0984e3,color:#2d3436
  style NUMBER fill:#f0e6ff,stroke:#6c5ce7,color:#2d3436
  style NOTES fill:#ffeaa7,stroke:#fdcb6e,color:#2d3436
  style V fill:#0984e3,color:#fff
  style NUM2 fill:#6c5ce7,color:#fff
```

---

## v1: HashMap + SmolStr — 24 bytes

```mermaid
graph LR
  subgraph VALUE["<b>v1: HashMap + SmolStr</b> — 24 bytes"]
    direction TB
    V{{"Value<br/>(enum, 8 variants)"}}
    V --> N["Null"]
    V --> B["Bool(bool)"]
    V --> NUM["Number(Number)"]
    V --> S["String(Arc&lt;str&gt;)"]
    V --> A["Array(Arc&lt;Vec&lt;Value&gt;&gt;)"]
    V --> ST["Set(Arc&lt;BTreeSet&lt;Value&gt;&gt;)"]
    V --> O["Object(Arc&lt;ObjectMap&gt;)"]
    V --> U["Undefined"]
  end

  subgraph OBJMAP["<b>ObjectMap</b> — enum"]
    direction TB
    OM{{"ObjectMap"}}
    OM --> SK["StringKeyed(<br/>HashMap&lt;SmolStr, Value&gt;)"]
    OM --> MX["Mixed(<br/>HashMap&lt;Value, Value&gt;)"]
  end

  O --> OM

  subgraph DELTA["<b>Delta vs Baseline</b>"]
    direction TB
    D1["✅ HashMap objects — O(1) lookup"]
    D2["✅ SmolStr — inline ≤23B strings"]
    D3["✅ Arc — thread-safe sharing"]
    D4["❌ Sets still BTreeSet"]
  end

  style VALUE fill:#e8f4f8,stroke:#0984e3,color:#2d3436
  style OBJMAP fill:#f0e6ff,stroke:#6c5ce7,color:#2d3436
  style DELTA fill:#ffeaa7,stroke:#fdcb6e,color:#2d3436
  style V fill:#0984e3,color:#fff
  style OM fill:#6c5ce7,color:#fff
```

---

## v2: HashMap + Arc\<str\> — 24 bytes

```mermaid
graph LR
  subgraph VALUE["<b>v2: HashMap + Arc&lt;str&gt;</b> — 24 bytes"]
    direction TB
    V{{"Value<br/>(enum, 8 variants)"}}
    V --> N["Null"]
    V --> B["Bool(bool)"]
    V --> NUM["Number(Number)"]
    V --> S["String(Arc&lt;str&gt;)"]
    V --> A["Array(Arc&lt;Vec&lt;Value&gt;&gt;)"]
    V --> ST["Set(Arc&lt;BTreeSet&lt;Value&gt;&gt;)"]
    V --> O["Object(Arc&lt;ObjectMap&gt;)"]
    V --> U["Undefined"]
  end

  subgraph OBJMAP["<b>ObjectMap</b> — enum"]
    direction TB
    OM{{"ObjectMap"}}
    OM --> SK["StringKeyed(<br/>HashMap&lt;Arc&lt;str&gt;, Value&gt;)"]
    OM --> MX["Mixed(<br/>HashMap&lt;Value, Value&gt;)"]
  end

  O --> OM

  subgraph INTERN["<b>Optional: Key Interning</b>"]
    direction TB
    TL["Thread-local HashSet&lt;Arc&lt;str&gt;&gt;"]
    TL --> DD["Deduplicates keys across<br/>objects — refcount bump<br/>instead of new allocation"]
  end

  subgraph DELTA["<b>Delta vs v1</b>"]
    direction TB
    D1["✅ Arc&lt;str&gt; — sharable between<br/>HashMap keys and Value::String"]
    D2["✅ Faster sorted serialization<br/>(Arc::clone is refcount bump)"]
    D3["❌ No inline short strings"]
  end

  style VALUE fill:#e8f4f8,stroke:#0984e3,color:#2d3436
  style OBJMAP fill:#f0e6ff,stroke:#6c5ce7,color:#2d3436
  style INTERN fill:#dfe6e9,stroke:#636e72,color:#2d3436
  style DELTA fill:#ffeaa7,stroke:#fdcb6e,color:#2d3436
  style V fill:#0984e3,color:#fff
  style OM fill:#6c5ce7,color:#fff
  style TL fill:#636e72,color:#fff
```

---

## v3: HashSet + Cached Hash — 24 bytes

```mermaid
graph LR
  subgraph VALUE["<b>v3: HashSet + Cached Hash</b> — 24 bytes"]
    direction TB
    V{{"Value<br/>(enum, 8 variants)"}}
    V --> N["Null"]
    V --> B["Bool(bool)"]
    V --> NUM["Number(Number)"]
    V --> S["String(Arc&lt;str&gt;)"]
    V --> A["Array(Arc&lt;Vec&lt;Value&gt;&gt;)"]
    V --> ST["Set(Arc&lt;HashSet&lt;Value&gt;&gt;)"]
    V --> O["Object(Arc&lt;ObjectMap&gt;)"]
    V --> U["Undefined"]
  end

  subgraph OBJMAP["<b>ObjectMap</b> — struct"]
    direction TB
    OM["strings: HashMap&lt;Arc&lt;str&gt;, Value&gt;"]
    OT["other: Option&lt;HashMap&lt;Value,Value&gt;&gt;"]
    CH["cached_hash: u64 ✨"]
  end

  O --> OM

  subgraph DELTA["<b>Delta vs v2</b>"]
    direction TB
    D1["✅ HashSet — O(1) set membership"]
    D2["✅ cached_hash — O(1) Hash for objects"]
    D3["✅ Order-independent hash accumulation"]
    D4["❌ Deserialization ~22% slower<br/>(hash computation on every insert)"]
  end

  style VALUE fill:#e8f4f8,stroke:#0984e3,color:#2d3436
  style OBJMAP fill:#f0e6ff,stroke:#6c5ce7,color:#2d3436
  style DELTA fill:#ffeaa7,stroke:#fdcb6e,color:#2d3436
  style V fill:#0984e3,color:#fff
  style CH fill:#00b894,color:#fff
```

---

## v4: ArcStr Thin Pointer — 16 bytes

```mermaid
graph LR
  subgraph VALUE["<b>v4: ArcStr Thin Pointer</b> — 16 bytes ⬇"]
    direction TB
    V{{"Value<br/>(enum, 8 variants)"}}
    V --> N["Null"]
    V --> B["Bool(bool)"]
    V --> NUM["Number(Number)"]
    V --> S["String(ArcStr) 🔑"]
    V --> A["Array(Arc&lt;Vec&lt;Value&gt;&gt;)"]
    V --> ST["Set(Arc&lt;HashSet&lt;Value&gt;&gt;)"]
    V --> O["Object(Arc&lt;ObjectMap&gt;)"]
    V --> U["Undefined"]
  end

  subgraph ARCSTR["<b>ArcStr</b> — 8-byte thin pointer"]
    direction TB
    AS["Single *const pointer (8B)"]
    AS --> HEAP["Heap: {refcount, len, data...}<br/>All in one allocation"]
  end

  S --> AS

  subgraph OBJMAP["<b>ObjectMap</b> — struct"]
    direction TB
    OM["strings: HashMap&lt;ArcStr, Value&gt;"]
    OT["other: Option&lt;HashMap&lt;V,V&gt;&gt;"]
    CH["cached_hash: u64"]
  end

  O --> OM

  subgraph DELTA["<b>Delta vs v3</b>"]
    direction TB
    D1["✅ 24B → 16B (33% smaller)"]
    D2["✅ ArcStr: 8B thin ptr vs<br/>Arc&lt;str&gt;: 16B fat ptr"]
    D3["✅ Better cache density<br/>(4 Values per cache line)"]
    D4["✅ 15% faster unsorted serialization"]
  end

  style VALUE fill:#e8f4f8,stroke:#0984e3,color:#2d3436
  style ARCSTR fill:#dfe6e9,stroke:#636e72,color:#2d3436
  style OBJMAP fill:#f0e6ff,stroke:#6c5ce7,color:#2d3436
  style DELTA fill:#ffeaa7,stroke:#fdcb6e,color:#2d3436
  style V fill:#0984e3,color:#fff
  style S fill:#00b894,color:#fff
  style AS fill:#636e72,color:#fff
```

---

## v5: NaN-Boxed Value — 8 bytes

```mermaid
graph LR
  subgraph VALUE["<b>v5: NaN-Boxed Value</b> — 8 bytes ⬇⬇"]
    direction TB
    V["Value { bits: u64 }<br/>Single u64 — all types packed"]
  end

  subgraph ENCODING["<b>NaN Boxing Encoding</b> — upper 16 bits = tag"]
    direction TB
    E1["Normal f64 bits → Float"]
    E2["0xFFF8 → Immediate (Null/Bool/Undef)"]
    E3["0xFFFA + 48-bit ptr → HeapNumber"]
    E4["0xFFFC + 48-bit ptr → String (ArcStr)"]
    E5["0xFFFD + 48-bit ptr → Array"]
    E6["0xFFFE + 48-bit ptr → Object"]
    E7["0xFFFF + 48-bit ptr → Set"]
  end

  V --> ENCODING

  subgraph HEAP["<b>HeapNumber</b>"]
    direction TB
    H1["UInt(u64)"]
    H2["Int(i64)"]
    H3["BigInt(Arc&lt;BigInt&gt;)"]
  end

  E3 --> H1

  subgraph DELTA["<b>Delta vs v4</b>"]
    direction TB
    D1["✅ 16B → 8B (8 Values/cache line)"]
    D2["✅ Floats stored directly as bits"]
    D3["✅ Small ints: exact f64 repr"]
    D4["❌ Assumes 48-bit VA — NOT portable"]
    D5["❌ Arithmetic 1.7× slower (f64 round-trip)"]
  end

  style VALUE fill:#e8f4f8,stroke:#0984e3,color:#2d3436
  style ENCODING fill:#f0e6ff,stroke:#6c5ce7,color:#2d3436
  style HEAP fill:#dfe6e9,stroke:#636e72,color:#2d3436
  style DELTA fill:#ffeaa7,stroke:#fdcb6e,color:#2d3436
  style V fill:#0984e3,color:#fff
  style D4 fill:#d63031,color:#fff
  style D5 fill:#d63031,color:#fff
```

---

## v6: Portable Tagged Pointer — 8 bytes

```mermaid
graph LR
  subgraph VALUE["<b>v6: Portable Tagged Pointer</b> — 8 bytes"]
    direction TB
    V["Value { bits: usize }<br/>Low 3 bits = tag"]
  end

  subgraph ENCODING["<b>Tag Encoding</b> — bits[0:2]"]
    direction TB
    E1["0b000 → Pointer to Arc&lt;HeapValue&gt;"]
    E2["0b001 → UInt (61-bit inline)"]
    E3["0b010 → NegInt (61-bit inline)"]
    E4["0b011 → Immediate (Null/Bool/Undef)"]
  end

  V --> ENCODING

  subgraph HEAPVAL["<b>HeapValue</b> — Arc-wrapped enum"]
    direction TB
    H1["Float(f64)"]
    H2["BigInt(Arc&lt;BigInt&gt;)"]
    H3["LargeUInt(u64) / LargeInt(i64)"]
    H4["String(ArcStr)"]
    H5["Array(Vec&lt;Value&gt;)"]
    H6["Object(ObjectMap)"]
    H7["Set(HashSet&lt;Value&gt;)"]
  end

  E1 --> H1

  subgraph DELTA["<b>Delta vs v5</b>"]
    direction TB
    D1["✅ Fully portable — no VA-width assumption"]
    D2["✅ Inline integers up to 61 bits"]
    D3["✅ Arithmetic 6.7× faster than v5<br/>(shift+add vs f64 round-trip)"]
    D4["✅ Number eq 2.8× faster (usize ==)"]
    D5["❌ Arc&lt;HeapValue&gt; per non-int value"]
    D6["❌ Deserialization 1.4× slower"]
  end

  style VALUE fill:#e8f4f8,stroke:#0984e3,color:#2d3436
  style ENCODING fill:#f0e6ff,stroke:#6c5ce7,color:#2d3436
  style HEAPVAL fill:#dfe6e9,stroke:#636e72,color:#2d3436
  style DELTA fill:#ffeaa7,stroke:#fdcb6e,color:#2d3436
  style V fill:#0984e3,color:#fff
  style E2 fill:#00b894,color:#fff
  style E3 fill:#00b894,color:#fff
```

---

## v7: Schema-Shared Compact Objects — 8 bytes

```mermaid
graph LR
  subgraph VALUE["<b>v7: Schema-Shared Compact Objects</b> — 8 bytes"]
    direction TB
    V["Value { bits: usize }<br/>Same tagged-pointer as v6"]
  end

  subgraph OBJMAP["<b>ObjectMap</b> — enum repr"]
    direction TB
    OM{{"ObjectRepr"}}
    OM --> COMPACT
    OM --> MAP["MapObject<br/>(HashMap fallback)"]
  end

  subgraph COMPACT["<b>CompactObject</b> ✨"]
    direction TB
    SCH["schema: Arc&lt;Schema&gt;"]
    VALS["values: Box&lt;[Value]&gt;"]
    CH["cached_hash: u64"]
  end

  subgraph SCHEMA["<b>Schema</b> — interned, shared"]
    direction TB
    SK["keys: Arc&lt;[ArcStr]&gt;<br/>(sorted)"]
    SL["lookup: HashMap&lt;ArcStr, u32&gt;"]
  end

  SCH --> SK

  subgraph DELTA["<b>Delta vs v6</b>"]
    direction TB
    D1["✅ Object eq 40% faster<br/>(Arc::ptr_eq on Schema)"]
    D2["✅ Sorted serialization 42% faster<br/>(keys pre-sorted in Schema)"]
    D3["✅ Memory: N objects share 1 Schema"]
    D4["❌ Deserialization 8% slower<br/>(schema interning overhead)"]
  end

  style VALUE fill:#e8f4f8,stroke:#0984e3,color:#2d3436
  style OBJMAP fill:#f0e6ff,stroke:#6c5ce7,color:#2d3436
  style COMPACT fill:#00b894,color:#fff
  style SCHEMA fill:#dfe6e9,stroke:#636e72,color:#2d3436
  style DELTA fill:#ffeaa7,stroke:#fdcb6e,color:#2d3436
  style V fill:#0984e3,color:#fff
  style OM fill:#6c5ce7,color:#fff
```

---

## v8: 16-Byte Enum + Flattened Number + Schema — 16 bytes

```mermaid
graph LR
  subgraph VALUE["<b>v8: 16-Byte Enum + Flattened Number + Schema</b> — 16 bytes"]
    direction TB
    V{{"Value<br/>(enum, 11 variants)"}}
    V --> N["Null"]
    V --> B["Bool(bool)"]
    V --> UI["UInt(u64) 🔑"]
    V --> NI["Int(i64) 🔑"]
    V --> FL["Float(f64) 🔑"]
    V --> BI["BigInt(Arc&lt;BigInt&gt;) 🔑"]
    V --> S["String(ArcStr)"]
    V --> A["Array(Arc&lt;Vec&lt;Value&gt;&gt;)"]
    V --> ST["Set(Arc&lt;HashSet&lt;Value&gt;&gt;)"]
    V --> O["Object(Arc&lt;ObjectMap&gt;)"]
    V --> U["Undefined"]
  end

  subgraph OBJMAP["<b>ObjectMap</b> — same as v7"]
    direction TB
    OM{{"ObjectRepr"}}
    OM --> C["CompactObject<br/>(schema + values[])"]
    OM --> M["MapObject<br/>(HashMap fallback)"]
  end

  O --> OM

  subgraph DELTA["<b>Delta vs v7</b>"]
    direction TB
    D1["✅ Number flattened into Value<br/>(no nested enum)"]
    D2["✅ Object eq 41% faster<br/>(direct enum cmp, no Arc deref)"]
    D3["✅ Sorted serialization 30% faster"]
    D4["✅ Deserialization 20% faster<br/>(no Arc&lt;HeapValue&gt; allocation)"]
    D5["✅ Simple: pure Rust enum, no unsafe"]
    D6["❌ 16B vs 8B (half the cache density)"]
    D7["❌ Arithmetic 3.8× slower<br/>(Number::add vs tagged shift+add)"]
  end

  style VALUE fill:#e8f4f8,stroke:#0984e3,color:#2d3436
  style OBJMAP fill:#f0e6ff,stroke:#6c5ce7,color:#2d3436
  style DELTA fill:#ffeaa7,stroke:#fdcb6e,color:#2d3436
  style V fill:#0984e3,color:#fff
  style OM fill:#6c5ce7,color:#fff
  style UI fill:#00b894,color:#fff
  style NI fill:#00b894,color:#fff
  style FL fill:#00b894,color:#fff
  style BI fill:#00b894,color:#fff
```

---

## v9: Arena Two-Enum + Schema + v8 Interop — 16 bytes, Copy

```mermaid
graph LR
  subgraph WRAPPER["<b>v9: Arena-Allocated Two-Enum + Schema + v8 Interop</b> — 16 bytes, Copy"]
    direction TB
    VAL{{"Value&lt;'a&gt;<br/>(2 variants)"}}
    VAL --> ARENA["Arena(ArenaValue&lt;'a&gt;)"]
    VAL --> EXT["Ext(&amp;'a v8::Value) 🔑"]
  end

  subgraph INNER["<b>ArenaValue&lt;'a&gt;</b> — 11 variants, 16B, Copy"]
    direction TB
    AV{{"ArenaValue"}}
    AV --> N["Null"]
    AV --> B["Bool(bool)"]
    AV --> UI["UInt(u64)"]
    AV --> NI["Int(i64)"]
    AV --> FL["Float(f64)"]
    AV --> BI["BigInt(&amp;'a BigInt)"]
    AV --> S["String(&amp;'a ArenaStr)"]
    AV --> A["Array(&amp;'a ArenaArray)"]
    AV --> ST["Set(&amp;'a ArenaSet)"]
    AV --> O["Object(&amp;'a ObjectMap)"]
    AV --> U["Undefined"]
  end

  ARENA --> AV

  subgraph BUMP["<b>Bump Arena</b>"]
    direction TB
    B1["All data allocated via pointer bump"]
    B2["Clone = memcpy (Copy trait)"]
    B3["Drop = no-op (bulk free)"]
  end

  subgraph INTEROP["<b>v8 Interop</b>"]
    direction TB
    I1["Value::from_ref(&amp;v8::Value)"]
    I2["O(1) zero-copy wrapping"]
    I3["No allocation needed"]
  end

  EXT --> I1

  subgraph DELTA["<b>Delta vs v8</b>"]
    direction TB
    D1["✅ Arithmetic 6.9× faster"]
    D2["✅ Deser 11% faster (arena bump)"]
    D3["✅ Set create 20% faster"]
    D4["✅ Zero-cost Copy clone"]
    D5["✅ O(1) v8 interop via Ext"]
    D6["❌ Object eq 22% slower<br/>(two-enum branch overhead)"]
    D7["❌ Lifetime 'a threading required"]
  end

  style WRAPPER fill:#e8f4f8,stroke:#0984e3,color:#2d3436
  style INNER fill:#f0e6ff,stroke:#6c5ce7,color:#2d3436
  style BUMP fill:#dfe6e9,stroke:#636e72,color:#2d3436
  style INTEROP fill:#00b894,color:#fff
  style DELTA fill:#ffeaa7,stroke:#fdcb6e,color:#2d3436
  style VAL fill:#0984e3,color:#fff
  style AV fill:#6c5ce7,color:#fff
  style EXT fill:#00b894,color:#fff
  style ARENA fill:#6c5ce7,color:#fff
```

---

## Color Legend

| Color | Meaning |
|-------|---------|
| 🔵 Blue | Value type (main enum / wrapper) |
| 🟣 Purple | Inner type (Number, ArenaValue, ObjectRepr) |
| 🟢 Green | Key innovation for that version |
| 🟡 Yellow | Delta / change notes |
| ⬜ Gray | Supporting types (ArcStr, HeapValue, Arena) |
| 🔴 Red | Portability / performance concern |
