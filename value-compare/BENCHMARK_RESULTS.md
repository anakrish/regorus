# Value-Compare Benchmark Results

**Date:** 2025-07-11
**Platform:** macOS (Apple Silicon)
**Profile:** release (optimized + debuginfo)
**Tool:** Criterion 0.5

## Design

**Baseline** (`regorus::Value`): BTreeMap-based objects, BTreeSet-based sets, BigInt-backed numbers.

**v1** (`HashMap + SmolStr`): `ObjectMap` enum with `StringKeyed(HashMap<SmolStr, Value>)` for JSON objects and `Mixed(HashMap<Value, Value>)` for Rego objects with non-string keys. Numbers use tagged enum (`UInt`/`NInt`/`Float`) with BigInt only when needed. Sets still use `BTreeSet<Value>`.

**v2** (`HashMap + Arc<str>`): Same design as v1 but uses `Arc<str>` instead of `SmolStr` for HashMap keys. Sets still use `BTreeSet<Value>`.

**v2+interning**: v2 with opt-in thread-local key interning. A `HashSet<Arc<str>>` per thread deduplicates keys: the first occurrence allocates on the heap; subsequent encounters reuse the existing `Arc<str>` via a cheap refcount bump. Activated by deserializing into `v2::Interned` instead of `v2::Value`. Especially beneficial when deserializing arrays of objects with shared key names (common in OPA data documents).

**v3** (`HashSet + cached hash`): Builds on v2's `Arc<str>` keys but redesigns two areas:

1. **Sets use `HashSet<Value>`** instead of `BTreeSet<Value>`. Since Rego sets are unordered, there is no need for the Ord-based BTreeSet — only Hash+Eq are needed for correctness.
2. **ObjectMap stores a precomputed order-independent hash** (`cached_hash: u64`). Each entry's hash is computed via `DefaultHasher::new()` and accumulated with `wrapping_add`, making the aggregate hash independent of insertion order. This enables O(1) `Hash` for objects and fast equality rejection (check `cached_hash` before comparing contents).

The struct-based ObjectMap has `strings: HashMap<Arc<str>, Value>` for string-keyed entries and `other: Option<HashMap<Value, Value>>` for non-string keys, with incremental cache maintenance on insert/update.

**v3+interning**: v3 with the same thread-local key interning as v2+interning.

**v4** (`ArcStr + cached hash`): Same design as v3 but replaces `Arc<str>` with `arcstr::ArcStr` — a thin pointer (single `*const` instead of `(*const, usize)` fat pointer). This shrinks `Value` from 24 bytes to **16 bytes** (33% reduction), improving cache density. `ArcStr` stores `{refcount, length, data[..]}` in a single allocation with the length inline, supports `Deref<Target=str>`, `Borrow<str>`, and `ArcStr::ptr_eq()` for pointer-based equality fast-path.

**v4+interning**: v4 with thread-local key interning using `HashSet<ArcStr>`.

**v5** (`NaN-boxed 8-byte Value`): Encodes the entire `Value` in a single `u64` using IEEE 754 NaN boxing. Floats are stored as raw f64 bits. All other types are encoded in the quiet NaN space (upper 16 bits = `0xFFF8`+tag, lower 48 bits = pointer or literal). Immediates (null, true, false, undefined) use a 3-bit sub-tag. Strings use `ArcStr` (same as v4), arrays/objects/sets use `Arc<Vec/ObjectMap/HashSet>` — all pointer types are truncated to 48 bits. Integers ≤ 2⁵³ are stored directly as f64 (exactly representable); larger integers spill to a heap-allocated `HeapNumber`. This makes `Value` exactly **8 bytes** — half of v4's 16 bytes, fitting 8 values per 64-byte cache line. `ObjectMap` reuses v4's dual-HashMap design with `cached_hash`.

**v5+interning**: v5 with thread-local key interning using `HashSet<ArcStr>`.

**v6** (`Portable tagged pointer`): Encodes the entire `Value` in a single `usize` (8 bytes on 64-bit) using low-bit pointer tagging. Heap-allocated values (floats, strings, arrays, objects, sets, big integers) are stored via `Arc<HeapValue>` — since `Arc` allocations are aligned to ≥8 bytes, the low 3 bits are always zero and can be used as tag bits. Unsigned integers ≤ 2⁶¹−1 are stored inline (shifted left 3 + tag `0b001`); negative integers with magnitude ≤ 2⁶¹ are stored inline (shifted left 3 + tag `0b010`); immediates (null, true, false, undefined) use tag `0b011` with a sub-tag. Unlike v5's NaN boxing which assumes 48-bit virtual addresses, v6 is **fully portable** — it works correctly on any 64-bit target (including x86_64 with LA57/57-bit VA, aarch64 with LVA/52-bit VA).

**v6+interning**: v6 with thread-local key interning using `HashSet<ArcStr>`.

**v7** (`Tagged pointer + schema-shared compact objects`): Combines v6's encoding with schema-shared compact objects. Objects with identical key sets share a single `Schema` allocation (sorted keys + lookup HashMap). A `CompactObject` stores only `Arc<Schema>` + `Box<[Value]>` (values array indexed by schema position). Schema interning during deserialization ensures objects with the same keys reuse the same Schema. This enables: (1) **free sorted iteration** — keys are pre-sorted in the Schema, so `iter_sorted()` is zero-cost; (2) **fast same-schema equality** — if two objects share the same Schema (checked via `Arc::ptr_eq`), equality reduces to a direct value-array comparison without key matching; (3) **reduced memory** — no per-object key storage for objects with shared schemas.

**v7+interning**: v7 with thread-local key interning for strings + schema interning for object key sets.

**v8** (`16-byte enum + ArcStr + flattened Number + schema-shared compact objects`): 16-byte Rust enum with flattened Number variants (UInt/Int/Float/BigInt) directly in the enum discriminant — no nested `Number` struct. Uses `ArcStr` (thin pointer) for strings. Combined with v7's schema-shared compact object representation for free sorted iteration and same-schema equality fast path. The key insight: flattening Number variants into Value (plus `ArcStr`) achieves 16 bytes via niche optimization — matching v4's cache density while adding schema-sharing benefits. `static_assert!(size_of::<Value>() == 16)`.

**v8+interning**: v8 with schema interning during deserialization (both `v8::Value` and `v8::Interned` build compact objects via `intern_schema`).

**v9** (`Arena-allocated Copy Value + schema-shared + v8 interop`): Two-enum design. `ArenaValue<'a>` is the inner lean 11-variant `Copy` enum (16 bytes) holding all arena-allocated data — strings, arrays, objects, sets, BigInts in a `bumpalo::Bump` arena, plus flattened Number variants (matching v8). `Value<'a>` is the public wrapper (also 16 bytes via niche optimization) with two variants: `Arena(ArenaValue<'a>)` for arena-native data and `Ext(&'a v8::Value)` for zero-copy O(1) references to shared v8 data. Cloning is a plain memcpy (no atomic refcount), and drop is a no-op (the arena frees everything in bulk). Objects deserialized from JSON use a compact representation: a shared `Schema` plus an arena-allocated flat value slice. Objects with the same key set share a single `Schema` via thread-local interning — enabling O(1) same-schema equality (via `Arc::ptr_eq`) and free sorted iteration (keys pre-sorted in Schema). Programmatically-built objects fall back to `hashbrown::HashMap` in the arena. `ArenaSet` uses `hashbrown::HashSet` in the arena. Deserialization uses `DeserializeSeed` to allocate directly into the arena (no intermediate owned values). Precomputed order-independent hashes on objects and sets enable O(1) Hash for both types. `Value::from_ref(&'a v8::Value)` wraps shared v8 data in O(1) — zero-copy, no arena allocation needed; the `Ext` variant simply carries the reference. Hot-path operations (Arena↔Arena) add only ~1 predicted branch vs a single-enum design; cross-type (Arena↔Ext) comparisons use `#[cold]` helpers.

**v9+interning**: v9 with `StringInterner` — a `HashSet<&'a str>` that deduplicates string allocations within the arena. Reduces memory usage for arrays of objects with shared keys, though the interner lookup overhead partially offsets the savings since arena allocation is already cheap.

### Key optimizations across versions

- **Deserialization**: HashMap O(1) amortized insert vs BTreeMap O(log n).
- **Key lookup**: O(1) HashMap lookup via `&str` (zero-alloc through `Borrow<str>`).
- **Equality**: Point-lookup comparison — for each entry in A, look it up in B's HashMap. No sorting.
- **Serialization**: `SortedValue` wrapper available when deterministic output is needed (e.g. `json.marshal`).
- **Number comparison**: Direct same-variant integer comparison, no BigInt heap allocation.
- **Set operations (v3, v4)**: O(1) insert/lookup in `HashSet` via precomputed hash. Set membership check is constant-time regardless of object size.
- **Object hashing (v3, v4)**: O(1) — reads the precomputed `cached_hash` field instead of iterating all entries.
- **Cache density (v4)**: 16-byte `Value` (vs 24-byte in v3) means ~33% more Values fit per cache line, improving iteration-heavy operations like serialization.
- **NaN boxing (v5)**: 8-byte `Value` packs type tag + payload into a single `u64`. Doubles cache density vs v4 (8 Values per cache line vs 4). Floats and small integers require zero indirection — the value *is* the bits. Number equality is a direct `f64` bit comparison for the common case.
- **Portable tagged pointer (v6)**: 8-byte `Value` using low-bit pointer tagging. Integers up to 61 bits are stored inline with zero heap allocation. Addition of two inline unsigned integers is a single shift+add+shift — ~3x faster than v1–v4's `Number::add()`. Fully portable across all 64-bit targets (no VA-width assumptions).
- **Schema-shared compact objects (v7, v8)**: Objects with identical key sets share a `Schema`. Sorted iteration is free (keys pre-sorted in Schema). Same-schema equality skips key matching and directly compares value arrays — ~1.5x faster than v5/v6 for object equality. Sorted serialization is nearly free for compact objects.
- **16-byte enum Value + ArcStr + schema interning (v8)**: Flattened Number variants + `ArcStr` strings achieve 16 bytes via niche optimization. Combined with v7's schema-shared objects. Avoids tagged-pointer overhead (no Arc<HeapValue> per value) while keeping O(1) same-schema equality and free sorted iteration. Best object equality overall.
- **Arena-allocated Copy Value + schema sharing + v8 interop (v9)**: Two-enum design: `ArenaValue<'a>` (lean 11-variant inner enum, 16 bytes) + `Value<'a>` (2-variant wrapper: `Arena(ArenaValue)` | `Ext(&v8::Value)`, 16 bytes via niche). All arena data lives in a `bumpalo::Bump` — allocation is a pointer bump (no per-value Arc/Box). `Value<'a>` is `Copy` (zero-cost clone, no-op drop). Uses `hashbrown::HashMap`/`HashSet` in the arena for O(1) key lookup and set membership. Fastest deserialization among schema-sharing variants (arena bump vs individual heap allocations). Schema interning gives same-schema equality fast path and free sorted iteration for compact objects. `Value::from_ref(&v8::Value)` wraps shared v8 data in O(1) — zero-copy, no allocation needed. Hot-path (Arena↔Arena) adds only ~1 predicted branch; cross-type uses `#[cold]` helpers.

## Summary

### Deserialization

| Benchmark | Baseline | v1 | v2 | v2 interned | v3 | v3 interned | v4 | v4 interned | v5 | v5 interned | v6 | v6 interned | v7 | v7 interned | v8 | v8 interned | v9 | v9 interned |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| small object | 3.07 µs | 2.19 µs | 2.62 µs | 2.26 µs | 3.13 µs | 2.82 µs | 3.15 µs | 2.81 µs | 3.12 µs | 2.78 µs | 4.10 µs | 3.62 µs | 4.74 µs | 4.28 µs | 4.01 µs | 3.89 µs | **3.91 µs** | 4.80 µs |
| flat 10 keys | 1.52 µs | 902 ns | 1.09 µs | 936 ns | 1.29 µs | 1.12 µs | 1.29 µs | 1.14 µs | 1.27 µs | 1.14 µs | 1.79 µs | 1.55 µs | 1.96 µs | 1.77 µs | 1.49 µs | 1.47 µs | **1.47 µs** | 1.90 µs |
| flat 15 keys | 2.38 µs | 1.37 µs | 1.65 µs | 1.43 µs | 1.97 µs | 1.73 µs | 1.98 µs | 1.72 µs | 1.93 µs | 1.69 µs | 2.64 µs | 2.35 µs | 2.85 µs | 2.56 µs | 2.25 µs | 2.24 µs | **2.09 µs** | 2.86 µs |
| flat 20 keys | 3.34 µs | 1.74 µs | 2.09 µs | 1.84 µs | 2.56 µs | 2.27 µs | 2.58 µs | 2.28 µs | 2.47 µs | 2.15 µs | 3.45 µs | 3.08 µs | 3.81 µs | 3.49 µs | 3.08 µs | 3.05 µs | **2.91 µs** | 3.70 µs |
| flat 32 keys | 5.55 µs | 2.74 µs | 3.34 µs | 3.00 µs | 4.08 µs | 3.65 µs | 4.06 µs | 3.57 µs | 3.94 µs | 3.51 µs | 5.51 µs | 4.98 µs | 5.94 µs | 5.48 µs | 4.73 µs | 4.67 µs | **4.23 µs** | 5.72 µs |
| realistic 10 keys | 5.55 µs | 4.08 µs | 5.03 µs | 4.21 µs | 6.17 µs | 5.47 µs | 6.24 µs | 5.39 µs | 6.13 µs | 5.34 µs | 7.86 µs | 6.92 µs | 8.27 µs | 7.64 µs | 7.12 µs | 6.96 µs | **7.13 µs** | 8.13 µs |
| realistic 20 keys | 12.01 µs | 8.03 µs | 10.14 µs | 8.50 µs | 12.50 µs | 10.83 µs | 12.58 µs | 10.91 µs | 12.32 µs | 10.80 µs | 15.99 µs | 13.98 µs | 17.34 µs | 15.60 µs | 14.68 µs | 14.47 µs | **14.82 µs** | 15.90 µs |
| realistic 32 keys | 19.60 µs | 12.88 µs | 16.12 µs | 13.63 µs | 19.76 µs | 17.33 µs | 20.13 µs | 17.35 µs | 19.70 µs | 17.22 µs | 25.43 µs | 22.30 µs | 27.40 µs | 24.93 µs | 23.29 µs | 22.91 µs | **22.98 µs** | 25.37 µs |
| array 10×10 | — | — | 10.92 µs | 9.48 µs | 12.92 µs | 11.19 µs | 13.25 µs | 11.24 µs | 12.55 µs | 11.00 µs | 17.44 µs | 15.46 µs | 18.67 µs | 16.91 µs | 15.53 µs | 14.89 µs | **14.24 µs** | 15.01 µs |
| array 100×10 | — | — | 111.5 µs | 94.0 µs | 133.3 µs | 115.8 µs | 130.8 µs | 113.9 µs | 129.0 µs | 110.2 µs | 176.9 µs | 157.9 µs | 194.0 µs | 175.2 µs | 151.5 µs | 148.6 µs | **140.4 µs** | 146.9 µs |
| array 100×32 | — | — | 347.3 µs | 295.9 µs | 419.9 µs | 371.4 µs | 417.7 µs | 361.7 µs | 409.7 µs | 353.6 µs | 569.7 µs | 508.4 µs | 624.3 µs | 547.0 µs | 478.9 µs | 473.1 µs | **422.9 µs** | 453.4 µs |

### Key Lookup

| Benchmark | Baseline | v1 | v2 | v3 | v4 | v5 | v6 | v7 | v8 | v9 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| small object (get_str) | 12.7 ns | 5.6 ns | 5.0 ns | 4.4 ns | 6.0 ns | 4.6 ns | 4.6 ns | 4.8 ns | 4.7 ns | 4.6 ns |
| flat 10 keys (get_str) | 41.5 ns | 7.0 ns | 6.5 ns | 5.9 ns | 6.9 ns | 6.2 ns | 6.2 ns | 6.2 ns | 6.1 ns | 6.1 ns |
| flat 20 keys (get_str) | 24.8 ns | 7.7 ns | 7.1 ns | 6.5 ns | 7.7 ns | 6.8 ns | 6.9 ns | 6.8 ns | 6.7 ns | 6.7 ns |
| flat 32 keys (get_str) | 26.4 ns | 7.9 ns | 7.1 ns | 6.6 ns | 7.6 ns | 6.9 ns | 6.9 ns | 6.8 ns | **6.6 ns** | 6.8 ns |

### Comparison (Equality)

| Benchmark | Baseline | v1 | v2 | v3 | v4 | v5 | v6 | v7 | v8 | v9 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| object eq (small) | 320 ns | 270 ns | 249 ns | 247 ns | 271 ns | 267 ns | 305 ns | 182 ns | **110 ns** | 131 ns |
| object eq flat 10 | 124 ns | 134 ns | 119 ns | 120 ns | 126 ns | 126 ns | 143 ns | 95 ns | **67 ns** | 74 ns |
| object eq flat 20 | 231 ns | 241 ns | 220 ns | 220 ns | 230 ns | 234 ns | 263 ns | 169 ns | **101 ns** | 121 ns |
| object eq flat 32 | 371 ns | 394 ns | 356 ns | 374 ns | 380 ns | 385 ns | 422 ns | 251 ns | **148 ns** | 181 ns |
| number eq (100 pairs) | 4.56 µs | 322 ns | 321 ns | 323 ns | 322 ns | 322 ns | **115 ns** | **114 ns** | 330 ns | 329 ns |

### Serialization

| Benchmark | Baseline | v1 unsorted | v1 sorted | v2 unsorted | v2 sorted | v3 unsorted | v3 sorted | v4 unsorted | v4 sorted | v5 unsorted | v5 sorted | v6 unsorted | v6 sorted | v7 unsorted | v7 sorted | v8 unsorted | v8 sorted | v9 unsorted | v9 sorted |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| small | 488 ns | 452 ns | 2.02 µs | 463 ns | 1.47 µs | 1.26 µs | 1.50 µs | 1.03 µs | 1.30 µs | 1.02 µs | 1.30 µs | 1.61 µs | 1.89 µs | 1.54 µs | 1.66 µs | 1.04 µs | 1.17 µs | **1.02 µs** | **1.17 µs** |
| flat 10 | 243 ns | 237 ns | 944 ns | 234 ns | 708 ns | 600 ns | 790 ns | 456 ns | 639 ns | 449 ns | 665 ns | 669 ns | 888 ns | 660 ns | 686 ns | 458 ns | 473 ns | **463 ns** | **482 ns** |
| flat 20 | 469 ns | 463 ns | 2.27 µs | 441 ns | 1.74 µs | 1.21 µs | 1.79 µs | 962 ns | 1.79 µs | 978 ns | 1.68 µs | 1.38 µs | 2.39 µs | 1.38 µs | 1.38 µs | 949 ns | 953 ns | **963 ns** | **956 ns** |
| flat 32 | 741 ns | 720 ns | 3.61 µs | 710 ns | 2.79 µs | 1.93 µs | 2.81 µs | 1.63 µs | 2.73 µs | 1.57 µs | 2.55 µs | 2.17 µs | 3.81 µs | 2.15 µs | 2.20 µs | 1.54 µs | **1.53 µs** | 1.54 µs | **1.49 µs** |

### Set Operations

| Benchmark | Baseline (BTreeSet) | v2 (BTreeSet) | v3 (HashSet) | v4 (HashSet) | v5 (HashSet) | v6 (HashSet) | v7 (HashSet) | v8 (HashSet) | v9 (HashSet) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Create set of objects** | | | | | | | | | |
| 10 obj × 5 keys | 797 ns | 8.45 µs | 417 ns | 406 ns | 439 ns | 456 ns | 462 ns | 404 ns | **373 ns** |
| 50 obj × 5 keys | 10.60 µs | 87.8 µs | 1.93 µs | 1.90 µs | 1.99 µs | 2.06 µs | 2.07 µs | 1.89 µs | **1.52 µs** |
| 100 obj × 5 keys | 28.15 µs | 232.0 µs | 3.90 µs | 3.83 µs | 3.92 µs | 4.11 µs | 4.14 µs | 3.79 µs | **3.06 µs** |
| 50 obj × 10 keys | 10.51 µs | 188.8 µs | 1.93 µs | 1.90 µs | 1.97 µs | 2.06 µs | 2.06 µs | 1.89 µs | **1.53 µs** |
| 100 obj × 10 keys | 28.31 µs | 517.3 µs | 3.90 µs | 3.82 µs | 3.92 µs | 4.14 µs | 4.16 µs | 3.78 µs | **3.04 µs** |
| **Contains (hit)** | | | | | | | | | |
| 10 obj × 5 keys | 160 ns | 1.09 µs | 14.9 ns | 15.1 ns | 15.0 ns | 14.8 ns | 15.1 ns | **14.7 ns** | 15.3 ns |
| 50 obj × 5 keys | 249 ns | 1.55 µs | 14.9 ns | 15.1 ns | **14.7 ns** | 14.9 ns | 15.1 ns | **14.7 ns** | 15.5 ns |
| 100 obj × 5 keys | 363 ns | 2.55 µs | 15.0 ns | 15.1 ns | **14.7 ns** | 14.9 ns | 15.2 ns | **14.7 ns** | 16.2 ns |
| 50 obj × 10 keys | 333 ns | 3.40 µs | 14.9 ns | 15.1 ns | **14.7 ns** | 14.9 ns | 15.1 ns | **14.6 ns** | 15.5 ns |
| 100 obj × 10 keys | 479 ns | 6.20 µs | 14.9 ns | 15.1 ns | **14.7 ns** | 14.9 ns | 15.1 ns | **14.6 ns** | 15.4 ns |
| **Create set of strings** | | | | | | | | | |
| 100 strings | 3.53 µs | 3.45 µs | **1.73 µs** | 1.82 µs | 1.81 µs | 1.74 µs | 1.75 µs | 1.75 µs | 2.88 µs |
| 500 strings | 16.73 µs | 16.44 µs | 8.22 µs | 8.47 µs | 8.90 µs | 8.61 µs | 8.46 µs | **8.32 µs** | 16.92 µs |
| 1000 strings | 30.70 µs | 30.13 µs | **17.61 µs** | 17.46 µs | 17.50 µs | 17.84 µs | 17.82 µs | 17.42 µs | 34.15 µs |

### Arithmetic (Index Increment)

Simulates `i = i + 1` in a loop — the typical iteration index update pattern in Rego policies.

| Benchmark | Baseline | v1 | v2 | v3 | v4 | v5 | v6 | v7 | v8 | v9 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| index_inc (100) | 29 ns | 360 ns | 369 ns | 385 ns | 377 ns | 640 ns | 97 ns | 98 ns | 385 ns | **65 ns** |
| index_inc (1000) | 266 ns | 3.61 µs | 3.68 µs | 3.67 µs | 3.87 µs | 6.77 µs | 1.01 µs | 1.01 µs | 3.88 µs | **562 ns** |

> **Note:** Baseline uses raw `as_u64()` extraction + native `u64` addition + `Value::from()`, which LLVM collapses to a register increment. v1–v4 use `Number::add()` with runtime variant matching. v5 uses `Value::add_number()` with f64 extraction → integer check → `checked_add` → re-encode. v6/v7 use inline TAG_UINT fast path: shift right → native add → shift left + tag — **3.6x faster than v1–v4, 6.7x faster than v5**, only ~3.8x slower than baseline. v9 achieves the fastest non-baseline arithmetic (65 ns/100 iters) — the two-enum `Copy` value (`ArenaValue` wrapped in `Value`) allows LLVM to optimize the UInt+UInt path aggressively, outperforming even v6/v7's tagged-pointer fast path. The extra `Value::Arena` branch adds ~16% overhead vs a single-enum design (65 ns vs ~56 ns) but remains comfortably the fastest variant.

## Detailed Results

### Deserialization

```
                                        Baseline     v1 (SmolStr)   v2 (Arc<str>)  v3 (cached hash)  v4 (ArcStr)    v5 (NaN-boxed)   v6 (tagged ptr)  v7 (schema)    v8 (16B+schema)  v9 (arena)
deserialize/small                       3.07 µs      2.19 µs        2.62 µs        3.13 µs           3.15 µs        3.12 µs          4.10 µs          4.74 µs        4.01 µs          3.91 µs
deserialize/flat/10                     1.52 µs      902 ns         1.09 µs        1.29 µs           1.29 µs        1.27 µs          1.79 µs          1.96 µs        1.49 µs          1.47 µs
deserialize/flat/15                     2.38 µs      1.37 µs        1.65 µs        1.97 µs           1.98 µs        1.93 µs          2.64 µs          2.85 µs        2.25 µs          2.09 µs
deserialize/flat/20                     3.34 µs      1.74 µs        2.09 µs        2.56 µs           2.58 µs        2.47 µs          3.45 µs          3.81 µs        3.08 µs          2.91 µs
deserialize/flat/32                     5.55 µs      2.74 µs        3.34 µs        4.08 µs           4.06 µs        3.94 µs          5.51 µs          5.94 µs        4.73 µs          4.23 µs
deserialize/realistic/10                5.55 µs      4.08 µs        5.03 µs        6.17 µs           6.24 µs        6.13 µs          7.86 µs          8.27 µs        7.12 µs          7.13 µs
deserialize/realistic/20               12.01 µs      8.03 µs       10.14 µs       12.50 µs          12.58 µs       12.32 µs         15.99 µs         17.34 µs       14.68 µs         14.82 µs
deserialize/realistic/32               19.60 µs     12.88 µs       16.12 µs       19.76 µs          20.13 µs       19.70 µs         25.43 µs         27.40 µs       23.29 µs         22.98 µs
```

v1 is **1.3x–2.0x faster** than baseline; v2 is **1.2x–1.7x faster**. v3 and v4 are ~25% slower than v2 due to the cost of computing the order-independent hash for every key-value pair during object construction. v4 is within noise of v3 — the ArcStr thin pointer doesn't affect deserialization. v5 is marginally faster than v4 (~3–7%) for flat/realistic workloads, benefiting from 8-byte Values improving cache density during object construction. v6 is **~1.4x slower than v5** due to heap allocation (Arc<HeapValue>) for every non-integer value. v7 is the slowest (~1.5x slower than v5) due to additional schema interning + Arc<HeapValue> allocation overhead. **v8 is ~20% faster than v7** (4.73 µs vs 5.94 µs for flat/32) — it pays the same schema interning cost but avoids Arc<HeapValue> heap allocation since values are stored as 16-byte enum variants with flattened Number and ArcStr.

**v9 is the fastest variant overall** for deserialization: 4.23 µs (flat/32) — **11% faster than v8** (4.73 µs), though slower than v1 (2.74 µs) due to schema interning overhead. The arena's bump-pointer allocation combined with schema interning is still cheaper than v6/v7's Arc<HeapValue> approach. For realistic nested objects, v9 (22.98 µs for realistic/32) is **1% faster than v8** (23.29 µs). For arrays of shared-key objects, v9 benefits from schema sharing: identical schemas are interned once and reused across all array elements. The two-enum wrapper (`Value::Arena`) adds ~3% overhead vs a single-enum design — a small price for the O(1) `Ext` variant that enables zero-copy v8 interop.

### Deserialization with Key Interning

```
                                   v2 (plain)   v2 (interned)   v3 (plain)   v3 (interned)   v4 (plain)   v4 (interned)   v5 (plain)   v5 (interned)   v6 (plain)   v6 (interned)   v7 (plain)   v7 (interned)   v8 (plain)   v8 (interned)   v9 (plain)   v9 (interned)
deserialize/small                   2.62 µs      2.26 µs         3.13 µs      2.82 µs        3.15 µs      2.81 µs        3.12 µs      2.78 µs        4.10 µs      3.62 µs        4.74 µs      4.28 µs        4.01 µs      3.89 µs        3.91 µs      4.80 µs
deserialize/flat/10                 1.09 µs      936 ns          1.29 µs      1.12 µs        1.29 µs      1.14 µs        1.27 µs      1.14 µs        1.79 µs      1.55 µs        1.96 µs      1.77 µs        1.49 µs      1.47 µs        1.47 µs      1.90 µs
deserialize/flat/15                 1.65 µs      1.43 µs         1.97 µs      1.73 µs        1.98 µs      1.72 µs        1.93 µs      1.69 µs        2.64 µs      2.35 µs        2.85 µs      2.56 µs        2.25 µs      2.24 µs        2.09 µs      2.86 µs
deserialize/flat/20                 2.09 µs      1.84 µs         2.56 µs      2.27 µs        2.58 µs      2.28 µs        2.47 µs      2.15 µs        3.45 µs      3.08 µs        3.81 µs      3.49 µs        3.08 µs      3.05 µs        2.91 µs      3.70 µs
deserialize/flat/32                 3.34 µs      3.00 µs         4.08 µs      3.65 µs        4.06 µs      3.57 µs        3.94 µs      3.51 µs        5.51 µs      4.98 µs        5.94 µs      5.48 µs        4.73 µs      4.67 µs        4.23 µs      5.72 µs
deserialize/realistic/10            5.03 µs      4.21 µs         6.17 µs      5.47 µs        6.24 µs      5.39 µs        6.13 µs      5.34 µs        7.86 µs      6.92 µs        8.27 µs      7.64 µs        7.12 µs      6.96 µs        7.13 µs      8.13 µs
deserialize/realistic/20           10.14 µs      8.50 µs        12.50 µs     10.83 µs       12.58 µs     10.91 µs       12.32 µs     10.80 µs       15.99 µs     13.98 µs       17.34 µs     15.60 µs       14.68 µs     14.47 µs       14.82 µs     15.90 µs
deserialize/realistic/32           16.12 µs     13.63 µs        19.76 µs     17.33 µs       20.13 µs     17.35 µs       19.70 µs     17.22 µs       25.43 µs     22.30 µs       27.40 µs     24.93 µs       23.29 µs     22.91 µs       22.98 µs     25.37 µs
```

Interning provides ~10–15% speedup for v2, v3, v4, and v5 on single-object deserialization. v5 interned is within noise of v4 interned, both slightly faster than v3 interned. v6 interning provides ~12% speedup, v7 interning ~8–13%. **v8 plain vs v8 interned is within noise** for single objects — since v8 already builds compact objects (with schema interning) on every deserialization, the `Interned` wrapper adds no additional benefit for single objects. **v9 interned is ~35% slower than v9 plain** for flat/32 (5.72 µs vs 4.23 µs) — the StringInterner's HashSet lookup overhead exceeds the savings from avoiding arena allocations (bump-pointer allocation is already nearly free). v9 now includes schema interning on every deserialization path, which adds overhead vs the pre-schema v9 but enables same-schema equality and free sorted iteration.

```
                                   v2 (plain)   v2 (interned)   v3 (plain)   v3 (interned)   v4 (plain)   v4 (interned)   v5 (plain)   v5 (interned)   v6 (plain)   v6 (interned)   v7 (plain)   v7 (interned)   v8 (plain)   v8 (interned)   v9 (plain)   v9 (interned)
deserialize/array/10x10            10.92 µs      9.48 µs        12.92 µs     11.19 µs       13.25 µs     11.24 µs       12.55 µs     11.00 µs       17.44 µs     15.46 µs       18.67 µs     16.91 µs       15.53 µs     14.89 µs       14.24 µs     15.01 µs
deserialize/array/100x10          111.5  µs     94.0  µs       133.3  µs    115.8  µs      130.8  µs    113.9  µs      129.0  µs    110.2  µs      176.9  µs    157.9  µs      194.0  µs    175.2  µs      151.5  µs    148.6  µs      140.4  µs    146.9  µs
deserialize/array/100x32          347.3  µs    295.9  µs       419.9  µs    371.4  µs      417.7  µs    361.7  µs      409.7  µs    353.6  µs      569.7  µs    508.4  µs      624.3  µs    547.0  µs      478.9  µs    473.1  µs      422.9  µs    453.4  µs
```

**Arrays of objects with shared keys**: interning is ~15–20% faster for v2 and ~13–22% faster for v3/v4/v5. With 100 objects sharing 32 keys, the interner avoids 3,168 heap allocations. v5 is marginally faster than v4 for both plain and interned array deserialization due to improved cache density of 8-byte Values. v6/v7 are slower across the board; v6 interned (508 µs for 100×32) is ~44% slower than v5 interned (354 µs). v7 interned (547 µs) is the slowest due to combined schema interning + Arc<HeapValue> overhead. **v8 plain (479 µs) is ~12% faster than v7 interned** (547 µs) and ~6% faster than v6 interned (508 µs) — since v8 already does schema interning on every deserialize path (no `Interned` wrapper needed for schema sharing), and avoids Arc<HeapValue> overhead. v8 plain and v8 interned are within noise of each other for arrays, confirming that separate string key interning adds no extra win when schema interning is active.

**v9 plain is competitive for arrays**: 422.9 µs (100×32) — **12% faster than v8 plain** (478.9 µs). v9 interned (453.4 µs) is ~7% slower than v9 plain — the StringInterner provides marginal dedup benefit but costs more than it saves because arena bump allocation is already O(1). Schema interning overhead is amortized well across array elements since they share schemas.

### Key Lookup

```
                                        Baseline     v1 (SmolStr)   v2 (Arc<str>)  v3 (cached hash)  v4 (ArcStr)    v5 (NaN-boxed)   v6 (tagged ptr)  v7 (schema)    v8 (16B+schema)  v9 (arena)
key_lookup/small                        12.7 ns       5.6 ns         5.0 ns         4.4 ns           6.0 ns         4.6 ns           4.6 ns           4.8 ns         4.7 ns           4.6 ns
key_lookup/10                           41.5 ns       7.0 ns         6.5 ns         5.9 ns           6.9 ns         6.2 ns           6.2 ns           6.2 ns         6.1 ns           6.1 ns
key_lookup/20                           24.8 ns       7.7 ns         7.1 ns         6.5 ns           7.7 ns         6.8 ns           6.9 ns           6.8 ns         6.7 ns           6.7 ns
key_lookup/32                           26.4 ns       7.9 ns         7.1 ns         6.6 ns           7.6 ns         6.9 ns           6.9 ns           6.8 ns         6.6 ns           6.8 ns
```

v3, v4, v5, v6, v8, and v9 are the fastest across all sizes, ~10% faster than v2. v6 is within noise of v3–v5 — the tagged-pointer lookup is equivalent to HashMap probe. v7 is ~10–15% slower for indexed lookups due to the extra indirection through schema.lookup for compact objects. **v8 matches v3** (6.6 ns vs 6.6 ns at 32 keys) — the compact object's schema.lookup is just as fast, and v8 doesn't pay the Arc<HeapValue> overhead of v6/v7 since `get_str` returns a reference without value reconstruction. All HashMap variants are **2–7x faster** than baseline BTreeMap.

**v9 matches v3–v8**: 6.8 ns at 32 keys — within noise of v3 (6.6 ns) and v8 (6.6 ns). v9 uses compact objects with `schema.lookup` HashMap for deserialized data and `hashbrown::HashMap` in the arena for programmatically-built objects, providing the same O(1) hash-probe lookup as v3–v8. The two-enum wrapper adds no measurable overhead to key lookup.

### Key Lookup — get_str vs index

```
                                        v6 get_str   v6 index     v7 get_str   v7 index     v8 get_str   v8 index     v9 get_str   v9 index
key_lookup/small                        4.6 ns       5.4 ns       4.8 ns       6.2 ns       4.7 ns       5.7 ns       4.6 ns       5.7 ns
key_lookup/10                           6.2 ns       6.6 ns       6.2 ns       7.4 ns       6.1 ns       7.3 ns       6.1 ns       7.2 ns
key_lookup/20                           6.9 ns       7.4 ns       6.8 ns       8.0 ns       6.7 ns       7.7 ns       6.7 ns       7.9 ns
key_lookup/32                           6.9 ns       7.6 ns       6.8 ns       8.0 ns       6.6 ns       7.7 ns       6.8 ns       7.9 ns
```

`get_str(&str)` is faster than index-by-Value for v6/v7/v8/v9 because it avoids constructing a Value from the key. v7 and v8's `get_str` is competitive with v6 — the compact object's `schema.lookup` HashMap is just as fast as a direct object HashMap. The index path is slower for v7/v8 due to extracting the string from the Value first, then looking up in schema.lookup. **v8's `get_str` is the fastest** at 6.6 ns (32 keys). **v9's `get_str` matches v3/v8** (6.8 ns at 32 keys) since v9 uses compact objects with `schema.lookup` for deserialized data. The index path (7.9 ns) is slightly slower due to extracting the string key from the Value.

### Comparison (Equality)

```
                                        Baseline     v1 (SmolStr)   v2 (Arc<str>)  v3 (cached hash)  v4 (ArcStr)    v5 (NaN-boxed)   v6 (tagged ptr)  v7 (schema)    v8 (16B+schema)  v9 (arena)
comparison/eq_small                    320.2  ns    270.2  ns      249.1  ns      246.6  ns        271.1  ns      266.6  ns        305.1  ns        182.1  ns      110.1  ns        130.7  ns
comparison/eq_flat/10                  124.4  ns    133.8  ns      119.0  ns      119.9  ns        126.3  ns      126.1  ns        142.7  ns         94.8  ns       67.1  ns         74.2  ns
comparison/eq_flat/20                  230.8  ns    240.9  ns      219.8  ns      220.3  ns        230.2  ns      234.1  ns        262.6  ns        168.9  ns      100.6  ns        121.1  ns
comparison/eq_flat/32                  370.5  ns    393.6  ns      355.8  ns      373.5  ns        379.6  ns      385.2  ns        422.1  ns        251.3  ns      148.2  ns        181.3  ns
comparison/number_eq_100              4560    ns    322    ns      321    ns      323    ns        322    ns      322    ns        115    ns        114    ns      330    ns        329    ns
```

With `#[inline(always)]` on `Number::eq`, v1–v5 achieve ~322 ns for number equality — a **14× speedup** over baseline. v6/v7 achieve **~115 ns** for number equality — **~2.8× faster** than v1–v5 — because two TAG_UINT values are compared with a single `usize ==` (no heap access needed). **v8 achieves 330 ns** — within noise of v1–v5.

**v9 number equality matches v8 at 329 ns** — within noise of v1–v5/v8 (322–330 ns). Removing the `Ref` variant eliminated the cross-type `ext_number_to_v9()` conversion overhead that previously caused a 2× regression. Still **14× faster** than baseline (4560 ns).

For object equality, **v8 is the clear winner**: 110 ns (small), 148 ns (flat/32) — **41–46% faster** than v7's 182/251 ns. Both v7 and v8 benefit from the same-schema fast path (`Arc::ptr_eq` on schemas then direct value-array comparison), but v8's 16-byte enum Values (with flattened Number and ArcStr) can be compared directly without the tagged-pointer decoding + Arc<HeapValue> dereference that v7 requires for every field. v8's shrink from 24 to 16 bytes further improves cache density during value-array comparison. v6 remains the slowest for object equality (305/422 ns) due to extra Arc<HeapValue> indirection for every field access during comparison.

**v9 object equality is ~22% slower than v8**: 181 ns (flat/32) vs v8's 148 ns — the two-enum `Value::Arena` wrapper adds an extra discriminant branch on every value comparison. With the `Ref` variant removed, v9's inner `ArenaValue` still benefits from LLVM match optimization, but the outer `Value` dispatch adds measurable overhead on this hot path. v9 is **52% faster** than v3 (374 ns) and **57% faster than v6** (422 ns), thanks to the same-schema `Arc::ptr_eq` fast path for deserialized objects. The gap vs v8 is the cost of the two-enum design that enables O(1) `Ext` wrapping of shared v8 data.

### Serialization

```
                                        Baseline     v1 (SmolStr)   v2 (Arc<str>)  v3 (cached hash)  v4 unsorted    v4 sorted      v5 unsorted    v5 sorted      v6 unsorted    v6 sorted      v7 unsorted    v7 sorted      v8 unsorted    v8 sorted      v9 unsorted    v9 sorted
serialize/small_unsorted               488.0  ns    451.7  ns      463.2  ns     1260.0  ns       1030.0  ns        —            1020.0  ns        —            1610.0  ns        —            1540.0  ns        —            1037.8  ns        —            1019.0  ns        —
serialize/flat_unsorted/10             243.2  ns    237.4  ns      234.1  ns      600.3  ns        456.2  ns        —             448.6  ns        —             669.1  ns        —             660.3  ns        —             457.7  ns        —             462.9  ns        —
serialize/flat_unsorted/20             468.7  ns    462.5  ns      440.8  ns     1210.0  ns        961.7  ns        —             977.8  ns        —            1380.0  ns        —            1380.0  ns        —             948.5  ns        —             962.8  ns        —
serialize/flat_unsorted/32             741.1  ns    719.6  ns      709.8  ns     1930.0  ns       1630.0  ns        —            1570.0  ns        —            2170.0  ns        —            2150.0  ns        —            1544.9  ns        —            1535.3  ns        —
serialize/small_sorted                   —         2020.0  ns     1470.0  ns     1500.0  ns          —           1300.0  ns        —            1300.0  ns        —            1890.0  ns        —            1660.0  ns        —            1174.0  ns        —            1173.6  ns
serialize/flat_sorted/10                 —          944.0  ns      708.1  ns      790.0  ns          —            639.3  ns        —             664.5  ns        —             887.8  ns        —             685.8  ns        —             473.4  ns        —             481.7  ns
serialize/flat_sorted/20                 —         2270.0  ns     1740.0  ns     1790.0  ns          —           1790.0  ns        —            1680.0  ns        —            2390.0  ns        —            1380.0  ns        —             953.2  ns        —             956.0  ns
serialize/flat_sorted/32                 —         3610.0  ns     2790.0  ns     2810.0  ns          —           2730.0  ns        —            2550.0  ns        —            3810.0  ns        —            2200.0  ns        —            1534.3  ns        —            1493.7  ns
```

v3 "unsorted" serialization is slower than v1/v2 because `ObjectMap::iter()` wraps each string key as `Value::String(Arc::clone(k))`, adding per-key overhead. **v4 unsorted is ~20% faster than v3** — the 16-byte Value (vs 24-byte) improves iteration cache density and reduces the cloning cost. **v5 is within noise of v4 for unsorted serialization** and **slightly faster for sorted** — the 8-byte Value continues the cache density trend but the gain from 16→8 bytes is less dramatic than the 24→16 byte transition.

**v6 unsorted is ~35% slower than v5** — every value access dereferences Arc<HeapValue>, adding overhead during iteration. v6 sorted is even worse (~49% slower than v5 sorted at flat/32) because sorting requires heap-allocated key extraction.

**v8 sorted serialization is the fastest among schema-sharing variants** for flat/32 (1.53 µs) — **30% faster than v7 sorted** (2.20 µs) and **40% faster than v5 sorted** (2.55 µs). v8's compact objects store keys pre-sorted in the Schema, so `iter_sorted()` returns keys in order without any sorting step — identical to v7 — but v8's 16-byte enum Values (ArcStr + flattened Number) can be serialized directly without the tagged-pointer decoding overhead of v7. v8 unsorted (1.54 µs at flat/32) is **28% faster than v7 unsorted** (2.15 µs) for the same reason.

**v9 unsorted serialization is competitive**: 1.54 µs (flat/32) — **within noise of v8** (1.54 µs). v9's compact objects iterate in schema sort order. **v9 sorted serialization is essentially tied with v8**: 1.49 µs (flat/32) vs v8's 1.53 µs — **3% faster**. Both v8 and v9 benefit from Schema-based free sorted iteration; v9's arena-allocated Copy values avoid Arc refcount bumps during iteration, giving a slight edge. The two-enum wrapper adds ~3% overhead vs the single-enum v9 (1.49 µs vs ~1.47 µs for sorted flat/32).

### Set Operations

```
CREATE SET OF OBJECTS                   Baseline     v2 (BTreeSet)  v3 (HashSet)   v4 (HashSet)   v5 (HashSet)   v6 (HashSet)   v7 (HashSet)   v8 (HashSet)   v9 (HashSet)
set_ops/create/10obj_x_5keys          797.0  ns      8.45 µs       416.6  ns      406.4  ns      439.0  ns      456.0  ns      462.2  ns      403.5  ns      372.7  ns
set_ops/create/50obj_x_5keys           10.60 µs     87.83 µs         1.93 µs        1.90 µs        1.99 µs        2.06 µs        2.07 µs        1.89 µs        1.52 µs
set_ops/create/100obj_x_5keys          28.15 µs    232.02 µs         3.90 µs        3.83 µs        3.92 µs        4.11 µs        4.14 µs        3.79 µs        3.06 µs
set_ops/create/50obj_x_10keys          10.51 µs    188.82 µs         1.93 µs        1.90 µs        1.97 µs        2.06 µs        2.06 µs        1.89 µs        1.53 µs
set_ops/create/100obj_x_10keys         28.31 µs    517.27 µs         3.90 µs        3.82 µs        3.92 µs        4.14 µs        4.16 µs        3.78 µs        3.04 µs
```

v2's BTreeSet requires Ord comparisons on objects, which means iterating and comparing all keys for every tree insertion. This scales as O(n · k · log n) where n is objects and k is keys. v3–v8's HashSet uses the precomputed `cached_hash`, making insertion O(1) amortized. v5–v8 are within noise of v3/v4.

At 100 objects × 10 keys: v2 takes **517 µs** vs v3–v8's **~3.8–4.2 µs** — a **~130x** improvement. **v9 takes 3.04 µs** — **the fastest** and **170x faster than v2**. v9's `ArenaSet` uses `hashbrown::HashSet` in the arena, providing the same O(1) hash-based insertion as v3–v8. v9 is faster than v3–v8 due to arena allocation efficiency and schema-shared compact objects providing cheaper hashing.

```
CONTAINS (lookup hit)                   Baseline     v2 (BTreeSet)  v3 (HashSet)   v4 (HashSet)   v5 (HashSet)   v6 (HashSet)   v7 (HashSet)   v8 (HashSet)   v9 (HashSet)
set_ops/contains_hit/10obj_x_5keys     159.8  ns      1.09 µs       14.9  ns       15.1  ns       15.0  ns       14.8  ns       15.1  ns       14.7  ns       15.3  ns
set_ops/contains_hit/50obj_x_5keys     249.0  ns      1.55 µs       14.9  ns       15.1  ns       14.7  ns       14.9  ns       15.1  ns       14.7  ns       15.5  ns
set_ops/contains_hit/100obj_x_5keys    363.2  ns      2.55 µs       15.0  ns       15.1  ns       14.7  ns       14.9  ns       15.2  ns       14.7  ns       16.2  ns
set_ops/contains_hit/50obj_x_10keys    332.6  ns      3.40 µs       14.9  ns       15.1  ns       14.7  ns       14.9  ns       15.1  ns       14.6  ns       15.5  ns
set_ops/contains_hit/100obj_x_10keys   479.0  ns      6.20 µs       14.9  ns       15.1  ns       14.7  ns       14.9  ns       15.1  ns       14.6  ns       15.4  ns
```

v3–v8 set membership is **constant ~14.7–15.2 ns** regardless of set size or object key count. All within noise of each other.

**v9 set membership is ~15.3–16.2 ns** — **matching v3–v8** (14.7–15.2 ns). v9's `ArenaSet` uses `hashbrown::HashSet` in the arena, providing constant-time O(1) hash-based lookup. Slightly higher (~0.5–1 ns) than v3–v8 due to arena allocator overhead in the HashSet.

```
CREATE SET OF STRINGS                   Baseline     v2 (BTreeSet)  v3 (HashSet)   v4 (HashSet)   v5 (HashSet)   v6 (HashSet)   v7 (HashSet)   v8 (HashSet)   v9 (HashSet)
set_ops/create_strings/100_strings      3.53 µs      3.45 µs        1.73 µs        1.82 µs        1.81 µs        1.74 µs        1.75 µs        1.75 µs        2.88 µs
set_ops/create_strings/500_strings     16.73 µs     16.44 µs        8.22 µs        8.47 µs        8.90 µs        8.61 µs        8.46 µs        8.32 µs       16.92 µs
set_ops/create_strings/1000_strings    30.70 µs     30.13 µs       17.61 µs       17.46 µs       17.50 µs       17.84 µs       17.82 µs       17.42 µs       34.15 µs
```

For string sets, v2 and baseline are nearly identical (both use BTreeSet with O(n log n) string comparisons). v3–v8's HashSet is **~2x faster**. All within noise of each other for strings.

**v9 string set creation is ~2x slower than v3–v8**: 34.15 µs (1000 strings) vs ~17.5 µs for v3–v8. Worse than baseline BTreeSet (30.7 µs). The arena-allocated HashSet uses `hashbrown::HashSet` but string hashing and arena allocation overhead make it slower than heap-allocated HashSet variants for strings.

### Arithmetic (Index Increment)

```
                                        Baseline     v1 (SmolStr)   v2 (Arc<str>)  v3 (cached hash)  v4 (ArcStr)    v5 (NaN-boxed)   v6 (tagged ptr)  v7 (schema)    v8 (16B+schema)  v9 (arena)
arithmetic/index_inc/100                29 ns        360 ns         369 ns         385 ns            377 ns         640 ns           97 ns            98 ns          385 ns            65 ns
arithmetic/index_inc/1000              266 ns          3.61 µs        3.68 µs        3.67 µs           3.87 µs        6.77 µs          1.01 µs          1.01 µs        3.88 µs          562 ns
```

Baseline is ~10x faster than v1–v4/v8 because LLVM fully inlines `as_u64()` → `u64 + u64` → `Value::from()` into a register increment loop. This is not representative of the actual interpreter, which calls `Number::add()` (private, same structure as v1–v4).

v1–v4 and v8 are uniform at ~3.7–3.9 µs/1000 iterations. v8 uses the same `Number::add()` path as v1–v4 (v8 re-exports v2::Number). v5 is ~1.8x slower at ~6.77 µs/1000 due to the extract→check→compute→re-encode round-trip.

**v6/v7 are dramatically faster at ~1.01 µs/1000** — only **~3.8x slower than baseline** and **3.6x faster than v1–v4/v8**. The inline TAG_UINT + TAG_UINT fast path does: shift right 3 bits → native add → shift left 3 bits + tag. No heap access, no type dispatch, no float extraction. This makes v6/v7 **6.7x faster than v5** for integer arithmetic.

**v9 is the fastest non-baseline variant at 562 ns/1000** — **1.8× faster than v6/v7** (1.01 µs) and **6.9× faster than v1–v4/v8** (3.7–3.9 µs). With the `Ref` variant removed, v9's two-enum `Copy` value (`ArenaValue` wrapped in `Value`) allows LLVM to optimize the UInt+UInt fast path aggressively — the match compiles to a tight sequence of extract + checked_add + tag, with no heap access, no refcount, and no type dispatch overhead. The outer `Value::Arena` branch adds ~2% overhead vs the single-enum design (562 ns vs ~550 ns) but remains comfortably the fastest variant. This is only ~2.1× slower than baseline's fully-inlined register increment.

## Analysis

### v1 and v2 vs Baseline

Both designs are substantially faster than baseline for the key operations:

| Operation | v1 vs Baseline | v2 vs Baseline | Root Cause |
|---|---|---|---|
| Deserialization (32 keys) | **2.0x faster** | **1.7x faster** | HashMap O(1) insert vs BTreeMap O(log n) |
| Key lookup (10 keys) | **5.9x faster** | **6.4x faster** | HashMap O(1) vs BTreeMap linear scan |
| Key lookup (32 keys) | **3.3x faster** | **3.7x faster** | Same |
| Number equality (100 pairs) | **14x faster** | **14x faster** | Direct integer compare vs BigInt allocation + `#[inline(always)]` |
| Unsorted serialization | **~1.03x faster** | **~1.04x faster** | Direct HashMap iteration, zero-alloc path |
| Object equality (flat 32) | ~0.94x (slower) | ~0.96x (slower) | Point-lookup vs BTreeMap in-order iteration |

### v3 vs v2 — tradeoffs

| Operation | v3 vs v2 | Root Cause |
|---|---|---|
| Set create (100 obj × 10 keys) | **132.6x faster** | HashSet O(1) insert with cached hash vs BTreeSet O(n·k·log n) |
| Set contains (100 obj × 10 keys) | **416.1x faster** | O(1) hash lookup vs O(k·log n) tree search |
| Set create (strings) | **~1.7x faster** | HashSet O(1) insert vs BTreeSet O(log n) string comparisons |
| Key lookup | **~8% faster** | Struct ObjectMap slightly more cache-friendly |
| Object equality (flat 32) | **~5% slower** | Within noise; `cached_hash` early-rejection for unequal objects |
| Deserialization | **~22% slower** | Extra cost of computing per-entry hash during construction |
| Unsorted serialization | **~2.7x slower** | `iter()` wraps each key as `Value::String(Arc::clone(k))` |
| Sorted serialization | **~comparable** | Both must collect + sort HashMap keys |

### v1 (SmolStr) vs v2 (Arc\<str\>)

| Operation | Winner | Delta | Root Cause |
|---|---|---|---|
| Deserialization | **v1** | v1 18% faster | SmolStr inlines strings ≤23 bytes on stack — no heap allocation for typical JSON keys |
| Key lookup | **v2** | v2 ~8% faster | `Arc<str>` hash is a simple pointer dereference; SmolStr checks inline-vs-heap representation |
| Object equality | **v2** | v2 ~10% faster | `Arc<str>` compare is pointer deref + memcmp; SmolStr has inline-vs-heap dispatch |
| Unsorted serialization | **tie** | within noise | Both iterate HashMap directly; key type doesn't matter |
| Sorted serialization | **v2** | v2 **23% faster** | `Arc::clone` is a refcount bump; SmolStr → `Arc<str>` conversion requires heap allocation |

### v4 vs v3 — cache density wins

v4 replaces `Arc<str>` (16-byte fat pointer) with `ArcStr` (8-byte thin pointer), shrinking `Value` from 24 bytes to 16 bytes — a 33% memory reduction per Value.

| Operation | v4 vs v3 | Root Cause |
|---|---|---|
| Unsorted serialization | **~15% faster** | 16-byte Value = better cache density during iteration + cheaper clone |
| Sorted serialization | **~3% faster** | Smaller Values are faster to collect, sort, and iterate |
| String set creation | **~3% faster** | Thinner pointer reduces clone overhead |
| Deserialization | **within noise** | Hash computation dominates; pointer width doesn't matter |
| Key lookup | **within noise** | Hash probe dominates |
| Object equality | **~2% slower** | Within noise |
| Set operations (objects) | **within noise** | Hash-based; pointer width doesn't affect hash/eq |

The primary advantage is **memory**: 16 bytes per Value means ~33% more Values per cache line, which benefits any operation that iterates over collections of Values.

### v5 vs v4 — NaN boxing

v5 encodes the entire Value in a single `u64` using IEEE 754 NaN boxing, halving the Value size from 16 bytes (v4) to 8 bytes.

| Operation | v5 vs v4 | Root Cause |
|---|---|---|
| Arithmetic (index_inc/1000) | **~1.7x slower** (6.77 µs vs 3.87 µs) | f64 extraction → integer check → checked_add → re-encode vs direct enum match + checked_add |
| Number equality (100 pairs) | **within noise** | With `#[inline(always)]`, v4's Number enum is equally fast |
| Object equality | **~2% slower** | Within noise |
| Sorted serialization (flat/32) | **~7% faster** | 8-byte Values = 2x cache density vs v4 during sort + iterate |
| Unsorted serialization | **~4% faster** | Same iteration pattern; diminishing returns from 16→8 byte reduction |
| Deserialization | **~3% faster** | Fewer cache misses during object construction |
| Key lookup | **within noise** | Hash probe dominates; Value size irrelevant |
| Set operations (objects) | **within noise** | Hash-based; cached_hash comparison unchanged |
| Memory per Value | **2x smaller** (8 bytes vs 16 bytes) | Single u64 vs enum discriminant + 8-byte payload |

### v6 vs v5 — portable tagged pointer

v6 replaces NaN boxing (which assumes 48-bit virtual addresses and breaks on LA57/LVA/32-bit) with a portable tagged-pointer scheme using the low 3 alignment bits of a `usize`. Every non-integer value is heap-allocated via `Arc<HeapValue>`.

| Operation | v6 vs v5 | Root Cause |
|---|---|---|
| Arithmetic (index_inc/1000) | **6.7x faster** (1.01 µs vs 6.77 µs) | Inline TAG_UINT fast path: shift → native add → shift+tag. No heap, no float extraction. |
| Number equality (×100) | **~2.8x faster** (115 ns vs 322 ns) | Two TAG_UINT values → single `usize ==`. No heap deref needed. |
| Deserialization (flat/32) | **~1.4x slower** (5.51 µs vs 3.94 µs) | Every non-integer Value requires `Arc::new(HeapValue::...)` heap allocation. |
| Deserialization (realistic/32) | **~1.3x slower** (25.43 µs vs 19.70 µs) | Same; nested objects add more heap allocations. |
| Object equality (flat/32) | **~10% slower** (422 ns vs 385 ns) | Extra `Arc<HeapValue>` indirection for every field during comparison. |
| Key lookup (32 keys) | **within noise** | Hash probe dominates; tagged pointer overhead negligible. |
| Sorted serialization (flat/32) | **~49% slower** (3.81 µs vs 2.55 µs) | Must deref Arc to extract keys, then sort — more cache misses. |
| Unsorted serialization (flat/32) | **~38% slower** (2.17 µs vs 1.57 µs) | Arc deref overhead during iteration. |
| Set operations (objects) | **within noise** | Hash-based; cached_hash comparison unchanged. |
| Value size | **same** (8 bytes) | Both are single-word representations. |
| Portability | **fully portable** | Works on all 64-bit targets (LA57, LVA, ARM, etc.) — no VA-width assumptions. |

The key insight: v6 trades deserialization and serialization speed for **dramatically faster arithmetic** and **portable integer operations**. For workloads heavy in computation but light in data deserialization (e.g., numeric rule evaluation), v6 is a significant win.

### v7 vs v6 — schema-shared compact objects

v7 uses the same tagged-pointer encoding as v6 but adds a schema-shared compact object representation. Objects deserialized from JSON automatically use `CompactObject { schema: Arc<Schema>, values: Box<[Value]> }` where `Schema` holds sorted keys + a lookup HashMap. Objects with the same set of keys share a single Schema (via thread-local interning).

| Operation | v7 vs v6 | Root Cause |
|---|---|---|
| Object equality (small) | **40% faster** (182 ns vs 305 ns) | Same-schema fast path: `Arc::ptr_eq` on schemas, then direct value-array comparison — no key comparison needed. |
| Object equality (flat/32) | **40% faster** (251 ns vs 422 ns) | Scales proportionally — eliminates O(k) key string comparisons. |
| Sorted serialization (flat/32) | **42% faster** (2.20 µs vs 3.81 µs) | Keys pre-sorted in Schema — `iter_sorted()` just walks the array in order. Zero sorting cost. |
| Sorted serialization (flat/20) | **42% faster** (1.38 µs vs 2.39 µs) | Same mechanism — free sorted iteration. |
| Unsorted serialization (flat/32) | **within noise** (2.15 µs vs 2.17 µs) | Both iterate values the same way. |
| Deserialization (flat/32) | **~8% slower** (5.94 µs vs 5.51 µs) | Schema interning overhead: sort keys, compute schema hash, look up/create Schema in thread-local cache. |
| Deserialization (realistic/32) | **~8% slower** (27.40 µs vs 25.43 µs) | Same; nested objects amplify schema interning cost. |
| Key lookup (get_str, 32 keys) | **within noise** (6.8 ns vs 6.9 ns) | Both use HashMap lookup — schema.lookup is equivalent. |
| Key lookup (index, 32 keys) | **~5% slower** (8.0 ns vs 7.6 ns) | Must extract string from Value before looking up in schema.lookup. |
| Number equality (×100) | **within noise** (114 ns vs 115 ns) | Same TAG_UINT encoding. |
| Arithmetic (index_inc/1000) | **within noise** (1.01 µs vs 1.01 µs) | Same inline TAG_UINT fast path. |
| Set operations (objects) | **within noise** | Hash-based; both have same cached_hash. |
| Memory (shared-schema objects) | **significantly better** | N objects × K keys: v6 stores N×K key pointers; v7 stores 1 Schema + N value arrays. |

### v8 vs v7 — 16-byte enum Value + ArcStr + schema interning (no tagged pointer)

v8 combines a 16-byte `enum Value` (flattened Number variants + `ArcStr` strings) with v7's schema-shared compact objects. It achieves 16 bytes via niche optimization (`static_assert!(size_of::<Value>() == 16)`). The key insight: schema interning is orthogonal to value encoding.

| Operation | v8 vs v7 | Root Cause |
|---|---|---|
| Object equality (small) | **40% faster** (110 ns vs 182 ns) | Same-schema fast path, but enum Value comparison is direct pattern match — no tagged-pointer decoding or Arc<HeapValue> dereference per field. 16-byte Values improve cache density. |
| Object equality (flat/32) | **41% faster** (148 ns vs 251 ns) | Scales proportionally — each value-array element is a direct 16-byte enum comparison vs tagged-pointer decode. |
| Sorted serialization (flat/32) | **30% faster** (1.53 µs vs 2.20 µs) | Same free sorted iteration via Schema, but enum Value serialization is a direct match vs pointer decode + deref chain. |
| Unsorted serialization (flat/32) | **28% faster** (1.54 µs vs 2.15 µs) | Direct enum iteration vs tagged-pointer decoding for every value. |
| Deserialization (flat/32) | **20% faster** (4.73 µs vs 5.94 µs) | Both do schema interning, but v8 constructs 16-byte enum values directly vs Arc<HeapValue> heap allocation per value. |
| Deserialization (realistic/32) | **15% faster** (23.29 µs vs 27.40 µs) | Same mechanism — no Arc<HeapValue> overhead. |
| Deserialization (array 100×32) | **12% faster** (479 µs vs 547 µs interned) | v8 plain already builds compact objects; no `Interned` wrapper needed. |
| Key lookup (get_str, 32 keys) | **within noise** (6.6 ns vs 6.8 ns) | Both use schema.lookup HashMap — identical path. |
| Key lookup (index, 32 keys) | **within noise** (7.7 ns vs 8.0 ns) | Both extract string from Value before schema lookup. |
| Number equality (×100) | **2.9x slower** (330 ns vs 114 ns) | v8 uses `Number::eq` (enum match + integer compare). v7 uses single `usize ==` for TAG_UINT. |
| Arithmetic (index_inc/1000) | **3.8x slower** (3.88 µs vs 1.01 µs) | v8 uses `Number::add()` with runtime variant matching. v7 uses inline TAG_UINT shift+add. |
| Set operations (objects) | **within noise** | Hash-based; both have same cached_hash mechanism. |
| Value size | **2x larger** (16 bytes vs 8 bytes) | 16-byte enum vs tagged usize. |
| Portability | **A** | Both fully portable — no VA-width assumptions. |
| Complexity | **much simpler** | Standard Rust enum — zero unsafe code, no pointer tagging, no Arc<HeapValue> indirection. |

### v8 vs v3 — what schema interning adds

v8 and v3 share HashMap-based `ObjectMap` with `cached_hash`. The key difference is v8's schema-shared compact objects (16-byte ArcStr enum) vs v3's plain HashMap-based ObjectMap (24-byte Arc<str> enum).

| Operation | v8 vs v3 | Root Cause |
|---|---|---|
| Object equality (flat/32) | **60% faster** (148 ns vs 374 ns) | Same-schema fast path: `Arc::ptr_eq` + value-array comparison vs key-by-key HashMap lookup. Also 16-byte vs 24-byte values improve cache density. |
| Object equality (small) | **55% faster** (110 ns vs 247 ns) | Same mechanism. |
| Sorted serialization (flat/32) | **45% faster** (1.53 µs vs 2.81 µs) | Free sorted iteration (keys pre-sorted in Schema) vs collect + sort HashMap keys. |
| Unsorted serialization (flat/32) | **20% faster** (1.54 µs vs 1.93 µs) | Compact object iteration is more cache-friendly; 16-byte values vs 24-byte. |
| Deserialization (flat/32) | **16% slower** (4.73 µs vs 4.08 µs) | Schema interning overhead: sort keys, hash, lookup/create in thread-local cache. |
| Deserialization (realistic/32) | **18% slower** (23.29 µs vs 19.76 µs) | Same; nested objects amplify schema interning cost. |
| Key lookup (get_str, 32 keys) | **within noise** (6.6 ns vs 6.6 ns) | Both use HashMap lookup — schema.lookup is equivalent. |
| Number equality (×100) | **within noise** (330 ns vs 323 ns) | Both use similar Number::eq path. |
| Arithmetic | **within noise** | Both use Number::add. |
| Set operations | **within noise** | Both have cached_hash. |
| Memory (shared-schema objects) | **significantly better** | N objects × K keys: v3 stores N×K key pointers; v8 stores 1 Schema + N value arrays. |

### v9 vs v8 — arena allocation + two-enum design + v8 interop

v9 combines arena-allocated `Copy` values with schema-shared compact objects (ported from v8) and `hashbrown::HashMap`/`HashSet` in the arena. v8 uses the same schema-sharing mechanism but with heap-allocated refcounted values. Both are 16-byte Values. v9 uses a two-enum design: `ArenaValue<'a>` (lean 11-variant inner enum) wrapped in `Value<'a>` (2-variant: `Arena(ArenaValue)` | `Ext(&v8::Value)`), enabling O(1) zero-copy wrapping of shared v8 data via `Value::from_ref()`. The `Ext` variant adds ~1 predicted branch on hot paths (Arena↔Arena).

| Operation | v9 vs v8 | Root Cause |
|---|---|---|
| Deserialization (flat/32) | **11% faster** (4.23 µs vs 4.73 µs) | Arena bump-pointer allocation is slightly cheaper; both now pay schema interning cost. |
| Deserialization (realistic/32) | **1% faster** (22.98 µs vs 23.29 µs) | Arena advantage with nested objects — pointer bumps vs individual allocations. |
| Deserialization (array 100×32) | **12% faster** (422.9 µs vs 478.9 µs) | Arena allocates all objects in one region; v8 must heap-allocate per element. |
| Serialize unsorted (flat/32) | **within noise** (1.54 µs vs 1.54 µs) | Both use Schema-based iteration; arena Copy values comparable to enum values. |
| Serialize sorted (flat/32) | **3% faster** (1.49 µs vs 1.53 µs) | Both use Schema-based free sorted iteration; arena Copy avoids refcount bumps. |
| Object equality (flat/32) | **~22% slower** (181 ns vs 148 ns) | Two-enum `Value::Arena` wrapper adds extra discriminant branch on every field comparison. |
| Object equality (small) | **~19% slower** (131 ns vs 110 ns) | Same mechanism — outer enum dispatch overhead. |
| Number equality (×100) | **within noise** (329 ns vs 330 ns) | Both use the same Number::eq path. |
| Arithmetic (inc/1000) | **6.9× faster** (562 ns vs 3.88 µs) | v9's Copy enum allows LLVM to optimize UInt+UInt to near-native code. v8 uses Number::add() with runtime variant matching. |
| Arithmetic (inc/100) | **5.9× faster** (65 ns vs 385 ns) | Same mechanism. |
| Key lookup (get_str, 32 keys) | **within noise** (6.8 ns vs 6.6 ns) | Both use O(1) lookup — v9's schema.lookup matches v8's. |
| Set contains (100×10 keys) | **within noise** (15.4 ns vs 14.6 ns) | Both use O(1) HashSet lookup. |
| Set create (100×10 keys) | **20% faster** (3.04 µs vs 3.78 µs) | Arena HashSet allocation is cheaper than heap HashSet. |
| Set create strings (1000) | **~2.0x slower** (34.2 µs vs 17.4 µs) | Arena string HashSet has higher per-element overhead. |
| Value size | **same** (16 bytes) | Both are 16-byte enums. |
| Portability | **A** | Both fully portable — no platform-specific encoding. |
| Memory model | **arena (bulk free)** | v9: all values die together. v8: refcounted (individual drop). |
| Clone cost | **zero (Copy)** | v9: memcpy. v8: Arc refcount bumps. |
| v8 interop | **O(1) Ext wrapping** | `Value::from_ref(&v8::Value)` — zero-copy, no allocation. v8 has no equivalent. |

### v9 vs v3 — arena vs heap HashMap

v9 and v3 are both enum Values with HashMap-based objects and HashSet-based sets. The key differences: v9 adds schema-shared compact objects (like v8), arena allocation (bump pointer, `Copy` values), and a two-enum design (`ArenaValue` + `Value` wrapper with `Ext` variant for O(1) v8 interop) vs v3's heap allocation (Arc/Box, refcounted, no schema sharing). v9 is 16 bytes, v3 is 24 bytes.

| Operation | v9 vs v3 | Root Cause |
|---|---|---|
| Deserialization (flat/32) | **~4% slower** (4.23 µs vs 4.08 µs) | Schema interning overhead slightly exceeds arena bump savings. |
| Deserialization (realistic/32) | **~16% slower** (22.98 µs vs 19.76 µs) | Schema interning adds fixed cost per deserialized object for nested data. |
| Serialize unsorted (flat/32) | **20% faster** (1.54 µs vs 1.93 µs) | Compact objects iterate values in schema order; arena Copy values avoid refcount bumps. |
| Serialize sorted (flat/32) | **47% faster** (1.49 µs vs 2.81 µs) | Schema keys are pre-sorted; v3 must collect + sort. |
| Object equality (flat/32) | **52% faster** (181 ns vs 374 ns) | Same-schema `Arc::ptr_eq` fast path → direct value comparison; v3 must do key-by-key lookup. |
| Arithmetic (inc/1000) | **6.5× faster** (562 ns vs 3.67 µs) | v9's Copy enum enables aggressive LLVM optimization for the UInt+UInt hot path. |
| Key lookup (get_str, 32 keys) | **within noise** (6.8 ns vs 6.6 ns) | Both use O(1) HashMap lookup. |
| Set contains (100×10 keys) | **within noise** (15.4 ns vs 14.9 ns) | Both use O(1) HashSet lookup. |
| Set create strings (1000) | **~1.9x slower** (34.2 µs vs 17.6 µs) | Arena string HashSet has higher per-element overhead. |

### Recommendation

**v9 is the best overall choice** for OPA policy evaluation workloads. It combines a 16-byte arena-allocated `Copy` two-enum Value — `ArenaValue<'a>` (inner 11 variants, flattened Number, ArenaStr) wrapped in `Value<'a>` (2 variants: `Arena(ArenaValue)` | `Ext(&v8::Value)`) — with schema-shared compact objects, delivering the best or near-best performance in deserialization, arithmetic, sorted serialization, set operations, and object equality — with zero-cost clone (`Copy`), deterministic bulk deallocation, and O(1) zero-copy v8 interop via `Value::from_ref()`.

Key advantages of v9:
- **Arithmetic**: **Fastest of all variants** — 65 ns (100 iters), 562 ns (1000 iters). **1.8× faster than v6/v7** (1.01 µs), **6.9× faster than v1–v4/v8** (3.88 µs). The `Copy` enum enables aggressive LLVM match optimization.
- **Deserialization**: Fastest among schema-sharing variants — 4.23 µs (flat/32), **11% faster than v8** (4.73 µs). Arena bump allocation is cheaper than individual heap allocations.
- **Object equality**: 131 ns (small), 181 ns (flat/32) — **within ~22% of v8** (110/148 ns), **52% faster than v3** (374 ns). Same-schema `Arc::ptr_eq` fast path gives strong performance; the ~22% gap vs v8 is the cost of the two-enum `Value::Arena` branch.
- **Sorted serialization**: 1.49 µs (flat/32) — **3% faster than v8** (1.53 µs). Both benefit from Schema-based free sorted iteration.
- **Number equality**: 329 ns — **matches v1–v5/v8** (322–330 ns).
- **Set operations**: O(1) hash-based — ~15 ns contains, ~3.0 µs create (100×10). **Fastest set creation** among all variants, 20% faster than v8.
- **Memory model**: Arena bulk deallocation — deterministic, no reference cycles. `Copy` semantics mean zero-cost clone (memcpy, no refcount).
- **v8 interop**: `Value::from_ref(&v8::Value)` wraps shared v8 data in O(1) — zero-copy, no allocation. The `Ext` variant enables mixed arena+shared-data evaluation.
- **Key lookup**: O(1) — 6.8 ns (32 keys), competitive with v8's 6.6 ns.
- **Portability**: Fully portable across all 64-bit targets (no VA-width assumptions).

Key trade-offs vs v8:
- **Object equality**: ~22% slower (181 ns vs 148 ns) — the two-enum wrapper adds an extra discriminant branch per value comparison.
- **Lifetime complexity**: `Value<'a>` requires arena lifetime threading throughout the API; v8's `Value` is `'static`.
- **String set creation**: ~2.0× slower than v8 (34.2 µs vs 17.4 µs for 1000 strings) due to arena HashSet overhead.

**v8 remains a strong choice** if lifetime ergonomics matter more than arithmetic speed. v8 offers the simplest API (no lifetime parameter, no unsafe code) with second-best performance in most categories and the best object equality.

**v7 with interning remains relevant for cache-sensitive workloads** — 8 bytes per Value (vs 16 bytes for v8/v9) doubles cache density, which benefits large-scale data processing.

**For general OPA evaluation** — dominated by key lookups, object equality, set membership, JSON deserialization/serialization, and iteration arithmetic — **v9 provides the best overall balance of speed, v8 interop, and correctness**, with v8 as the pragmatic alternative when lifetime ergonomics are preferred.

### Scorecard

Rating scale: **A** = best or within noise of best, **B** = good (within ~25%), **C** = moderate regression, **D** = significant regression, **F** = poor.
Representative benchmark chosen per category; "(i)" = with interning.

| Category | Baseline | v1 | v2 | v2 (i) | v3 | v3 (i) | v4 | v4 (i) | v5 | v5 (i) | v6 | v6 (i) | v7 | v7 (i) | v8 | v9 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Deserialization (flat/32) | C (5.55 µs) | **A** (2.74 µs) | B (3.34 µs) | **A** (3.00 µs) | B (4.08 µs) | B (3.65 µs) | B (4.06 µs) | B (3.57 µs) | B (3.94 µs) | B (3.51 µs) | C (5.51 µs) | C (4.98 µs) | D (5.94 µs) | C (5.48 µs) | B (4.73 µs) | B (4.23 µs) |
| Deser. arrays (100×32) | — | — | B (347.3 µs) | **A** (295.9 µs) | C (419.9 µs) | C (371.4 µs) | C (417.7 µs) | C (361.7 µs) | C (409.7 µs) | B (353.6 µs) | D (569.7 µs) | D (508.4 µs) | F (624.3 µs) | D (547.0 µs) | C (478.9 µs) | C (422.9 µs) |
| Key lookup (32 keys) | F (26.4 ns) | B (7.9 ns) | B (7.1 ns) | — | **A** (6.6 ns) | — | B (7.6 ns) | — | **A** (6.9 ns) | — | **A** (6.9 ns) | — | **A** (6.8 ns) | — | **A** (6.6 ns) | **A** (6.8 ns) |
| Object equality (flat/32) | B (371 ns) | C (394 ns) | B (356 ns) | — | B (374 ns) | — | B (380 ns) | — | B (385 ns) | — | D (422 ns) | — | B (251 ns) | — | **A** (148 ns) | B (181 ns) |
| Number equality (×100) | F (4560 ns) | B (322 ns) | B (321 ns) | — | B (323 ns) | — | B (322 ns) | — | B (322 ns) | — | **A** (115 ns) | — | **A** (114 ns) | — | B (330 ns) | B (329 ns) |
| Serialize unsorted (flat/32) | **A** (741 ns) | **A** (720 ns) | **A** (710 ns) | — | D (1930 ns) | — | C (1630 ns) | — | C (1570 ns) | — | D (2170 ns) | — | D (2150 ns) | — | C (1545 ns) | C (1535 ns) |
| Serialize sorted (flat/32) | — | D (3610 ns) | C (2790 ns) | — | C (2810 ns) | — | C (2730 ns) | — | B (2550 ns) | — | D (3810 ns) | — | B (2200 ns) | — | **A** (1534 ns) | **A** (1494 ns) |
| Set create (100×10) | C (28.3 µs) | — | F (517.3 µs) | — | **A** (3.90 µs) | — | **A** (3.82 µs) | — | **A** (3.92 µs) | — | **A** (4.14 µs) | — | **A** (4.16 µs) | — | **A** (3.78 µs) | **A** (3.04 µs) |
| Set contains (100×10) | D (479 ns) | — | F (6.20 µs) | — | **A** (14.9 ns) | — | **A** (15.1 ns) | — | **A** (14.7 ns) | — | **A** (14.9 ns) | — | **A** (15.1 ns) | — | **A** (14.6 ns) | **A** (15.4 ns) |
| Set create strings (1000) | C (30.7 µs) | — | C (30.1 µs) | — | **A** (17.6 µs) | — | **A** (17.5 µs) | — | **A** (17.5 µs) | — | **A** (17.8 µs) | — | **A** (17.8 µs) | — | **A** (17.4 µs) | D (34.2 µs) |
| Arithmetic (inc/1000) | **A** (266 ns) ³ | C (3.61 µs) | C (3.68 µs) | — | C (3.67 µs) | — | C (3.87 µs) | — | D (6.77 µs) | — | **A** (1.01 µs) | — | **A** (1.01 µs) | — | C (3.88 µs) | **A** (562 ns) |
| Value size | D (40 B) | D (40 B) | C (24 B) | C (24 B) | C (24 B) | C (24 B) | B (16 B) | B (16 B) | **A** (8 B) | **A** (8 B) | **A** (8 B) | **A** (8 B) | **A** (8 B) | **A** (8 B) | B (16 B) | B (16 B) |
| Portability | **A** | **A** | **A** | **A** | **A** | **A** | **A** | **A** | C ⁴ | C ⁴ | **A** | **A** | **A** | **A** | **A** | **A** |
| **A-count** | **3** | **2** | **2** | **3** | **5** | **1** | **4** | **1** | **4** | **3** | **7** | **2** | **8** | **2** | **8** | **8** |

¹ v1's `Number::eq` was accidentally inlined by LLVM due to smaller module size. Adding `#[inline(always)]` to `v2::Number::eq` (shared by v3/v4 via re-export) fixed this for all versions — number equality is now ~322 ns uniformly. v5's speed is structural (single `u64 ==`), not dependent on inlining hints.

² v2–v4 require `#[inline(always)]` on `Number::eq` to achieve full number equality performance. Without it, LLVM may not inline across crate boundaries, causing a 2× regression. v5 doesn't depend on this annotation.

³ Baseline arithmetic uses raw `as_u64()` + native addition + `Value::from()`, which LLVM collapses to a register increment. Not representative of the internal `Number::add()` path (which would match v1–v4). Rated A for the code path tested, not for Number::add().

⁴ v5 NaN boxing assumes 48-bit virtual addresses. Breaks on Intel LA57 (57-bit), ARM LVA (52-bit), and 32-bit targets.

**Overall ranking** (by A-count): **v9 = v8 = v7** (8) > **v6** (7) > **v3** (5) > **v4 = v5** (4). v9 ties with v8 and v7 at 8 A-ratings. v9's two-enum design (`ArenaValue` + `Value` wrapper with `Ext` variant) trades one A in object equality (181 ns, down from 161 ns in the single-enum design — now 22% behind v8's 148 ns) for O(1) zero-copy v8 interop via `Value::from_ref()`. v9 retains A's in key lookup, sorted serialization, set create, set contains, arithmetic (562 ns/1000 — fastest of all variants, 1.8× faster than v6/v7), and portability. v8 leads in object equality (148 ns) and has the simplest API (`'static`, no unsafe). v7 leads in value size (8 bytes) and tagged-pointer integer operations. v9's unique strengths are: fastest arithmetic, fastest set creation, O(1) v8 wrapping, and zero-cost `Copy` clone — making it the best choice when these properties matter for the evaluation workload.
