# Object

Opaque container for `Value::Object`'s key→value storage, enabling
alternative backends without call-site changes.

## Design

`Object` wraps a `BTreeMap<Value, Value>` today but exposes only a curated
method surface (`get`, `insert`, `remove`, `iter`, `iter_sorted`, `cursor`,
serde). The inner map is private — callers cannot pattern-match or pass
references to the backing store, so the backend can change without churn.

Two iteration methods reflect a real distinction: `iter()` makes no
ordering promise (lets future hash/lazy backends skip sorting work);
`iter_sorted()` guarantees deterministic order (used by serialization and
Ord). Cursor types support incremental traversal needed by the RVM
iteration state without exposing iterator internals.

`Ord` is hand-written against `iter_sorted` rather than derived, so two
backends that store entries differently still compare equal when their
sorted contents match.

## Scenarios enabled

- **Hash-backed storage** — for policies where keys aren't compared
  ordinally; swap to FxHashMap-backed inner without touching call sites.
- **Lazy/streaming** — wrap a `LazyObjectProvider` (DB query, CBOR slice,
  REST endpoint) and materialize entries on demand.
- **Arena allocation** — bumpalo-backed inner for eval-time temporaries;
  drop the whole arena at query end with zero per-entry free cost.
- **FFI-backed** — host-language callbacks (Python dict, JS object) without
  copying into Rust.
- **Small-map optimization** — inline storage for ≤N entries, heap above;
  eliminates per-object BTreeMap heap allocation for the common case.

## Known use cases

- **Azure Policy aliases** — policy authors write paths like
  `Microsoft.Compute/virtualMachines/storageProfile.osDisk.managedDisk.id`;
  the same logical property is exposed under multiple aliases by ARM.
  An alias-aware Object backend resolves lookups across canonical and
  alias forms without rewriting every policy.
- **Azure Policy case-insensitive compare** — resource property names in
  ARM are case-preserving but case-insensitive on lookup
  (`tags.Environment` vs `tags.environment` resolve identically). A
  case-insensitive Object backend implements this once at the storage
  layer instead of every comparison site in policies.
- **SARIF small-object pressure** — SARIF reports contain millions of
  small objects (location records, rule references, message arguments),
  most with 2-5 keys. A small-map-optimized backend eliminates per-object
  BTreeMap heap allocation for the common case.
- **Kubernetes admission policies** — large, deeply-nested resource
  objects (Pod specs, CRDs) where policies typically touch a handful
  of paths. A lazy-materializing Object backend parses only accessed
  subtrees from the incoming JSON.
- **Cloud config drift detection** — comparing current vs desired
  resource state requires structural equality that's tolerant of
  key-order differences and provider-specific casing. Centralizing this
  in the Object backend keeps policies portable across cloud providers.

## Precedents

- **serde_json::Map** — opaque newtype over `BTreeMap`/`IndexMap` selected
  by Cargo feature. We extend the pattern with cursor and (future) lazy
  variants.
- **toml::Table** — opaque over `IndexMap`; preserves insertion order
  behind a stable surface.
- **simdjson DOM** — lazy JSON tree, materializes on access; informs the
  `LazyObjectProvider` scenario.
- **indexmap::IndexMap** — itself precedent for "map abstraction with
  pluggable order semantics."

## Notes

Cursor types are `pub` (referenced by public `IterationState`) but not
re-exported at the crate root. Future Array and String abstractions
follow the same shape — see `docs/value/array.md` and `docs/value/string.md`
when they land.

## Upgrade notes (0.11.0)

`Value::Object`'s payload changed from `Rc<BTreeMap<Value, Value>>` to
`Rc<Object>`. `Object` mirrors the shape of `BTreeMap<Value, Value>` so
most call sites compile unchanged; only the return types of
`Value::as_object` / `as_object_mut` differ:

```rust
// Before
let m: &BTreeMap<Value, Value> = v.as_object()?;
// After
let m: &Object = v.as_object()?;
m.get(&key);          // same
m.iter();             // same
m.contains_key(&key); // same
```

The `_mut` sibling still goes through `Rc::make_mut` (copy-on-write).

### Constructing a `Value::Object` from a literal

```rust
// Before
Value::Object(Rc::new(BTreeMap::from_iter(pairs)))
// After
Object::from_iter(pairs).into()
// or, equivalently:
Object::from_iter(pairs).into_value()
```

### Pattern-matching `Value::Object(rc)`

`rc` is now `&Rc<Object>` instead of `&Rc<BTreeMap>`. All the methods
you used on the inner collection (`len`, `is_empty`, `get`,
`contains_key`, `iter`, `keys`, `values`, `insert`, `remove`, `retain`,
`clear`, `append`, `extend`, `Index` by key, `IntoIterator`) exist on
`Object` with identical signatures and semantics.

### Removed surface

The full `BTreeMap` surface is *not* re-exposed. In particular these
methods are gone — file an issue with your use case if you need them,
they aren't exposed yet because no internal caller does:

- `BTreeMap::entry` (use `Object::get_or_insert_with` or
  `Object::insert_if_absent`)
- `BTreeMap::range`, `BTreeMap::range_mut`
- `BTreeMap::first_key_value`, `BTreeMap::last_key_value`
- `BTreeMap::pop_first`, `BTreeMap::pop_last`
- `BTreeMap::split_off`

The `IntoIter`, `Iter`, `IterMut` types returned by `into_iter()` /
`iter()` / `iter_mut()` are now opaque newtypes rather than
`btree_map::Iter`. Callers that named the concrete type need to switch
to `impl Iterator<Item = ...>` or the new wrapper types.

### Iteration-order semantics

| Method                          | Order                  | Use for                       |
| ------------------------------- | ---------------------- | ----------------------------- |
| `iter()` / `keys()` / `values()`| implementation-defined | Rego evaluation iteration     |
| `iter_sorted()` / `keys_sorted()`| sorted by `Value::Ord`| canonical / user-visible output|

Today the BTree-backed storage means `iter()` happens to return sorted
order, but **callers must not depend on that**. Both execution backends
(interpreter and RVM) use `iter()` for evaluation iteration; sites that
produce canonical output (`Serialize`, `Debug`, `to_printable`, sprintf
`%v`, the RVM binary value serializer) use `iter_sorted()` explicitly.

### Resumable iteration: `cursor()` / `next()`

Use the cursor API when your caller must yield mid-iteration and resume
later (the RVM's `IterationState` does this for loops and
comprehensions):

```rust
let mut cursor = obj.cursor();
while let Some((k, v)) = obj.next(&mut cursor) {
    // ...possibly yield to the outer scheduler, then resume later.
}
```

- `cursor()` / `next()` — implementation-defined order; cheapest per-step cost.
- `cursor_sorted()` / `next_sorted()` — sorted order, for canonical resumable iteration.

For one-shot consumption use `iter()` / `iter_sorted()`; reach for
cursors only when the iteration must suspend.

### Things that did not change

- Equality, ordering, and hashing of `Object` are unchanged (`Ord` is
  now hand-written against `iter_sorted()` so it is consistent across
  storage variants, but produces the same result on the BTree backend).
- `Serialize` / `Deserialize` for `Value::Object` produce the same JSON
  as before. (`Value`'s `Serialize` impl now delegates to `Object` so
  there is a single canonical path.)
- `Rc::make_mut` copy-on-write semantics for `Value::as_object_mut`
  are unchanged.
