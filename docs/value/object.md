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
