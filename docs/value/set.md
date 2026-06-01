# Set

Opaque container for `Value::Set`'s element storage, enabling alternative
backends without call-site changes. Pairs with [`Object`](object.md) under
a shared design philosophy.

## Design

`Set` wraps a `BTreeSet<Value>` today but exposes only a curated method
surface (`contains`, `insert`, `remove`, `iter`, `iter_sorted`, `cursor`,
`is_subset`, `intersection`, `difference`, serde). The inner set is
private — callers cannot pattern-match it or hand out references to the
backing store, so the backend can change without churn at the ~400 call
sites that name `Set`.

Two iteration methods reflect a real distinction: `iter()` makes no
ordering promise (lets future hash/lazy backends skip sorting work);
`iter_sorted()` guarantees deterministic order (used by serialization and
`Ord`). Cursor types support incremental traversal needed by the RVM
iteration state without exposing iterator internals.

`Ord` is hand-written against `iter_sorted` rather than derived, so two
backends that store elements differently still compare equal when their
sorted contents match.

## Scenarios enabled

- **Hash-backed storage** — `FxHashSet`-backed inner turns O(log n)
  membership checks into O(1); swap in for policies where elements aren't
  compared ordinally.
- **Lazy/streaming** — wrap a `LazySetProvider` (DB query, CBOR slice,
  REST endpoint) and materialize elements on demand.
- **Arena allocation** — bumpalo-backed inner for eval-time temporaries;
  drop the whole arena at query end with zero per-element free cost.
- **FFI-backed** — host-language collections (Python set, JS Set) without
  copying into Rust.
- **Bloom-filter pre-check** — front a large backing set with a Bloom
  filter for fast negative-membership tests on read-mostly allowlists.

## Known use cases

- **Azure Policy allowed-values lists** — large allowlists (allowed
  regions, allowed SKUs, allowed image publishers) compared against
  single resource values. Hash-backed Set turns O(log n) membership
  checks into O(1).
- **SARIF rule deduplication** — collapsing duplicate rule references
  across thousands of result records. Set-of-objects with structural
  hashing avoids the BTreeSet sort cost on every insert.
- **RBAC role membership** — checking whether a principal belongs to any
  of dozens of role groups. Hash-backed Set scales to thousands of
  members with constant-time membership.
- **Azure Policy denied-resource-type sets** — exclusion lists used by
  deny-effect policies; same hash-backed pattern as allowed-values.

## Precedents

- **`indexmap::IndexSet`** — opaque newtype that pairs hash lookup with
  insertion-order iteration; precedent for "Set with alternative
  ordering semantics behind a stable surface."
- **`hashbrown::HashSet`** — backs Rust's `std::collections::HashSet`
  and demonstrates a fully swappable backend behind a stable API.
- **`roaring::RoaringBitmap`** — bitmap-backed integer set. Not
  applicable to `Value` keys directly, but a precedent for the broader
  idea of "Set with alternative storage representations chosen by
  workload shape."
- **`serde_json`** — note that `serde_json` has no Set equivalent: its
  Value enum collapses sets into arrays. Regorus's first-class Set with
  storage abstraction is therefore unusually well-positioned among JSON
  value libraries.

## Notes

Cursor types are `pub` (referenced by public `IterationState`) but not
re-exported at the crate root. The crate-internal `Set`/`Map`/`MapEntry`
aliases for `BTreeSet`/`BTreeMap` in `lib.rs` were renamed to
`MapSet`/`Map`/`MapEntry` when this type landed, to free the `Set` name
for the new public type. Future Array and String abstractions follow the
same shape — see `docs/value/array.md` and `docs/value/string.md` when
they land.

## Upgrade notes (0.11.0)

`Value::Set`'s payload changed from `Rc<BTreeSet<Value>>` to
`Rc<Set>`. `Set` mirrors the shape of `BTreeSet<Value>` so most call
sites compile unchanged; only the return types of `Value::as_set` /
`as_set_mut` differ:

```rust
// Before
let s: &BTreeSet<Value> = v.as_set()?;
// After
let s: &Set = v.as_set()?;
s.contains(&item);     // same
s.iter();              // same
s.is_subset(&other);   // same
```

The `_mut` sibling still goes through `Rc::make_mut` (copy-on-write).

### Constructing a `Value::Set` from a literal

```rust
// Before
Value::Set(Rc::new(BTreeSet::from_iter(items)))
// After
Set::from_iter(items).into()
// or, equivalently:
Set::from_iter(items).into_value()
```

### Pattern-matching `Value::Set(rc)`

`rc` is now `&Rc<Set>` instead of `&Rc<BTreeSet>`. All the methods you
used on the inner collection (`len`, `is_empty`, `contains`, `iter`,
`insert`, `remove`, `retain`, `clear`, `append`, `extend`,
`IntoIterator`, plus the algebra: `union`, `intersection`,
`difference`, `symmetric_difference`, `is_subset`, `is_superset`,
`is_disjoint`) exist on `Set` with identical signatures and semantics.

### Removed surface

The full `BTreeSet` surface is *not* re-exposed. In particular these
methods are gone — file an issue with your use case if you need them:

- `BTreeSet::range`
- `BTreeSet::split_off`
- `BTreeSet::pop_first`, `BTreeSet::pop_last`

The `IntoIter`, `Iter` types returned by `into_iter()` / `iter()` are
now opaque newtypes rather than `btree_set::Iter`. Callers that named
the concrete type need to switch to `impl Iterator<Item = ...>` or the
new wrapper types.

### Iteration-order semantics

| Method                | Order                  | Use for                       |
| --------------------- | ---------------------- | ----------------------------- |
| `iter()`              | implementation-defined | Rego evaluation iteration     |
| `iter_sorted()`       | sorted by `Value::Ord` | canonical / user-visible output|

Today the BTree-backed storage means `iter()` happens to return sorted
order, but **callers must not depend on that**. Both execution backends
(interpreter and RVM) use `iter()` for evaluation iteration; sites that
produce canonical output (`Serialize`, `Debug`, `to_printable`,
`Set::first` / `Set::last`, sprintf `%v`, the RVM binary value
serializer) use `iter_sorted()` explicitly.

### Resumable iteration: `cursor()` / `next()`

Use the cursor API when your caller must yield mid-iteration and resume
later (the RVM's `IterationState` does this for loops and
comprehensions):

```rust
let mut cursor = set.cursor();
while let Some(item) = set.next(&mut cursor) {
    // ...possibly yield to the outer scheduler, then resume later.
}
```

- `cursor()` / `next()` — implementation-defined order; cheapest per-step cost.
- `cursor_sorted()` / `next_sorted()` — sorted order, for canonical resumable iteration.

For one-shot consumption use `iter()` / `iter_sorted()`; reach for
cursors only when the iteration must suspend.

### Things that did not change

- Equality, ordering, and hashing of `Set` are unchanged (`Ord` is now
  hand-written against `iter_sorted()` so it is consistent across
  storage variants, but produces the same result on the BTree backend).
- `Serialize` / `Deserialize` for `Value::Set` produce the same JSON as
  before. (`Value`'s `Serialize` impl now delegates to `Set` so there
  is a single canonical path.)
- The set algebra surface is preserved.
- `Rc::make_mut` copy-on-write semantics for `Value::as_set_mut` are
  unchanged.
