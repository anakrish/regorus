# Migration: `Value::Object` / `Value::Set` payload swap (0.11.0)

In `0.11.0` the inner storage of `Value::Object` and `Value::Set` was hidden
behind two opaque types re-exported from the crate root:

| Old                                    | New                       |
| -------------------------------------- | ------------------------- |
| `Value::Object(Rc<BTreeMap<Value,V>>)` | `Value::Object(Rc<Object>)` |
| `Value::Set(Rc<BTreeSet<Value>>)`      | `Value::Set(Rc<Set>)`     |

`Object` and `Set` mirror the shape of `BTreeMap<Value, Value>` and
`BTreeSet<Value>` respectively, so most call sites compile unchanged.

## Source-of-truth: the public surface

The `collections` module is a crate-private implementation detail — the
types are re-exported at the crate root:

```rust
use regorus::{Object, Set};

let mut o = Object::new();
o.insert(Value::from("k"), Value::from(1));
assert!(o.contains_key(&Value::from("k")));
let v: Value = o.into(); // From<Object> for Value
```

The cursor types are also re-exported when you need resumable iteration:

```rust
use regorus::{Object, ObjectCursor, ObjectCursorSorted, Set, SetCursor, SetCursorSorted};
```

## Per-pattern recipes

### `as_object()` / `as_object_mut()` / `as_set()` / `as_set_mut()`

**Method names unchanged.** Only the return type changed:

```rust
// Before
let m: &BTreeMap<Value, Value> = v.as_object()?;

// After
let m: &Object = v.as_object()?;
m.get(&key);          // same
m.iter();             // same
m.contains_key(&key); // same
```

The `_mut` siblings still go through `Rc::make_mut` (copy-on-write) under the
hood — mutating one `Value` clone does not affect aliased holders.

### Constructing a `Value::Object` from a literal

```rust
// Before
Value::Object(Rc::new(BTreeMap::from_iter(pairs)))

// After
Object::from_iter(pairs).into()
// or, equivalently:
Object::from_iter(pairs).into_value()
```

`Set` mirrors this:

```rust
// Before
Value::Set(Rc::new(BTreeSet::from_iter(items)))

// After
Set::from_iter(items).into()
```

### Pattern-matching `Value::Object(rc)` / `Value::Set(rc)`

`rc` is now `&Rc<Object>` / `&Rc<Set>` instead of `&Rc<BTreeMap>` /
`&Rc<BTreeSet>`. All the methods you used on the inner collection
(`len`, `is_empty`, `get`, `contains_key`, `iter`, `keys`, `values`,
`insert`, `remove`, `retain`, `clear`, `append`, `extend`, `Index` by key,
`IntoIterator`) exist on `Object` / `Set` with identical signatures and
semantics.

### Removed surface

The full `BTreeMap` / `BTreeSet` surface is *not* re-exposed. In particular
these methods are gone:

- `BTreeMap::entry` (use `Object::get_or_insert_with` or `Object::insert_if_absent`)
- `BTreeMap::range`, `BTreeMap::range_mut`
- `BTreeMap::first_key_value`, `BTreeMap::last_key_value`
- `BTreeMap::pop_first`, `BTreeMap::pop_last`
- `BTreeMap::split_off`
- `BTreeSet::range`, `BTreeSet::split_off`

If you used any of these, please file an issue with your use case — they
aren't exposed yet because no internal caller needs them; we'd like to add
them with a real shape to fit the actual workload.

The `IntoIter`, `Iter`, `IterMut` types returned by `into_iter()`, `iter()`,
and `iter_mut()` are now opaque newtypes (e.g.
`regorus::collections::object::Iter`) rather than `btree_map::Iter`. Callers
that named the concrete `btree_map::Iter` type will need to switch to
`impl Iterator<Item = ...>` or to the new wrapper types.

## Iteration-order semantics (read this)

Iteration is split into **two methods** that mirror std's `HashMap` vs
`BTreeMap` convention:

| Method                                       | Order                                | Use for                              |
| -------------------------------------------- | ------------------------------------ | ------------------------------------ |
| `iter()` / `keys()` / `values()`             | implementation-defined               | Rego evaluation iteration            |
| `iter_sorted()` / `keys_sorted()`            | sorted by `Value::Ord`               | canonical / user-visible output      |

Today the BTree-backed storage means `iter()` happens to return sorted order,
but **callers must not depend on that**. A future hash-backed variant could
change it.

**Both execution backends (interpreter and RVM) use `iter()` / `keys()` for
evaluation iteration**, to preserve dual-path equivalence. Sites that produce
canonical output (`Serialize`, `Debug`, `to_printable`, `Set::first` /
`Set::last`, sprintf `%v`, `urlquery.encode_object`, the RVM binary value
serializer) use `iter_sorted()` explicitly.

If you call `iter()` and rely on the iteration being sorted, switch to
`iter_sorted()`.

## Resumable iteration: `cursor()` / `next()`

Use the cursor API when your caller must yield mid-iteration and resume
later (the RVM's `IterationState` does this for loops and comprehensions):

```rust
let mut cursor = obj.cursor();
while let Some((k, v)) = obj.next(&mut cursor) {
    // ...possibly yield to the outer scheduler, then resume the loop later.
    // `cursor` survives across yields, no eager pair snapshot is built.
}
```

- `cursor()` / `next()` — implementation-defined order; cheapest per-step cost.
- `cursor_sorted()` / `next_sorted()` — sorted order, for canonical resumable iteration.

The cursor types (`ObjectCursor`, `ObjectCursorSorted`, `SetCursor`,
`SetCursorSorted`) are opaque so future storage variants can change their
resume-state representation. They're stable for the lifetime of the borrow
(the underlying `Object`/`Set` is owned and not mutated mid-iteration).

For one-shot consumption use `iter()` / `iter_sorted()`; reach for cursors
only when the iteration must suspend.

## Things that did not change

- Equality, ordering, and hashing of `Object` / `Set` are unchanged (`Ord`
  is now hand-written against `iter_sorted()` so it is consistent across
  storage variants, but produces the same result on the BTree backend).
- `Serialize` / `Deserialize` for `Value::Object` / `Value::Set` produce the
  same JSON as before. (`Value`'s `Serialize` impl now delegates to
  `Object` / `Set` so there is a single canonical path.)
- `Rc::make_mut` copy-on-write semantics for `Value::as_object_mut` /
  `Value::as_set_mut` are unchanged.
- The set algebra surface (`union`, `intersection`, `difference`,
  `symmetric_difference`, `is_subset`, `is_superset`, `is_disjoint`) is
  preserved.
