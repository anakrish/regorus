# Migration: `Value::Object` / `Value::Set` payload swap (0.11.0)

In `0.11.0` the inner storage of `Value::Object` and `Value::Set` was hidden
behind two opaque types in the new `regorus::collections` module:

| Old                                    | New                       |
| -------------------------------------- | ------------------------- |
| `Value::Object(Rc<BTreeMap<Value,V>>)` | `Value::Object(Rc<Object>)` |
| `Value::Set(Rc<BTreeSet<Value>>)`      | `Value::Set(Rc<Set>)`     |

`Object` mirrors the shape of `BTreeMap<Value, Value>` and `Set` mirrors
`BTreeSet<Value>`, so most call sites compile unchanged. This document covers
the few that don't, plus iteration-order semantics that callers should be
aware of even when their code still compiles.

## Source-of-truth: the public surface

```rust
use regorus::collections::{Object, Set};

let mut o = Object::new();
o.insert(Value::from("k"), Value::from(1));
assert!(o.contains_key(&Value::from("k")));
let v: Value = o.into(); // From<Object> for Value
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

The one collection-specific surface that disappeared is the `BTreeMap::entry`
API. Use `Object::get_or_insert_with(key, default)` for the common
entry-pattern shape (single-probe insert-if-absent).

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
`Set::last`) use `iter_sorted()` explicitly.

If you call `iter()` and rely on the iteration being sorted, switch to
`iter_sorted()`.

## Things that did not change

- Equality, ordering, and hashing of `Object` / `Set` are unchanged.
- `Serialize` / `Deserialize` for `Value::Object` / `Value::Set` produce the
  same JSON as before.
- `Rc::make_mut` copy-on-write semantics for `Value::as_object_mut` /
  `Value::as_set_mut` are unchanged.
- The set algebra surface (`union`, `intersection`, `difference`,
  `symmetric_difference`, `is_subset`, `is_superset`, `is_disjoint`) is
  preserved.
