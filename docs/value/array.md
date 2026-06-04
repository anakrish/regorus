# Array

Opaque container for `Value::Array`'s element storage, enabling alternative
backends without call-site changes. Pairs with [`Object`](object.md) under a
shared design philosophy.

## Design

`Array` wraps a `Vec<Value>` today but exposes only a curated method surface
(`get`, `get_mut`, `push`, `pop`, `insert`, `remove`, `iter`, `iter_mut`,
`cursor`, serde). The inner vector is private — callers cannot pattern-match it
or hand out mutable references to the backing store, so the backend can change
without churn at call sites that currently assume `Vec<Value>`.

Iteration follows sequence order. Cursor types support incremental traversal
needed by the RVM iteration state without exposing iterator internals.

`Ord` is hand-written against the sequence iterator rather than derived from the
storage, so future backends compare exactly like today's `Vec<Value>` payload.

## Scenarios enabled

- **Inline-small storage** — store short arrays inline and spill to heap only for
  larger values.
- **Lazy/streaming** — wrap a provider over JSON/CBOR/host data and materialize
  elements on demand.
- **Arena allocation** — bumpalo-backed arrays for eval-time temporaries; drop
  the whole arena at query end with zero per-element free cost.
- **FFI-backed** — host-language lists or arrays without copying into Rust on
  every binding boundary.

## Notes

`Value::Array` is not migrated by the foundation PR that introduces this type;
it still wraps `Rc<Vec<Value>>` until the follow-up migration.
