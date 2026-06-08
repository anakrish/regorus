# Array

Opaque container for `Value::Array`'s element storage, enabling alternative
backends without call-site changes. Pairs with [`Object`](object.md) under a
shared design philosophy.

## Design

`Array` wraps a `Vec<Value>` today, but the inner vector is private: callers
cannot pattern-match it or take ownership of the backing store. The module
itself is private (`mod array;` in `value/mod.rs`); `Array` (and the
`rvm`-gated `ArrayCursor`) are the only types re-exported, so the module
layout is not part of the public API. The curated surface in
`src/value/array/mod.rs` groups roughly as:

- construction/conversion: `new`, `with_capacity`, `try_from_vec`,
  `try_from_iter`, `From<Vec<Value>>`, `FromIterator<Value>`, `IntoIterator`,
  `From<Array> for Value`, `into_value`
- read access: `len`, `is_empty`, `get`, `first`, `last`, `as_slice`, indexing
- mutation: `get_mut`, `push`, `pop`, `clear`, `insert`, `remove`, `truncate`,
  `extend_from_slice`, `iter_mut`, `sort`, `sort_by`, `dedup`, `reverse`
- iteration: `iter`, borrowed/mutable/owned `IntoIterator`, serde
- RVM-only resumable traversal: `cursor` and `next`, both compiled only with
  `#[cfg(feature = "rvm")]`; the cursor type is `ArrayCursor`, mirroring
  `ObjectCursor`.

Iteration follows sequence order. Cursor types support incremental traversal
needed by the RVM iteration state without exposing iterator internals.

Some ergonomic APIs (`as_slice`, `iter_mut`, indexing) expose contiguous-sequence
semantics. Future non-`Vec` backends should preserve the API contract, possibly
by materializing a contiguous view internally.

`Ord` is hand-written against the sequence iterator rather than derived from the
storage, so future backends compare exactly like today's `Vec<Value>` payload.

## Memory-limit enforcement

Growth-path methods that return `Result` (`push`, `extend_from_slice`,
`insert`, `with_capacity`, `try_from_vec`, `try_from_iter`) consult the
cooperative memory limit and report `Err` when it would be exceeded; the
array is left in a consistent state — any in-progress mutation that would
cross the limit is rolled back before the error is returned.

Infallible trait impls (`Extend<Value>`, `FromIterator<Value>`,
`From<Vec<Value>>`) match the [`Object`](object.md) convention and **do not**
consult the cooperative limit; they exist for ergonomic and migration use and
rely on the allocator to fail on true OOM. Limit-aware callers must use the
explicit fallible methods above.

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
