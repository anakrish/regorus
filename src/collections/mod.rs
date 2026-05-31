// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Storage abstraction for `Value::Object` and `Value::Set`.
//!
//! [`Object`] and [`Set`] are opaque wrappers around the current backing
//! storage (`BTreeMap<Value, Value>` and `BTreeSet<Value>`). Their inner
//! fields are private so that future storage representations (two-tier
//! inline+hash, lazy, schema-shared, projection-aware) can swap in without
//! touching the ~400 call sites that name these types.
//!
//! ## Iteration order
//!
//! - [`Object::iter`] / [`Set::iter`] are **implementation-defined order**
//!   (mirroring `HashMap::iter`). Today they happen to iterate in sorted order
//!   because storage is BTree-backed, but callers MUST NOT depend on that.
//! - [`Object::iter_sorted`] / [`Set::iter_sorted`] (and `keys_sorted`) are
//!   **sorted by `Value::Ord`**. Use these whenever deterministic order is
//!   required (serialization, snapshots, hashing, `Debug`, the `object.keys`
//!   builtin, RVM↔interpreter parity).
//!
//! ## Resumable iteration
//!
//! Use [`Object::cursor`] / [`Object::next`] (and the `_sorted` siblings) when
//! callers must yield mid-iteration and resume later (e.g. the RVM
//! `IterationState`). The cursor types are opaque so future storage variants
//! can change their resume-state representation. Use plain `iter()` /
//! `iter_sorted()` for one-shot consumption.

mod object;
mod set;

#[cfg(test)]
mod tests;

pub use object::{Object, ObjectCursor, ObjectCursorSorted};
pub use set::{Set, SetCursor, SetCursorSorted};
