// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Storage abstraction for `Value::Object`.
//!
//! [`Object`] is an opaque wrapper around the current backing storage
//! (`BTreeMap<Value, Value>`). Its inner field is private so that future
//! storage representations (two-tier inline+hash, lazy, schema-shared,
//! projection-aware) can swap in without touching call sites.
//!
//! ## Iteration order
//!
//! - [`Object::iter`] is **implementation-defined order** (mirroring
//!   `HashMap::iter`). Today it happens to iterate in sorted order because
//!   storage is BTree-backed, but callers MUST NOT depend on that.
//! - [`Object::iter_sorted`] is **sorted by `Value::Ord`**. Use this whenever
//!   deterministic order is required (serialization, snapshots, hashing,
//!   `Debug`, the `object.keys` builtin, RVM↔interpreter parity).
//!
//! ## Resumable iteration
//!
//! Use [`Object::cursor`] / [`Object::next`] when callers must yield
//! mid-iteration and resume later (e.g. the RVM `IterationState`). The
//! cursor types are crate-internal so future storage variants can change
//! their resume-state representation. Use plain [`Object::iter`] /
//! [`Object::iter_sorted`] for one-shot consumption.

mod object;

#[cfg(test)]
mod tests;

#[allow(unused_imports)] // surface for downstream PRs; cursor used internally in PR1b
pub use object::{IntoIter, Iter, IterMut, Object};

#[cfg(feature = "rvm")]
#[allow(unused_imports)] // surface for downstream PRs
pub use object::ObjectCursor;
