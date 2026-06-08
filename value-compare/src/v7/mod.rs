// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! v7 — Portable tagged pointer + schema-shared compact objects.
//!
//! Combines v6's encoding with schema-shared compact objects:
//! - Same 8-byte tagged-pointer Value as v6 (fully portable).
//! - Objects with identical key sets share a single `Schema` allocation.
//! - Schema-shared objects store only values (no per-object key storage).
//! - Schema interning during deserialization amortizes key allocation.
//! - Same-schema equality is a fast value-array comparison.

pub mod interner;
pub mod object_map;
pub(crate) mod serde_impl;
pub mod value;

pub use object_map::ObjectMap;
pub use serde_impl::{Interned, SortedValue};
pub use value::Value;
