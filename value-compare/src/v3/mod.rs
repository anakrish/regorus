// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! v3 — Value with HashSet for sets and precomputed order-independent hashes.
//!
//! Key differences from v2:
//! - `Set` uses `HashSet<Value>` instead of `BTreeSet<Value>`.
//! - `ObjectMap` is a struct with precomputed hash, not an enum.
//! - `Hash` for sets and objects is order-independent (no sorting needed).
//! - `PartialEq` on ObjectMap checks cached hash first for fast rejection.

pub mod interner;
pub mod number;
pub mod object_map;
pub(crate) mod serde_impl;
pub mod value;

pub use number::Number;
pub use object_map::ObjectMap;
pub use serde_impl::{Interned, SortedValue};
pub use value::Value;
