// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! v8 — 16-byte Value: ArcStr strings, flattened Number, schema-shared compact objects.
//!
//! Combines v3's simple enum-based Value with v7's schema interning for
//! objects.  Uses `ArcStr` (thin pointer) for strings and flattens Number
//! variants directly into the Value enum to achieve 16+1 → 16 bytes via
//! niche optimization.
//!
//! Key features:
//! - 16 bytes per Value (down from 24) — better cache density
//! - Same-schema equality fast path (Arc::ptr_eq on schemas → value-array compare)
//! - Free sorted iteration for compact objects (keys pre-sorted in Schema)
//! - Fast deserialization (inline enum values, no heap-per-value overhead)
//! - Precomputed order-independent cached_hash on objects

pub mod number;
pub mod object_map;
pub(crate) mod serde_impl;
pub mod value;

pub use number::Number;
pub use object_map::ObjectMap;
pub use serde_impl::{Interned, SortedValue};
pub use value::Value;
