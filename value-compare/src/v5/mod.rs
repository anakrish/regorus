// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! v5 — NaN-boxed Value: entire Value in 8 bytes using IEEE 754 NaN boxing.
//!
//! Key differences from v4:
//! - `Value` is a single `u64` (8 bytes) instead of an enum (16 bytes).
//! - Floats stored as raw f64 bits. Tagged values use quiet NaN bit patterns.
//! - 8 Values per cache line (vs 4 in v4).
//! - Integers ≤ 2^53 stored as f64 (exactly representable).
//! - Larger integers stored as heap-allocated `HeapNumber`.

pub mod interner;
pub mod object_map;
pub(crate) mod serde_impl;
pub mod value;

pub use object_map::ObjectMap;
pub use serde_impl::{Interned, SortedValue};
pub use value::Value;
