// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! v6 — Portable tagged pointer Value: 8-byte Value using low-bit pointer tagging.
//!
//! Key differences from v5 (NaN boxing):
//! - Uses low alignment bits (3 bits) instead of IEEE 754 NaN space.
//! - **Fully portable**: works on 32-bit, wasm32, LA57, aarch64 LVA — no VA-width
//!   assumptions.
//! - Integers ≤ 61 bits stored inline (shift + tag). Larger integers go to heap.
//! - Floats always heap-allocated (rare in OPA workloads).
//! - Same ObjectMap/HashSet/cached-hash features as v3–v5.

pub mod interner;
pub mod object_map;
pub(crate) mod serde_impl;
pub mod value;

pub use object_map::ObjectMap;
pub use serde_impl::{Interned, SortedValue};
pub use value::Value;
