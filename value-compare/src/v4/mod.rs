// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! v4 — Value with `arcstr::ArcStr` for 16-byte Value (thin string pointer).
//!
//! Key differences from v3:
//! - `String` variant uses `arcstr::ArcStr` (8 bytes, thin pointer) instead of
//!   `Arc<str>` (16 bytes, fat pointer).
//! - Total `Value` size: 16 bytes (down from 24 in v3).
//! - 2x cache density: 4 Values per cache line vs 2.
//! - All other v3 features retained: HashSet for sets, precomputed object hash.

pub mod interner;
pub mod number;
pub mod object_map;
pub(crate) mod serde_impl;
pub mod value;

pub use number::Number;
pub use object_map::ObjectMap;
pub use serde_impl::{Interned, SortedValue};
pub use value::Value;
