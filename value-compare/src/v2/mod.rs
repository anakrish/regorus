// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! V2 Value implementation.
//!
//! Same as v1 but uses `Arc<str>` instead of `SmolStr` for HashMap keys in ObjectMap.
//! This lets us avoid the SmolStr dependency and share Arc<str> between keys and Value::String.

pub mod interner;
mod number;
mod object_map;
mod serde_impl;
mod value;

pub use number::Number;
pub use object_map::ObjectMap;
pub use serde_impl::{Interned, SortedValue};
pub use value::Value;
