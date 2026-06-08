// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! V1 Value implementation.
//!
//! Key differences from regorus::Value:
//! - Objects use `ObjectMap` which specializes for string keys using `HashMap<SmolStr, Value>`.
//! - Mixed-key objects (rare) fall back to `BTreeMap<Value, Value>`.
//! - Number comparison has fast paths for Int-vs-Int, avoiding BigInt allocation.

mod number;
mod object_map;
mod serde_impl;
mod value;

pub use number::Number;
pub use object_map::ObjectMap;
pub use serde_impl::SortedValue;
pub use value::Value;
