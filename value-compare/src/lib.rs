// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Benchmark crate comparing different `Value` implementations.
//!
//! - `v1`: HashMap<SmolStr, Value> for string-keyed objects (+ BTreeMap fallback for mixed keys).
//! - Future: additional implementations.

pub mod v1;
pub mod v2;
pub mod v3;
pub mod v4;
pub mod v5;
pub mod v6;
pub mod v7;
pub mod v8;
pub mod v9;

/// Re-export the original regorus Value as the baseline.
pub use regorus::Value as BaselineValue;
