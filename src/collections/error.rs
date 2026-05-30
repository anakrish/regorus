// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use core::fmt;

/// Error returned by `ObjectRefMut::insert` and `SetRefMut::insert` when the
/// supplied key or element cannot be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InsertError {
    /// A `Number::Float(NaN | +INF | -INF)` was supplied as a key or set
    /// element. The check is uniform across storage variants so callers
    /// observe a consistent contract.
    NonFiniteKey,
}

impl fmt::Display for InsertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonFiniteKey => f.write_str("non-finite numeric key is not allowed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InsertError {}
