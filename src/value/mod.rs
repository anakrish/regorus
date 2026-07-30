// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Value type for Rego documents.
//!
//! Two implementations are available, selected at compile time via the
//! `optimized-value` Cargo feature:
//!
//! - **default** (`src/value/default.rs`): BTreeSet/BTreeMap-backed containers
//!   with derived Eq/Ord.  This is the original, well-tested implementation.
//!
//! - **optimized** (`src/value/optimized.rs`): Incorporates optimizations from
//!   the v8 experimental Value (pointer-equality fast paths in Eq/Ord, Hash
//!   implementation, and further container changes over time).

#[cfg(not(feature = "optimized-value"))]
mod default;
#[cfg(not(feature = "optimized-value"))]
pub use default::*;

#[cfg(feature = "optimized-value")]
mod optimized;
#[cfg(feature = "optimized-value")]
pub use optimized::*;

/// Helper trait so that `Rc<str>` (default Value) and `ArcStr` (optimized Value)
/// share the same `.as_str()` API.  `ArcStr` already has a stable `.as_str()`;
/// `Rc<str>` does not (it's behind `str_as_str`), so we provide our own impl.
#[cfg(not(feature = "optimized-value"))]
pub trait RcStrExt {
    fn as_str(&self) -> &str;
}

#[cfg(not(feature = "optimized-value"))]
impl RcStrExt for crate::Rc<str> {
    #[inline]
    fn as_str(&self) -> &str {
        self
    }
}

/// Lazy element access used by the interpreter's array loops.  In the optimized
/// Value this is an inherent method on the `Array` newtype (supporting foreign
/// backends); the default Value has no newtype, so provide the same API on the
/// underlying `Vec<Value>` for source compatibility.
#[cfg(not(feature = "optimized-value"))]
pub trait ArrayLazy {
    fn element(&self, index: usize) -> Option<Value>;
}

#[cfg(not(feature = "optimized-value"))]
impl ArrayLazy for alloc::vec::Vec<Value> {
    #[inline]
    fn element(&self, index: usize) -> Option<Value> {
        self.get(index).cloned()
    }
}
