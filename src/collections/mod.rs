// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Storage-agnostic abstraction layer for `Value::Object` and `Value::Set`.
//!
//! See `DESIGN.md` (v6) for the full design rationale. Public types:
//!
//! - [`Object`] / [`Set`] — opaque owned collections embedded in `Value`.
//! - [`ObjectRef`] / [`ObjectRefMut`] / [`SetRef`] / [`SetRefMut`] — borrow views.
//! - [`MapEntry`] / [`OccupiedMapEntry`] / [`VacantMapEntry`] — entry API.
//! - [`InsertError`] — uniform key/element validation error.

#![allow(
    clippy::missing_const_for_fn,
    clippy::pattern_type_mismatch,
    clippy::redundant_pub_crate,
    clippy::unused_trait_names,
    clippy::collapsible_if,
    clippy::explicit_deref_methods,
    clippy::std_instead_of_core
)]

mod entry;
mod error;
mod iter;
mod object;
pub(crate) mod object_storage;
mod set;
pub(crate) mod set_storage;

pub use entry::{MapEntry, OccupiedMapEntry, VacantMapEntry};
pub use error::InsertError;
pub use iter::{
    IntoIter, Iter, IterMut, IterSorted, Keys, SetIntoIter, SetIter, SetIterSorted, Values,
    ValuesMut,
};
pub use object::{Object, ObjectRef, ObjectRefMut};
pub use set::{Set, SetRef, SetRefMut};

#[cfg(test)]
mod tests;
