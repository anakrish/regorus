// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! v9 — Arena-allocated Value with `Copy` semantics.
//!
//! All heap data (strings, arrays, objects, sets, BigInts) is allocated in a
//! `bumpalo::Bump` arena.  `Value<'a>` is 16 bytes and `Copy` — cloning is a
//! plain memcpy (no atomic refcount), and drop is a no-op (the arena frees
//! everything in bulk).
//!
//! Key features:
//! - `Value<'a>` is `Copy` — zero-cost clone, no-op drop.
//! - 16 bytes: Number variants flattened into Value, String/Array use thin-pointer wrappers.
//! - All allocations go through a `&'a Bump` arena.
//! - `ObjectMap` uses `hashbrown::HashMap` — O(1) lookup.
//! - `ArenaSet` uses `hashbrown::HashSet` — O(1) `contains`.
//! - `from_json` / `from_json_interned` use `DeserializeSeed` to deserialize
//!   directly into the arena (no intermediate owned values).
//! - Precomputed order-independent hashes on objects and sets.

pub mod number;
pub mod object_map;
pub mod serde_impl;
pub mod value;

pub use number::Number;
pub use object_map::{clear_schema_cache, intern_schema, ObjectMap, ObjectMapBuilder};
pub use serde_impl::{from_json, from_json_interned, SortedValue, StringInterner};
pub use value::{ArenaArray, ArenaSet, ArenaStr, ArenaValue, Value};
