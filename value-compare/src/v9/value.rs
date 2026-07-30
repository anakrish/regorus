// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Arena-allocated Rego value.  `Copy` — zero-cost clone, no-op drop.

use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use bumpalo::Bump;
use hashbrown::HashSet;
use num_bigint::BigInt;

use super::number::Number;
use super::object_map::{ObjectMap, ObjectMapBuilder};

/// The external Value type (v8's 16-byte Value).
use crate::v8::Value as ExtValue;

// ---------------------------------------------------------------------------
//  ArenaStr — thin-pointer string wrapper (8 bytes vs 16 for &str)
// ---------------------------------------------------------------------------

/// Arena-allocated string wrapper.  `&'a ArenaStr<'a>` is a thin pointer (8 bytes)
/// that dereferences to `&str`.
pub struct ArenaStr<'a>(pub(crate) &'a str);

impl<'a> ArenaStr<'a> {
    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

impl std::fmt::Debug for ArenaStr<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::fmt::Display for ArenaStr<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl PartialEq for ArenaStr<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for ArenaStr<'_> {}

impl PartialOrd for ArenaStr<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ArenaStr<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(other.0)
    }
}

impl Hash for ArenaStr<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl std::borrow::Borrow<str> for &ArenaStr<'_> {
    fn borrow(&self) -> &str {
        self.0
    }
}

impl std::ops::Deref for ArenaStr<'_> {
    type Target = str;
    fn deref(&self) -> &str {
        self.0
    }
}

// ---------------------------------------------------------------------------
//  ArenaArray — thin-pointer array wrapper (8 bytes vs 16 for &[Value])
// ---------------------------------------------------------------------------

/// Arena-allocated array wrapper.  `&'a ArenaArray<'a>` is a thin pointer (8 bytes)
/// that dereferences to `&[Value<'a>]`.
pub struct ArenaArray<'a>(pub(crate) &'a [Value<'a>]);

impl<'a> ArenaArray<'a> {
    pub fn as_slice(&self) -> &'a [Value<'a>] {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Value<'a>> {
        self.0.iter()
    }
}

impl PartialEq for ArenaArray<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for ArenaArray<'_> {}

impl PartialOrd for ArenaArray<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ArenaArray<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(other.0)
    }
}

impl Hash for ArenaArray<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl std::fmt::Debug for ArenaArray<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.0.iter()).finish()
    }
}

// ---------------------------------------------------------------------------
//  ArenaSet — hashbrown::HashSet with precomputed hash
// ---------------------------------------------------------------------------

/// An immutable set of values backed by `hashbrown::HashSet` in an arena.
///
/// `contains` is O(1).  Precomputed order-independent hash for fast equality
/// rejection and O(1) `Hash`.
pub struct ArenaSet<'a> {
    set: HashSet<Value<'a>, hashbrown::DefaultHashBuilder, &'a Bump>,
    cached_hash: u64,
}

impl<'a> ArenaSet<'a> {
    /// Create an empty set in the given arena.
    pub fn empty_in(arena: &'a Bump) -> &'a ArenaSet<'a> {
        arena.alloc(ArenaSet {
            set: HashSet::new_in(arena),
            cached_hash: 0,
        })
    }

    pub fn contains(&self, v: &Value<'a>) -> bool {
        self.set.contains(v)
    }

    pub fn get(&self, v: &Value<'a>) -> Option<&Value<'a>> {
        self.set.get(v)
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    pub fn iter(&self) -> hashbrown::hash_set::Iter<'_, Value<'a>> {
        self.set.iter()
    }

    pub fn cached_hash(&self) -> u64 {
        self.cached_hash
    }

    /// Build a set from a possibly-duplicate iterator.
    pub fn from_iter_in(
        arena: &'a Bump,
        iter: impl IntoIterator<Item = Value<'a>>,
    ) -> &'a ArenaSet<'a> {
        let mut set = HashSet::new_in(arena);
        let mut combined_hash: u64 = 0;
        for v in iter {
            if set.insert(v) {
                let mut h = DefaultHasher::new();
                v.hash_content(&mut h);
                combined_hash = combined_hash.wrapping_add(h.finish());
            }
        }
        arena.alloc(ArenaSet {
            set,
            cached_hash: combined_hash,
        })
    }

    /// Sorted elements (allocates a temporary Vec).
    fn sorted_elements(&self) -> Vec<Value<'a>> {
        let mut v: Vec<_> = self.set.iter().copied().collect();
        v.sort_unstable();
        v
    }
}

// ArenaSet equality: hash + length + set containment check.
impl PartialEq for ArenaSet<'_> {
    fn eq(&self, other: &Self) -> bool {
        if self.cached_hash != other.cached_hash {
            return false;
        }
        if self.set.len() != other.set.len() {
            return false;
        }
        self.set.iter().all(|v| other.set.contains(v))
    }
}
impl Eq for ArenaSet<'_> {}

impl PartialOrd for ArenaSet<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ArenaSet<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        let a = self.sorted_elements();
        let b = other.sorted_elements();
        a.cmp(&b)
    }
}

impl Hash for ArenaSet<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.set.len().hash(state);
        self.cached_hash.hash(state);
    }
}

impl std::fmt::Debug for ArenaSet<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_set().entries(self.set.iter()).finish()
    }
}

// ---------------------------------------------------------------------------
//  Value
// ---------------------------------------------------------------------------

// ===========================================================================
//  ArenaValue — inner, lean 11-variant enum
// ===========================================================================

/// Arena-allocated Rego value (inner, lean 11-variant enum).
///
/// 16 bytes, `Copy`.  Number variants are flattened into the enum,
/// and String/Array use thin-pointer wrappers.  All heap data lives in a
/// `bumpalo::Bump` arena — cloning is a plain `memcpy`, dropping is a no-op.
///
/// This is the inner type — use [`Value`] for the public API, which wraps
/// `ArenaValue` and adds `Ext(&'a v8::Value)` for zero-copy v8 references.
#[derive(Clone, Copy)]
pub enum ArenaValue<'a> {
    Null,
    Bool(bool),
    UInt(u64),
    Int(i64),
    Float(f64),
    BigInt(&'a BigInt),
    String(&'a ArenaStr<'a>),
    Array(&'a ArenaArray<'a>),
    Set(&'a ArenaSet<'a>),
    Object(&'a ObjectMap<'a>),
    Undefined,
}

const _: () = assert!(std::mem::size_of::<ArenaValue<'static>>() == 16);

// ===========================================================================
//  Value — public wrapper: Arena(ArenaValue) | Ext(&v8::Value)
// ===========================================================================

/// Public Rego value type.
///
/// Two variants:
/// - `Arena(ArenaValue<'a>)` — arena-allocated, `Copy`, lean 11 variants.
/// - `Ext(&'a v8::Value)` — zero-copy reference to shared v8 data.
///
/// 16 bytes via niche optimization.
#[derive(Clone, Copy)]
pub enum Value<'a> {
    Arena(ArenaValue<'a>),
    Ext(&'a ExtValue),
}

const _: () = assert!(std::mem::size_of::<Value<'static>>() == 16);

// ---------------------------------------------------------------------------
//  Static UNDEFINED + helper
// ---------------------------------------------------------------------------

#[repr(transparent)]
struct SyncUndefined(Value<'static>);
// SAFETY: Value::Arena(ArenaValue::Undefined) has no data, no references,
// no interior mutability.
unsafe impl Sync for SyncUndefined {}
static UNDEFINED_WRAPPER: SyncUndefined = SyncUndefined(Value::Arena(ArenaValue::Undefined));

fn undefined_ref() -> &'static Value<'static> {
    &UNDEFINED_WRAPPER.0
}

// ===========================================================================
//  ArenaValue — Construction helpers
// ===========================================================================

impl<'a> ArenaValue<'a> {
    pub fn new_object(arena: &'a Bump) -> ArenaValue<'a> {
        ArenaValue::Object(arena.alloc(ObjectMap::new_in(arena)))
    }

    pub fn new_array(arena: &'a Bump) -> ArenaValue<'a> {
        ArenaValue::Array(arena.alloc(ArenaArray(&[])))
    }

    pub fn new_set(arena: &'a Bump) -> ArenaValue<'a> {
        ArenaValue::Set(ArenaSet::empty_in(arena))
    }

    pub fn from_u64(n: u64) -> Self {
        ArenaValue::UInt(n)
    }

    pub fn from_i64(n: i64) -> Self {
        ArenaValue::Int(n)
    }

    pub fn from_f64(f: f64) -> Self {
        ArenaValue::Float(f)
    }

    pub fn from_number(n: Number<'a>) -> Self {
        match n {
            Number::UInt(v) => ArenaValue::UInt(v),
            Number::Int(v) => ArenaValue::Int(v),
            Number::Float(v) => ArenaValue::Float(v),
            Number::BigInt(v) => ArenaValue::BigInt(v),
        }
    }

    pub fn as_number(&self) -> Option<Number<'a>> {
        match *self {
            ArenaValue::UInt(v) => Some(Number::UInt(v)),
            ArenaValue::Int(v) => Some(Number::Int(v)),
            ArenaValue::Float(v) => Some(Number::Float(v)),
            ArenaValue::BigInt(v) => Some(Number::BigInt(v)),
            _ => None,
        }
    }

    pub fn from_str(arena: &'a Bump, s: &str) -> ArenaValue<'a> {
        ArenaValue::String(arena.alloc(ArenaStr(arena.alloc_str(s))))
    }

    pub fn from_str_ref(arena: &'a Bump, s: &'a str) -> ArenaValue<'a> {
        ArenaValue::String(arena.alloc(ArenaStr(s)))
    }

    pub fn from_array(arena: &'a Bump, items: &'a [Value<'a>]) -> ArenaValue<'a> {
        ArenaValue::Array(arena.alloc(ArenaArray(items)))
    }
}

// ===========================================================================
//  ArenaValue — Type queries
// ===========================================================================

impl ArenaValue<'_> {
    pub fn is_null(&self) -> bool {
        matches!(self, ArenaValue::Null)
    }
    pub fn is_undefined(&self) -> bool {
        matches!(self, ArenaValue::Undefined)
    }
    pub fn is_bool(&self) -> bool {
        matches!(self, ArenaValue::Bool(_))
    }
    pub fn is_number(&self) -> bool {
        matches!(
            self,
            ArenaValue::UInt(_) | ArenaValue::Int(_) | ArenaValue::Float(_) | ArenaValue::BigInt(_)
        )
    }
    pub fn is_string(&self) -> bool {
        matches!(self, ArenaValue::String(_))
    }
    pub fn is_array(&self) -> bool {
        matches!(self, ArenaValue::Array(_))
    }
    pub fn is_object(&self) -> bool {
        matches!(self, ArenaValue::Object(_))
    }
    pub fn is_set(&self) -> bool {
        matches!(self, ArenaValue::Set(_))
    }
}

// ===========================================================================
//  ArenaValue — Accessors
// ===========================================================================

impl<'a> ArenaValue<'a> {
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ArenaValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.as_number().and_then(|n| n.as_u64())
    }

    pub fn as_i64(&self) -> Option<i64> {
        self.as_number().and_then(|n| n.as_i64())
    }

    pub fn as_f64(&self) -> Option<f64> {
        self.as_number().and_then(|n| n.as_f64())
    }

    pub fn as_str_ref(&self) -> Option<&'a str> {
        match self {
            ArenaValue::String(s) => Some(s.0),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&'a [Value<'a>]> {
        match self {
            ArenaValue::Array(a) => Some(a.0),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&'a ObjectMap<'a>> {
        match self {
            ArenaValue::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn as_set(&self) -> Option<&'a ArenaSet<'a>> {
        match self {
            ArenaValue::Set(s) => Some(s),
            _ => None,
        }
    }
}

// ===========================================================================
//  ArenaValue — Kind ordinal + hash
// ===========================================================================

impl ArenaValue<'_> {
    pub(crate) fn kind_ordinal(&self) -> u8 {
        match self {
            ArenaValue::Null => 0,
            ArenaValue::Bool(_) => 1,
            ArenaValue::UInt(_)
            | ArenaValue::Int(_)
            | ArenaValue::Float(_)
            | ArenaValue::BigInt(_) => 2,
            ArenaValue::String(_) => 3,
            ArenaValue::Array(_) => 4,
            ArenaValue::Object(_) => 5,
            ArenaValue::Set(_) => 6,
            ArenaValue::Undefined => 7,
        }
    }

    /// Hash the content of this arena value.
    /// NOTE: array/set/object elements are `Value<'a>` (the outer type),
    /// so recursive hashing goes through `Value::hash_content`.
    pub(crate) fn hash_content<H: Hasher>(&self, state: &mut H) {
        self.kind_ordinal().hash(state);
        match self {
            ArenaValue::Null | ArenaValue::Undefined => {}
            ArenaValue::Bool(b) => b.hash(state),
            ArenaValue::String(s) => s.0.hash(state),
            ArenaValue::Array(a) => {
                a.0.len().hash(state);
                for v in a.0.iter() {
                    v.hash_content(state);
                }
            }
            ArenaValue::Set(s) => {
                s.len().hash(state);
                s.cached_hash().hash(state);
            }
            ArenaValue::Object(o) => {
                o.len().hash(state);
                o.cached_hash().hash(state);
            }
            // All number variants
            _ => self.as_number().unwrap().hash(state),
        }
    }
}

// ===========================================================================
//  ArenaValue — Arithmetic
// ===========================================================================

impl<'a> ArenaValue<'a> {
    pub fn add_number(&self, rhs: &Self, arena: &'a Bump) -> ArenaValue<'a> {
        match (self.as_number(), rhs.as_number()) {
            (Some(a), Some(b)) => ArenaValue::from_number(a.add(&b, arena)),
            _ => ArenaValue::Undefined,
        }
    }
}

// ===========================================================================
//  ArenaValue — PartialEq / Eq  (lean 11-variant match)
// ===========================================================================

impl PartialEq for ArenaValue<'_> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ArenaValue::Null, ArenaValue::Null)
            | (ArenaValue::Undefined, ArenaValue::Undefined) => true,
            (ArenaValue::Bool(a), ArenaValue::Bool(b)) => a == b,
            (ArenaValue::String(a), ArenaValue::String(b)) => std::ptr::eq(*a, *b) || a.0 == b.0,
            (ArenaValue::Array(a), ArenaValue::Array(b)) => {
                // Array elements are Value<'a>, so == goes through Value::eq.
                std::ptr::eq(*a, *b) || a.0 == b.0
            }
            (ArenaValue::Set(a), ArenaValue::Set(b)) => std::ptr::eq(*a, *b) || *a == *b,
            (ArenaValue::Object(a), ArenaValue::Object(b)) => std::ptr::eq(*a, *b) || *a == *b,
            _ => match (self.as_number(), other.as_number()) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            },
        }
    }
}

impl Eq for ArenaValue<'_> {}

// ===========================================================================
//  ArenaValue — Ord
// ===========================================================================

impl PartialOrd for ArenaValue<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ArenaValue<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        let ka = self.kind_ordinal();
        let kb = other.kind_ordinal();
        if ka != kb {
            return ka.cmp(&kb);
        }
        match (self, other) {
            (ArenaValue::Null, ArenaValue::Null)
            | (ArenaValue::Undefined, ArenaValue::Undefined) => Ordering::Equal,
            (ArenaValue::Bool(a), ArenaValue::Bool(b)) => a.cmp(b),
            (ArenaValue::String(a), ArenaValue::String(b)) => a.0.cmp(b.0),
            (ArenaValue::Array(a), ArenaValue::Array(b)) => a.0.cmp(b.0),
            (ArenaValue::Set(a), ArenaValue::Set(b)) => a.cmp(b),
            (ArenaValue::Object(a), ArenaValue::Object(b)) => a.cmp(b),
            _ => self.as_number().unwrap().cmp(&other.as_number().unwrap()),
        }
    }
}

// ===========================================================================
//  ArenaValue — Hash
// ===========================================================================

impl Hash for ArenaValue<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash_content(state);
    }
}

// ===========================================================================
//  ArenaValue — Debug
// ===========================================================================

impl std::fmt::Debug for ArenaValue<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArenaValue::Null => write!(f, "Null"),
            ArenaValue::Bool(b) => write!(f, "Bool({b})"),
            ArenaValue::String(s) => write!(f, "String({:?})", s.0),
            ArenaValue::Array(a) => f.debug_list().entries(a.0.iter()).finish(),
            ArenaValue::Set(s) => s.fmt(f),
            ArenaValue::Object(o) => o.fmt(f),
            ArenaValue::Undefined => write!(f, "Undefined"),
            _ => {
                let n = self.as_number().unwrap();
                write!(f, "Number({n:?})")
            }
        }
    }
}

// ###########################################################################
// ###########################################################################
//  Value<'a> — public wrapper impls
// ###########################################################################
// ###########################################################################

impl<'a> From<ArenaValue<'a>> for Value<'a> {
    #[inline(always)]
    fn from(v: ArenaValue<'a>) -> Self {
        Value::Arena(v)
    }
}

// ===========================================================================
//  Value — Construction helpers (delegate to ArenaValue)
// ===========================================================================

impl<'a> Value<'a> {
    pub fn new_object(arena: &'a Bump) -> Value<'a> {
        Value::Arena(ArenaValue::new_object(arena))
    }

    pub fn new_array(arena: &'a Bump) -> Value<'a> {
        Value::Arena(ArenaValue::new_array(arena))
    }

    pub fn new_set(arena: &'a Bump) -> Value<'a> {
        Value::Arena(ArenaValue::new_set(arena))
    }

    pub fn from_u64(n: u64) -> Self {
        Value::Arena(ArenaValue::UInt(n))
    }

    pub fn from_i64(n: i64) -> Self {
        Value::Arena(ArenaValue::Int(n))
    }

    pub fn from_f64(f: f64) -> Self {
        Value::Arena(ArenaValue::Float(f))
    }

    pub fn from_number(n: Number<'a>) -> Self {
        Value::Arena(ArenaValue::from_number(n))
    }

    pub fn from_str(arena: &'a Bump, s: &str) -> Value<'a> {
        Value::Arena(ArenaValue::from_str(arena, s))
    }

    pub fn from_str_ref(arena: &'a Bump, s: &'a str) -> Value<'a> {
        Value::Arena(ArenaValue::from_str_ref(arena, s))
    }

    pub fn from_array(arena: &'a Bump, items: &'a [Value<'a>]) -> Value<'a> {
        Value::Arena(ArenaValue::from_array(arena, items))
    }

    /// Wrap a v8::Value as an Ext reference (O(1), zero copy).
    pub fn from_ref(ext: &'a ExtValue) -> Value<'a> {
        Value::Ext(ext)
    }
}

// ===========================================================================
//  Value — Accessors (dispatch Arena / Ext)
// ===========================================================================

impl<'a> Value<'a> {
    #[inline(always)]
    pub fn as_number(&self) -> Option<Number<'a>> {
        match self {
            Value::Arena(inner) => inner.as_number(),
            Value::Ext(ext) => {
                // Bridge ext Number to v9 Number.
                match ext {
                    ExtValue::UInt(v) => Some(Number::UInt(*v)),
                    ExtValue::Int(v) => Some(Number::Int(*v)),
                    ExtValue::Float(v) => Some(Number::Float(*v)),
                    _ => None,
                }
            }
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Arena(inner) => inner.as_bool(),
            Value::Ext(ExtValue::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.as_number().and_then(|n| n.as_u64())
    }

    pub fn as_i64(&self) -> Option<i64> {
        self.as_number().and_then(|n| n.as_i64())
    }

    pub fn as_f64(&self) -> Option<f64> {
        self.as_number().and_then(|n| n.as_f64())
    }

    pub fn as_str_ref(&self) -> Option<&str> {
        match self {
            Value::Arena(inner) => inner.as_str_ref(),
            Value::Ext(ExtValue::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&'a [Value<'a>]> {
        match self {
            Value::Arena(inner) => inner.as_array(),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&'a ObjectMap<'a>> {
        match self {
            Value::Arena(inner) => inner.as_object(),
            _ => None,
        }
    }

    pub fn as_set(&self) -> Option<&'a ArenaSet<'a>> {
        match self {
            Value::Arena(inner) => inner.as_set(),
            _ => None,
        }
    }
}

// ===========================================================================
//  Value — Type queries
// ===========================================================================

impl Value<'_> {
    pub fn is_null(&self) -> bool {
        match self {
            Value::Arena(inner) => inner.is_null(),
            Value::Ext(ExtValue::Null) => true,
            _ => false,
        }
    }
    pub fn is_undefined(&self) -> bool {
        match self {
            Value::Arena(inner) => inner.is_undefined(),
            Value::Ext(ExtValue::Undefined) => true,
            _ => false,
        }
    }
    pub fn is_bool(&self) -> bool {
        match self {
            Value::Arena(inner) => inner.is_bool(),
            Value::Ext(ExtValue::Bool(_)) => true,
            _ => false,
        }
    }
    pub fn is_number(&self) -> bool {
        match self {
            Value::Arena(inner) => inner.is_number(),
            Value::Ext(
                ExtValue::UInt(_) | ExtValue::Int(_) | ExtValue::Float(_) | ExtValue::BigInt(_),
            ) => true,
            _ => false,
        }
    }
    pub fn is_string(&self) -> bool {
        match self {
            Value::Arena(inner) => inner.is_string(),
            Value::Ext(ExtValue::String(_)) => true,
            _ => false,
        }
    }
    pub fn is_array(&self) -> bool {
        match self {
            Value::Arena(inner) => inner.is_array(),
            Value::Ext(ExtValue::Array(_)) => true,
            _ => false,
        }
    }
    pub fn is_object(&self) -> bool {
        match self {
            Value::Arena(inner) => inner.is_object(),
            Value::Ext(ExtValue::Object(_)) => true,
            _ => false,
        }
    }
    pub fn is_set(&self) -> bool {
        match self {
            Value::Arena(inner) => inner.is_set(),
            Value::Ext(ExtValue::Set(_)) => true,
            _ => false,
        }
    }
}

// ===========================================================================
//  Value — Key lookup
// ===========================================================================

impl<'a> Value<'a> {
    pub fn get_str(&self, key: &str) -> &Value<'a> {
        match self {
            Value::Arena(ArenaValue::Object(o)) => o.get_str(key).unwrap_or(undefined_ref()),
            _ => undefined_ref(),
        }
    }

    pub fn get_str_val(&self, key: &str) -> Value<'a> {
        match self {
            Value::Arena(ArenaValue::Object(o)) => o
                .get_str(key)
                .copied()
                .unwrap_or(Value::Arena(ArenaValue::Undefined)),
            _ => Value::Arena(ArenaValue::Undefined),
        }
    }
}

// ===========================================================================
//  Value — Kind ordinal + hash
// ===========================================================================

impl Value<'_> {
    pub(crate) fn kind_ordinal(&self) -> u8 {
        match self {
            Value::Arena(inner) => inner.kind_ordinal(),
            Value::Ext(ext) => ext_kind_ordinal(ext),
        }
    }

    pub(crate) fn hash_content<H: Hasher>(&self, state: &mut H) {
        match self {
            Value::Arena(inner) => inner.hash_content(state),
            Value::Ext(ext) => ext_hash_content(ext, state),
        }
    }
}

fn ext_kind_ordinal(v: &ExtValue) -> u8 {
    match v {
        ExtValue::Null => 0,
        ExtValue::Bool(_) => 1,
        ExtValue::UInt(_) | ExtValue::Int(_) | ExtValue::Float(_) | ExtValue::BigInt(_) => 2,
        ExtValue::String(_) => 3,
        ExtValue::Array(_) => 4,
        ExtValue::Object(_) => 5,
        ExtValue::Set(_) => 6,
        ExtValue::Undefined => 7,
    }
}

fn ext_hash_content<H: Hasher>(v: &ExtValue, state: &mut H) {
    ext_kind_ordinal(v).hash(state);
    match v {
        ExtValue::Null | ExtValue::Undefined => {}
        ExtValue::Bool(b) => b.hash(state),
        ExtValue::String(s) => s.as_str().hash(state),
        ExtValue::Array(a) => {
            a.len().hash(state);
            for item in a.iter() {
                ext_hash_content(item, state);
            }
        }
        ExtValue::Object(o) => {
            o.len().hash(state);
            o.cached_hash().hash(state);
        }
        ExtValue::Set(s) => {
            s.len().hash(state);
            let mut combined: u64 = 0;
            for item in s.iter() {
                let mut h = DefaultHasher::new();
                ext_hash_content(item, &mut h);
                combined = combined.wrapping_add(h.finish());
            }
            combined.hash(state);
        }
        _ => {
            if let Some(n) = v.as_number() {
                n.hash(state);
            }
        }
    }
}

// ===========================================================================
//  Value — Arithmetic
// ===========================================================================

impl<'a> Value<'a> {
    pub fn add_number(&self, rhs: &Self, arena: &'a Bump) -> Value<'a> {
        match (self.as_number(), rhs.as_number()) {
            (Some(a), Some(b)) => Value::from_number(a.add(&b, arena)),
            _ => Value::Arena(ArenaValue::Undefined),
        }
    }
}

// ===========================================================================
//  Value — Shallow-copy from v8::Value
// ===========================================================================

impl<'a> Value<'a> {
    /// Shallow-copy a `v8::Value` into the arena.  Scalars are copied inline.
    /// Strings borrow from the v8 `ArcStr` (which must outlive the arena).
    /// Containers are walked recursively, allocating v9 equivalents in the
    /// arena.
    pub fn from_v8(ext: &'a crate::v8::Value, arena: &'a Bump) -> Value<'a> {
        Value::Arena(match ext {
            crate::v8::Value::Null => ArenaValue::Null,
            crate::v8::Value::Bool(b) => ArenaValue::Bool(*b),
            crate::v8::Value::UInt(v) => ArenaValue::UInt(*v),
            crate::v8::Value::Int(v) => ArenaValue::Int(*v),
            crate::v8::Value::Float(v) => ArenaValue::Float(*v),
            crate::v8::Value::BigInt(arc) => ArenaValue::BigInt(arena.alloc((**arc).clone())),
            crate::v8::Value::String(s) => {
                // Borrow the ArcStr's buffer — no copy.  ArcStr outlives arena.
                ArenaValue::String(arena.alloc(ArenaStr(s.as_str())))
            }
            crate::v8::Value::Array(a) => {
                let items = arena.alloc_slice_fill_iter(a.iter().map(|v| Value::from_v8(v, arena)));
                ArenaValue::Array(arena.alloc(ArenaArray(items)))
            }
            crate::v8::Value::Set(s) => {
                return Value::Arena(ArenaValue::Set(ArenaSet::from_iter_in(
                    arena,
                    s.iter().map(|v| Value::from_v8(v, arena)),
                )));
            }
            crate::v8::Value::Object(o) => {
                let mut builder = ObjectMapBuilder::new(arena);
                for (k, v) in o.iter() {
                    builder.insert(Value::from_ext(arena, &k), Value::from_v8(v, arena));
                }
                ArenaValue::Object(builder.build())
            }
            crate::v8::Value::Undefined => ArenaValue::Undefined,
        })
    }
}

// ===========================================================================
//  Value — PartialEq / Eq  (2x2 outer dispatch)
// ===========================================================================

impl PartialEq for Value<'_> {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Arena(a), Value::Arena(b)) => a == b,
            (Value::Ext(a), Value::Ext(b)) => *a == *b,
            _ => cross_eq(self, other),
        }
    }
}

impl Eq for Value<'_> {}

// ===========================================================================
//  Value — Ord  (2-way dispatch)
// ===========================================================================

impl PartialOrd for Value<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Value<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Value::Arena(a), Value::Arena(b)) => a.cmp(b),
            (Value::Ext(a), Value::Ext(b)) => (*a).cmp(*b),
            _ => cross_cmp(self, other),
        }
    }
}

// ===========================================================================
//  Value — Hash
// ===========================================================================

impl Hash for Value<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash_content(state);
    }
}

// ===========================================================================
//  Value — Debug / Display
// ===========================================================================

impl std::fmt::Debug for Value<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Arena(inner) => inner.fmt(f),
            Value::Ext(ext) => ext.fmt(f),
        }
    }
}

impl std::fmt::Display for Value<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => write!(f, "{s}"),
            Err(_) => Err(std::fmt::Error),
        }
    }
}

// ===========================================================================
//  Value — Index
// ===========================================================================

impl<'a> std::ops::Index<&Value<'a>> for Value<'a> {
    type Output = Value<'a>;

    fn index(&self, key: &Value<'a>) -> &Self::Output {
        match self {
            Value::Arena(ArenaValue::Object(o)) => o.get(key).unwrap_or(undefined_ref()),
            Value::Arena(ArenaValue::Set(s)) => s.get(key).unwrap_or(undefined_ref()),
            Value::Arena(ArenaValue::Array(a)) => match key.as_number().and_then(|n| n.as_u64()) {
                Some(idx) if (idx as usize) < a.0.len() => &a.0[idx as usize],
                _ => undefined_ref(),
            },
            _ => undefined_ref(),
        }
    }
}

// ===========================================================================
//  Value — From impls
// ===========================================================================

impl From<bool> for Value<'_> {
    fn from(b: bool) -> Self {
        Value::Arena(ArenaValue::Bool(b))
    }
}
impl From<i64> for Value<'_> {
    fn from(n: i64) -> Self {
        Value::Arena(ArenaValue::Int(n))
    }
}
impl From<u64> for Value<'_> {
    fn from(n: u64) -> Self {
        Value::Arena(ArenaValue::UInt(n))
    }
}
impl From<i32> for Value<'_> {
    fn from(n: i32) -> Self {
        Value::Arena(ArenaValue::Int(n as i64))
    }
}
impl From<u32> for Value<'_> {
    fn from(n: u32) -> Self {
        Value::Arena(ArenaValue::UInt(n as u64))
    }
}
impl From<f64> for Value<'_> {
    fn from(n: f64) -> Self {
        Value::Arena(ArenaValue::Float(n))
    }
}

// ===========================================================================
//  Value — Conversion from/to ExtValue
// ===========================================================================

impl<'a> Value<'a> {
    /// Deep-copy from a v8::Value into the arena.
    pub fn from_ext(arena: &'a Bump, v: &ExtValue) -> Self {
        Value::Arena(match v {
            ExtValue::Null => ArenaValue::Null,
            ExtValue::Bool(b) => ArenaValue::Bool(*b),
            ExtValue::Undefined => ArenaValue::Undefined,
            ExtValue::String(s) => ArenaValue::from_str(arena, s.as_str()),
            ExtValue::UInt(u) => ArenaValue::UInt(*u),
            ExtValue::Int(i) => ArenaValue::Int(*i),
            ExtValue::Float(f) => ArenaValue::Float(*f),
            ExtValue::BigInt(b) => ArenaValue::BigInt(arena.alloc((**b).clone())),
            ExtValue::Array(a) => {
                let mut items = bumpalo::collections::Vec::with_capacity_in(a.len(), arena);
                for item in a.iter() {
                    items.push(Value::from_ext(arena, item));
                }
                ArenaValue::from_array(arena, items.into_bump_slice())
            }
            ExtValue::Set(s) => {
                return Value::Arena(ArenaValue::Set(ArenaSet::from_iter_in(
                    arena,
                    s.iter().map(|v| Value::from_ext(arena, v)),
                )));
            }
            ExtValue::Object(m) => {
                let mut builder = ObjectMapBuilder::with_capacity(arena, m.len());
                for (k, v) in m.iter() {
                    builder.insert(Value::from_ext(arena, &k), Value::from_ext(arena, v));
                }
                ArenaValue::Object(builder.build())
            }
        })
    }

    /// Materialize this v9 Value back to a v8::Value.
    pub fn to_ext(&self) -> ExtValue {
        match self {
            Value::Ext(ext) => (*ext).clone(),
            Value::Arena(inner) => match inner {
                ArenaValue::Null => ExtValue::Null,
                ArenaValue::Bool(b) => ExtValue::Bool(*b),
                ArenaValue::Undefined => ExtValue::Undefined,
                ArenaValue::String(s) => ExtValue::String(arcstr::ArcStr::from(s.0)),
                ArenaValue::UInt(u) => ExtValue::UInt(*u),
                ArenaValue::Int(i) => ExtValue::Int(*i),
                ArenaValue::Float(f) => ExtValue::Float(*f),
                ArenaValue::BigInt(b) => ExtValue::BigInt(std::sync::Arc::new((*b).clone())),
                ArenaValue::Array(a) => {
                    let items: Vec<ExtValue> = a.0.iter().map(|v| v.to_ext()).collect();
                    ExtValue::Array(std::sync::Arc::new(items))
                }
                ArenaValue::Set(s) => {
                    let items: hashbrown::HashSet<ExtValue> =
                        s.iter().map(|v| v.to_ext()).collect();
                    ExtValue::Set(std::sync::Arc::new(items))
                }
                ArenaValue::Object(o) => {
                    let mut obj = crate::v8::ObjectMap::with_capacity(o.len());
                    for (k, v) in o.iter() {
                        obj.insert(k.to_ext(), v.to_ext());
                    }
                    ExtValue::Object(std::sync::Arc::new(obj))
                }
            },
        }
    }
}

// ===========================================================================
//  Cross-type helpers  (Arena <-> Ext, cold path)
// ===========================================================================

#[cold]
fn cross_eq(a: &Value<'_>, b: &Value<'_>) -> bool {
    let (av, ev) = match (a, b) {
        (Value::Arena(inner), Value::Ext(ext)) => (inner, *ext),
        (Value::Ext(ext), Value::Arena(inner)) => (inner, *ext),
        _ => unreachable!(),
    };
    match (av, ev) {
        (ArenaValue::Null, ExtValue::Null) | (ArenaValue::Undefined, ExtValue::Undefined) => true,
        (ArenaValue::Bool(a), ExtValue::Bool(b)) => *a == *b,
        (ArenaValue::String(a), ExtValue::String(b)) => a.0 == b.as_str(),
        _ => match (av.as_number(), a.as_number()) {
            (Some(an), Some(bn)) => an == bn,
            _ => false,
        },
    }
}

#[cold]
fn cross_cmp(a: &Value<'_>, b: &Value<'_>) -> Ordering {
    let ka = a.kind_ordinal();
    let kb = b.kind_ordinal();
    if ka != kb {
        return ka.cmp(&kb);
    }
    let (av, ev, swapped) = match (a, b) {
        (Value::Arena(inner), Value::Ext(ext)) => (inner, *ext, false),
        (Value::Ext(ext), Value::Arena(inner)) => (inner, *ext, true),
        _ => unreachable!(),
    };
    let ord = match (av, ev) {
        (ArenaValue::Null, ExtValue::Null) | (ArenaValue::Undefined, ExtValue::Undefined) => {
            Ordering::Equal
        }
        (ArenaValue::Bool(a), ExtValue::Bool(b)) => a.cmp(b),
        (ArenaValue::String(a), ExtValue::String(b)) => a.0.cmp(b.as_str()),
        _ => match (av.as_number(), a.as_number()) {
            (Some(an), Some(bn)) => an.cmp(&bn),
            _ => Ordering::Equal,
        },
    };
    if swapped {
        ord.reverse()
    } else {
        ord
    }
}
