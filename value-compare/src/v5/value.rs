// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NaN-boxed Rego Value — exactly 8 bytes.
//!
//! Uses IEEE 754 NaN boxing to pack every Value variant into a single `u64`:
//!
//! - **Float**: stored as raw `f64` bits.  NaN and −0 are canonicalized.
//! - **Tagged**: top 13 bits all 1 → 3-bit sub-tag + 48-bit payload.
//!
//! | Tag (upper 16 bits) | Meaning    | Payload                           |
//! |---------------------|------------|-----------------------------------|
//! | 0xFFF8              | Immediate  | 0=Null, 1=False, 2=True, 3=Undef |
//! | 0xFFFA              | HeapNumber | `Arc<HeapNumber>` raw ptr         |
//! | 0xFFFC              | String     | `ArcStr` thin ptr                 |
//! | 0xFFFD              | Array      | `Arc<Vec<Value>>` raw ptr         |
//! | 0xFFFE              | Object     | `Arc<ObjectMap>` raw ptr          |
//! | 0xFFFF              | Set        | `Arc<HashSet<Value>>` raw ptr     |

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::mem::ManuallyDrop;
use std::sync::Arc;

use arcstr::ArcStr;
use hashbrown::HashSet;
use num_bigint::BigInt;

use super::object_map::ObjectMap;

// ─── Tag constants ───────────────────────────────────────────────────────────

/// Minimum value in our tagged space (quiet NaN with sign bit set).
const QNAN: u64 = 0xFFF8_0000_0000_0000;
const TAG_MASK: u64 = 0xFFFF_0000_0000_0000;
const PAYLOAD_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

const TAG_IMMEDIATE: u64 = 0xFFF8_0000_0000_0000;
const TAG_HEAP_NUM: u64 = 0xFFFA_0000_0000_0000;
const TAG_STRING: u64 = 0xFFFC_0000_0000_0000;
const TAG_ARRAY: u64 = 0xFFFD_0000_0000_0000;
const TAG_OBJECT: u64 = 0xFFFE_0000_0000_0000;
const TAG_SET: u64 = 0xFFFF_0000_0000_0000;

const IMM_NULL: u64 = 0;
const IMM_FALSE: u64 = 1;
const IMM_TRUE: u64 = 2;
const IMM_UNDEFINED: u64 = 3;

/// Canonical quiet NaN (sign = 0 → outside our tagged space).
const CANONICAL_NAN: u64 = 0x7FF8_0000_0000_0000;

// ─── HeapNumber ──────────────────────────────────────────────────────────────

/// Heap-allocated number for integers that cannot be exactly represented as f64.
#[derive(Clone)]
#[allow(dead_code)]
pub(crate) enum HeapNumber {
    Int(i64),
    UInt(u64),
    BigInt(Arc<BigInt>),
}

impl PartialEq for HeapNumber {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (HeapNumber::Int(a), HeapNumber::Int(b)) => a == b,
            (HeapNumber::UInt(a), HeapNumber::UInt(b)) => a == b,
            (HeapNumber::Int(a), HeapNumber::UInt(b)) => *a >= 0 && *a as u64 == *b,
            (HeapNumber::UInt(a), HeapNumber::Int(b)) => *b >= 0 && *b as u64 == *a,
            (HeapNumber::BigInt(a), HeapNumber::BigInt(b)) => a == b,
            (HeapNumber::Int(a), HeapNumber::BigInt(b)) => **b == BigInt::from(*a),
            (HeapNumber::BigInt(a), HeapNumber::Int(b)) => **a == BigInt::from(*b),
            (HeapNumber::UInt(a), HeapNumber::BigInt(b)) => **b == BigInt::from(*a),
            (HeapNumber::BigInt(a), HeapNumber::UInt(b)) => **a == BigInt::from(*b),
        }
    }
}

impl Eq for HeapNumber {}

impl Ord for HeapNumber {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (HeapNumber::Int(a), HeapNumber::Int(b)) => a.cmp(b),
            (HeapNumber::UInt(a), HeapNumber::UInt(b)) => a.cmp(b),
            (HeapNumber::Int(a), HeapNumber::UInt(b)) => {
                if *a < 0 {
                    Ordering::Less
                } else {
                    (*a as u64).cmp(b)
                }
            }
            (HeapNumber::UInt(a), HeapNumber::Int(b)) => {
                if *b < 0 {
                    Ordering::Greater
                } else {
                    a.cmp(&(*b as u64))
                }
            }
            (HeapNumber::BigInt(a), HeapNumber::BigInt(b)) => a.cmp(b),
            (HeapNumber::Int(a), HeapNumber::BigInt(b)) => BigInt::from(*a).cmp(b),
            (HeapNumber::BigInt(a), HeapNumber::Int(b)) => (**a).cmp(&BigInt::from(*b)),
            (HeapNumber::UInt(a), HeapNumber::BigInt(b)) => BigInt::from(*a).cmp(b),
            (HeapNumber::BigInt(a), HeapNumber::UInt(b)) => (**a).cmp(&BigInt::from(*b)),
        }
    }
}

impl PartialOrd for HeapNumber {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for HeapNumber {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            HeapNumber::UInt(u) => {
                0u8.hash(state);
                u.hash(state);
            }
            HeapNumber::Int(i) if *i >= 0 => {
                0u8.hash(state);
                (*i as u64).hash(state);
            }
            HeapNumber::Int(i) => {
                1u8.hash(state);
                i.hash(state);
            }
            HeapNumber::BigInt(b) => {
                use num_traits::ToPrimitive;
                if let Some(u) = b.to_u64() {
                    0u8.hash(state);
                    u.hash(state);
                } else if let Some(i) = b.to_i64() {
                    if i >= 0 {
                        0u8.hash(state);
                        (i as u64).hash(state);
                    } else {
                        1u8.hash(state);
                        i.hash(state);
                    }
                } else {
                    2u8.hash(state);
                    let (sign, bytes) = b.to_bytes_be();
                    sign.hash(state);
                    bytes.hash(state);
                }
            }
        }
    }
}

impl HeapNumber {
    fn to_f64_lossy(&self) -> f64 {
        match self {
            HeapNumber::Int(i) => *i as f64,
            HeapNumber::UInt(u) => *u as f64,
            HeapNumber::BigInt(b) => {
                use num_traits::ToPrimitive;
                b.to_f64().unwrap_or(if b.sign() == num_bigint::Sign::Minus {
                    f64::NEG_INFINITY
                } else {
                    f64::INFINITY
                })
            }
        }
    }

    fn format_decimal(&self) -> String {
        match self {
            HeapNumber::Int(i) => i.to_string(),
            HeapNumber::UInt(u) => u.to_string(),
            HeapNumber::BigInt(b) => b.to_string(),
        }
    }
}

// ─── Value ───────────────────────────────────────────────────────────────────

/// A NaN-boxed Rego value in exactly 8 bytes.
///
/// Every variant (Null, Bool, Number, String, Array, Set, Object, Undefined)
/// is encoded in a single `u64` using IEEE 754 NaN boxing.
pub struct Value {
    bits: u64,
}

const _: () = assert!(std::mem::size_of::<Value>() == 8);
const _: () = assert!(std::mem::size_of::<ArcStr>() == 8);

// ─── Classification helpers ──────────────────────────────────────────────────

impl Value {
    /// Is this a tagged (non-float) value?
    #[inline(always)]
    fn is_tagged(&self) -> bool {
        self.bits >= QNAN
    }

    /// Extract the tag (upper 16 bits). Only meaningful when `is_tagged()`.
    #[inline(always)]
    fn tag(&self) -> u64 {
        self.bits & TAG_MASK
    }

    /// Extract the payload (lower 48 bits). Only meaningful when `is_tagged()`.
    #[inline(always)]
    fn payload(&self) -> u64 {
        self.bits & PAYLOAD_MASK
    }

    /// Get a raw const pointer from the payload bits.
    #[inline(always)]
    unsafe fn ptr<T>(&self) -> *const T {
        self.payload() as *const T
    }
}

// ─── Constructors ────────────────────────────────────────────────────────────

impl Value {
    pub const fn null() -> Self {
        Value {
            bits: TAG_IMMEDIATE | IMM_NULL,
        }
    }

    pub const fn undefined() -> Self {
        Value {
            bits: TAG_IMMEDIATE | IMM_UNDEFINED,
        }
    }

    pub const fn bool_val(b: bool) -> Self {
        Value {
            bits: TAG_IMMEDIATE | if b { IMM_TRUE } else { IMM_FALSE },
        }
    }

    /// Store an f64. Canonicalizes NaN and -0.0.
    #[inline]
    pub fn from_f64(f: f64) -> Self {
        if f.is_nan() {
            return Value {
                bits: CANONICAL_NAN,
            };
        }
        let bits = f.to_bits();
        // Canonicalize -0.0 to +0.0
        if bits == 0x8000_0000_0000_0000 {
            return Value { bits: 0 };
        }
        debug_assert!(
            bits < QNAN,
            "non-NaN float bits collide with tagged space: {bits:#018X}"
        );
        Value { bits }
    }

    /// Store a heap number (large integer) behind an `Arc`.
    pub(crate) fn from_heap_number(n: HeapNumber) -> Self {
        let arc = Arc::new(n);
        let raw = Arc::into_raw(arc) as u64;
        debug_assert!(raw & !PAYLOAD_MASK == 0, "pointer exceeds 48 bits");
        Value {
            bits: TAG_HEAP_NUM | raw,
        }
    }

    /// Store an `ArcStr` string.
    pub fn from_arcstr(s: ArcStr) -> Self {
        // SAFETY: ArcStr is a thin pointer (8 bytes = u64). We store its
        // representation in the payload. Heap pointers on x86_64/ARM64 use
        // at most 48 bits.
        let raw: u64 = unsafe { std::mem::transmute(s) };
        debug_assert!(raw & !PAYLOAD_MASK == 0, "ArcStr pointer exceeds 48 bits");
        Value {
            bits: TAG_STRING | raw,
        }
    }

    pub fn from_array(a: Vec<Value>) -> Self {
        let arc = Arc::new(a);
        let raw = Arc::into_raw(arc) as u64;
        debug_assert!(raw & !PAYLOAD_MASK == 0, "pointer exceeds 48 bits");
        Value {
            bits: TAG_ARRAY | raw,
        }
    }

    pub fn from_object(o: ObjectMap) -> Self {
        let arc = Arc::new(o);
        let raw = Arc::into_raw(arc) as u64;
        debug_assert!(raw & !PAYLOAD_MASK == 0, "pointer exceeds 48 bits");
        Value {
            bits: TAG_OBJECT | raw,
        }
    }

    pub fn from_set(s: HashSet<Value>) -> Self {
        let arc = Arc::new(s);
        let raw = Arc::into_raw(arc) as u64;
        debug_assert!(raw & !PAYLOAD_MASK == 0, "pointer exceeds 48 bits");
        Value {
            bits: TAG_SET | raw,
        }
    }
}

// ─── Accessors ───────────────────────────────────────────────────────────────

static UNDEFINED_STATIC: Value = Value {
    bits: TAG_IMMEDIATE | IMM_UNDEFINED,
};

impl Value {
    pub fn is_null(&self) -> bool {
        self.bits == TAG_IMMEDIATE | IMM_NULL
    }
    pub fn is_undefined(&self) -> bool {
        self.bits == TAG_IMMEDIATE | IMM_UNDEFINED
    }
    pub fn is_bool(&self) -> bool {
        self.bits == (TAG_IMMEDIATE | IMM_TRUE) || self.bits == (TAG_IMMEDIATE | IMM_FALSE)
    }
    pub fn is_number(&self) -> bool {
        !self.is_tagged() || self.tag() == TAG_HEAP_NUM
    }
    pub fn is_string(&self) -> bool {
        self.is_tagged() && self.tag() == TAG_STRING
    }
    pub fn is_array(&self) -> bool {
        self.is_tagged() && self.tag() == TAG_ARRAY
    }
    pub fn is_object(&self) -> bool {
        self.is_tagged() && self.tag() == TAG_OBJECT
    }
    pub fn is_set(&self) -> bool {
        self.is_tagged() && self.tag() == TAG_SET
    }

    pub fn as_bool(&self) -> Option<bool> {
        if self.bits == TAG_IMMEDIATE | IMM_TRUE {
            Some(true)
        } else if self.bits == TAG_IMMEDIATE | IMM_FALSE {
            Some(false)
        } else {
            None
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        if !self.is_tagged() {
            Some(f64::from_bits(self.bits))
        } else if self.tag() == TAG_HEAP_NUM {
            Some(self.heap_number().to_f64_lossy())
        } else {
            None
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        if !self.is_tagged() {
            let f = f64::from_bits(self.bits);
            if f.is_finite() && f >= 0.0 && f.fract() == 0.0 && f <= u64::MAX as f64 {
                let c = f as u64;
                if (c as f64) == f {
                    return Some(c);
                }
            }
            None
        } else if self.tag() == TAG_HEAP_NUM {
            match self.heap_number() {
                HeapNumber::UInt(u) => Some(*u),
                HeapNumber::Int(i) if *i >= 0 => Some(*i as u64),
                HeapNumber::BigInt(b) => num_traits::ToPrimitive::to_u64(b.as_ref()),
                _ => None,
            }
        } else {
            None
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        if !self.is_tagged() {
            let f = f64::from_bits(self.bits);
            if f.is_finite() && f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 {
                let c = f as i64;
                if (c as f64) == f {
                    return Some(c);
                }
            }
            None
        } else if self.tag() == TAG_HEAP_NUM {
            match self.heap_number() {
                HeapNumber::Int(i) => Some(*i),
                HeapNumber::UInt(u) if *u <= i64::MAX as u64 => Some(*u as i64),
                HeapNumber::BigInt(b) => num_traits::ToPrimitive::to_i64(b.as_ref()),
                _ => None,
            }
        } else {
            None
        }
    }

    /// Borrow the string content. Valid for the lifetime of `&self`.
    pub fn as_str_ref(&self) -> Option<&str> {
        if !self.is_string() {
            return None;
        }
        unsafe {
            let ptr_bits = self.payload();
            let arc = ManuallyDrop::new(std::mem::transmute::<u64, ArcStr>(ptr_bits));
            // The str data lives on the heap and is valid while our refcount > 0.
            Some(&*(arc.as_str() as *const str))
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Value>> {
        if self.is_array() {
            Some(unsafe { &*self.ptr::<Vec<Value>>() })
        } else {
            None
        }
    }

    pub fn as_object(&self) -> Option<&ObjectMap> {
        if self.is_object() {
            Some(unsafe { &*self.ptr::<ObjectMap>() })
        } else {
            None
        }
    }

    pub fn as_set(&self) -> Option<&HashSet<Value>> {
        if self.is_set() {
            Some(unsafe { &*self.ptr::<HashSet<Value>>() })
        } else {
            None
        }
    }

    fn heap_number(&self) -> &HeapNumber {
        debug_assert!(self.tag() == TAG_HEAP_NUM);
        unsafe { &*self.ptr::<HeapNumber>() }
    }
}

// ─── Arithmetic ──────────────────────────────────────────────────────────────

impl Value {
    /// Add two numeric Values, preserving exact integer semantics.
    ///
    /// If either operand is a non-integer float, the result is float.
    /// For integer-valued operands: extracts the exact integer, performs
    /// checked u64/i64 arithmetic, and re-encodes (to f64 if ≤ 2⁵³, else HeapNumber).
    #[inline]
    pub fn add_number(&self, rhs: &Self) -> Value {
        // Fast path: both inline f64.
        if !self.is_tagged() && !rhs.is_tagged() {
            let a = f64::from_bits(self.bits);
            let b = f64::from_bits(rhs.bits);

            // If both are integer-valued, do exact integer arithmetic.
            if a.fract() == 0.0 && b.fract() == 0.0 && a.is_finite() && b.is_finite() {
                // Both fit in u64 range (common case: non-negative indices).
                if a >= 0.0 && b >= 0.0 {
                    let ai = a as u64;
                    let bi = b as u64;
                    return match ai.checked_add(bi) {
                        Some(sum) => Value::from(sum),
                        None => Value::from_heap_number(HeapNumber::BigInt(
                            Arc::new(BigInt::from(ai) + BigInt::from(bi)),
                        )),
                    };
                }
                // Signed path.
                let ai = a as i64;
                let bi = b as i64;
                if (ai as f64) == a && (bi as f64) == b {
                    return match ai.checked_add(bi) {
                        Some(sum) => Value::from(sum),
                        None => Value::from_heap_number(HeapNumber::BigInt(
                            Arc::new(BigInt::from(ai) + BigInt::from(bi)),
                        )),
                    };
                }
            }
            // Float addition.
            return Value::from_f64(a + b);
        }

        // HeapNumber path — at least one operand > 2⁵³.
        let a_big = self.to_bigint_for_arith();
        let b_big = rhs.to_bigint_for_arith();
        match (a_big, b_big) {
            (Some(a), Some(b)) => {
                let sum = a + b;
                // Try to fit back into u64/i64.
                use num_traits::ToPrimitive;
                if let Some(u) = sum.to_u64() {
                    Value::from(u)
                } else if let Some(i) = sum.to_i64() {
                    Value::from(i)
                } else {
                    Value::from_heap_number(HeapNumber::BigInt(Arc::new(sum)))
                }
            }
            // Fallback: float addition.
            _ => {
                let a = self.as_f64().unwrap_or(0.0);
                let b = rhs.as_f64().unwrap_or(0.0);
                Value::from_f64(a + b)
            }
        }
    }

    /// Extract a BigInt for arithmetic purposes.
    fn to_bigint_for_arith(&self) -> Option<BigInt> {
        if !self.is_tagged() {
            let f = f64::from_bits(self.bits);
            if f.fract() == 0.0 && f.is_finite() {
                if f >= 0.0 {
                    return Some(BigInt::from(f as u64));
                } else {
                    return Some(BigInt::from(f as i64));
                }
            }
            None
        } else if self.tag() == TAG_HEAP_NUM {
            match self.heap_number() {
                HeapNumber::UInt(u) => Some(BigInt::from(*u)),
                HeapNumber::Int(i) => Some(BigInt::from(*i)),
                HeapNumber::BigInt(b) => Some((**b).clone()),
            }
        } else {
            None
        }
    }
}

// ─── Public high-level API ───────────────────────────────────────────────────

impl Value {
    pub fn new_object() -> Value {
        Value::from_object(ObjectMap::new())
    }

    pub fn new_array() -> Value {
        Value::from_array(Vec::new())
    }

    pub fn new_set() -> Value {
        Value::from_set(HashSet::new())
    }

    /// Lookup by string key — zero allocation for string-keyed objects.
    pub fn get_str(&self, key: &str) -> &Value {
        if self.is_object() {
            let obj = unsafe { &*self.ptr::<ObjectMap>() };
            match obj.get_str(key) {
                Some(v) => v,
                None => &UNDEFINED_STATIC,
            }
        } else {
            &UNDEFINED_STATIC
        }
    }

    /// Returns a u8 ordinal for Rego's type ordering:
    ///   null < bool < number < string < array < object < set
    pub(crate) fn kind_ordinal(&self) -> u8 {
        if !self.is_tagged() {
            return 2; // number (float)
        }
        match self.tag() {
            TAG_IMMEDIATE => match self.payload() {
                IMM_NULL => 0,
                IMM_FALSE | IMM_TRUE => 1,
                IMM_UNDEFINED => 7,
                _ => unreachable!(),
            },
            TAG_HEAP_NUM => 2,
            TAG_STRING => 3,
            TAG_ARRAY => 4,
            TAG_OBJECT => 5,
            TAG_SET => 6,
            _ => unreachable!(),
        }
    }

    /// Hash the *content* of this value (for ObjectMap entry hashing).
    pub(crate) fn hash_content<H: Hasher>(&self, state: &mut H) {
        self.kind_ordinal().hash(state);
        self.hash_inner(state);
    }

    fn hash_inner<H: Hasher>(&self, state: &mut H) {
        if !self.is_tagged() {
            // Inline f64 — hash the canonicalized bits.
            self.bits.hash(state);
            return;
        }
        match self.tag() {
            TAG_IMMEDIATE => {
                self.payload().hash(state);
            }
            TAG_HEAP_NUM => {
                self.heap_number().hash(state);
            }
            TAG_STRING => {
                let s = self.as_str_ref().unwrap();
                s.hash(state);
            }
            TAG_ARRAY => {
                let a = unsafe { &*self.ptr::<Vec<Value>>() };
                a.len().hash(state);
                for v in a.iter() {
                    v.hash_content(state);
                }
            }
            TAG_SET => {
                let s = unsafe { &*self.ptr::<HashSet<Value>>() };
                s.len().hash(state);
                Self::set_hash(s).hash(state);
            }
            TAG_OBJECT => {
                let o = unsafe { &*self.ptr::<ObjectMap>() };
                o.hash(state);
            }
            _ => {}
        }
    }

    fn set_hash(s: &HashSet<Value>) -> u64 {
        let mut combined: u64 = 0;
        for v in s.iter() {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            v.hash_content(&mut h);
            combined = combined.wrapping_add(h.finish());
        }
        combined
    }

    /// Format the number for serialization / display.
    pub(crate) fn format_number(&self) -> String {
        if !self.is_tagged() {
            let f = f64::from_bits(self.bits);
            if f.fract() == 0.0 && f.is_finite() {
                // Integer-valued float — format without decimal point.
                if f >= 0.0 {
                    if let Some(u) = self.as_u64() {
                        return u.to_string();
                    }
                } else if let Some(i) = self.as_i64() {
                    return i.to_string();
                }
            }
            f.to_string()
        } else {
            self.heap_number().format_decimal()
        }
    }
}

// ─── From impls ──────────────────────────────────────────────────────────────

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::bool_val(b)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::from_arcstr(ArcStr::from(s))
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::from_arcstr(ArcStr::from(s.as_str()))
    }
}

impl From<ArcStr> for Value {
    fn from(s: ArcStr) -> Self {
        Value::from_arcstr(s)
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Self {
        // Store as f64 if losslessly representable.
        if (n as f64 as i64) == n {
            Value::from_f64(n as f64)
        } else {
            Value::from_heap_number(HeapNumber::Int(n))
        }
    }
}

impl From<u64> for Value {
    fn from(n: u64) -> Self {
        if (n as f64 as u64) == n {
            Value::from_f64(n as f64)
        } else {
            Value::from_heap_number(HeapNumber::UInt(n))
        }
    }
}

impl From<i32> for Value {
    fn from(n: i32) -> Self {
        Value::from(n as i64)
    }
}

impl From<u32> for Value {
    fn from(n: u32) -> Self {
        Value::from(n as u64)
    }
}

impl From<f64> for Value {
    fn from(n: f64) -> Self {
        Value::from_f64(n)
    }
}

impl From<Vec<Value>> for Value {
    fn from(a: Vec<Value>) -> Self {
        Value::from_array(a)
    }
}

impl From<HashSet<Value>> for Value {
    fn from(s: HashSet<Value>) -> Self {
        Value::from_set(s)
    }
}

impl From<BTreeSet<Value>> for Value {
    fn from(s: BTreeSet<Value>) -> Self {
        let hs: HashSet<Value> = s.into_iter().collect();
        Value::from_set(hs)
    }
}

impl From<BTreeMap<Value, Value>> for Value {
    fn from(m: BTreeMap<Value, Value>) -> Self {
        Value::from_object(ObjectMap::from_pairs(m))
    }
}

impl From<ObjectMap> for Value {
    fn from(m: ObjectMap) -> Self {
        Value::from_object(m)
    }
}

// ─── Clone ───────────────────────────────────────────────────────────────────

impl Clone for Value {
    fn clone(&self) -> Self {
        if self.is_tagged() {
            match self.tag() {
                TAG_STRING => unsafe {
                    // Increment ArcStr refcount.
                    let ptr_bits = self.payload();
                    let borrowed =
                        ManuallyDrop::new(std::mem::transmute::<u64, ArcStr>(ptr_bits));
                    let _ = ManuallyDrop::new(ArcStr::clone(&borrowed));
                }
                TAG_ARRAY => unsafe {
                    Arc::increment_strong_count(self.ptr::<Vec<Value>>());
                }
                TAG_OBJECT => unsafe {
                    Arc::increment_strong_count(self.ptr::<ObjectMap>());
                }
                TAG_SET => unsafe {
                    Arc::increment_strong_count(self.ptr::<HashSet<Value>>());
                }
                TAG_HEAP_NUM => unsafe {
                    Arc::increment_strong_count(self.ptr::<HeapNumber>());
                }
                _ => {} // immediates — no refcount
            }
        }
        Value { bits: self.bits }
    }
}

// ─── Drop ────────────────────────────────────────────────────────────────────

impl Drop for Value {
    fn drop(&mut self) {
        if self.is_tagged() {
            match self.tag() {
                TAG_STRING => unsafe {
                    // Reconstruct ArcStr from payload and let it drop (decrements refcount).
                    let ptr_bits = self.payload();
                    let _: ArcStr = std::mem::transmute::<u64, ArcStr>(ptr_bits);
                }
                TAG_ARRAY => unsafe {
                    Arc::decrement_strong_count(self.ptr::<Vec<Value>>());
                }
                TAG_OBJECT => unsafe {
                    Arc::decrement_strong_count(self.ptr::<ObjectMap>());
                }
                TAG_SET => unsafe {
                    Arc::decrement_strong_count(self.ptr::<HashSet<Value>>());
                }
                TAG_HEAP_NUM => unsafe {
                    Arc::decrement_strong_count(self.ptr::<HeapNumber>());
                }
                _ => {} // immediates — no-op
            }
        }
    }
}

// ─── PartialEq / Eq ─────────────────────────────────────────────────────────

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        // Fast path: identical bits (covers immediates, canonicalized floats, pointer identity).
        if self.bits == other.bits {
            return true;
        }

        let a_tagged = self.is_tagged();
        let b_tagged = other.is_tagged();

        // Both inline f64 with different bits → unequal (NaN and -0 are canonicalized).
        if !a_tagged && !b_tagged {
            return false;
        }

        // A float can never equal a HeapNumber in our representation because
        // integers ≤ 2^53 go to f64 and HeapNumber only stores those > 2^53.
        if !a_tagged || !b_tagged {
            return false;
        }

        // Both tagged — different tags → different types → unequal.
        if self.tag() != other.tag() {
            return false;
        }

        // Same tag, different bits → deep comparison for heap types.
        match self.tag() {
            TAG_IMMEDIATE => false,
            TAG_HEAP_NUM => self.heap_number() == other.heap_number(),
            TAG_STRING => self.as_str_ref().unwrap() == other.as_str_ref().unwrap(),
            TAG_ARRAY => {
                let a = unsafe { &*self.ptr::<Vec<Value>>() };
                let b = unsafe { &*other.ptr::<Vec<Value>>() };
                a == b
            }
            TAG_OBJECT => {
                let a = unsafe { &*self.ptr::<ObjectMap>() };
                let b = unsafe { &*other.ptr::<ObjectMap>() };
                a == b
            }
            TAG_SET => {
                let a = unsafe { &*self.ptr::<HashSet<Value>>() };
                let b = unsafe { &*other.ptr::<HashSet<Value>>() };
                if a.len() != b.len() {
                    return false;
                }
                a.iter().all(|v| b.contains(v))
            }
            _ => false,
        }
    }
}

impl Eq for Value {}

// ─── Ord ─────────────────────────────────────────────────────────────────────

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Value {
    fn cmp(&self, other: &Self) -> Ordering {
        let ka = self.kind_ordinal();
        let kb = other.kind_ordinal();
        if ka != kb {
            return ka.cmp(&kb);
        }

        // Same kind — compare within type.
        match ka {
            0 | 7 => Ordering::Equal, // Null / Undefined
            1 => {
                // Bool
                let a = self.as_bool().unwrap();
                let b = other.as_bool().unwrap();
                a.cmp(&b)
            }
            2 => self.cmp_numbers(other), // Number
            3 => {
                // String
                let a = self.as_str_ref().unwrap();
                let b = other.as_str_ref().unwrap();
                a.cmp(b)
            }
            4 => {
                // Array
                let a = unsafe { &*self.ptr::<Vec<Value>>() };
                let b = unsafe { &*other.ptr::<Vec<Value>>() };
                a.cmp(b)
            }
            5 => {
                // Object
                let a = unsafe { &*self.ptr::<ObjectMap>() };
                let b = unsafe { &*other.ptr::<ObjectMap>() };
                a.cmp(b)
            }
            6 => {
                // Set
                let a = unsafe { &*self.ptr::<HashSet<Value>>() };
                let b = unsafe { &*other.ptr::<HashSet<Value>>() };
                let mut a_sorted: Vec<&Value> = a.iter().collect();
                let mut b_sorted: Vec<&Value> = b.iter().collect();
                a_sorted.sort();
                b_sorted.sort();
                a_sorted.cmp(&b_sorted)
            }
            _ => Ordering::Equal,
        }
    }
}

impl Value {
    fn cmp_numbers(&self, other: &Self) -> Ordering {
        let a_float = !self.is_tagged();
        let b_float = !other.is_tagged();

        if a_float && b_float {
            let a = f64::from_bits(self.bits);
            let b = f64::from_bits(other.bits);
            return a.partial_cmp(&b).unwrap_or(Ordering::Equal);
        }

        if !a_float && !b_float {
            // Both HeapNumber.
            return self.heap_number().cmp(other.heap_number());
        }

        // Cross: one inline f64, one HeapNumber — use lossy f64.
        let a_f = if a_float {
            f64::from_bits(self.bits)
        } else {
            self.heap_number().to_f64_lossy()
        };
        let b_f = if b_float {
            f64::from_bits(other.bits)
        } else {
            other.heap_number().to_f64_lossy()
        };
        a_f.partial_cmp(&b_f).unwrap_or(Ordering::Equal)
    }
}

// ─── Hash ────────────────────────────────────────────────────────────────────

impl Hash for Value {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.kind_ordinal().hash(state);
        self.hash_inner(state);
    }
}

// ─── Debug ───────────────────────────────────────────────────────────────────

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.is_tagged() {
            let float = f64::from_bits(self.bits);
            write!(f, "{float}")
        } else {
            match self.tag() {
                TAG_IMMEDIATE => match self.payload() {
                    IMM_NULL => write!(f, "Null"),
                    IMM_FALSE => write!(f, "Bool(false)"),
                    IMM_TRUE => write!(f, "Bool(true)"),
                    IMM_UNDEFINED => write!(f, "Undefined"),
                    _ => unreachable!(),
                },
                TAG_HEAP_NUM => write!(f, "{}", self.heap_number().format_decimal()),
                TAG_STRING => write!(f, "String({:?})", self.as_str_ref().unwrap()),
                TAG_ARRAY => {
                    let a = unsafe { &*self.ptr::<Vec<Value>>() };
                    write!(f, "Array({a:?})")
                }
                TAG_OBJECT => {
                    let o = unsafe { &*self.ptr::<ObjectMap>() };
                    write!(f, "Object({o:?})")
                }
                TAG_SET => {
                    let s = unsafe { &*self.ptr::<HashSet<Value>>() };
                    write!(f, "Set({s:?})")
                }
                _ => write!(f, "Unknown({:#x})", self.bits),
            }
        }
    }
}

// ─── Display ─────────────────────────────────────────────────────────────────

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => write!(f, "{s}"),
            Err(_) => Err(fmt::Error),
        }
    }
}

// ─── Index impls ─────────────────────────────────────────────────────────────

impl std::ops::Index<&Value> for Value {
    type Output = Value;

    fn index(&self, key: &Value) -> &Self::Output {
        if self.is_object() {
            let o = unsafe { &*self.ptr::<ObjectMap>() };
            return o.get(key).unwrap_or(&UNDEFINED_STATIC);
        }
        if self.is_set() {
            let s = unsafe { &*self.ptr::<HashSet<Value>>() };
            if let Some(v) = s.get(key) {
                return v;
            }
            return &UNDEFINED_STATIC;
        }
        if self.is_array() {
            let a = unsafe { &*self.ptr::<Vec<Value>>() };
            if let Some(idx) = key.as_u64() {
                if (idx as usize) < a.len() {
                    return &a[idx as usize];
                }
            }
            return &UNDEFINED_STATIC;
        }
        &UNDEFINED_STATIC
    }
}

impl<T> std::ops::Index<T> for Value
where
    Value: From<T>,
{
    type Output = Value;

    fn index(&self, key: T) -> &Self::Output {
        &self[&Value::from(key)]
    }
}

// ─── Conversion from regorus::Value ──────────────────────────────────────────

impl Value {
    /// Convert from regorus::Value (baseline) to v5::Value.
    pub fn from_regorus(v: &regorus::Value) -> Self {
        match v {
            regorus::Value::Null => Value::null(),
            regorus::Value::Bool(b) => Value::bool_val(*b),
            regorus::Value::String(s) => Value::from_arcstr(ArcStr::from(s.as_ref())),
            regorus::Value::Number(_) => {
                let json_str = v.to_json_str().unwrap_or_default();
                let parsed: Value = serde_json::from_str(&json_str).unwrap_or(Value::null());
                parsed
            }
            regorus::Value::Array(a) => {
                let items: Vec<Value> = a.iter().map(Value::from_regorus).collect();
                Value::from(items)
            }
            regorus::Value::Set(s) => {
                let items: HashSet<Value> = s.iter().map(Value::from_regorus).collect();
                Value::from(items)
            }
            regorus::Value::Object(m) => {
                let obj = ObjectMap::from_regorus_btree(m);
                Value::from_object(obj)
            }
            regorus::Value::Undefined => Value::undefined(),
        }
    }
}
