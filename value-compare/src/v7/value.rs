// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! v7 Value — same portable tagged-pointer encoding as v6, paired with
//! schema-shared compact objects.
//!
//! This file is identical to v6/value.rs except it imports from the v7 module
//! (using v7's ObjectMap which supports schema-shared compact objects).

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use arcstr::ArcStr;
use hashbrown::HashSet;
use num_bigint::BigInt;

use super::object_map::ObjectMap;

// ─── Tag constants (identical to v6) ─────────────────────────────────────────

const TAG_BITS: u32 = 3;
const TAG_MASK: usize = 0b111;
const PAYLOAD_SHIFT: u32 = TAG_BITS;

const TAG_PTR: usize = 0b000;
const TAG_UINT: usize = 0b001;
const TAG_NEG_INT: usize = 0b010;
const TAG_IMMEDIATE: usize = 0b011;

const IMM_NULL: usize = 0;
const IMM_FALSE: usize = 1;
const IMM_TRUE: usize = 2;
const IMM_UNDEFINED: usize = 3;

const MAX_INLINE_UINT: u64 = (1u64 << 61) - 1;
const MAX_INLINE_NEG_MAG: u64 = 1u64 << 61;

// ─── HeapValue ───────────────────────────────────────────────────────────────

#[derive(Clone)]
pub(crate) enum HeapValue {
    Float(f64),
    BigInt(Arc<BigInt>),
    LargeUInt(u64),
    LargeInt(i64),
    String(ArcStr),
    Array(Vec<Value>),
    Object(ObjectMap),
    Set(HashSet<Value>),
}

// ─── Value ───────────────────────────────────────────────────────────────────

pub struct Value {
    bits: usize,
}

const _: () = assert!(std::mem::size_of::<Value>() == std::mem::size_of::<usize>());
#[cfg(target_pointer_width = "64")]
const _: () = assert!(std::mem::size_of::<Value>() == 8);

// ─── Classification helpers ──────────────────────────────────────────────────

impl Value {
    #[inline(always)]
    fn tag(&self) -> usize {
        self.bits & TAG_MASK
    }

    #[inline(always)]
    fn is_ptr(&self) -> bool {
        self.tag() == TAG_PTR && self.bits != 0
    }

    #[inline(always)]
    fn payload(&self) -> usize {
        self.bits >> PAYLOAD_SHIFT
    }

    #[inline]
    fn heap(&self) -> &HeapValue {
        debug_assert!(self.is_ptr());
        let ptr = (self.bits & !TAG_MASK) as *const HeapValue;
        unsafe { &*ptr }
    }

    #[inline]
    #[allow(dead_code)]
    unsafe fn take_arc(&self) -> Arc<HeapValue> {
        debug_assert!(self.is_ptr());
        let ptr = (self.bits & !TAG_MASK) as *const HeapValue;
        Arc::from_raw(ptr)
    }
}

// ─── Constructors ────────────────────────────────────────────────────────────

impl Value {
    pub const fn null() -> Self {
        Value {
            bits: TAG_IMMEDIATE | (IMM_NULL << PAYLOAD_SHIFT),
        }
    }

    pub const fn undefined() -> Self {
        Value {
            bits: TAG_IMMEDIATE | (IMM_UNDEFINED << PAYLOAD_SHIFT),
        }
    }

    pub const fn bool_val(b: bool) -> Self {
        Value {
            bits: TAG_IMMEDIATE
                | (if b { IMM_TRUE } else { IMM_FALSE } << PAYLOAD_SHIFT),
        }
    }

    #[inline]
    pub fn from_u64(n: u64) -> Self {
        if n <= MAX_INLINE_UINT {
            Value {
                bits: TAG_UINT | ((n as usize) << PAYLOAD_SHIFT),
            }
        } else {
            Self::from_heap(HeapValue::LargeUInt(n))
        }
    }

    #[inline]
    pub fn from_i64(n: i64) -> Self {
        if n >= 0 {
            Self::from_u64(n as u64)
        } else {
            let mag = (n as i128).unsigned_abs();
            if mag <= MAX_INLINE_NEG_MAG as u128 {
                Value {
                    bits: TAG_NEG_INT | ((mag as usize) << PAYLOAD_SHIFT),
                }
            } else {
                Self::from_heap(HeapValue::LargeInt(n))
            }
        }
    }

    #[inline]
    pub fn from_f64(f: f64) -> Self {
        let f = if f == 0.0 { 0.0f64 } else { f };
        let f = if f.is_nan() { f64::NAN } else { f };

        if f.is_finite() && f.fract() == 0.0 {
            if f >= 0.0 && f <= MAX_INLINE_UINT as f64 {
                let n = f as u64;
                if (n as f64) == f {
                    return Self::from_u64(n);
                }
            } else if f < 0.0 && f >= -(MAX_INLINE_NEG_MAG as f64) {
                let n = f as i64;
                if (n as f64) == f {
                    return Self::from_i64(n);
                }
            }
        }

        Self::from_heap(HeapValue::Float(f))
    }

    pub fn from_arcstr(s: ArcStr) -> Self {
        Self::from_heap(HeapValue::String(s))
    }

    pub fn from_array(a: Vec<Value>) -> Self {
        Self::from_heap(HeapValue::Array(a))
    }

    pub fn from_object(o: ObjectMap) -> Self {
        Self::from_heap(HeapValue::Object(o))
    }

    pub fn from_set(s: HashSet<Value>) -> Self {
        Self::from_heap(HeapValue::Set(s))
    }

    fn from_heap(hv: HeapValue) -> Self {
        let arc = Arc::new(hv);
        let raw = Arc::into_raw(arc) as usize;
        debug_assert!(raw & TAG_MASK == 0, "Arc pointer not aligned: {raw:#x}");
        Value {
            bits: raw | TAG_PTR,
        }
    }
}

// ─── Accessors ───────────────────────────────────────────────────────────────

static UNDEFINED_STATIC: Value = Value {
    bits: TAG_IMMEDIATE | (IMM_UNDEFINED << PAYLOAD_SHIFT),
};

impl Value {
    pub fn is_null(&self) -> bool {
        self.bits == TAG_IMMEDIATE | (IMM_NULL << PAYLOAD_SHIFT)
    }
    pub fn is_undefined(&self) -> bool {
        self.bits == TAG_IMMEDIATE | (IMM_UNDEFINED << PAYLOAD_SHIFT)
    }
    pub fn is_bool(&self) -> bool {
        self.tag() == TAG_IMMEDIATE
            && (self.payload() == IMM_TRUE || self.payload() == IMM_FALSE)
    }
    pub fn is_number(&self) -> bool {
        match self.tag() {
            TAG_UINT | TAG_NEG_INT => true,
            TAG_PTR if self.is_ptr() => matches!(
                self.heap(),
                HeapValue::Float(_) | HeapValue::BigInt(_) | HeapValue::LargeUInt(_) | HeapValue::LargeInt(_)
            ),
            _ => false,
        }
    }
    pub fn is_string(&self) -> bool {
        self.is_ptr() && matches!(self.heap(), HeapValue::String(_))
    }
    pub fn is_array(&self) -> bool {
        self.is_ptr() && matches!(self.heap(), HeapValue::Array(_))
    }
    pub fn is_object(&self) -> bool {
        self.is_ptr() && matches!(self.heap(), HeapValue::Object(_))
    }
    pub fn is_set(&self) -> bool {
        self.is_ptr() && matches!(self.heap(), HeapValue::Set(_))
    }

    pub fn as_bool(&self) -> Option<bool> {
        if self.tag() == TAG_IMMEDIATE {
            match self.payload() {
                IMM_TRUE => Some(true),
                IMM_FALSE => Some(false),
                _ => None,
            }
        } else {
            None
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self.tag() {
            TAG_UINT => Some(self.payload() as u64),
            TAG_NEG_INT => None,
            TAG_PTR if self.is_ptr() => match self.heap() {
                HeapValue::LargeUInt(u) => Some(*u),
                HeapValue::LargeInt(i) if *i >= 0 => Some(*i as u64),
                HeapValue::Float(f) => {
                    if f.is_finite() && *f >= 0.0 && f.fract() == 0.0 && *f <= u64::MAX as f64 {
                        let c = *f as u64;
                        if (c as f64) == *f { return Some(c); }
                    }
                    None
                }
                HeapValue::BigInt(b) => num_traits::ToPrimitive::to_u64(b.as_ref()),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self.tag() {
            TAG_UINT => {
                let v = self.payload() as u64;
                if v <= i64::MAX as u64 { Some(v as i64) } else { None }
            }
            TAG_NEG_INT => {
                let mag = self.payload() as u64;
                if mag <= i64::MAX as u64 {
                    Some(-(mag as i64))
                } else if mag == i64::MAX as u64 + 1 {
                    Some(i64::MIN)
                } else {
                    None
                }
            }
            TAG_PTR if self.is_ptr() => match self.heap() {
                HeapValue::LargeInt(i) => Some(*i),
                HeapValue::LargeUInt(u) if *u <= i64::MAX as u64 => Some(*u as i64),
                HeapValue::Float(f) => {
                    if f.is_finite() && f.fract() == 0.0 && *f >= i64::MIN as f64 && *f <= i64::MAX as f64 {
                        let c = *f as i64;
                        if (c as f64) == *f { return Some(c); }
                    }
                    None
                }
                HeapValue::BigInt(b) => num_traits::ToPrimitive::to_i64(b.as_ref()),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self.tag() {
            TAG_UINT => Some(self.payload() as u64 as f64),
            TAG_NEG_INT => Some(-(self.payload() as i64 as f64)),
            TAG_PTR if self.is_ptr() => match self.heap() {
                HeapValue::Float(f) => Some(*f),
                HeapValue::LargeUInt(u) => Some(*u as f64),
                HeapValue::LargeInt(i) => Some(*i as f64),
                HeapValue::BigInt(b) => num_traits::ToPrimitive::to_f64(b.as_ref()),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn as_str_ref(&self) -> Option<&str> {
        if self.is_ptr() {
            match self.heap() {
                HeapValue::String(s) => Some(s.as_str()),
                _ => None,
            }
        } else {
            None
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Value>> {
        if self.is_ptr() {
            match self.heap() {
                HeapValue::Array(a) => Some(a),
                _ => None,
            }
        } else {
            None
        }
    }

    pub fn as_object(&self) -> Option<&ObjectMap> {
        if self.is_ptr() {
            match self.heap() {
                HeapValue::Object(o) => Some(o),
                _ => None,
            }
        } else {
            None
        }
    }

    pub fn as_set(&self) -> Option<&HashSet<Value>> {
        if self.is_ptr() {
            match self.heap() {
                HeapValue::Set(s) => Some(s),
                _ => None,
            }
        } else {
            None
        }
    }
}

// ─── Arithmetic ──────────────────────────────────────────────────────────────

impl Value {
    #[inline]
    pub fn add_number(&self, rhs: &Self) -> Value {
        if self.tag() == TAG_UINT && rhs.tag() == TAG_UINT {
            let a = self.payload() as u64;
            let b = rhs.payload() as u64;
            return match a.checked_add(b) {
                Some(sum) => Value::from_u64(sum),
                None => Value::from_heap(HeapValue::BigInt(
                    Arc::new(BigInt::from(a) + BigInt::from(b)),
                )),
            };
        }

        if let (Some(a), Some(b)) = (self.as_u64(), rhs.as_u64()) {
            return match a.checked_add(b) {
                Some(sum) => Value::from_u64(sum),
                None => Value::from_heap(HeapValue::BigInt(
                    Arc::new(BigInt::from(a) + BigInt::from(b)),
                )),
            };
        }

        if let (Some(a), Some(b)) = (self.as_i64(), rhs.as_i64()) {
            return match a.checked_add(b) {
                Some(sum) => Value::from_i64(sum),
                None => Value::from_heap(HeapValue::BigInt(
                    Arc::new(BigInt::from(a) + BigInt::from(b)),
                )),
            };
        }

        let a = self.as_f64().unwrap_or(0.0);
        let b = rhs.as_f64().unwrap_or(0.0);
        Value::from_f64(a + b)
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

    pub fn get_str(&self, key: &str) -> &Value {
        if let Some(o) = self.as_object() {
            match o.get_str(key) {
                Some(v) => v,
                None => &UNDEFINED_STATIC,
            }
        } else {
            &UNDEFINED_STATIC
        }
    }

    pub(crate) fn kind_ordinal(&self) -> u8 {
        match self.tag() {
            TAG_UINT | TAG_NEG_INT => 2,
            TAG_IMMEDIATE => match self.payload() {
                IMM_NULL => 0,
                IMM_FALSE | IMM_TRUE => 1,
                IMM_UNDEFINED => 7,
                _ => unreachable!(),
            },
            TAG_PTR if self.is_ptr() => match self.heap() {
                HeapValue::Float(_) | HeapValue::BigInt(_) | HeapValue::LargeUInt(_) | HeapValue::LargeInt(_) => 2,
                HeapValue::String(_) => 3,
                HeapValue::Array(_) => 4,
                HeapValue::Object(_) => 5,
                HeapValue::Set(_) => 6,
            },
            _ => 7,
        }
    }

    pub(crate) fn hash_content<H: Hasher>(&self, state: &mut H) {
        self.kind_ordinal().hash(state);
        self.hash_inner(state);
    }

    fn hash_inner<H: Hasher>(&self, state: &mut H) {
        match self.tag() {
            TAG_UINT => {
                0u8.hash(state);
                (self.payload() as u64).hash(state);
            }
            TAG_NEG_INT => {
                1u8.hash(state);
                (self.payload() as u64).hash(state);
            }
            TAG_IMMEDIATE => {
                self.payload().hash(state);
            }
            TAG_PTR if self.is_ptr() => match self.heap() {
                HeapValue::Float(f) => { f.to_bits().hash(state); }
                HeapValue::LargeUInt(u) => { 0u8.hash(state); u.hash(state); }
                HeapValue::LargeInt(i) if *i >= 0 => { 0u8.hash(state); (*i as u64).hash(state); }
                HeapValue::LargeInt(i) => { 1u8.hash(state); i.hash(state); }
                HeapValue::BigInt(b) => {
                    use num_traits::ToPrimitive;
                    if let Some(u) = b.to_u64() { 0u8.hash(state); u.hash(state); }
                    else if let Some(i) = b.to_i64() {
                        if i >= 0 { 0u8.hash(state); (i as u64).hash(state); }
                        else { 1u8.hash(state); i.hash(state); }
                    } else {
                        2u8.hash(state);
                        let (sign, bytes) = b.to_bytes_be();
                        sign.hash(state); bytes.hash(state);
                    }
                }
                HeapValue::String(s) => { s.as_str().hash(state); }
                HeapValue::Array(a) => {
                    a.len().hash(state);
                    for v in a.iter() { v.hash_content(state); }
                }
                HeapValue::Set(s) => {
                    s.len().hash(state);
                    Self::set_hash(s).hash(state);
                }
                HeapValue::Object(o) => { o.hash(state); }
            },
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

    pub(crate) fn format_number(&self) -> String {
        match self.tag() {
            TAG_UINT => (self.payload() as u64).to_string(),
            TAG_NEG_INT => format!("-{}", self.payload() as u64),
            TAG_PTR if self.is_ptr() => match self.heap() {
                HeapValue::Float(f) => {
                    if f.fract() == 0.0 && f.is_finite() {
                        if *f >= 0.0 { (*f as u64).to_string() }
                        else { (*f as i64).to_string() }
                    } else { f.to_string() }
                }
                HeapValue::LargeUInt(u) => u.to_string(),
                HeapValue::LargeInt(i) => i.to_string(),
                HeapValue::BigInt(b) => b.to_string(),
                _ => "0".to_string(),
            },
            _ => "0".to_string(),
        }
    }
}

// ─── From impls ──────────────────────────────────────────────────────────────

impl From<bool> for Value {
    fn from(b: bool) -> Self { Value::bool_val(b) }
}
impl From<&str> for Value {
    fn from(s: &str) -> Self { Value::from_arcstr(ArcStr::from(s)) }
}
impl From<String> for Value {
    fn from(s: String) -> Self { Value::from_arcstr(ArcStr::from(s.as_str())) }
}
impl From<ArcStr> for Value {
    fn from(s: ArcStr) -> Self { Value::from_arcstr(s) }
}
impl From<i64> for Value {
    fn from(n: i64) -> Self { Value::from_i64(n) }
}
impl From<u64> for Value {
    fn from(n: u64) -> Self { Value::from_u64(n) }
}
impl From<i32> for Value {
    fn from(n: i32) -> Self { Value::from_i64(n as i64) }
}
impl From<u32> for Value {
    fn from(n: u32) -> Self { Value::from_u64(n as u64) }
}
impl From<f64> for Value {
    fn from(n: f64) -> Self { Value::from_f64(n) }
}
impl From<Vec<Value>> for Value {
    fn from(a: Vec<Value>) -> Self { Value::from_array(a) }
}
impl From<HashSet<Value>> for Value {
    fn from(s: HashSet<Value>) -> Self { Value::from_set(s) }
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
    fn from(m: ObjectMap) -> Self { Value::from_object(m) }
}

// ─── Clone ───────────────────────────────────────────────────────────────────

impl Clone for Value {
    fn clone(&self) -> Self {
        if self.is_ptr() {
            unsafe {
                Arc::increment_strong_count(
                    (self.bits & !TAG_MASK) as *const HeapValue,
                );
            }
        }
        Value { bits: self.bits }
    }
}

// ─── Drop ────────────────────────────────────────────────────────────────────

impl Drop for Value {
    fn drop(&mut self) {
        if self.is_ptr() {
            unsafe {
                Arc::decrement_strong_count(
                    (self.bits & !TAG_MASK) as *const HeapValue,
                );
            }
        }
    }
}

// ─── PartialEq / Eq ─────────────────────────────────────────────────────────

impl PartialEq for Value {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        if self.bits == other.bits {
            return true;
        }
        let at = self.tag();
        let bt = other.tag();
        if at == TAG_UINT && bt == TAG_UINT { return false; }
        if at == TAG_NEG_INT && bt == TAG_NEG_INT { return false; }
        if (at == TAG_UINT && bt == TAG_NEG_INT) || (at == TAG_NEG_INT && bt == TAG_UINT) {
            return false;
        }
        if at == TAG_IMMEDIATE && bt == TAG_IMMEDIATE { return false; }
        if !self.is_ptr() && !other.is_ptr() { return false; }

        let ak = self.kind_ordinal();
        let bk = other.kind_ordinal();
        if ak != bk { return false; }

        match (self.heap(), other.heap()) {
            (HeapValue::Float(a), HeapValue::Float(b)) => a.to_bits() == b.to_bits(),
            (HeapValue::LargeUInt(a), HeapValue::LargeUInt(b)) => a == b,
            (HeapValue::LargeInt(a), HeapValue::LargeInt(b)) => a == b,
            (HeapValue::BigInt(a), HeapValue::BigInt(b)) => a == b,
            (HeapValue::String(a), HeapValue::String(b)) => a == b,
            (HeapValue::Array(a), HeapValue::Array(b)) => a == b,
            (HeapValue::Object(a), HeapValue::Object(b)) => a == b,
            (HeapValue::Set(a), HeapValue::Set(b)) => {
                if a.len() != b.len() { return false; }
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
        if ka != kb { return ka.cmp(&kb); }

        match ka {
            0 | 7 => Ordering::Equal,
            1 => self.as_bool().unwrap().cmp(&other.as_bool().unwrap()),
            2 => self.cmp_numbers(other),
            3 => self.as_str_ref().unwrap().cmp(other.as_str_ref().unwrap()),
            4 => self.as_array().unwrap().cmp(other.as_array().unwrap()),
            5 => self.as_object().unwrap().cmp(other.as_object().unwrap()),
            6 => {
                let a = self.as_set().unwrap();
                let b = other.as_set().unwrap();
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
        if self.tag() == TAG_UINT && other.tag() == TAG_UINT {
            return (self.payload() as u64).cmp(&(other.payload() as u64));
        }
        if self.tag() == TAG_NEG_INT && other.tag() == TAG_NEG_INT {
            return (other.payload() as u64).cmp(&(self.payload() as u64));
        }
        if self.tag() == TAG_UINT && other.tag() == TAG_NEG_INT { return Ordering::Greater; }
        if self.tag() == TAG_NEG_INT && other.tag() == TAG_UINT { return Ordering::Less; }

        let a = self.as_f64().unwrap_or(0.0);
        let b = other.as_f64().unwrap_or(0.0);
        a.partial_cmp(&b).unwrap_or(Ordering::Equal)
    }
}

// ─── Hash ────────────────────────────────────────────────────────────────────

impl Hash for Value {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.kind_ordinal().hash(state);
        self.hash_inner(state);
    }
}

// ─── Debug / Display ─────────────────────────────────────────────────────────

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.tag() {
            TAG_UINT => write!(f, "{}", self.payload() as u64),
            TAG_NEG_INT => write!(f, "-{}", self.payload() as u64),
            TAG_IMMEDIATE => match self.payload() {
                IMM_NULL => write!(f, "Null"),
                IMM_FALSE => write!(f, "Bool(false)"),
                IMM_TRUE => write!(f, "Bool(true)"),
                IMM_UNDEFINED => write!(f, "Undefined"),
                _ => unreachable!(),
            },
            TAG_PTR if self.is_ptr() => match self.heap() {
                HeapValue::Float(fl) => write!(f, "{fl}"),
                HeapValue::LargeUInt(u) => write!(f, "{u}"),
                HeapValue::LargeInt(i) => write!(f, "{i}"),
                HeapValue::BigInt(b) => write!(f, "{b}"),
                HeapValue::String(s) => write!(f, "String({s:?})"),
                HeapValue::Array(a) => write!(f, "Array({a:?})"),
                HeapValue::Object(o) => write!(f, "Object({o:?})"),
                HeapValue::Set(s) => write!(f, "Set({s:?})"),
            },
            _ => write!(f, "Null"),
        }
    }
}

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
        if let Some(o) = self.as_object() {
            return o.get(key).unwrap_or(&UNDEFINED_STATIC);
        }
        if let Some(s) = self.as_set() {
            if let Some(v) = s.get(key) { return v; }
            return &UNDEFINED_STATIC;
        }
        if let Some(a) = self.as_array() {
            if let Some(idx) = key.as_u64() {
                if (idx as usize) < a.len() { return &a[idx as usize]; }
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
    pub fn from_regorus(v: &regorus::Value) -> Self {
        match v {
            regorus::Value::Null => Value::null(),
            regorus::Value::Bool(b) => Value::bool_val(*b),
            regorus::Value::String(s) => Value::from_arcstr(ArcStr::from(s.as_ref())),
            regorus::Value::Number(_) => {
                let json_str = v.to_json_str().unwrap_or_default();
                serde_json::from_str(&json_str).unwrap_or(Value::null())
            }
            regorus::Value::Array(a) => {
                Value::from(a.iter().map(Value::from_regorus).collect::<Vec<_>>())
            }
            regorus::Value::Set(s) => {
                Value::from(s.iter().map(Value::from_regorus).collect::<HashSet<_>>())
            }
            regorus::Value::Object(m) => {
                let obj = ObjectMap::from_regorus_btree(m);
                Value::from_object(obj)
            }
            regorus::Value::Undefined => Value::undefined(),
        }
    }
}
