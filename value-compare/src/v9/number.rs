// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Arena-allocated numeric value.  `Copy` — no reference counting.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use bumpalo::Bump;
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive, Zero};

/// A numeric value: unsigned, signed, float, or arbitrary-precision integer.
///
/// All variants except `BigInt` are inline (no allocation).
/// `BigInt` holds a reference into the arena.
#[derive(Clone, Copy)]
pub enum Number<'a> {
    UInt(u64),
    Int(i64),
    Float(f64),
    BigInt(&'a BigInt),
}

// ---------------------------------------------------------------------------
//  Construction
// ---------------------------------------------------------------------------

impl<'a> Number<'a> {
    /// Allocate a BigInt in the arena, normalizing to UInt/Int when possible.
    pub fn from_bigint_in(arena: &'a Bump, value: BigInt) -> Self {
        if value.is_zero() {
            return Number::Int(0);
        }
        if value.is_negative() {
            if let Some(i) = value.to_i64() {
                return Number::Int(i);
            }
        } else if let Some(u) = value.to_u64() {
            return Number::UInt(u);
        } else if let Some(i) = value.to_i64() {
            return Number::Int(i);
        }
        Number::BigInt(arena.alloc(value))
    }
}

// ---------------------------------------------------------------------------
//  Accessors
// ---------------------------------------------------------------------------

impl Number<'_> {
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Number::UInt(v) => Some(*v),
            Number::Int(v) if *v >= 0 => Some(*v as u64),
            Number::BigInt(v) => v.to_u64(),
            Number::Float(f) => {
                if f.is_finite() && *f >= 0.0 && f.fract() == 0.0 && *f <= u64::MAX as f64 {
                    let c = *f as u64;
                    if (c as f64) == *f {
                        return Some(c);
                    }
                }
                None
            }
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Number::Int(v) => Some(*v),
            Number::UInt(v) if *v <= i64::MAX as u64 => Some(*v as i64),
            Number::BigInt(v) => v.to_i64(),
            Number::Float(f) => {
                if f.is_finite()
                    && f.fract() == 0.0
                    && *f >= i64::MIN as f64
                    && *f <= i64::MAX as f64
                {
                    let c = *f as i64;
                    if (c as f64) == *f {
                        return Some(c);
                    }
                }
                None
            }
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Number::Float(f) if f.is_finite() => Some(*f),
            Number::UInt(v) if *v <= (1u64 << 53) => Some(*v as f64),
            Number::Int(v) if (*v as i128).unsigned_abs() <= (1u128 << 53) => Some(*v as f64),
            Number::BigInt(v) if v.bits() <= 53 => v.to_f64(),
            _ => None,
        }
    }

    fn to_f64_lossy(&self) -> f64 {
        match self {
            Number::UInt(v) => *v as f64,
            Number::Int(v) => *v as f64,
            Number::Float(v) => *v,
            Number::BigInt(v) => v.to_f64().unwrap_or(if v.is_negative() {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            }),
        }
    }

    fn to_bigint(&self) -> Option<BigInt> {
        match self {
            Number::UInt(v) => Some(BigInt::from(*v)),
            Number::Int(v) => Some(BigInt::from(*v)),
            Number::BigInt(v) => Some((*v).clone()),
            Number::Float(f) => {
                if !f.is_finite() || f.fract() != 0.0 {
                    return None;
                }
                let safe = 9_007_199_254_740_992.0_f64; // 2^53
                if f.abs() > safe {
                    return None;
                }
                if *f >= 0.0 {
                    let u = *f as u64;
                    if (u as f64) == *f {
                        return Some(BigInt::from(u));
                    }
                } else {
                    let i = *f as i64;
                    if (i as f64) == *f {
                        return Some(BigInt::from(i));
                    }
                }
                None
            }
        }
    }

    pub fn format_decimal(&self) -> String {
        match self {
            Number::UInt(v) => v.to_string(),
            Number::Int(v) => v.to_string(),
            Number::BigInt(v) => v.to_string(),
            Number::Float(f) => {
                if f.is_nan() {
                    "NaN".to_string()
                } else {
                    f.to_string()
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
//  Arithmetic
// ---------------------------------------------------------------------------

impl<'a> Number<'a> {
    /// Add two numbers, preserving exact integer semantics.
    pub fn add(&self, rhs: &Self, arena: &'a Bump) -> Number<'a> {
        if matches!(self, Number::Float(_)) || matches!(rhs, Number::Float(_)) {
            return Number::Float(self.to_f64_lossy() + rhs.to_f64_lossy());
        }

        match (self, rhs) {
            (Number::UInt(a), Number::UInt(b)) => match a.checked_add(*b) {
                Some(sum) => Number::UInt(sum),
                None => Number::from_bigint_in(arena, BigInt::from(*a) + BigInt::from(*b)),
            },
            (Number::Int(a), Number::Int(b)) => match a.checked_add(*b) {
                Some(sum) => Number::Int(sum),
                None => Number::from_bigint_in(arena, BigInt::from(*a) + BigInt::from(*b)),
            },
            (Number::Int(a), Number::UInt(b)) | (Number::UInt(b), Number::Int(a)) => {
                let sum = *a as i128 + *b as i128;
                if sum >= 0 && sum <= u64::MAX as i128 {
                    Number::UInt(sum as u64)
                } else if sum >= i64::MIN as i128 && sum <= i64::MAX as i128 {
                    Number::Int(sum as i64)
                } else {
                    Number::from_bigint_in(arena, BigInt::from(sum))
                }
            }
            (Number::BigInt(a), Number::BigInt(b)) => {
                Number::from_bigint_in(arena, (*a).clone() + (*b).clone())
            }
            (Number::BigInt(a), other) | (other, Number::BigInt(a)) => {
                let b = match other {
                    Number::UInt(u) => BigInt::from(*u),
                    Number::Int(i) => BigInt::from(*i),
                    _ => unreachable!(),
                };
                Number::from_bigint_in(arena, (*a).clone() + b)
            }
            _ => unreachable!(),
        }
    }
}

// ---------------------------------------------------------------------------
//  PartialEq — fast paths avoid BigInt allocation
// ---------------------------------------------------------------------------

impl PartialEq for Number<'_> {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Number::UInt(a), Number::UInt(b)) => a == b,
            (Number::Int(a), Number::Int(b)) => a == b,
            (Number::Float(a), Number::Float(b)) => a == b,
            (Number::BigInt(a), Number::BigInt(b)) => a == b,
            (Number::UInt(a), Number::Int(b)) | (Number::Int(b), Number::UInt(a)) => {
                *b >= 0 && *a == (*b as u64)
            }
            (Number::UInt(a), Number::BigInt(b)) | (Number::BigInt(b), Number::UInt(a)) => {
                **b == BigInt::from(*a)
            }
            (Number::Int(a), Number::BigInt(b)) | (Number::BigInt(b), Number::Int(a)) => {
                **b == BigInt::from(*a)
            }
            _ => {
                if let (Some(a), Some(b)) = (self.to_bigint(), other.to_bigint()) {
                    return a == b;
                }
                let a = self.to_f64_lossy();
                let b = other.to_f64_lossy();
                if a.is_nan() || b.is_nan() {
                    return false;
                }
                a == b
            }
        }
    }
}

impl Eq for Number<'_> {}

// ---------------------------------------------------------------------------
//  Ord
// ---------------------------------------------------------------------------

impl Ord for Number<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Number::UInt(a), Number::UInt(b)) => a.cmp(b),
            (Number::Int(a), Number::Int(b)) => a.cmp(b),
            (Number::BigInt(a), Number::BigInt(b)) => a.cmp(b),
            (Number::Float(a), Number::Float(b)) => {
                a.partial_cmp(b).unwrap_or(Ordering::Equal)
            }
            (Number::UInt(a), Number::Int(b)) => {
                if *b < 0 {
                    Ordering::Greater
                } else {
                    a.cmp(&(*b as u64))
                }
            }
            (Number::Int(a), Number::UInt(b)) => {
                if *a < 0 {
                    Ordering::Less
                } else {
                    (*a as u64).cmp(b)
                }
            }
            (Number::UInt(a), Number::BigInt(b)) => BigInt::from(*a).cmp(b),
            (Number::BigInt(a), Number::UInt(b)) => (**a).cmp(&BigInt::from(*b)),
            (Number::Int(a), Number::BigInt(b)) => BigInt::from(*a).cmp(b),
            (Number::BigInt(a), Number::Int(b)) => (**a).cmp(&BigInt::from(*b)),
            _ => {
                if let (Some(a), Some(b)) = (self.to_bigint(), other.to_bigint()) {
                    return a.cmp(&b);
                }
                self.to_f64_lossy()
                    .partial_cmp(&other.to_f64_lossy())
                    .unwrap_or(Ordering::Equal)
            }
        }
    }
}

impl PartialOrd for Number<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ---------------------------------------------------------------------------
//  Hash — canonical: same integer value → same hash regardless of variant
// ---------------------------------------------------------------------------

impl Hash for Number<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Number::UInt(v) => {
                0u8.hash(state);
                v.hash(state);
            }
            Number::Int(v) if *v >= 0 => {
                0u8.hash(state);
                (*v as u64).hash(state);
            }
            Number::Int(v) => {
                1u8.hash(state);
                v.hash(state);
            }
            Number::Float(f) => {
                // If the float is an exact integer, hash as the integer.
                if f.is_finite() && f.fract() == 0.0 {
                    if *f >= 0.0 {
                        let u = *f as u64;
                        if (u as f64) == *f {
                            0u8.hash(state);
                            u.hash(state);
                            return;
                        }
                    } else {
                        let i = *f as i64;
                        if (i as f64) == *f {
                            if i >= 0 {
                                0u8.hash(state);
                                (i as u64).hash(state);
                            } else {
                                1u8.hash(state);
                                i.hash(state);
                            }
                            return;
                        }
                    }
                }
                2u8.hash(state);
                f.to_bits().hash(state);
            }
            Number::BigInt(v) => {
                if let Some(u) = v.to_u64() {
                    0u8.hash(state);
                    u.hash(state);
                } else if let Some(i) = v.to_i64() {
                    if i >= 0 {
                        0u8.hash(state);
                        (i as u64).hash(state);
                    } else {
                        1u8.hash(state);
                        i.hash(state);
                    }
                } else {
                    2u8.hash(state);
                    let (sign, bytes) = v.to_bytes_be();
                    sign.hash(state);
                    bytes.hash(state);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
//  Debug / Display
// ---------------------------------------------------------------------------

impl fmt::Debug for Number<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Number::UInt(v) => write!(f, "UInt({v})"),
            Number::Int(v) => write!(f, "Int({v})"),
            Number::Float(v) => write!(f, "Float({v})"),
            Number::BigInt(v) => write!(f, "BigInt({v})"),
        }
    }
}

impl fmt::Display for Number<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_decimal())
    }
}

// ---------------------------------------------------------------------------
//  Serialize
// ---------------------------------------------------------------------------

impl serde::Serialize for Number<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let s = self.format_decimal();
        let v = serde_json::Number::from_str(&s)
            .map_err(|_| serde::ser::Error::custom("could not serialize number"))?;
        v.serialize(serializer)
    }
}

// ---------------------------------------------------------------------------
//  FromStr (used to parse BigInt from stringified JSON numbers)
// ---------------------------------------------------------------------------

impl<'a> Number<'a> {
    /// Parse a number from a string, allocating BigInt in the arena if needed.
    pub fn from_str_in(arena: &'a Bump, s: &str) -> Option<Self> {
        if let Ok(u) = s.parse::<u64>() {
            return Some(Number::UInt(u));
        }
        if let Ok(i) = s.parse::<i64>() {
            return Some(Number::Int(i));
        }
        if let Ok(f) = s.parse::<f64>() {
            if s.contains('.') || s.contains('e') || s.contains('E') {
                return Some(Number::Float(f));
            }
            // Large integer that doesn't fit in i64/u64 — try BigInt.
            if let Ok(b) = BigInt::from_str(s) {
                return Some(Number::from_bigint_in(arena, b));
            }
            return Some(Number::Float(f));
        }
        None
    }
}
