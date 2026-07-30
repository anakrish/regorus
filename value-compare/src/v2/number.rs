// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Number type with optimized comparison.
//!
//! Key difference from `regorus::Number`:
//! - `PartialEq` and `Ord` use fast paths for same-variant comparisons
//!   (e.g., `UInt(a) == UInt(b)` is just `a == b`, no BigInt allocation).
//! - Cross-variant integer comparisons use i128/u128 widening before resorting to BigInt.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use std::sync::Arc;

use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive, Zero};

/// A numeric value: unsigned, signed, float, or arbitrary-precision integer.
#[derive(Clone)]
pub enum Number {
    UInt(u64),
    Int(i64),
    Float(f64),
    BigInt(Arc<BigInt>),
}

// ---------------------------------------------------------------------------
//  Construction
// ---------------------------------------------------------------------------

impl From<u64> for Number {
    fn from(v: u64) -> Self {
        Number::UInt(v)
    }
}

impl From<i64> for Number {
    fn from(v: i64) -> Self {
        Number::Int(v)
    }
}

impl From<f64> for Number {
    fn from(v: f64) -> Self {
        Number::Float(v)
    }
}

impl From<BigInt> for Number {
    fn from(v: BigInt) -> Self {
        Number::from_bigint(v)
    }
}

impl Number {
    fn from_bigint(value: BigInt) -> Self {
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
        Number::BigInt(Arc::new(value))
    }

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
            Number::BigInt(v) => Some((**v).clone()),
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
//  PartialEq — fast paths avoid BigInt allocation
// ---------------------------------------------------------------------------

impl PartialEq for Number {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            // Same-variant fast paths (no allocation):
            (Number::UInt(a), Number::UInt(b)) => a == b,
            (Number::Int(a), Number::Int(b)) => a == b,
            (Number::Float(a), Number::Float(b)) => a == b,
            (Number::BigInt(a), Number::BigInt(b)) => a == b,

            // Cross-variant integer: widen to i128/u128 first.
            (Number::UInt(a), Number::Int(b)) | (Number::Int(b), Number::UInt(a)) => {
                if *b < 0 {
                    false
                } else {
                    *a == (*b as u64)
                }
            }

            // Integer vs BigInt: convert the small side (cheap).
            (Number::UInt(a), Number::BigInt(b)) | (Number::BigInt(b), Number::UInt(a)) => {
                **b == BigInt::from(*a)
            }
            (Number::Int(a), Number::BigInt(b)) | (Number::BigInt(b), Number::Int(a)) => {
                **b == BigInt::from(*a)
            }

            // Float vs integer: try bigint comparison first.
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

impl Eq for Number {}

// ---------------------------------------------------------------------------
//  Ord — fast paths for same-variant
// ---------------------------------------------------------------------------

impl Ord for Number {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            // Same-variant:
            (Number::UInt(a), Number::UInt(b)) => a.cmp(b),
            (Number::Int(a), Number::Int(b)) => a.cmp(b),
            (Number::BigInt(a), Number::BigInt(b)) => a.cmp(b),
            (Number::Float(a), Number::Float(b)) => a.partial_cmp(b).unwrap_or(Ordering::Equal),

            // Cross-variant integer widening:
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

            // Integer vs BigInt:
            (Number::UInt(a), Number::BigInt(b)) => BigInt::from(*a).cmp(b),
            (Number::BigInt(a), Number::UInt(b)) => (**a).cmp(&BigInt::from(*b)),
            (Number::Int(a), Number::BigInt(b)) => BigInt::from(*a).cmp(b),
            (Number::BigInt(a), Number::Int(b)) => (**a).cmp(&BigInt::from(*b)),

            // Float involved: fallthrough to bigint then f64.
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

impl PartialOrd for Number {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ---------------------------------------------------------------------------
//  Hash — canonical: must agree with Eq.
// ---------------------------------------------------------------------------

impl Hash for Number {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Canonical form: if the number can be represented as i128, hash the i128.
        // This ensures UInt(5), Int(5), Float(5.0) all hash the same.
        match self {
            Number::UInt(v) => {
                0u8.hash(state); // tag: integer
                (*v as i128).hash(state);
            }
            Number::Int(v) => {
                0u8.hash(state);
                (*v as i128).hash(state);
            }
            Number::BigInt(v) => {
                // BigInt might not fit i128. Hash its bytes.
                if let Some(i) = v.to_i128() {
                    0u8.hash(state);
                    i.hash(state);
                } else {
                    1u8.hash(state); // tag: big
                    let (sign, bytes) = v.to_bytes_be();
                    sign.hash(state);
                    bytes.hash(state);
                }
            }
            Number::Float(f) => {
                // If integer-valued, hash as integer for consistency.
                if f.is_finite() && f.fract() == 0.0 {
                    if let Some(i) = self.as_i64() {
                        0u8.hash(state);
                        (i as i128).hash(state);
                        return;
                    }
                }
                2u8.hash(state); // tag: float
                f.to_bits().hash(state);
            }
        }
    }
}

// ---------------------------------------------------------------------------
//  Debug / Display
// ---------------------------------------------------------------------------

impl fmt::Debug for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.format_decimal())
    }
}

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.format_decimal())
    }
}

// ---------------------------------------------------------------------------
//  FromStr (for serde deserialization round-trip)
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub struct ParseNumberError;

impl fmt::Display for ParseNumberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid number")
    }
}

impl std::error::Error for ParseNumberError {}

impl FromStr for Number {
    type Err = ParseNumberError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(ParseNumberError);
        }

        // Try u64, then i64, then f64.
        if let Ok(v) = trimmed.parse::<u64>() {
            return Ok(Number::UInt(v));
        }
        if let Ok(v) = trimmed.parse::<i64>() {
            return Ok(Number::Int(v));
        }
        if let Ok(v) = trimmed.parse::<f64>() {
            return Ok(Number::Float(v));
        }

        // Try BigInt as last resort.
        if let Ok(v) = trimmed.parse::<BigInt>() {
            return Ok(Number::from_bigint(v));
        }

        Err(ParseNumberError)
    }
}

// ---------------------------------------------------------------------------
//  Serde
// ---------------------------------------------------------------------------

impl serde::Serialize for Number {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let s = self.format_decimal();
        let v = serde_json::Number::from_str(&s)
            .map_err(|_| serde::ser::Error::custom("could not serialize number"))?;
        v.serialize(serializer)
    }
}

// ---------------------------------------------------------------------------
//  Arithmetic — integer-exact addition
// ---------------------------------------------------------------------------

impl Number {
    /// Add two numbers, preserving exact integer semantics.
    ///
    /// If either operand is Float, the result is Float.
    /// Otherwise, uses checked integer arithmetic with BigInt fallback.
    #[inline]
    pub fn add(&self, rhs: &Self) -> Number {
        // Float fast path.
        if matches!(self, Number::Float(_)) || matches!(rhs, Number::Float(_)) {
            return Number::Float(self.to_f64_lossy() + rhs.to_f64_lossy());
        }

        match (self, rhs) {
            (Number::UInt(a), Number::UInt(b)) => match a.checked_add(*b) {
                Some(sum) => Number::UInt(sum),
                None => Number::BigInt(Arc::new(BigInt::from(*a) + BigInt::from(*b))),
            },
            (Number::Int(a), Number::Int(b)) => match a.checked_add(*b) {
                Some(sum) => Number::Int(sum),
                None => Number::BigInt(Arc::new(BigInt::from(*a) + BigInt::from(*b))),
            },
            (Number::Int(a), Number::UInt(b)) | (Number::UInt(b), Number::Int(a)) => {
                let sum = *a as i128 + *b as i128;
                if sum >= 0 && sum <= u64::MAX as i128 {
                    Number::UInt(sum as u64)
                } else if sum >= i64::MIN as i128 && sum <= i64::MAX as i128 {
                    Number::Int(sum as i64)
                } else {
                    Number::BigInt(Arc::new(BigInt::from(sum)))
                }
            }
            (Number::BigInt(a), Number::BigInt(b)) => {
                Number::from_bigint((**a).clone() + (**b).clone())
            }
            (Number::BigInt(a), other) | (other, Number::BigInt(a)) => {
                let b = match other {
                    Number::UInt(u) => BigInt::from(*u),
                    Number::Int(i) => BigInt::from(*i),
                    _ => unreachable!(),
                };
                Number::from_bigint((**a).clone() + b)
            }
            _ => unreachable!(),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Number {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NumberVisitor;

        impl<'de> serde::de::Visitor<'de> for NumberVisitor {
            type Value = Number;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a number")
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Number, E> {
                Ok(Number::UInt(v))
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Number, E> {
                Ok(Number::Int(v))
            }

            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Number, E> {
                Ok(Number::Float(v))
            }
        }

        deserializer.deserialize_any(NumberVisitor)
    }
}
