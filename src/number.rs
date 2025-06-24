// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use alloc::str::FromStr;
use core::cmp::{Ord, Ordering};
use core::fmt::{Debug, Formatter};
use rust_decimal::MathematicalOps;

use anyhow::{bail, Result};

use serde::ser::Serializer;
use serde::Serialize;

use crate::*;
use rust_decimal::prelude::{FromPrimitive, ToPrimitive};


type BigDecimal = rust_decimal::Decimal;

#[derive(Clone)]
pub enum Number {
    // TODO: maybe specialize for u64, i64, f64
    Big(BigDecimal),
}

impl Debug for Number {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            Number::Big(b) => b.fmt(f),
        }
    }
}

impl Serialize for Number {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Big(_) => {
                let s = self.format_decimal();
                let v = serde_json::Number::from_str(&s)
                    .map_err(|_| serde::ser::Error::custom("could not serialize big number"))?;
                v.serialize(serializer)
            }
        }
    }
}

use Number::*;

impl From<u64> for Number {
    fn from(n: u64) -> Self {
        Big(BigDecimal::from(n))
    }
}

impl From<usize> for Number {
    fn from(n: usize) -> Self {
        Big(BigDecimal::from(n))
    }
}

impl From<i64> for Number {
    fn from(n: i64) -> Self {
        Big(BigDecimal::from(n))
    }
}

impl From<f64> for Number {
    fn from(n: f64) -> Self {
        match BigDecimal::from_f64(n) {
            Some(v) => Big(v),
            None => Big(BigDecimal::ZERO), // Fallback to zero if conversion fails
        }
    }
}

impl Number {
    pub fn try_from_i128(n: i128) -> Option<Self> {
        BigDecimal::try_from_i128_with_scale(n, 0).ok().map(Big)
    }

    pub fn try_from_u128(n: u128) -> Option<Self> {
        match i128::try_from(n) {
            Ok(i) => Self::try_from_i128(i),
            _ => None,
        }
    }
}

impl Number {
    pub fn as_u128(&self) -> Option<u128> {
        match self {
            Big(b) if b.is_integer() => b.to_u128(),
            _ => None,
        }
    }

    pub fn as_i128(&self) -> Option<i128> {
        match self {
            Big(b) if b.is_integer() => b.to_i128(),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Big(b) if b.is_integer() => b.to_u64(),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Big(b) if b.is_integer() => b.to_i64(),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Big(b) => b.to_f64(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseNumberError;

impl FromStr for Number {
    type Err = ParseNumberError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(v) = BigDecimal::from_str_exact(s) {
            return Ok(Big(v));
        }
        Ok(f64::from_str(s).map_err(|_| ParseNumberError)?.into())
    }
}

impl Eq for Number {}

impl PartialEq for Number {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Big(a), Big(b)) => a == b,
        }
    }
}

impl Ord for Number {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Big(a), Big(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for Number {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Number {
    pub fn add_assign(&mut self, rhs: &Self) -> Result<()> {
        *self = self.add(rhs)?;
        Ok(())
    }

    pub fn add(&self, rhs: &Self) -> Result<Number> {
        match (self, rhs) {
            (Big(a), Big(b)) => {
                if let Some(c) = a.checked_add(*b) {
                    Ok(Big(c.into()))
                } else {
                    bail!("Overflow in addition of big numbers")
                }
            }
        }
    }

    pub fn sub_assign(&mut self, rhs: &Self) -> Result<()> {
        *self = self.sub(rhs)?;
        Ok(())
    }

    pub fn sub(&self, rhs: &Self) -> Result<Number> {
        match (self, rhs) {
            (Big(a), Big(b)) => {
                if let Some(c) = a.checked_sub(*b) {
                    Ok(Big(c.into()))
                } else {
                    bail!("Overflow in subtraction of big numbers")
                }
            }
        }
    }

    pub fn mul_assign(&mut self, rhs: &Self) -> Result<()> {
        *self = self.mul(rhs)?;
        Ok(())
    }

    pub fn mul(&self, rhs: &Self) -> Result<Number> {
        match (self, rhs) {
            (Big(a), Big(b)) => {
                if let Some(c) = a.checked_mul(*b) {
                    Ok(Big(c.into()))
                } else {
                    bail!("Overflow in multiplication of big numbers")
                }
            }
        }
    }

    pub fn divide(self, rhs: &Self) -> Result<Number> {
        match (self, rhs) {
            (Big(a), Big(b)) => {
                if let Some(c) = a.checked_div(*b) {
                    Ok(Big(c.into()))
                } else {
                    bail!("Failure in division of big numbers")
                }
            }
        }
    }

    pub fn modulo(self, rhs: &Self) -> Result<Number> {
        match (self, rhs) {
            (Big(a), Big(b)) => {
                if let Some(c) = a.checked_rem(*b) {
                    Ok(Big(c.into()))
                } else {
                    bail!("Failure in modulo of big numbers")
                }
            }
        }
    }

    pub fn is_integer(&self) -> bool {
        match self {
            Big(b) => b.is_integer(),
        }
    }

    pub fn is_positive(&self) -> bool {
        match self {
            Big(b) => b.is_sign_positive(),
        }
    }

    fn ensure_integers(a: &Number, b: &Number) -> Option<(i64, i64)> {
        match (a, b) {
            (Big(a), Big(b)) if a.is_integer() && b.is_integer() => {
                match (a.to_i64(), b.to_i64()) {
                    (Some(a), Some(b)) => Some((a, b)),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn ensure_integer(&self) -> Option<i64> {
        match self {
            Big(a) if a.is_integer() => a.to_i64(),
            _ => None,
        }
    }

    pub fn and(&self, rhs: &Self) -> Option<Number> {
        match Self::ensure_integers(self, rhs) {
            Some((a, b)) => Some((a & b).into()),
            _ => None,
        }
    }

    pub fn or(&self, rhs: &Self) -> Option<Number> {
        match Self::ensure_integers(self, rhs) {
            Some((a, b)) => Some((a | b).into()),
            _ => None,
        }
    }

    pub fn xor(&self, rhs: &Self) -> Option<Number> {
        match Self::ensure_integers(self, rhs) {
            Some((a, b)) => Some((a ^ b).into()),
            _ => None,
        }
    }

    pub fn lsh(&self, rhs: &Self) -> Option<Number> {
        match Self::ensure_integers(self, rhs) {
            Some((a, b)) => a.checked_shl(b as u32).map(|v| v.into()),
            _ => None,
        }
    }

    pub fn rsh(&self, rhs: &Self) -> Option<Number> {
        match Self::ensure_integers(self, rhs) {
            Some((a, b)) => a.checked_shr(b as u32).map(|v| v.into()),
            _ => None,
        }
    }

    pub fn neg(&self) -> Option<Number> {
        self.ensure_integer().map(|a| (!a).into())
    }

    pub fn abs(&self) -> Number {
        match self {
            Big(b) => Big(b.abs()),
        }
    }

    pub fn floor(&self) -> Number {
        match self {
            Big(b) => Big(b.floor()),
        }
    }

    pub fn ceil(&self) -> Number {
        match self {
            Big(b) => Big(b.ceil()),
        }
    }

    pub fn round(&self) -> Number {
        match self {
            Big(b) => Big(b.round()),
        }
    }

    pub fn two_pow(e: i32) -> Result<Number> {
        if let Some(v) = BigDecimal::from(2).checked_powi(e as i64) {
            Ok(Big(v))
        } else {
            bail!("overflow in pow of big number")
        }
    }

    pub fn ten_pow(e: i32) -> Result<Number> {
        if let Some(v) = BigDecimal::from(10).checked_powi(e as i64) {
            Ok(Big(v))
        } else {
            bail!("overflow in pow of big number")
        }
    }

    pub fn format_bin(&self) -> String {
        self.ensure_integer()
            .map(|a| format!("{a:b}"))
            .unwrap_or("".to_string())
    }

    pub fn format_octal(&self) -> String {
        self.ensure_integer()
            .map(|a| format!("{a:o}"))
            .unwrap_or("".to_string())
    }

    pub fn format_scientific(&self) -> String {
        match self {
            Big(b) => format!("{}", b),
        }
    }

    pub fn format_decimal(&self) -> String {
        if let Some(u) = self.as_u64() {
            u.to_string()
        } else if let Some(i) = self.as_i64() {
            i.to_string()
        } else if let Some(f) = self.as_f64() {
            f.to_string()
        } else {
            let s = match self {
                Big(b) => format!("{}", b),
            };

            // Remove trailing e0
            //if s.ends_with("e0") {
            //    return s[..s.len() - 2].to_string();
            //}

            // Avoid e notation if full mantissa is written out.
            /*let parts: Vec<&str> = s.split('e').collect();
            match self {
                Big(b) => {
                    if b.is_sign_positive() {
                        if parts[0].len() == b.exponent1() as usize + 2 {
                            return parts[0].replace('.', "");
                        }
                    } else if parts[0].len() == b.d.exponent1() as usize + 3 {
                        return parts[0].replace('.', "");
                    }
                }
            }*/

            s
        }
    }

    pub fn format_decimal_with_width(&self, d: u32) -> String {
        match self {
            Big(b) => {
                let n = b.round_dp(d);
                format!("{}", n)
            }
        }
    }

    pub fn format_hex(&self) -> String {
        self.ensure_integer()
            .map(|a| format!("{a:x}"))
            .unwrap_or("".to_string())
    }

    pub fn format_big_hex(&self) -> String {
        self.ensure_integer()
            .map(|a| format!("{a:X}"))
            .unwrap_or("".to_string())
    }
}

#[cfg(test)]
mod test {
    use crate::number::*;

    #[test]
    fn display_number() {
        let n = Number::from(123456f64);
        assert_eq!(format!("{}", n.format_decimal()), "123456");
    }
}
