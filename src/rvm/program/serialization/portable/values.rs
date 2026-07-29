// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Portable, language-neutral encoding for [`Value`].
//!
//! The encoding is a compact tagged tree that covers everything a Rego value
//! can hold, including the cases JSON cannot express:
//!
//! * `Undefined` — a first-class tag, never conflated with `Null`.
//! * `Set` — written in `Value::Ord` order so output is deterministic.
//! * Objects with **arbitrary value keys** — keys are full values, not strings.
//! * Arbitrary-precision integers — exact decimal text via the string table.
//!
//! Decoding is bounded on three axes: nesting depth, total node count, and
//! per-collection length.  All three are validated before any allocation.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::str::FromStr as _;

use super::errors::{PortableError, PortableLimits, PortableResult};
use super::format::value_tag;
use super::io::{Reader, Writer};
use super::strings::{StringTable, StringTableBuilder};
use crate::number::Number;
use crate::value::{Object, Value};

/// Encode `value` into `writer`, interning strings into `strings`.
pub fn encode_value<'a>(
    writer: &mut Writer,
    strings: &mut StringTableBuilder<'a>,
    value: &'a Value,
    depth: usize,
    limits: &PortableLimits,
) -> PortableResult<()> {
    if depth > limits.max_value_depth {
        return Err(PortableError::DepthExceeded {
            max: limits.max_value_depth,
        });
    }
    let child_depth = depth.checked_add(1).ok_or(PortableError::IntegerOverflow {
        context: "value depth",
    })?;

    match *value {
        Value::Null => writer.u8(value_tag::NULL),
        Value::Bool(false) => writer.u8(value_tag::FALSE),
        Value::Bool(true) => writer.u8(value_tag::TRUE),
        Value::Undefined => writer.u8(value_tag::UNDEFINED),
        Value::Number(ref number) => encode_number(writer, strings, number)?,
        Value::String(ref text) => {
            let index = strings.intern(text.as_ref())?;
            writer.u8(value_tag::STRING);
            writer.varint(u64::from(index));
        }
        Value::Array(ref items) => {
            PortableLimits::check("array length", items.len(), limits.max_collection_len)?;
            writer.u8(value_tag::ARRAY);
            writer.varint_usize(items.len());
            for item in items.iter() {
                encode_value(writer, strings, item, child_depth, limits)?;
            }
        }
        Value::Set(ref items) => {
            PortableLimits::check("set length", items.len(), limits.max_collection_len)?;
            writer.u8(value_tag::SET);
            writer.varint_usize(items.len());
            // `BTreeSet` iteration is already `Value::Ord` order — deterministic.
            for item in items.iter() {
                encode_value(writer, strings, item, child_depth, limits)?;
            }
        }
        Value::Object(ref fields) => {
            PortableLimits::check("object length", fields.len(), limits.max_collection_len)?;
            writer.u8(value_tag::OBJECT);
            writer.varint_usize(fields.len());
            // `iter_sorted` gives `Value::Ord` key order — deterministic and
            // independent of insertion order.
            for (key, field_value) in fields.iter_sorted() {
                encode_value(writer, strings, key, child_depth, limits)?;
                encode_value(writer, strings, field_value, child_depth, limits)?;
            }
        }
    }

    Ok(())
}

fn encode_number<'a>(
    writer: &mut Writer,
    strings: &mut StringTableBuilder<'a>,
    number: &Number,
) -> PortableResult<()> {
    match *number {
        Number::Int(value) => {
            writer.u8(value_tag::INT);
            writer.zigzag(value);
        }
        Number::UInt(value) => {
            writer.u8(value_tag::UINT);
            writer.varint(value);
        }
        Number::Float(value) => {
            writer.u8(value_tag::FLOAT);
            writer.f64_bits(value);
        }
        Number::BigInt(_) => {
            // Normalize so encoding is idempotent: a big integer that happens
            // to fit a machine word is written as such, matching what the
            // decoder would reconstruct.
            if let Some(value) = number.as_i64() {
                writer.u8(value_tag::INT);
                writer.zigzag(value);
            } else if let Some(value) = number.as_u64() {
                writer.u8(value_tag::UINT);
                writer.varint(value);
            } else {
                let index = strings.intern_owned(number.format_decimal())?;
                writer.u8(value_tag::BIGINT);
                writer.varint(u64::from(index));
            }
        }
    }
    Ok(())
}

/// Budgeted decoding context shared by all value reads in one artifact.
#[derive(Debug)]
pub struct ValueBudget {
    remaining_nodes: usize,
}

impl ValueBudget {
    /// Create a budget allowing `limits.max_value_nodes` nodes in total.
    pub const fn new(limits: &PortableLimits) -> Self {
        Self {
            remaining_nodes: limits.max_value_nodes,
        }
    }

    fn consume(&mut self, count: usize) -> PortableResult<()> {
        self.remaining_nodes =
            self.remaining_nodes
                .checked_sub(count)
                .ok_or(PortableError::LimitExceeded {
                    limit: "decoded value nodes",
                    value: count,
                    max: self.remaining_nodes,
                })?;
        Ok(())
    }
}

/// Decode one value from `reader`.
pub fn decode_value(
    reader: &mut Reader<'_>,
    strings: &StringTable<'_>,
    depth: usize,
    limits: &PortableLimits,
    budget: &mut ValueBudget,
) -> PortableResult<Value> {
    if depth > limits.max_value_depth {
        return Err(PortableError::DepthExceeded {
            max: limits.max_value_depth,
        });
    }
    budget.consume(1)?;
    let child_depth = depth.checked_add(1).ok_or(PortableError::IntegerOverflow {
        context: "value depth",
    })?;

    let tag = reader.u8()?;
    match tag {
        value_tag::NULL => Ok(Value::Null),
        value_tag::FALSE => Ok(Value::Bool(false)),
        value_tag::TRUE => Ok(Value::Bool(true)),
        value_tag::UNDEFINED => Ok(Value::Undefined),
        value_tag::INT => Ok(Value::Number(Number::Int(reader.zigzag()?))),
        value_tag::UINT => Ok(Value::Number(Number::UInt(reader.varint()?))),
        value_tag::FLOAT => Ok(Value::Number(Number::Float(reader.f64_bits()?))),
        value_tag::BIGINT => {
            let text = strings.get(reader.varint_u32()?)?;
            let number = Number::from_str(text).map_err(|_| PortableError::InvalidNumber)?;
            Ok(Value::Number(number))
        }
        value_tag::STRING => {
            let text = strings.get(reader.varint_u32()?)?;
            Ok(Value::String(text.into()))
        }
        value_tag::ARRAY => {
            let count = read_collection_len(reader, limits, "array length")?;
            // One byte is the minimum size of any encoded value, so a length
            // larger than the remaining bytes is rejected before allocating.
            ensure_representable(reader, count)?;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                items.push(decode_value(reader, strings, child_depth, limits, budget)?);
            }
            Ok(Value::from(items))
        }
        value_tag::SET => {
            let count = read_collection_len(reader, limits, "set length")?;
            ensure_representable(reader, count)?;
            let mut items = BTreeSet::new();
            for _ in 0..count {
                items.insert(decode_value(reader, strings, child_depth, limits, budget)?);
            }
            Ok(Value::from(items))
        }
        value_tag::OBJECT => {
            let count = read_collection_len(reader, limits, "object length")?;
            let pair_bytes = count.checked_mul(2).ok_or(PortableError::IntegerOverflow {
                context: "object length",
            })?;
            ensure_representable(reader, pair_bytes)?;
            let mut fields = Object::new();
            for _ in 0..count {
                let key = decode_value(reader, strings, child_depth, limits, budget)?;
                let field_value = decode_value(reader, strings, child_depth, limits, budget)?;
                fields.insert(key, field_value);
            }
            Ok(Value::Object(crate::Rc::new(fields)))
        }
        other => Err(PortableError::UnknownValueTag { tag: other }),
    }
}

fn read_collection_len(
    reader: &mut Reader<'_>,
    limits: &PortableLimits,
    label: &'static str,
) -> PortableResult<usize> {
    let count = reader.varint_usize()?;
    PortableLimits::check(label, count, limits.max_collection_len)?;
    Ok(count)
}

/// Reject a declared element count that cannot possibly fit in the remaining
/// bytes, so an attacker cannot make the decoder reserve a huge allocation.
const fn ensure_representable(reader: &Reader<'_>, count: usize) -> PortableResult<()> {
    if count > reader.remaining() {
        return Err(PortableError::Truncated {
            offset: reader.position(),
            needed: count,
            available: reader.remaining(),
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use alloc::string::String;

    fn round_trip(value: &Value) -> Value {
        let limits = PortableLimits::new();
        let mut strings = StringTableBuilder::new();
        let mut writer = Writer::new();
        encode_value(&mut writer, &mut strings, value, 0, &limits).unwrap();
        let body = writer.into_vec();
        let table_body = strings.encode().unwrap();
        let table = StringTable::decode(&table_body, &limits).unwrap();
        let mut reader = Reader::new(&body);
        let mut budget = ValueBudget::new(&limits);
        let decoded = decode_value(&mut reader, &table, 0, &limits, &mut budget).unwrap();
        assert!(reader.is_empty());
        decoded
    }

    #[test]
    fn scalars_round_trip() {
        for value in [
            Value::Null,
            Value::Bool(true),
            Value::Bool(false),
            Value::Undefined,
            Value::String("hello".into()),
            Value::Number(Number::Int(-42)),
            Value::Number(Number::UInt(u64::MAX)),
            Value::Number(Number::Float(1.5)),
        ] {
            assert_eq!(round_trip(&value), value);
        }
    }

    #[test]
    fn undefined_is_distinct_from_null() {
        assert_ne!(round_trip(&Value::Undefined), Value::Null);
        assert_eq!(round_trip(&Value::Undefined), Value::Undefined);
    }

    #[test]
    fn sets_round_trip() {
        let mut set = BTreeSet::new();
        set.insert(Value::from(3_i64));
        set.insert(Value::from(1_i64));
        set.insert(Value::String("x".into()));
        let value = Value::from(set);
        assert_eq!(round_trip(&value), value);
    }

    #[test]
    fn arbitrary_object_keys_round_trip() {
        let mut object = Object::new();
        object.insert(Value::from(1_i64), Value::String("int-key".into()));
        object.insert(
            Value::from(alloc::vec![Value::from(1_i64), Value::from(2_i64)]),
            Value::String("array-key".into()),
        );
        object.insert(Value::Null, Value::Undefined);
        let value = Value::Object(crate::Rc::new(object));
        assert_eq!(round_trip(&value), value);
    }

    #[test]
    fn big_numbers_round_trip() {
        let text = "123456789012345678901234567890123456789012345678901234567890";
        let number = Number::from_str(text).unwrap();
        let value = Value::Number(number);
        let decoded = round_trip(&value);
        assert_eq!(decoded, value);
        let formatted = match decoded {
            Value::Number(ref n) => n.format_decimal(),
            _ => String::new(),
        };
        assert_eq!(formatted, String::from(text));
    }

    #[test]
    fn depth_limit_enforced() {
        let mut limits = PortableLimits::new();
        limits.max_value_depth = 2;
        let nested = Value::from(alloc::vec![Value::from(alloc::vec![Value::from(
            alloc::vec![Value::Null]
        )])]);
        let mut strings = StringTableBuilder::new();
        let mut writer = Writer::new();
        assert!(matches!(
            encode_value(&mut writer, &mut strings, &nested, 0, &limits),
            Err(PortableError::DepthExceeded { .. })
        ));
    }

    #[test]
    fn oversized_declared_length_rejected() {
        let limits = PortableLimits::new();
        let mut writer = Writer::new();
        writer.u8(value_tag::ARRAY);
        writer.varint(1_000_000);
        let body = writer.into_vec();
        let table_body = StringTableBuilder::new().encode().unwrap();
        let table = StringTable::decode(&table_body, &limits).unwrap();
        let mut reader = Reader::new(&body);
        let mut budget = ValueBudget::new(&limits);
        assert!(matches!(
            decode_value(&mut reader, &table, 0, &limits, &mut budget),
            Err(PortableError::Truncated { .. })
        ));
    }
}
