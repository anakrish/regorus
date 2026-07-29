// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bounds-checked primitive readers and writers for the RVMP format.
//!
//! Every integer read is bounds-checked, every offset computation is checked
//! for overflow, and LEB128 varints are rejected unless they use the minimal
//! encoding.  This makes decoding deterministic and canonical: re-encoding a
//! decoded artifact reproduces the original bytes.

use alloc::vec::Vec;

use super::errors::{PortableError, PortableResult};

/// Maximum number of bytes a canonical LEB128 `u64` may occupy.
const MAX_VARINT_BYTES: u32 = 10;

/// A cursor over a byte slice that never indexes out of bounds.
#[derive(Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Create a reader positioned at the start of `data`.
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Current offset from the start of the slice.
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Number of unread bytes.
    pub const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// True when every byte has been consumed.
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Consume `n` bytes.
    pub fn take(&mut self, n: usize) -> PortableResult<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(PortableError::IntegerOverflow {
                context: "reader offset",
            })?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or(PortableError::Truncated {
                offset: self.pos,
                needed: n,
                available: self.remaining(),
            })?;
        self.pos = end;
        Ok(slice)
    }

    /// Read one byte.
    pub fn u8(&mut self) -> PortableResult<u8> {
        let slice = self.take(1)?;
        slice.first().copied().ok_or(PortableError::Truncated {
            offset: self.pos,
            needed: 1,
            available: 0,
        })
    }

    /// Read a little-endian `u16`.
    pub fn u16(&mut self) -> PortableResult<u16> {
        let slice = self.take(2)?;
        let bytes = <[u8; 2]>::try_from(slice).map_err(|_| PortableError::Truncated {
            offset: self.pos,
            needed: 2,
            available: 0,
        })?;
        Ok(u16::from_le_bytes(bytes))
    }

    /// Read a little-endian `u32`.
    pub fn u32(&mut self) -> PortableResult<u32> {
        let slice = self.take(4)?;
        let bytes = <[u8; 4]>::try_from(slice).map_err(|_| PortableError::Truncated {
            offset: self.pos,
            needed: 4,
            available: 0,
        })?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Read a little-endian `u64`.
    pub fn u64(&mut self) -> PortableResult<u64> {
        let slice = self.take(8)?;
        let bytes = <[u8; 8]>::try_from(slice).map_err(|_| PortableError::Truncated {
            offset: self.pos,
            needed: 8,
            available: 0,
        })?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Read an IEEE-754 binary64 stored as little-endian bits.
    pub fn f64_bits(&mut self) -> PortableResult<f64> {
        Ok(f64::from_bits(self.u64()?))
    }

    /// Read a canonical (minimal) LEB128 `u64`.
    pub fn varint(&mut self) -> PortableResult<u64> {
        let start = self.pos;
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        let mut consumed: u32 = 0;

        loop {
            if consumed >= MAX_VARINT_BYTES || shift >= 64 {
                return Err(PortableError::MalformedVarint { offset: start });
            }
            let byte = self.u8()?;
            consumed = consumed
                .checked_add(1)
                .ok_or(PortableError::MalformedVarint { offset: start })?;

            let payload = u64::from(byte & 0x7F);
            let max_payload = u64::MAX
                .checked_shr(shift)
                .ok_or(PortableError::MalformedVarint { offset: start })?;
            if payload > max_payload {
                return Err(PortableError::MalformedVarint { offset: start });
            }
            let shifted = payload
                .checked_shl(shift)
                .ok_or(PortableError::MalformedVarint { offset: start })?;
            result |= shifted;

            if byte & 0x80 == 0 {
                // Reject overlong encodings so decoding stays canonical.
                if consumed > 1 && payload == 0 {
                    return Err(PortableError::MalformedVarint { offset: start });
                }
                return Ok(result);
            }

            shift = shift
                .checked_add(7)
                .ok_or(PortableError::MalformedVarint { offset: start })?;
        }
    }

    /// Read a canonical LEB128 varint and narrow it to `u32`.
    pub fn varint_u32(&mut self) -> PortableResult<u32> {
        let start = self.pos;
        let value = self.varint()?;
        u32::try_from(value).map_err(|_| PortableError::MalformedVarint { offset: start })
    }

    /// Read a canonical LEB128 varint and narrow it to `usize`.
    pub fn varint_usize(&mut self) -> PortableResult<usize> {
        let start = self.pos;
        let value = self.varint()?;
        usize::try_from(value).map_err(|_| PortableError::MalformedVarint { offset: start })
    }

    /// Read a zig-zag encoded LEB128 `i64`.
    pub fn zigzag(&mut self) -> PortableResult<i64> {
        let start = self.pos;
        let raw = self.varint()?;
        zigzag_decode(raw).ok_or(PortableError::MalformedVarint { offset: start })
    }

    /// Fail unless the reader is exhausted.
    pub const fn expect_end(&self, section_id: u32) -> PortableResult<()> {
        if self.is_empty() {
            return Ok(());
        }
        Err(PortableError::TrailingSectionData {
            id: section_id,
            remaining: self.remaining(),
        })
    }
}

/// Decode a zig-zag encoded unsigned value back to `i64`.
pub fn zigzag_decode(raw: u64) -> Option<i64> {
    let half = raw.checked_div(2)?;
    if raw & 1 == 0 {
        i64::try_from(half).ok()
    } else {
        let magnitude = i128::from(half).checked_add(1)?;
        let negated = magnitude.checked_neg()?;
        i64::try_from(negated).ok()
    }
}

/// Encode `value` using zig-zag so small magnitudes stay short.
pub fn zigzag_encode(value: i64) -> u64 {
    if value >= 0 {
        // 0 <= value <= i64::MAX, so 2*value fits in u64.
        u64::try_from(value).unwrap_or(0).saturating_mul(2)
    } else {
        // magnitude in 1..=2^63; encoded value is 2*magnitude - 1.
        let magnitude = i128::from(value).checked_neg().unwrap_or(0);
        let magnitude = u64::try_from(magnitude).unwrap_or(0);
        magnitude
            .checked_sub(1)
            .and_then(|v| v.checked_mul(2))
            .and_then(|v| v.checked_add(1))
            .unwrap_or(u64::MAX)
    }
}

/// A growable little-endian byte sink.
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// Create an empty writer.
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Number of bytes written so far.
    pub const fn len(&self) -> usize {
        self.buf.len()
    }

    /// Consume the writer, yielding the bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    /// Borrow the written bytes.
    pub const fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    /// Append a raw byte slice.
    pub fn bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Append one byte.
    pub fn u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    /// Append a little-endian `u16`.
    pub fn u16(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Append a little-endian `u32`.
    pub fn u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Append a little-endian `u64`.
    pub fn u64(&mut self, value: u64) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Append an IEEE-754 binary64 as little-endian bits.
    pub fn f64_bits(&mut self, value: f64) {
        self.u64(value.to_bits());
    }

    /// Append a canonical LEB128 `u64`.
    pub fn varint(&mut self, value: u64) {
        let mut remaining = value;
        loop {
            let byte = u8::try_from(remaining & 0x7F).unwrap_or(0);
            remaining = remaining.checked_shr(7).unwrap_or(0);
            if remaining == 0 {
                self.buf.push(byte);
                return;
            }
            self.buf.push(byte | 0x80);
        }
    }

    /// Append a `usize` as a canonical LEB128 varint.
    pub fn varint_usize(&mut self, value: usize) {
        self.varint(u64::try_from(value).unwrap_or(u64::MAX));
    }

    /// Append a zig-zag LEB128 `i64`.
    pub fn zigzag(&mut self, value: i64) {
        self.varint(zigzag_encode(value));
    }

    /// Pad with zero bytes until the length is a multiple of `alignment`.
    #[cfg(test)]
    pub fn align_to(&mut self, alignment: usize) {
        if alignment <= 1 {
            return;
        }
        let remainder = self.buf.len().checked_rem(alignment).unwrap_or(0);
        if remainder == 0 {
            return;
        }
        let padding = alignment.saturating_sub(remainder);
        for _ in 0..padding {
            self.buf.push(0);
        }
    }

    /// Overwrite four bytes at `offset` with a little-endian `u32`.
    pub fn patch_u32(&mut self, offset: usize, value: u32) -> PortableResult<()> {
        let end = offset
            .checked_add(4)
            .ok_or(PortableError::IntegerOverflow {
                context: "patch offset",
            })?;
        let slot = self
            .buf
            .get_mut(offset..end)
            .ok_or(PortableError::IntegerOverflow {
                context: "patch offset",
            })?;
        slot.copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip() {
        for value in [
            0_u64,
            1,
            127,
            128,
            300,
            65_535,
            1 << 32,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let mut w = Writer::new();
            w.varint(value);
            let bytes = w.into_vec();
            let mut r = Reader::new(&bytes);
            assert_eq!(r.varint().unwrap(), value);
            assert!(r.is_empty());
        }
    }

    #[test]
    fn zigzag_round_trip() {
        for value in [0_i64, -1, 1, -2, 2, i64::MIN, i64::MAX, -1234567, 1234567] {
            let mut w = Writer::new();
            w.zigzag(value);
            let bytes = w.into_vec();
            let mut r = Reader::new(&bytes);
            assert_eq!(r.zigzag().unwrap(), value);
        }
    }

    #[test]
    fn overlong_varint_rejected() {
        // 0x80 0x00 encodes 0 non-minimally.
        let bytes = [0x80_u8, 0x00];
        let mut r = Reader::new(&bytes);
        assert!(matches!(
            r.varint(),
            Err(PortableError::MalformedVarint { .. })
        ));
    }

    #[test]
    fn oversized_varint_rejected() {
        let bytes = [0xFF_u8; 12];
        let mut r = Reader::new(&bytes);
        assert!(matches!(
            r.varint(),
            Err(PortableError::MalformedVarint { .. })
        ));
    }

    #[test]
    fn truncated_read_reports_offset() {
        let bytes = [1_u8, 2];
        let mut r = Reader::new(&bytes);
        assert!(matches!(r.u32(), Err(PortableError::Truncated { .. })));
    }

    #[test]
    fn align_to_pads_with_zeroes() {
        let mut w = Writer::new();
        w.u8(1);
        w.align_to(8);
        assert_eq!(w.len(), 8);
        assert_eq!(w.as_slice(), &[1, 0, 0, 0, 0, 0, 0, 0]);
    }
}
