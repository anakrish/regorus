// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared, deduplicated UTF-8 string table.
//!
//! Every string in the artifact (rule names, builtin names, entry point paths,
//! source text, literal strings, metadata) is stored exactly once here and
//! referenced by index.  The layout is designed so a managed reader can slice
//! the blob without copying and materialize strings lazily:
//!
//! ```text
//! u32 count
//! u32 blob_len
//! (count + 1) x u32 offsets   // offsets[0] == 0, offsets[count] == blob_len
//! blob_len bytes of UTF-8
//! ```

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::errors::{PortableError, PortableLimits, PortableResult};
use super::io::{Reader, Writer};

/// Builds the deduplicated string table while other sections are encoded.
///
/// The first entry is always the empty string, so index `0` can be used as a
/// well-known "no text" reference.
#[derive(Debug, Default)]
pub struct StringTableBuilder<'a> {
    entries: Vec<Cow<'a, str>>,
    lookup: BTreeMap<Cow<'a, str>, u32>,
}

impl<'a> StringTableBuilder<'a> {
    /// Create a builder pre-seeded with the empty string at index 0.
    pub fn new() -> Self {
        let mut builder = Self {
            entries: Vec::new(),
            lookup: BTreeMap::new(),
        };
        builder.entries.push(Cow::Borrowed(""));
        builder.lookup.insert(Cow::Borrowed(""), 0);
        builder
    }

    /// Number of interned strings.
    #[cfg(test)]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Intern a borrowed string, returning its index.
    pub fn intern(&mut self, text: &'a str) -> PortableResult<u32> {
        if let Some(&existing) = self.lookup.get(text) {
            return Ok(existing);
        }
        let index = self.next_index()?;
        self.entries.push(Cow::Borrowed(text));
        self.lookup.insert(Cow::Borrowed(text), index);
        Ok(index)
    }

    /// Intern an owned string, returning its index.
    pub fn intern_owned(&mut self, text: String) -> PortableResult<u32> {
        if let Some(&existing) = self.lookup.get(text.as_str()) {
            return Ok(existing);
        }
        let index = self.next_index()?;
        self.entries.push(Cow::Owned(text.clone()));
        self.lookup.insert(Cow::Owned(text), index);
        Ok(index)
    }

    fn next_index(&self) -> PortableResult<u32> {
        u32::try_from(self.entries.len()).map_err(|_| PortableError::LimitExceeded {
            limit: "string table entries",
            value: self.entries.len(),
            max: usize::try_from(u32::MAX).unwrap_or(usize::MAX),
        })
    }

    /// Encode the table body.
    pub fn encode(&self) -> PortableResult<Vec<u8>> {
        let count =
            u32::try_from(self.entries.len()).map_err(|_| PortableError::LimitExceeded {
                limit: "string table entries",
                value: self.entries.len(),
                max: usize::try_from(u32::MAX).unwrap_or(usize::MAX),
            })?;

        let mut blob_len: usize = 0;
        for entry in &self.entries {
            blob_len = blob_len
                .checked_add(entry.len())
                .ok_or(PortableError::IntegerOverflow {
                    context: "string table blob length",
                })?;
        }
        let blob_len_u32 = u32::try_from(blob_len).map_err(|_| PortableError::LimitExceeded {
            limit: "string table bytes",
            value: blob_len,
            max: usize::try_from(u32::MAX).unwrap_or(usize::MAX),
        })?;

        let mut writer = Writer::new();
        writer.u32(count);
        writer.u32(blob_len_u32);

        let mut running: u32 = 0;
        writer.u32(running);
        for entry in &self.entries {
            let entry_len =
                u32::try_from(entry.len()).map_err(|_| PortableError::IntegerOverflow {
                    context: "string table entry length",
                })?;
            running = running
                .checked_add(entry_len)
                .ok_or(PortableError::IntegerOverflow {
                    context: "string table offsets",
                })?;
            writer.u32(running);
        }

        for entry in &self.entries {
            writer.bytes(entry.as_bytes());
        }

        Ok(writer.into_vec())
    }
}

/// Read-only view over an encoded string table.
///
/// Holds borrowed slices only; strings are materialized on demand.
#[derive(Debug)]
pub struct StringTable<'a> {
    offsets: &'a [u8],
    blob: &'a [u8],
    count: usize,
}

impl<'a> StringTable<'a> {
    /// Parse and validate a string table section body.
    pub fn decode(body: &'a [u8], limits: &PortableLimits) -> PortableResult<Self> {
        let mut reader = Reader::new(body);
        let count = reader.u32()?;
        let blob_len = reader.u32()?;

        let count_usize = usize::try_from(count).map_err(|_| PortableError::IntegerOverflow {
            context: "string table count",
        })?;
        PortableLimits::check("string table entries", count_usize, limits.max_strings)?;

        let blob_len_usize =
            usize::try_from(blob_len).map_err(|_| PortableError::IntegerOverflow {
                context: "string table blob length",
            })?;
        PortableLimits::check(
            "string table bytes",
            blob_len_usize,
            limits.max_string_bytes,
        )?;

        let offsets_entries = count_usize
            .checked_add(1)
            .ok_or(PortableError::IntegerOverflow {
                context: "string table offsets",
            })?;
        let offsets_bytes =
            offsets_entries
                .checked_mul(4)
                .ok_or(PortableError::IntegerOverflow {
                    context: "string table offsets",
                })?;

        let offsets = reader.take(offsets_bytes)?;
        let blob = reader.take(blob_len_usize)?;
        reader.expect_end(super::format::SECTION_STRINGS)?;

        let table = Self {
            offsets,
            blob,
            count: count_usize,
        };
        table.validate()?;
        Ok(table)
    }

    /// Number of entries in the table.
    pub const fn len(&self) -> usize {
        self.count
    }

    fn raw_offset(&self, index: usize) -> PortableResult<u32> {
        let start = index.checked_mul(4).ok_or(PortableError::IntegerOverflow {
            context: "string table offsets",
        })?;
        let end = start.checked_add(4).ok_or(PortableError::IntegerOverflow {
            context: "string table offsets",
        })?;
        let slice = self
            .offsets
            .get(start..end)
            .ok_or(PortableError::MalformedStringTable {
                index: u32::try_from(index).unwrap_or(u32::MAX),
            })?;
        let bytes =
            <[u8; 4]>::try_from(slice).map_err(|_| PortableError::MalformedStringTable {
                index: u32::try_from(index).unwrap_or(u32::MAX),
            })?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn validate(&self) -> PortableResult<()> {
        let blob_len =
            u32::try_from(self.blob.len()).map_err(|_| PortableError::IntegerOverflow {
                context: "string table blob length",
            })?;

        let mut previous = self.raw_offset(0)?;
        if previous != 0 {
            return Err(PortableError::MalformedStringTable { index: 0 });
        }
        for index in 1..=self.count {
            let current = self.raw_offset(index)?;
            if current < previous || current > blob_len {
                return Err(PortableError::MalformedStringTable {
                    index: u32::try_from(index).unwrap_or(u32::MAX),
                });
            }
            previous = current;
        }
        if previous != blob_len {
            return Err(PortableError::MalformedStringTable {
                index: u32::try_from(self.count).unwrap_or(u32::MAX),
            });
        }
        Ok(())
    }

    /// Resolve a string by index, validating UTF-8 on first access.
    pub fn get(&self, index: u32) -> PortableResult<&'a str> {
        let index_usize = usize::try_from(index).map_err(|_| PortableError::IntegerOverflow {
            context: "string index",
        })?;
        if index_usize >= self.len() {
            return Err(PortableError::StringIndexOutOfRange {
                index,
                count: self.len(),
            });
        }
        let start = self.raw_offset(index_usize)?;
        let end = self.raw_offset(index_usize.checked_add(1).ok_or(
            PortableError::IntegerOverflow {
                context: "string index",
            },
        )?)?;
        let start_usize = usize::try_from(start).map_err(|_| PortableError::IntegerOverflow {
            context: "string offset",
        })?;
        let end_usize = usize::try_from(end).map_err(|_| PortableError::IntegerOverflow {
            context: "string offset",
        })?;
        let bytes = self
            .blob
            .get(start_usize..end_usize)
            .ok_or(PortableError::MalformedStringTable { index })?;
        core::str::from_utf8(bytes).map_err(|_| PortableError::InvalidUtf8 { index })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn intern_deduplicates() {
        let mut builder = StringTableBuilder::new();
        let first = builder.intern("hello").unwrap();
        let second = builder.intern("hello").unwrap();
        assert_eq!(first, second);
        assert_eq!(builder.len(), 2);
        assert_eq!(builder.intern("").unwrap(), 0);
    }

    #[test]
    fn round_trip() {
        let mut builder = StringTableBuilder::new();
        let a = builder.intern("alpha").unwrap();
        let b = builder.intern_owned(String::from("β-unicode")).unwrap();
        let body = builder.encode().unwrap();

        let limits = PortableLimits::new();
        let table = StringTable::decode(&body, &limits).unwrap();
        assert_eq!(table.len(), 3);
        assert_eq!(table.get(0).unwrap(), "");
        assert_eq!(table.get(a).unwrap(), "alpha");
        assert_eq!(table.get(b).unwrap(), "β-unicode");
        assert!(matches!(
            table.get(99),
            Err(PortableError::StringIndexOutOfRange { .. })
        ));
    }

    #[test]
    fn rejects_non_monotonic_offsets() {
        let mut writer = Writer::new();
        writer.u32(1); // count
        writer.u32(4); // blob_len
        writer.u32(4); // offsets[0] must be 0
        writer.u32(4);
        writer.bytes(b"abcd");
        let body = writer.into_vec();
        let limits = PortableLimits::new();
        assert!(matches!(
            StringTable::decode(&body, &limits),
            Err(PortableError::MalformedStringTable { .. })
        ));
    }
}
