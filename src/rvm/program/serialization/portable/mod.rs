// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! **RVMP** — the portable RVM execution artifact format.
//!
//! # Why a purpose-built format
//!
//! [`Program::serialize_binary`] (format version 6) is a Rust-shaped artifact:
//! most of it is `postcard` output driven by `#[derive(Serialize)]` on Rust
//! types.  It is compact and fast in Rust, but reading it from another
//! language means reimplementing `serde`'s derived layout, which is an
//! undocumented, silently-changing contract.  That is exactly the dependency a
//! managed (C#) runtime must not take.
//!
//! `RVMP` is therefore a small, explicitly specified, sectioned container:
//!
//! * **Magic, version, feature flags, section directory** — a reader validates
//!   sizes and counts before it allocates, and can skip sections it does not
//!   understand as long as they are not flagged must-understand.
//! * **Fixed-width instruction words** — the instruction stream is a flat
//!   8-byte-stride array that a managed reader can bulk-copy or reinterpret.
//! * **A single shared string table** — every name, path, and source text is
//!   stored once; readers can slice the UTF-8 blob without copying.
//! * **A tagged value encoding** that covers `Undefined`, `Set`, arbitrary
//!   object keys, and arbitrary-precision numbers — none of which JSON or a
//!   generic schema-less format expresses correctly.
//! * **Deterministic output** — sorted maps/sets, canonical LEB128, zeroed
//!   reserved fields.  The same program always encodes to the same bytes.
//! * **`no_std` friendly** — no new dependencies, `core`/`alloc` only, no
//!   `unsafe`.
//!
//! MessagePack was evaluated and rejected: it is self-describing (so it pays
//! per-field tag overhead without giving section-level skipping), it has no
//! notion of a section directory or bounded allocation, canonical output
//! requires extra rules on top of the spec, arbitrary-precision numbers and
//! `Undefined` need custom extension types anyway, and it would add a Rust
//! dependency plus a managed dependency for no structural benefit.  See
//! `docs/rvm/portable-format.md` for the full comparison and the normative
//! wire specification.
//!
//! # Compatibility
//!
//! This is **additive**.  [`Program::serialize_binary`] /
//! [`Program::deserialize_binary`] (`REGO`, v6) are untouched and remain the
//! default.  Portable artifacts use a different magic (`RVMP`), so the two can
//! always be told apart — see [`Program::is_portable_artifact`].

mod decode;
mod encode;
pub mod format;
mod instructions;
mod io;
mod strings;
mod values;

#[cfg(test)]
mod tests;

pub mod errors;

use alloc::vec::Vec;

pub use errors::{
    PortableError, PortableInfo, PortableLimits, PortableResult, PortableWriteOptions,
};

use super::super::Program;

impl Program {
    /// Serialize this program to the portable `RVMP` artifact format.
    ///
    /// Includes sources, spans, and metadata.  Use
    /// [`Program::serialize_portable_with_options`] for a smaller,
    /// execution-only artifact.
    ///
    /// Output is deterministic: identical programs produce identical bytes.
    pub fn serialize_portable(&self) -> PortableResult<Vec<u8>> {
        encode::encode_program(self, &PortableWriteOptions::all())
    }

    /// Serialize this program to the portable format, choosing which optional
    /// sections to emit.
    pub fn serialize_portable_with_options(
        &self,
        options: &PortableWriteOptions,
    ) -> PortableResult<Vec<u8>> {
        encode::encode_program(self, options)
    }

    /// Deserialize a portable `RVMP` artifact using the default limits.
    ///
    /// Unlike [`Program::deserialize_binary`], this never returns a partial
    /// program: an artifact either decodes into a fully executable program or
    /// the call fails with a typed [`PortableError`].
    pub fn deserialize_portable(data: &[u8]) -> PortableResult<Self> {
        decode::decode_program(data, &PortableLimits::new())
    }

    /// Deserialize a portable `RVMP` artifact with caller-supplied limits.
    pub fn deserialize_portable_with_limits(
        data: &[u8],
        limits: &PortableLimits,
    ) -> PortableResult<Self> {
        decode::decode_program(data, limits)
    }

    /// Read the artifact header without decoding the program body.
    ///
    /// Useful for cheap capability checks (for example "does this program
    /// suspend?") before committing to a full load.
    pub fn inspect_portable(data: &[u8]) -> PortableResult<PortableInfo> {
        decode::inspect(data)
    }

    /// Returns `true` when `data` starts with a portable artifact header this
    /// build can read.  Does not validate the body.
    pub fn is_portable_artifact(data: &[u8]) -> bool {
        decode::is_portable_artifact(data)
    }
}
