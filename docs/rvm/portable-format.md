<!-- Copyright (c) Microsoft Corporation. All rights reserved. -->
<!-- Licensed under the MIT License. -->

# RVMP — the portable RVM artifact format

**Status:** stable for format version `1`.
**Implementation:** `src/rvm/program/serialization/portable/`.
**Rust API:** `Program::serialize_portable`, `Program::deserialize_portable`,
`Program::inspect_portable`, `Program::is_portable_artifact`.

`RVMP` is the language-neutral on-disk container for a compiled Regorus RVM
program. It exists so that a non-Rust host (today: a C# loader) can read a
compiled policy without reimplementing `serde`'s derived layout.

Everything in this document is normative. All constants live in
[`format.rs`](../../src/rvm/program/serialization/portable/format.rs) and are
the single source of truth; if this document and that file disagree, the file
wins.

---

## 1. Why not the existing binary format, JSON, or MessagePack

| Option | Why it was rejected |
| --- | --- |
| `Program::serialize_binary` (`REGO`, v6) | Mostly `postcard` output driven by `#[derive(Serialize)]` on Rust types. The layout is an undocumented contract that changes silently when a Rust field is added or reordered. A managed loader must not depend on it. |
| JSON | Cannot express `Undefined`, sets, non-string object keys, or arbitrary-precision integers without inventing an encoding on top. No bounded allocation, no section skipping, ~3–5x larger. |
| MessagePack | Self-describing, so it pays per-field tag overhead without giving section-level skipping. No section directory, no declared-size validation, canonical output needs extra rules layered on the spec, and `Undefined`/sets/bignums still need custom extension types. Adds a dependency on both sides for no structural benefit. |

`RVMP` gives instead:

* a **section directory** — a reader validates sizes and counts before it
  allocates, and can skip sections it does not understand;
* **fixed-width instruction words** — the instruction stream is a flat
  8-byte-stride array a managed reader can bulk-copy;
* a **single shared string table** — every name, path, and source text is
  stored once and can be sliced without copying;
* a **tagged value encoding** that covers `Undefined`, sets, arbitrary object
  keys, and arbitrary-precision numbers;
* **determinism** — the same program always encodes to the same bytes;
* **`no_std` compatibility** — `core` + `alloc` only, no new dependencies, no
  `unsafe`.

---

## 2. Conventions

* All multi-byte integers are **little-endian**.
* `varint` is **canonical LEB128** over `u64`: minimal length, at most 10
  bytes. Overlong encodings are rejected.
* `zigzag` is a signed `i64` mapped as `(n << 1) ^ (n >> 63)` then written as a
  `varint`.
* `f64` is IEEE-754 binary64 written as 8 little-endian bytes of its bit
  pattern.
* `strref` is a `varint` index into the string table (section 2).
* All reserved bytes and reserved words are **zero**. Readers must reject a
  non-zero reserved header word.
* Section bodies start at an offset that is a multiple of **8**; padding bytes
  are zero.

---

## 3. File layout

```text
+---------------------------+ 0
| header (32 bytes)         |
+---------------------------+ 32
| directory                 |   section_count x 16 bytes
| (16 bytes per section)    |
+---------------------------+
| padding to 8-byte align   |
| section body              |
| padding to 8-byte align   |
| section body              |
| ...                       |
+---------------------------+ total_size
```

### 3.1 Header (32 bytes)

| Offset | Size | Field | Notes |
| --- | --- | --- | --- |
| 0 | 4 | `magic` | ASCII `RVMP` (`0x52 0x56 0x4D 0x50`) |
| 4 | 2 | `format_version` | `1` |
| 6 | 2 | `header_size` | must be `32` |
| 8 | 4 | `feature_flags` | see §3.3 |
| 12 | 4 | `section_count` | number of directory entries |
| 16 | 4 | `directory_offset` | must be `32` |
| 20 | 4 | `total_size` | must equal the file length |
| 24 | 4 | `checksum` | CRC-32 over bytes `[32, total_size)` |
| 28 | 4 | `reserved` | must be `0` |

`checksum` is CRC-32 (IEEE 802.3, reflected, polynomial `0xEDB88320`,
init `0xFFFFFFFF`, final xor `0xFFFFFFFF`) computed over the payload **after**
the header, i.e. the directory and all section bodies including padding.

The legacy container starts with `REGO`, so the two families can always be told
apart by their first four bytes.

### 3.2 Directory entry (16 bytes)

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | `section_id` |
| 4 | 4 | `offset` (from start of file) |
| 8 | 4 | `length` (bytes) |
| 12 | 4 | `section_flags` |

Directory entries are written **sorted by `section_id` ascending**, and section
bodies appear in that same order. A reader must reject: duplicate ids, a
section that starts inside the header/directory or extends past `total_size`,
and sections whose byte ranges overlap. (Ascending id order and 8-byte body
alignment are writer requirements; a reader may check them but the Rust
decoder does not depend on them.)

`section_flags` bit `0x00000001` (`SECTION_FLAG_REQUIRED`) means
*must-understand*: a reader that does not know the id must fail. Sections with
id `< 16` are execution-critical and are always written with this flag. Ids
`>= 16` are optional and carry flags `0`.

### 3.3 Feature flags

The low 16 bits are informational — an unknown bit there must be ignored. The
high 16 bits are must-understand — an unknown bit there must cause a load
failure (`UnsupportedFeatures`).

| Bit | Name | Meaning |
| --- | --- | --- |
| `1 << 0` | `FEATURE_DEBUG_INFO` | sources and/or spans present |
| `1 << 1` | `FEATURE_METADATA` | metadata section present |
| `1 << 2` | `FEATURE_HOST_AWAIT` | program contains `HostAwait` |
| `1 << 3` | `FEATURE_REGO_V0` | compiled with Rego v0 semantics |

No must-understand bits are defined in version 1
(`KNOWN_REQUIRED_FEATURES == 0`).

### 3.4 Section ids

| Id | Name | Required | Content |
| --- | --- | --- | --- |
| 1 | `PROGRAM_HEADER` | yes | scalar program header |
| 2 | `STRINGS` | yes | shared string table |
| 3 | `INSTRUCTIONS` | yes | fixed-width instruction words |
| 4 | `INSTRUCTION_PARAMS` | yes | instruction side tables |
| 5 | `LITERALS` | yes | literal value table |
| 6 | `BUILTINS` | yes | builtin declarations |
| 7 | `ENTRY_POINTS` | yes | ordered entry point table |
| 8 | `RULES` | yes | rule metadata |
| 9 | `RULE_TREE` | yes | rule lookup tree (a value) |
| 16 | `SOURCES` | no | source files |
| 17 | `SPANS` | no | per-instruction spans |
| 18 | `METADATA` | no | provenance and annotations |

A section body must be consumed exactly; trailing bytes inside a section are an
error (`TrailingSectionData`).

---

## 4. Section bodies

### 4.1 `PROGRAM_HEADER` (id 1, 8 bytes)

```text
u32 main_entry_point        // instruction index
u8  max_rule_window_size
u8  dispatch_window_size
u8  program_flags
u8  reserved                // 0
```

`program_flags`: `0x01` Rego v0, `0x02` needs runtime recursion check,
`0x04` has host-await. Unknown bits must be rejected.

### 4.2 `STRINGS` (id 2)

```text
u32 count
u32 blob_len
u32 offsets[count + 1]      // offsets[0] == 0, offsets[count] == blob_len
u8  blob[blob_len]          // UTF-8, not NUL-terminated
```

Entry `i` is `blob[offsets[i] .. offsets[i + 1]]`. Offsets must be
monotonically non-decreasing and the last must equal `blob_len`. Index `0` is
always the empty string, so `0` doubles as "no text". Every entry must be valid
UTF-8. Strings are deduplicated by the writer.

### 4.3 `INSTRUCTIONS` (id 3)

```text
u32 count
InstructionWord words[count]   // 8 bytes each
```

An `InstructionWord` is:

```text
offset 0  u8   opcode
offset 1  u8   a       // register / sub-mode
offset 2  u8   b       // register / sub-mode
offset 3  u8   c       // register / flag
offset 4  u16  imm0    // literal index, params index, or jump target
offset 6  u16  imm1    // secondary jump target
```

Unused fields are zero — that is what makes the encoding canonical. Opcodes are
**stable wire numbers assigned in `format::opcode`**; they are deliberately not
the Rust enum discriminants, so reordering the Rust `Instruction` enum cannot
change the wire format.

Operand mapping (`-` means the field is zero):

| Opcode | Mnemonic | a | b | c | imm0 | imm1 |
| --- | --- | --- | --- | --- | --- | --- |
| `0x01` | `Load` | dest | - | - | literal_idx | - |
| `0x02`..`0x04` | `LoadTrue`/`LoadFalse`/`LoadNull` | dest | - | - | - | - |
| `0x05` | `LoadBool` | dest | value (0/1) | - | - | - |
| `0x06`..`0x09` | `LoadData`/`LoadInput`/`LoadContext`/`LoadMetadata` | dest | - | - | - | - |
| `0x0A` | `Move` | dest | src | - | - | - |
| `0x0B`..`0x17` | `Add`…`Or` (binary ops) | dest | left | right | - | - |
| `0x18` | `Not` | dest | operand | - | - | - |
| `0x19` | `BuiltinCall` | - | - | - | params_index | - |
| `0x1A` | `HostAwait` | dest | arg | id | - | - |
| `0x1B` | `FunctionCall` | - | - | - | params_index | - |
| `0x1C` | `Return` | value | - | - | - | - |
| `0x1D` | `ObjectSet` | obj | key | value | - | - |
| `0x1E` | `ObjectCreate` | - | - | - | params_index | - |
| `0x1F` | `Index` | dest | container | key | - | - |
| `0x20` | `IndexLiteral` | dest | container | - | literal_idx | - |
| `0x21` | `ChainedIndex` | - | - | - | params_index | - |
| `0x22` | `ArrayNew` | dest | - | - | - | - |
| `0x23`/`0x24` | `ArrayPush`/`ArrayPushDefined` | arr | value | - | - | - |
| `0x25` | `ArrayCreate` | - | - | - | params_index | - |
| `0x26` | `SetNew` | dest | - | - | - | - |
| `0x27` | `SetAdd` | set | value | - | - | - |
| `0x28` | `SetCreate` | - | - | - | params_index | - |
| `0x29` | `Contains` | dest | collection | value | - | - |
| `0x2A` | `Count` | dest | collection | - | - | - |
| `0x2B` | `AssertEq` | left | right | - | - | - |
| `0x2C` | `Guard` | register | guard_mode | - | - | - |
| `0x2D` | `ReturnUndefinedIfNotTrue` | condition | - | - | - | - |
| `0x2E` | `CoalesceUndefinedToNull` | register | - | - | - | - |
| `0x2F` | `LoopStart` | - | - | - | params_index | - |
| `0x30` | `LoopNext` | - | - | - | body_start | loop_end |
| `0x31` | `CallRule` | dest | - | - | rule_index | - |
| `0x32` | `RuleInit` | result_reg | - | - | rule_index | - |
| `0x33` | `VirtualDataDocumentLookup` | - | - | - | params_index | - |
| `0x34`..`0x36` | `DestructuringSuccess`/`RuleReturn`/`Halt` | - | - | - | - | - |
| `0x37` | `ComprehensionBegin` | - | - | - | params_index | - |
| `0x38` | `ComprehensionYield` | value_reg | key_reg | has_key (0/1) | - | - |
| `0x39` | `ComprehensionEnd` | - | - | - | - | - |
| `0x3A` | `PolicyCondition` | dest | left | right | policy_op | - |
| `0x3B` | `LogicalBlockStart` | block_mode | result | - | end_pc | - |
| `0x3C`/`0x3D` | `AllOfNext`/`AnyOfNext` | check | result | - | end_pc | - |
| `0x3E` | `LogicalBlockEnd` | block_mode | result | - | - | - |

Sub-code enumerations:

| Enum | Codes |
| --- | --- |
| `LoopMode` | `0` Any, `1` Every, `2` ForEach |
| `ComprehensionMode` | `0` Set, `1` Array, `2` Object |
| `GuardMode` | `0` Not, `1` Condition, `2` NotUndefined |
| `LogicalBlockMode` | `0` AllOf, `1` AnyOf |
| `RuleType` | `0` Complete, `1` PartialSet, `2` PartialObject |
| `LiteralOrRegister` | `0` Literal (`u16` follows), `1` Register (`u8` follows) |
| `PolicyOp` | `0` Equals … `20` Not — see `format::policy_op` |

### 4.4 `INSTRUCTION_PARAMS` (id 4)

Nine side tables, in this fixed order. Each is preceded by a `u32` count.

```text
u32 loop_count
  { u8 mode; u8 collection; u8 key_reg; u8 value_reg; u8 result_reg;
    u8 reserved(0); u16 body_start; u16 loop_end }

u32 builtin_call_count
  { u8 dest; u8 num_args; u8 args[num_args]; u16 builtin_index }

u32 function_call_count
  { u8 dest; u8 num_args; u8 args[num_args]; u16 func_rule_index }

u32 object_create_count
  { u8 dest; u16 template_literal_idx;
    varint literal_key_field_count; { u16 literal_index; u8 register } *;
    varint field_count;             { u8 key_register; u8 value_register } * }

u32 array_create_count
  { u8 dest; varint element_count; u8 elements[element_count] }

u32 set_create_count
  { u8 dest; varint element_count; u8 elements[element_count] }

u32 virtual_data_lookup_count
  { u8 dest; path_components }

u32 chained_index_count
  { u8 dest; u8 root; path_components }

u32 comprehension_count
  { u8 mode; u8 collection_reg; u8 result_reg; u8 key_reg; u8 value_reg;
    u8 reserved(0); u16 body_start; u16 comprehension_end }
```

`path_components` is `varint count` followed by `count` entries, each a `u8`
tag (`0` literal, `1` register) then either a `u16` literal index or a `u8`
register.

`num_args` for builtin/function calls is bounded by the RVM's register file, so
`args` is a plain byte run.

### 4.5 `LITERALS` (id 5)

```text
u32 count
value literals[count]      // see §5
```

### 4.6 `BUILTINS` (id 6)

```text
u32 count
{ strref name; u16 num_args } entries[count]
```

Only the **name** is stored. Function pointers are a Rust-only concern; the
decoder re-resolves each name against its own builtin registry. A name that the
loading runtime does not implement makes the load fail — a program is never
handed back with a builtin it cannot call.

### 4.7 `ENTRY_POINTS` (id 7)

```text
u32 count
{ strref path; varint rule_index } entries[count]
```

Order is significant and preserved: entry points are addressable by index as
well as by path. `path` is the fully qualified rule path, e.g.
`data.example.authz.allow`.

### 4.8 `RULES` (id 8)

```text
u32 count
rule entries[count]
```

Each `rule` is:

```text
strref name
u8     rule_type              // see RuleType codes
u8     rule_flags
u8     result_reg
u8     num_registers
u16    default_literal_index  // present only if rule_flags & 0x02
varint definition_count
  varint instruction_count
    varint instruction_index *      // repeated instruction_count times
  ...                               // repeated definition_count times
varint destructuring_block_count
  varint slot *                     // 0 = none, otherwise entry_point + 1
[ varint num_params                 // present only if rule_flags & 0x01
  varint param_name_count
  strref param_name * ]
```

`rule_flags`: `0x01` has function info, `0x02` has default literal index,
`0x04` early exit on first success.

### 4.9 `RULE_TREE` (id 9)

A single encoded value (§5) that maps path segments to rule indices, e.g.
`{"example": {"authz": {"allow": 0}}}`.

### 4.10 `SOURCES` (id 16, optional)

```text
u32 count
{ strref name; strref content } entries[count]
```

### 4.11 `SPANS` (id 17, optional)

```text
u32 count                     // equals the instruction count when present
{ u32 source_index; u32 line; u32 column; u32 length } records[count]
```

`source_index == 0xFFFFFFFF` (`SPAN_ABSENT`) means "no span for this
instruction"; the other three words are then zero.

### 4.12 `METADATA` (id 18, optional)

```text
strref compiler_version
strref compiled_at
strref source_info
u8     optimization_level
strref language
varint annotation_count
  { strref key; value annotation } *
```

Annotations are written in key-sorted order.

---

## 5. Value encoding

A value is a one-byte tag followed by tag-specific data.

| Tag | Meaning | Payload |
| --- | --- | --- |
| `0x00` | `Null` | — |
| `0x01` | `false` | — |
| `0x02` | `true` | — |
| `0x03` | `Undefined` | — |
| `0x10` | signed integer | `zigzag` `i64` |
| `0x11` | unsigned integer | `varint` `u64` |
| `0x12` | float | 8 bytes IEEE-754 binary64, little-endian |
| `0x13` | big integer | `strref` to its exact decimal text |
| `0x20` | string | `strref` |
| `0x30` | array | `varint count`, then `count` values |
| `0x31` | set | `varint count`, then `count` values |
| `0x32` | object | `varint count`, then `count` (key, value) value pairs |

Notes:

* `Undefined` is a **distinct tag**, never `Null`. Rego is three-valued;
  conflating them changes allow/deny outcomes.
* Object keys are full values, not just strings.
* An integer that fits `i64` or `u64` is always written as `0x10`/`0x11`, never
  as `0x13`. This keeps encoding idempotent.
* A writer **must** emit set elements and object keys in Regorus `Value`
  ordering (`Undefined < Null < Bool < Number < String < Array < Set <
  Object`, then structurally). Readers accept any order but the canonical form
  is the sorted one; a writer that does not sort will not reproduce
  byte-identical artifacts.

---

## 6. Determinism

For a given `Program` and `PortableWriteOptions`, `serialize_portable` is a
pure function of the program: the same input always yields the same bytes.
This is guaranteed by:

* a fixed section order (sorted by id) and fixed table order within sections;
* canonical LEB128 (minimal length, overlong encodings rejected on read);
* sorted set elements, object keys, and metadata annotations;
* zeroed reserved fields and zero padding;
* string table order that follows first-use order, which is itself
  deterministic because the encoders run in a fixed order.

`decode(encode(p)) == p` and `encode(decode(encode(p))) == encode(p)` are both
covered by tests.

---

## 7. Security and resource bounds

The decoder is written so that a hostile artifact cannot make it panic, spin,
or allocate unboundedly.

* Every declared count is checked against `PortableLimits` **and** against the
  bytes actually remaining, before any allocation. A 100-byte file cannot ask
  for a 4-billion-element vector.
* Every offset computation uses checked arithmetic.
* Every index (literal, rule, builtin, string, jump target, params index) is
  validated against the table it points into.
* Value nesting is bounded by depth (default 64), total node count (default
  4,000,000), and per-collection length (default 1,000,000).
* CRC-32 is verified before any section is parsed.
* Unknown opcodes, unknown value tags, and out-of-range enum sub-codes are
  rejected.
* No `unsafe`, no unchecked indexing, no unchecked arithmetic.

Default limits (`PortableLimits::new()`): 64 MiB artifact, 64 sections,
262,144 strings, 32 MiB string blob, 65,535 instructions, 65,535 literals,
4,000 rules, 1,000 entry points, 256 sources, 512 builtins. Callers that need
different bounds use `Program::deserialize_portable_with_limits`.

Failures are typed (`PortableError`) and name the offending offset, index, or
limit. The decoder never returns a partially populated program: an artifact
either decodes into a fully executable `Program` or the call fails.

---

## 8. Versioning and migration

* `format_version` is `1`. A build accepts
  `MIN_FORMAT_VERSION ..= FORMAT_VERSION` and rejects anything else with
  `UnsupportedVersion`.
* **Never renumber** an existing section id, opcode, value tag, enum sub-code,
  or flag bit. New items are only ever appended.
* **Backward-compatible change** (no version bump needed): add a new optional
  section with id `>= 16` and flags `0`, or set a new *informational* feature
  flag bit. Old readers skip the section and ignore the bit.
* **Breaking change** (requires `format_version` bump to 2, and
  `MIN_FORMAT_VERSION` stays at 1 only if version 1 remains decodable):
  changing the meaning of an existing field, adding a required section, or
  adding a must-understand feature flag.
* A writer that needs to force old readers to refuse an artifact sets a bit in
  the must-understand range (`0xFFFF0000`).
* Programs whose `needs_recompilation` flag is set (a legacy partial
  deserialization result) cannot be exported; `serialize_portable` fails with
  `ProgramInvalid`. Recompile from source instead.

### Relationship to the legacy `REGO` v6 format

The legacy format is **unchanged and still the default** for
`Program::serialize_binary` / `Program::deserialize_binary` and for every
existing binding. `RVMP` is purely additive:

| | Legacy | Portable |
| --- | --- | --- |
| Magic | `REGO` | `RVMP` |
| Version | `6` (`SERIALIZATION_VERSION`) | `1` (`FORMAT_VERSION`) |
| Layout | `postcard` + derived serde | explicit, documented |
| Partial loads | possible (`DeserializationResult::Partial`) | never |
| Cross-language | not supported | supported |

`Program::is_portable_artifact` distinguishes them; each reader rejects the
other family's magic. Both encode the same program, so an artifact can be
re-emitted in either container after a load.

---

## 9. Requirements for a C# (or other managed) loader

A conforming reader must:

1. Verify `magic == "RVMP"`, `header_size == 32`, `directory_offset == 32`,
   `reserved == 0`, and `total_size == file.Length`.
2. Reject `format_version` outside the supported range.
3. Reject any set bit in `feature_flags & 0xFFFF0000` it does not implement;
   ignore unknown bits in `feature_flags & 0x0000FFFF`.
4. Verify CRC-32 over bytes `[32, total_size)` *before* parsing sections.
5. Validate the directory: ids unique, each section within
   `[directory_end, total_size]`, and no two byte ranges overlapping.
6. Fail on an unknown section whose flags have bit `0x1` set; skip an unknown
   section otherwise.
7. Require sections 1–9 to be present.
8. Apply its own allocation limits before allocating from any declared count,
   and cross-check each count against the remaining section bytes.
9. Reject overlong LEB128, non-UTF-8 string entries, non-monotonic string
   offsets, unknown opcodes, unknown value tags, and out-of-range enum
   sub-codes.
10. Bound value recursion by depth and total node count.
11. Model `Undefined` as a distinct value, separate from `Null`, and support
    sets and non-string object keys.
12. Preserve entry point order.
13. Treat the builtin table as **names only**, resolve them against its own
    builtin registry, and fail the load if a name is not implemented.
14. Cross-check the `FEATURE_REGO_V0` / `FEATURE_HOST_AWAIT` header flags
    against the corresponding `program_flags` bits; they must agree.

A conforming *writer* must additionally sort set elements, object keys, and
metadata annotations, emit canonical LEB128, zero all reserved fields and
padding, and write directory entries sorted by id — otherwise its output will
not be byte-identical to the Rust encoder's for the same program.

Recommended reader strategy in C#: memory-map or read the whole file into a
`byte[]`, then expose sections as `ReadOnlySpan<byte>` slices. Instructions can
be read with a single `MemoryMarshal.Cast<byte, ...>` over an 8-byte-stride
struct (the layout is explicitly little-endian; on a big-endian host, byte-swap
`imm0`/`imm1`). Strings can stay as slices into the blob and be materialized
lazily with `Encoding.UTF8.GetString`.

---

## 10. Producing and consuming artifacts

The `regorus` example binary has two commands for this
(see [`examples/regorus/rvm.rs`](../../examples/regorus/rvm.rs)):

```bash
# Compile Rego + data into a portable artifact (portable is the default).
cargo run --example regorus -- compile-rvm \
    --data examples/rvm_portable/policy.rego \
    --data examples/rvm_portable/data.json \
    --entrypoint data.example.authz.allow \
    --entrypoint data.example.authz.user_roles \
    --output target/rvm-artifacts/authz.rvmp \
    --listing target/rvm-artifacts/authz.rvmasm

# Evaluate one entry point out of the artifact.
cargo run --example regorus -- eval-rvm \
    --data examples/rvm_portable/data.json \
    --input examples/rvm_portable/input.json \
    --entrypoint data.example.authz.allow \
    target/rvm-artifacts/authz.rvmp

# Inspect the header without evaluating.
cargo run --example regorus -- eval-rvm --info target/rvm-artifacts/authz.rvmp
cargo run --example regorus -- eval-rvm --list-entrypoints target/rvm-artifacts/authz.rvmp
```

`--format legacy` writes the `REGO` v6 container instead; `eval-rvm` detects
either container from its magic bytes. `--execution-only` drops the sources,
spans, and metadata sections, which typically halves the artifact.

**Data is not baked into the artifact.** `data` participates in compilation
(rule tree construction) *and* must be supplied again at evaluation time, so
`eval-rvm` takes `--data` as well. `input` and `context` are runtime-only.

An end-to-end check lives in
[`tests/rvm/portable.rs`](../../tests/rvm/portable.rs) and the script
[`examples/rvm_portable/e2e.ps1`](../../examples/rvm_portable/e2e.ps1) /
[`e2e.sh`](../../examples/rvm_portable/e2e.sh).
