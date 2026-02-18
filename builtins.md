# Rego Builtins — Z3 Modelability Analysis

This document catalogs all 126 registered Rego builtins in regorus,
describes how each is currently handled by the Z3 symbolic translator,
and assesses what **can** be precisely modeled using Z3 theories.

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Already modeled with Z3 semantics |
| 🟢 | Can be precisely modeled using Z3 theories |
| 🟡 | Partially modelable (some constraints, not full semantics) |
| 🔴 | Not practically modelable in Z3 |
| ⚪ | Irrelevant to symbolic analysis |

**Current handling tiers** (in `translate_builtin_call`):

| Tier | Builtins | Treatment |
|------|----------|-----------|
| Special | `count` | SetCardinality extraction, concrete eval, string length via `str.len`, or fresh non-negative Int |
| Z3 String Theory | `startswith`, `endswith`, `contains`, `indexof`, `replace`, `substring`, `trim_prefix`, `trim_suffix` | Full Z3 string theory semantics with concrete eval fast path |
| Z3 Int Theory | `abs` | `ite(x >= 0, x, -x)` with concrete eval fast path |
| Z3 BV Theory | `bits.and`, `bits.or`, `bits.xor`, `bits.negate`, `bits.lsh`, `bits.rsh` | 64-bit bitvector ops with Int↔BV conversion |
| Sort-based | `is_string`, `is_number`, `is_boolean`, `is_array`, `is_set`, `is_object`, `is_null` | Resolves from concrete type, symbolic sort, or path registry |
| Concrete | `trace` | Always returns `true` |
| Bool (unconstrained) | `regex.match`, JWT verify builtins | Fresh unconstrained `Bool` |
| Int (unconstrained) | `sum`, `product`, `min`, `max`, `ceil`, `floor`, `round`, `to_number` | Fresh unconstrained `Int` |
| Default | ~80 builtins | Fresh unconstrained `String` |

---

## 1. Aggregates (6 builtins)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `count` | 1 | ✅ Special | ✅ | SetCardinality for symbolic sets; concrete eval; `str.len` for symbolic strings; fresh Int ≥ 0 |
| `sum` | 1 | Int | 🟡 | For concrete collections: evaluate directly. For symbolic: unconstrained Int is reasonable since the collection contents are typically unknown |
| `product` | 1 | Int | 🟡 | Same as `sum` |
| `min` | 1 | Int | 🟡 | For concrete collections: evaluate directly. Could constrain result ≤ all known elements |
| `max` | 1 | Int | 🟡 | For concrete collections: evaluate directly. Could constrain result ≥ all known elements |
| `sort` | 1 | Default | 🔴 | Returns an array — would need symbolic array theory. Not practical |

---

## 2. Strings (25 builtins)

Z3's sequence/string theory (`QF_SLIA`) provides native support for many string operations.

### Boolean-returning string builtins

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `startswith` | 2 | ✅ Z3 String | ✅ | `prefix.prefix(&full_str)` — Z3 `str.prefixof` |
| `endswith` | 2 | ✅ Z3 String | ✅ | `suffix.suffix(&full_str)` — Z3 `str.suffixof` |
| `contains` | 2 | ✅ Z3 String | ✅ | `s.contains(&substr)` — Z3 `str.contains` |
| `strings.any_prefix_match` | 2 | Default | 🟡 | Could model if collection is concrete: ∃ prefix ∈ set, `prefix.prefix(&s)` |
| `strings.any_suffix_match` | 2 | Default | 🟡 | Same approach with `suffix` |

### Integer-returning string builtins

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `indexof` | 2 | ✅ Z3 String | ✅ | `Z3_mk_seq_index(ctx, s, substr, 0)` — returns -1 if not found |
| `indexof_n` | 2 | Default | 🔴 | Returns array of all indices — no practical Z3 model |
| `strings.count` | 2 | Default | 🟡 | Count occurrences of substring. No direct Z3 op; could bound via `str.len` |

### String-returning string builtins

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `concat` | 2 | Default | 🟡 | OPA `concat(delimiter, collection)` joins a collection. If collection is concrete strings, could build `String::concat(ctx, &[...])`. If symbolic, not practical |
| `lower` | 1 | Default | 🟡 | Z3 has no native `toLower`. Could model as uninterpreted function with constraint `str.len(result) == str.len(input)` |
| `upper` | 1 | Default | 🟡 | Same as `lower` |
| `replace` | 3 | ✅ Z3 String | ✅ | `Z3_mk_seq_replace(ctx, s, old, new)` — replaces first occurrence |
| `substring` | 3 | ✅ Z3 String | ✅ | `Z3_mk_seq_extract(ctx, s, offset, length)` |
| `trim` | 2 | Default | 🟡 | No direct Z3 op. Could constrain: result is substring of input, `str.len(result) ≤ str.len(input)` |
| `trim_left` | 2 | Default | 🟡 | Partial: result is suffix of input |
| `trim_right` | 2 | Default | 🟡 | Partial: result is prefix of input |
| `trim_prefix` | 2 | ✅ Z3 String | ✅ | `ite(str.prefixof, str.substr, identity)` |
| `trim_suffix` | 2 | ✅ Z3 String | ✅ | `ite(str.suffixof, str.substr, identity)` |
| `trim_space` | 1 | Default | 🟡 | No direct Z3 op. Could constrain length |
| `split` | 2 | Default | 🔴 | Returns array of strings — would need symbolic array |
| `sprintf` | 2 | Default | 🔴 | Format string interpolation — not modelable |
| `format_int` | 2 | Default | 🔴 | Integer-to-string in arbitrary base — not practical |
| `strings.reverse` | 1 | Default | 🟡 | No direct Z3 op. Could constrain: `str.len(result) == str.len(input)` |
| `strings.replace_n` | 2 | Default | 🔴 | Multiple simultaneous replacements — not practical |

---

## 3. Regex (7 builtins, feature-gated)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `regex.match` | 2 | Bool | 🟡 | Z3 has `str.in.re` + regex algebra (`Regexp::literal`, `union`, `concat`, `star`, etc.). Works for **literal** patterns. OPA uses PCRE which has features (backrefs, lookahead) beyond Z3's regex theory |
| `regex.is_valid` | 1 | Default | ⚪ | Meta-validation — not relevant to symbolic analysis |
| `regex.find_n` | 3 | Default | 🔴 | Returns array of matches — not modelable |
| `regex.find_all_string_submatch_n` | 3 | Default | 🔴 | Returns nested arrays — not modelable |
| `regex.replace` | 3 | Default | 🔴 | Regex-based replacement — not directly in Z3 |
| `regex.split` | 2 | Default | 🔴 | Returns array — not modelable |
| `regex.template_match` | 4 | Default | 🔴 | Template-based matching — not modelable |

### Regex modeling notes

Z3's regex theory supports: literal strings, character ranges, union (`|`),
concatenation, Kleene star (`*`), plus (`+`), bounded repetition (`{n,m}`),
complement, and intersection. This covers many common patterns like
`[a-z]+`, `foo|bar`, `[0-9]{3}-[0-9]{4}`, etc.

**Not supported** by Z3's regex: backreferences (`\1`), lookahead/lookbehind
(`(?=...)`), non-greedy quantifiers (`*?`), and other PCRE extensions.

For `regex.match` with a **concrete pattern string**, we could:
1. Parse the regex pattern
2. If it uses only Z3-supported features, translate to `Regexp` and use `str.in.re`
3. Otherwise, fall back to unconstrained Bool

---

## 4. Numbers (7 builtins)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `abs` | 1 | ✅ Z3 Int | ✅ | `ite(x >= 0, x, -x)` — Z3 if-then-else on Int |
| `ceil` | 1 | Int | 🟡 | For integers, identity. For reals, Z3 has no native ceil; could use `ite(to_real(to_int(x)) == x, to_int(x), to_int(x) + 1)` |
| `floor` | 1 | Int | 🟡 | For integers, identity. For reals, `to_int(x)` (Z3's `to_int` floors) |
| `round` | 1 | Int | 🟡 | `floor(x + 0.5)` using the above |
| `numbers.range` | 2 | Default | 🔴 | Returns array — not modelable |
| `numbers.range_step` | 3 | Default | 🔴 | Returns array — not modelable |
| `rand.intn` | 2 | Default | 🔴 | Non-deterministic — not meaningful for symbolic analysis |

---

## 5. Conversions (1 builtin)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `to_number` | 1 | Int | 🟡 | String→Int: `Z3_mk_str_to_int`. Bool→Int: `ite(b, 1, 0)`. Null→Int: 0. Already-number: identity. The `str_to_int` only handles non-negative decimal integers |

---

## 6. Types (8 builtins)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `is_string` | 1 | ✅ Sort | ✅ | Resolves from concrete type, symbolic sort, or path registry |
| `is_number` | 1 | ✅ Sort | ✅ | Resolves from concrete type, symbolic sort (Int/Real), or path registry |
| `is_boolean` | 1 | ✅ Sort | ✅ | Same |
| `is_array` | 1 | ✅ Sort | ✅ | Concrete check + scalar-sort exclusion |
| `is_set` | 1 | ✅ Sort | ✅ | Same |
| `is_object` | 1 | ✅ Sort | ✅ | Same |
| `is_null` | 1 | ✅ Sort | ✅ | Same |
| `type_name` | 1 | Default | 🟡 | Could return concrete string if sort is known. Otherwise unconstrained from {"string","number","boolean","array","set","object","null"} — could model as Z3 enum or `str.in.re` membership |

---

## 7. Bitwise (6 builtins)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `bits.and` | 2 | ✅ Z3 BV | ✅ | `Int→BV64→bvand→BV64→Int` |
| `bits.or` | 2 | ✅ Z3 BV | ✅ | `Int→BV64→bvor→BV64→Int` |
| `bits.xor` | 2 | ✅ Z3 BV | ✅ | `Int→BV64→bvxor→BV64→Int` |
| `bits.negate` | 1 | ✅ Z3 BV | ✅ | `Int→BV64→bvnot→BV64→Int` |
| `bits.lsh` | 2 | ✅ Z3 BV | ✅ | `Int→BV64→bvshl→BV64→Int` |
| `bits.rsh` | 2 | ✅ Z3 BV | ✅ | `Int→BV64→bvlshr→BV64→Int` |

### Bitwise modeling notes

Z3's bitvector theory can model these precisely, but requires choosing a
fixed bit-width (e.g., 64-bit). Rego uses arbitrary-precision integers,
so there's a semantic gap for very large values. For practical policy
analysis, 64-bit bitvectors would be sufficient.

**Caveat**: Mixing Int and BV theories requires explicit conversions
(`int2bv`, `bv2int`), which can make Z3 solving slower.

---

## 8. Arrays (3 builtins)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `array.concat` | 2 | Default | 🔴 | Returns array — no symbolic array model |
| `array.reverse` | 1 | Default | 🔴 | Returns array |
| `array.slice` | 3 | Default | 🔴 | Returns array |

---

## 9. Sets (4 builtins)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `intersection` | 1 | Default | 🔴 | Set of sets → single set. Not practical |
| `union` | 1 | Default | 🔴 | Same |
| `__builtin_sets.union` | 2 | Default | 🟡 | Binary union. Could model cardinality: `|A∪B| ≤ |A|+|B|` |
| `__builtin_sets.intersection` | 2 | Default | 🟡 | Binary intersection. Could model: `|A∩B| ≤ min(|A|,|B|)` |

---

## 10. Object / JSON (11 builtins)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `object.get` | 3 | Default | 🟡 | If object and key are concrete, evaluate directly. Otherwise unconstrained |
| `object.keys` | 1 | Default | 🟡 | If object is concrete, return concrete set of keys |
| `object.filter` | 2 | Default | 🔴 | Returns filtered object |
| `object.remove` | 2 | Default | 🔴 | Returns modified object |
| `object.subset` | 2 | Default | 🟡 | Returns Bool — could check concrete objects |
| `object.union` | 2 | Default | 🔴 | Returns merged object |
| `object.union_n` | 1 | Default | 🔴 | Returns merged object |
| `json.filter` | 2 | Default | 🔴 | Returns filtered JSON |
| `json.remove` | 2 | Default | 🔴 | Returns modified JSON |
| `json.is_valid` | 1 | Default | 🟡 | Could return true for known-valid strings |
| `json.marshal` | 1 | Default | 🔴 | Serialization — not modelable |
| `json.marshal_with_options` | 2 | Default | 🔴 | Same |
| `json.unmarshal` | 1 | Default | 🔴 | Deserialization — returns object |
| `json.match_schema` | 2 | Default | 🔴 | Schema validation — complex |
| `json.verify_schema` | 1 | Default | 🔴 | Schema validation |

---

## 11. Encoding (15 builtins, mostly feature-gated)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `base64.encode` | 1 | Default | 🟡 | Could constrain: `str.len(result) == ceil(str.len(input) * 4/3)` rounded to multiple of 4 |
| `base64.decode` | 1 | Default | 🟡 | Inverse of encode — length constraints |
| `base64.is_valid` | 1 | Default | 🟡 | Could model via regex: `str.in.re([A-Za-z0-9+/=]*)` |
| `base64url.encode` | 1 | Default | 🟡 | Same as base64 with URL-safe alphabet |
| `base64url.decode` | 1 | Default | 🟡 | Same |
| `base64url.encode_no_pad` | 1 | Default | 🟡 | Same without padding |
| `hex.encode` | 1 | Default | 🟡 | Length constraint: `str.len(result) == 2 * str.len(input)` |
| `hex.decode` | 1 | Default | 🟡 | Inverse |
| `urlquery.encode` | 1 | Default | 🔴 | Percent-encoding is complex |
| `urlquery.decode` | 1 | Default | 🔴 | Same |
| `urlquery.encode_object` | 1 | Default | 🔴 | Object → query string |
| `urlquery.decode_object` | 1 | Default | 🔴 | Query string → object |
| `yaml.is_valid` | 1 | Default | 🔴 | YAML validation — not modelable |
| `yaml.marshal` | 1 | Default | 🔴 | Serialization |
| `yaml.unmarshal` | 1 | Default | 🔴 | Deserialization |

---

## 12. Glob (2 builtins, feature-gated)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `glob.match` | 3 | Default | 🟡 | Glob patterns are simpler than regex. Could translate `*` → `re.*`, `?` → `re.range`, etc., and use `str.in.re`. Practical for common patterns |
| `glob.quote_meta` | 1 | Default | 🔴 | String escaping — not meaningful for analysis |

---

## 13. Graph (3 builtins, feature-gated)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `graph.reachable` | 2 | Default | 🔴 | Transitive closure over graph — not practical in Z3 |
| `graph.reachable_paths` | 2 | Default | 🔴 | Returns all paths — not modelable |
| `walk` | 1 | Default | 🔴 | Tree traversal — not modelable |

---

## 14. Time (10 builtins, feature-gated)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `time.now_ns` | 0 | Default | 🟡 | Fresh non-negative Int (nanoseconds). Could constrain to plausible range |
| `time.parse_ns` | 2 | Default | 🔴 | String → timestamp. Format-dependent parsing |
| `time.parse_rfc3339_ns` | 1 | Default | 🔴 | RFC3339 string → Int |
| `time.parse_duration_ns` | 1 | Default | 🔴 | Duration string → Int |
| `time.date` | 1 | Default | 🔴 | Timestamp → [year, month, day] array |
| `time.clock` | 1 | Default | 🔴 | Timestamp → [hour, min, sec] array |
| `time.weekday` | 1 | Default | 🔴 | Timestamp → weekday string |
| `time.add_date` | 4 | Default | 🔴 | Calendar arithmetic |
| `time.diff` | 2 | Default | 🔴 | Returns [years, months, days, hours, mins, secs] |
| `time.format` | 1 | Default | 🔴 | Timestamp → formatted string |

---

## 15. Net (3 builtins, feature-gated)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `net.cidr_contains` | 2 | Default | 🟡 | For concrete CIDR + symbolic IP: could model as BV range check on parsed IP octets |
| `net.cidr_is_valid` | 1 | Default | 🟡 | Regex-based format validation |
| `net.cidr_expand` | 1 | Default | 🔴 | Returns set of IPs — not practical |

---

## 16. Semver (2 builtins, feature-gated)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `semver.compare` | 2 | Default | 🟡 | If both concrete: evaluate. If symbolic: result ∈ {-1, 0, 1} |
| `semver.is_valid` | 1 | Default | 🟡 | Could model as regex: `[0-9]+\.[0-9]+\.[0-9]+(-.*)?` |

---

## 17. UUID (2 builtins, feature-gated)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `uuid.rfc4122` | 1 | Default | 🟡 | Returns UUID string. Could constrain format via regex: `[0-9a-f]{8}-...` and `str.len == 36` |
| `uuid.parse` | 1 | Default | 🔴 | Returns object with UUID components |

---

## 18. HTTP (1 builtin, feature-gated)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `http.send` | 1 | Default | 🔴 | Network I/O — inherently non-modelable |

---

## 19. OPA Runtime (1 builtin, feature-gated)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `opa.runtime` | 0 | Default | ⚪ | Returns OPA metadata object — not relevant to policy analysis |

---

## 20. Tracing (1 builtin)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `trace` | 1 | ✅ Concrete | ✅ | Always returns concrete `true` |

---

## 21. Testing (1 builtin, feature-gated)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `test.sleep` | 1 | Default | ⚪ | Side-effect only — not relevant |

---

## 22. Units (2 builtins)

| Builtin | Arity | Current | Modelable | Z3 Approach |
|---------|-------|---------|-----------|-------------|
| `units.parse` | 1 | Default | 🔴 | String with unit suffix → number. Format-dependent |
| `units.parse_bytes` | 1 | Default | 🔴 | Same for byte units |

---

## Priority Implementation Plan

### Tier 1 — High value, easy to implement

These use Z3's native theories with direct API support:

| Builtin | Z3 Theory | Effort |
|---------|-----------|--------|
| `startswith` | `str.prefixof` | Low — direct API |
| `endswith` | `str.suffixof` | Low — direct API |
| `contains` | `str.contains` | Low — direct API |
| `indexof` | `Z3_mk_seq_index` | Low — unsafe FFI (pattern exists) |
| `replace` | `Z3_mk_seq_replace` | Low — unsafe FFI |
| `substring` | `Z3_mk_seq_extract` | Low — unsafe FFI |
| `trace` | Concrete `true` | Trivial |
| `abs` | `ite(x>=0, x, -x)` | Low |
| `is_*` (7) | Sort-based resolution | Medium — needs sort lookup |
| `trim_prefix` | Conditional `str.substr` | Medium |
| `trim_suffix` | Conditional `str.substr` | Medium |

### Tier 2 — Medium value, moderate effort

| Builtin | Z3 Theory | Effort |
|---------|-----------|--------|
| `regex.match` | `str.in.re` + regex parser | High — need to parse PCRE subset |
| `glob.match` | `str.in.re` + glob→regex | Medium |
| `type_name` | Sort-based String return | Medium |
| `lower`/`upper` | Uninterpreted + length equality | Low |
| `count` on strings | `Z3_mk_seq_length` | Low — already have the FFI |
| `to_number` | `Z3_mk_str_to_int` / `ite` | Medium |
| `bits.*` | BV theory | Medium — needs Int↔BV |
| `concat` (concrete collection) | `String::concat` | Medium |

### Tier 3 — Low value or high effort

| Category | Builtins | Reason |
|----------|----------|--------|
| Collection-returning | `sort`, `split`, `array.*`, `numbers.range*` | No symbolic array model |
| Serialization | `json.marshal`, `yaml.*` | Format-dependent |
| Network/Time/Graph | `http.send`, `time.*`, `graph.*` | External or complex semantics |
| Regex extraction | `regex.find_n`, `regex.split` | Returns collections |
| Format strings | `sprintf`, `format_int` | Format-dependent |

---

## Summary Statistics

| Category | Total | 🟢 Modelable | 🟡 Partial | 🔴 Not practical | ⚪ N/A |
|----------|-------|-------------|-----------|-----------------|--------|
| Aggregates | 6 | 1 | 4 | 1 | 0 |
| Strings | 25 | 6 | 10 | 9 | 0 |
| Regex | 7 | 0 | 1 | 6 | 0 |
| Numbers | 7 | 1 | 3 | 3 | 0 |
| Conversions | 1 | 0 | 1 | 0 | 0 |
| Types | 8 | 7 | 1 | 0 | 0 |
| Bitwise | 6 | 6 | 0 | 0 | 0 |
| Arrays | 3 | 0 | 0 | 3 | 0 |
| Sets | 4 | 0 | 2 | 2 | 0 |
| Objects/JSON | 15 | 0 | 3 | 12 | 0 |
| Encoding | 15 | 0 | 6 | 9 | 0 |
| Glob | 2 | 0 | 1 | 1 | 0 |
| Graph | 3 | 0 | 0 | 3 | 0 |
| Time | 10 | 0 | 1 | 9 | 0 |
| Net | 3 | 0 | 2 | 1 | 0 |
| Semver | 2 | 0 | 2 | 0 | 0 |
| UUID | 2 | 0 | 1 | 1 | 0 |
| HTTP | 1 | 0 | 0 | 1 | 0 |
| OPA | 1 | 0 | 0 | 0 | 1 |
| Tracing | 1 | 1 | 0 | 0 | 0 |
| Testing | 1 | 0 | 0 | 0 | 1 |
| Units | 2 | 0 | 0 | 2 | 0 |
| **Total** | **126** | **22** | **38** | **63** | **2** |

**Bottom line**: 22 builtins (17%) can be precisely modeled with Z3 theories.
Another 38 (30%) can be partially constrained. The remaining 63 (50%) are
not practically modelable and should remain as unconstrained symbolic
variables of the appropriate sort.

---

## Z3 Theory Usage Map

| Z3 Theory | Builtins it serves |
|-----------|-------------------|
| **Sequences/Strings** (`QF_SLIA`) | `startswith`, `endswith`, `contains`, `indexof`, `replace`, `substring`, `trim_prefix`, `trim_suffix`, `concat`, `lower`/`upper` (length), `count(string)`, `to_number` |
| **Regex** (`str.in.re`) | `regex.match`, `glob.match`, `base64.is_valid`, `semver.is_valid`, `uuid.rfc4122` (format) |
| **Integer arithmetic** (`QF_LIA`) | `abs`, `ceil`, `floor`, `round`, `count`, `sum`, `min`, `max` |
| **Bitvectors** (`QF_BV`) | `bits.and`, `bits.or`, `bits.xor`, `bits.negate`, `bits.lsh`, `bits.rsh` |
| **Bool** | `is_*` type checks, `trace` |
